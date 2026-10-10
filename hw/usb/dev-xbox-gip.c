/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Local Xbox GIP controller emulator used for protocol investigation.
 * This is intentionally a small startup-only model, not a general controller.
 */

#include "qemu/osdep.h"
#include "hw/usb/usb.h"
#include "hw/usb/desc.h"
#include "hw/core/qdev-properties.h"
#include "crypto/hash.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "migration/vmstate.h"
#include "qemu/timer.h"
#include "qemu/module.h"
#include "qom/object.h"

#define TYPE_USB_XBOX_GIP "usb-xbox-gip"
OBJECT_DECLARE_SIMPLE_TYPE(USBXboxGIPState, USB_XBOX_GIP)

#define GIP_EP_OUT 2
#define GIP_EP_IN  2
#define GIP_PACKET_MAX 64
#define GIP_QUEUE_DEPTH 32

#define GIP_OPT_ACK       0x10
#define GIP_OPT_INTERNAL  0x20
#define GIP_OPT_CHUNK_START 0x40
#define GIP_OPT_CHUNK     0x80

/*
 * UFU firmware update protocol, carried in GIP command 0x0c.  See
 * docs/firmware-update-host.md in the xbox-controller repository.  The
 * simulated flash covers every MERL component target address.
 */
#define UFU_FLASH_BASE    0x10000000u
#define UFU_FLASH_SIZE    0xa6000u
#define UFU_MAX_WRITE     0x1000u
#define UFU_MAX_MSG       (8 + UFU_MAX_WRITE)
#define UFU_MAX_COMPONENT 4
#define UFU_PARTITION_MAGIC 0x1a253a45u

/* Partition sizes a physical MERL controller (5.23.6.0) reports. */
static const uint32_t ufu_partition_sizes[UFU_MAX_COMPONENT + 1] = {
    [1] = 0x5000, [2] = 0x22000, [3] = 0x7e000, [4] = 0x7e000,
};

enum {
    UFU_GET_INFO = 0x00,
    UFU_GET_VERSION = 0x01,
    UFU_BEGIN_UPDATE = 0x02,
    UFU_GET_BLOCK_HASH = 0x03,
    UFU_WRITE_BLOCK = 0x04,
    UFU_COMPLETE_UPDATE = 0x05,
};

enum {
    UFU_OK = 0,
    UFU_INVALID_ARGUMENT = 1,
    UFU_UNKNOWN_COMPONENT = 2,
    UFU_MUST_RESET = 3,
    UFU_INVALID_RANGE = 5,
    UFU_UPDATE_NOT_IN_PROGRESS = 9,
    UFU_PROTOCOL_ERROR = 13,
};

typedef struct GIPFrame {
    uint8_t data[GIP_PACKET_MAX];
    uint8_t len;
} GIPFrame;

struct USBXboxGIPState {
    USBDevice dev;
    USBEndpoint *intr_in;
    QEMUTimer *hello_timer;
    /* Simulates the controller restarting on USB after a reset. */
    QEMUTimer *reboot_timer;
    bool reboot_detached;
    /*
     * After a restart the physical controller sends a single Hello. If the
     * host does not answer it with Start in time, the controller ignores the
     * host until it is unplugged; here, until QEMU restarts.
     */
    QEMUTimer *stuck_timer;
    bool rebooted;
    bool hello_once;
    bool awaiting_start;
    bool stuck;
    /* strict-hello: get stuck instead of only warning. */
    bool strict_hello;
    int64_t hello_read_ms;
    GIPFrame tx[GIP_QUEUE_DEPTH];
    unsigned int tx_head;
    unsigned int tx_count;
    uint8_t hello_sequence;
    uint8_t status_sequence;
    uint32_t rx_chunk_total;
    unsigned int metadata_ack_phase;
    /*
     * Firmware version reported in bcdDevice, Hello, and metadata.  The
     * defaults are the physical controller's 5.23.6.0.
     */
    uint16_t fw_major;
    uint16_t fw_minor;
    uint16_t fw_build;
    uint16_t fw_revision;
    USBDesc desc;
    uint8_t metadata_first[GIP_PACKET_MAX];
    /* Directory that receives each component after CompleteUpdate. */
    char *fw_dump_dir;
    uint8_t sys_sequence;
    uint8_t *ufu_flash;
    uint16_t ufu_versions[UFU_MAX_COMPONENT + 1][4];
    bool ufu_in_progress;
    /* BeginUpdate for component 4 already asked for its restart. */
    bool ufu_begin4_reset_done;
    uint32_t ufu_component;
    uint32_t ufu_address;
    uint32_t ufu_size;
    uint16_t ufu_version[4];
    uint8_t ufu_rx[UFU_MAX_MSG];
    uint32_t ufu_rx_total;
    uint32_t ufu_rx_filled;
    enum { GIP_ARRIVAL, GIP_METADATA, GIP_IDLE, GIP_ACTIVE, GIP_OFF } state;
};

static const USBDescStrings xbox_gip_strings = {
    [1] = "Microsoft",
    [2] = "Controller",
    [3] = "00000000000000000000aa8da38ded7e",
    /* Microsoft OS string: vendor request code 0x90. */
    [0xee] = "MSFT100\x90",
};

/* MS-GIPUSB Extended Compatible ID descriptor for a GIP controller with
 * the audio interface.  Windows first requests the 16-byte header, then the
 * complete 40-byte descriptor.
 */
static const uint8_t xbox_gip_compat_id[] = {
    0x28, 0x00, 0x00, 0x00, /* dwLength = 40 */
    0x00, 0x01,             /* bcdVersion = 1.0 */
    0x04, 0x00,             /* wIndex = Extended Compatible ID */
    0x01,                   /* bCount */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* reserved */
    0x00,                   /* first interface */
    0x02,                   /* GIP data + audio interfaces */
    'X', 'G', 'I', 'P', '1', '0', 0x00, 0x00, /* XGIP10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* sub-compatible ID */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* reserved */
};

static const USBDescEndpoint xbox_gip_ep_out = {
    .bEndpointAddress = 0x02,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = 64,
    .bInterval = 4,
};

static const USBDescEndpoint xbox_gip_ep_in = {
    .bEndpointAddress = USB_DIR_IN | 0x02,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = 64,
    .bInterval = 4,
};

static const USBDescEndpoint xbox_gip_ep_in_alt1 = {
    .bEndpointAddress = USB_DIR_IN | 0x02,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = 64,
    .bInterval = 2,
};

static const USBDescEndpoint xbox_gip_audio_out = {
    .bEndpointAddress = 0x03,
    .bmAttributes = USB_ENDPOINT_XFER_ISOC,
    .wMaxPacketSize = 228,
    .bInterval = 1,
};

static const USBDescEndpoint xbox_gip_audio_in = {
    .bEndpointAddress = USB_DIR_IN | 0x03,
    .bmAttributes = USB_ENDPOINT_XFER_ISOC,
    .wMaxPacketSize = 64,
    .bInterval = 1,
};

static const USBDescEndpoint xbox_gip_bulk_out = {
    .bEndpointAddress = 0x04,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = 64,
};

static const USBDescEndpoint xbox_gip_bulk_in = {
    .bEndpointAddress = USB_DIR_IN | 0x04,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = 64,
};

static const USBDescIface xbox_gip_ifaces[] = {
    {
        .bInterfaceNumber = 0,
        .bAlternateSetting = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = 0xff,
        .bInterfaceSubClass = 0x47,
        .bInterfaceProtocol = 0xd0,
        .eps = (USBDescEndpoint[]) { xbox_gip_ep_out, xbox_gip_ep_in },
    }, {
        .bInterfaceNumber = 0,
        .bAlternateSetting = 1,
        .bNumEndpoints = 2,
        .bInterfaceClass = 0xff,
        .bInterfaceSubClass = 0x47,
        .bInterfaceProtocol = 0xd0,
        .eps = (USBDescEndpoint[]) { xbox_gip_ep_out, xbox_gip_ep_in_alt1 },
    }, {
        .bInterfaceNumber = 1,
        .bAlternateSetting = 0,
        .bInterfaceClass = 0xff,
        .bInterfaceSubClass = 0x47,
        .bInterfaceProtocol = 0xd0,
    }, {
        .bInterfaceNumber = 1,
        .bAlternateSetting = 1,
        .bNumEndpoints = 2,
        .bInterfaceClass = 0xff,
        .bInterfaceSubClass = 0x47,
        .bInterfaceProtocol = 0xd0,
        .eps = (USBDescEndpoint[]) { xbox_gip_audio_out, xbox_gip_audio_in },
    }, {
        .bInterfaceNumber = 2,
        .bAlternateSetting = 0,
        .bInterfaceClass = 0xff,
        .bInterfaceSubClass = 0x47,
        .bInterfaceProtocol = 0xd0,
    }, {
        .bInterfaceNumber = 2,
        .bAlternateSetting = 1,
        .bNumEndpoints = 2,
        .bInterfaceClass = 0xff,
        .bInterfaceSubClass = 0x47,
        .bInterfaceProtocol = 0xd0,
        .eps = (USBDescEndpoint[]) { xbox_gip_bulk_out, xbox_gip_bulk_in },
    },
};

static const USBDescDevice xbox_gip_device = {
    .bcdUSB = 0x0200,
    .bDeviceClass = 0xff,
    .bDeviceSubClass = 0x47,
    .bDeviceProtocol = 0xd0,
    .bMaxPacketSize0 = 64,
    .bNumConfigurations = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces = 3,
            .bConfigurationValue = 1,
            .bmAttributes = USB_CFG_ATT_ONE | USB_CFG_ATT_WAKEUP,
            .bMaxPower = 250,
            .nif = ARRAY_SIZE(xbox_gip_ifaces),
            .ifs = xbox_gip_ifaces,
        },
    },
};

static const USBDesc xbox_gip_desc = {
    .id = {
        .idVendor = 0x045e,
        .idProduct = 0x0b12,
        .bcdDevice = 0x0517,
        .iManufacturer = 1,
        .iProduct = 2,
        .iSerialNumber = 3,
    },
    .full = &xbox_gip_device,
    .high = &xbox_gip_device,
    .str = xbox_gip_strings,
};

static const uint8_t metadata_frames[][GIP_PACKET_MAX] = {
    {
        0x04, 0xf0, 0x03, 0x3a, 0xa3, 0x02, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x01, 0xcd, 0x00,
        0x16, 0x00, 0x1b, 0x00, 0x1c, 0x00, 0x26, 0x00, 0x2f, 0x00, 0x4c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x17,
        0x00, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x0c, 0x0d, 0x1e,
        0x08, 0x01, 0x04, 0x05,
    },
    {
        0x04, 0xa0, 0x03, 0xba, 0x00, 0x3a, 0x06, 0x0a, 0x0c, 0x0d, 0x1e, 0x01,
        0x1a, 0x00, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2e, 0x58, 0x62,
        0x6f, 0x78, 0x2e, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x2e, 0x47, 0x61, 0x6d,
        0x65, 0x70, 0x61, 0x64, 0x08, 0x56, 0xff, 0x76, 0x97, 0xfd, 0x9b, 0x81,
        0x45, 0xad, 0x45, 0xb6, 0x45, 0xbb, 0xa5, 0x26, 0xd6, 0x2c, 0x40, 0x2e,
        0x08, 0xdf, 0x07, 0xe1,
    },
    {
        0x04, 0xa0, 0x03, 0xba, 0x00, 0x74, 0x45, 0xa5, 0xab, 0xa3, 0x12, 0x7a,
        0xf1, 0x97, 0xb5, 0xe7, 0x1f, 0xf3, 0xb8, 0x86, 0x73, 0xe9, 0x40, 0xa9,
        0xf8, 0x2f, 0x21, 0x26, 0x3a, 0xcf, 0xb7, 0xfe, 0xd2, 0xdd, 0xec, 0x87,
        0xd3, 0x94, 0x42, 0xbd, 0x96, 0x1a, 0x71, 0x2e, 0x3d, 0xc7, 0x7d, 0x6b,
        0xe5, 0xf2, 0x87, 0xbb, 0xc3, 0xb1, 0x49, 0x82, 0x65, 0xff, 0xff, 0xf3,
        0x77, 0x99, 0xee, 0x1e,
    },
    {
        0x04, 0xa0, 0x03, 0x3a, 0xae, 0x01, 0x9b, 0xad, 0x34, 0xad, 0x36, 0xb5,
        0x4f, 0x8a, 0xc7, 0x17, 0x23, 0x4c, 0x9f, 0x54, 0x6f, 0x77, 0xce, 0x34,
        0x7a, 0xe2, 0x7d, 0xc6, 0x45, 0x8c, 0xa4, 0x00, 0x42, 0xc0, 0x8b, 0xd9,
        0x4a, 0xc0, 0xc8, 0x96, 0xea, 0x16, 0xb2, 0x8b, 0x44, 0xbe, 0x80, 0x7e,
        0x5d, 0xeb, 0x06, 0x98, 0xe2, 0x03, 0x17, 0x00, 0x20, 0x2c, 0x00, 0x01,
        0x00, 0x10, 0x00, 0x00,
    },
    {
        0x04, 0xa0, 0x03, 0x3a, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x09, 0x3c, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x1e, 0x40, 0x00, 0x01,
        0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    },
    { 0x04, 0xb0, 0x03, 0x01, 0xa2, 0x02, 0x00 },
    { 0x04, 0xa0, 0x03, 0x00, 0xa3, 0x02 },
};

static const uint8_t metadata_lengths[] = { 64, 64, 64, 64, 64, 7, 6 };

static void xbox_gip_log_packet(const char *direction,
                                const uint8_t *data, size_t len)
{
    size_t i;

    fprintf(stderr, "Xbox GIP %s (%zu bytes):", direction, len);
    for (i = 0; i < len; i++) {
        fprintf(stderr, " %02x", data[i]);
    }
    fputc('\n', stderr);
}

static void xbox_gip_enqueue(USBXboxGIPState *s, const uint8_t *data, size_t len)
{
    unsigned int tail;

    if (len > GIP_PACKET_MAX || s->tx_count == GIP_QUEUE_DEPTH) {
        fprintf(stderr, "Xbox GIP IN queue full; dropped %zu bytes\n", len);
        return;
    }
    tail = (s->tx_head + s->tx_count) % GIP_QUEUE_DEPTH;
    memcpy(s->tx[tail].data, data, len);
    s->tx[tail].len = len;
    s->tx_count++;
    usb_wakeup(s->intr_in, 0);
}

static void xbox_gip_hello(void *opaque)
{
    USBXboxGIPState *s = opaque;
    uint8_t hello[32] = {
        0x02, 0x20, 0, 0x1c,
        0x7e, 0xed, 0x8d, 0xa3, 0x8d, 0xaa, 0x00, 0x00,
        0x5e, 0x04, 0x12, 0x0b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x01, 0x00,
        0x01, 0x00, 0x01, 0x00,
    };

    stw_le_p(&hello[16], s->fw_major);
    stw_le_p(&hello[18], s->fw_minor);
    stw_le_p(&hello[20], s->fw_build);
    stw_le_p(&hello[22], s->fw_revision);

    if (s->state == GIP_ARRIVAL && !s->awaiting_start && !s->stuck) {
        hello[2] = s->hello_sequence++;
        if (s->hello_sequence == 0) {
            s->hello_sequence = 1;
        }
        xbox_gip_enqueue(s, hello, sizeof(hello));
        if (s->hello_once) {
            /*
             * After a restart: one Hello, then wait for Start. The deadline
             * starts once the host has read the Hello (xbox_gip_handle_data).
             */
            s->hello_once = false;
            s->awaiting_start = true;
            return;
        }
    }
    timer_mod(s->hello_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
}

static void xbox_gip_stuck(void *opaque)
{
    USBXboxGIPState *s = opaque;

    if (!s->strict_hello) {
        fprintf(stderr, "Xbox GIP Hello after restart not answered after 10 s "
                "(continuing; strict-hello=on would stop here)\n");
        return;
    }
    s->awaiting_start = false;
    s->stuck = true;
    fprintf(stderr, "Xbox GIP Hello after restart was not answered; "
            "ignoring the host from now on (restart QEMU to recover)\n");
}

static bool xbox_gip_is_metadata_ack(const uint8_t *buf, size_t len)
{
    return len >= 6 && buf[0] == 0x01 && buf[3] >= 2 &&
           buf[4] == 0x00 && buf[5] == 0x04;
}

/* GIP lengths and chunk offsets are little-endian base-128 varints. */
static bool xbox_gip_read_varint(const uint8_t *buf, size_t len, size_t *pos,
                                 uint32_t *value)
{
    unsigned int shift = 0;

    *value = 0;
    while (*pos < len && shift < 28) {
        uint8_t b = buf[(*pos)++];
        *value |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            return true;
        }
        shift += 7;
    }
    return false;
}

/*
 * Acknowledge a host message that has GIP_OPT_ACK set.  The payload matches
 * the physical controller's ACKs: reserved byte, acknowledged command,
 * options, bytes received so far, two padding bytes, bytes remaining.
 */
static void xbox_gip_ack(USBXboxGIPState *s, const uint8_t *buf, size_t len)
{
    size_t pos = 3;
    uint32_t payload_len, offset = 0, received, remaining = 0;
    uint8_t ack[13] = { 0x01, GIP_OPT_INTERNAL, buf[2], 0x09, 0x00, buf[0],
                        GIP_OPT_INTERNAL | (buf[1] & 0x0f) };

    if (!xbox_gip_read_varint(buf, len, &pos, &payload_len)) {
        return;
    }
    if (buf[1] & GIP_OPT_CHUNK) {
        if (!xbox_gip_read_varint(buf, len, &pos, &offset)) {
            return;
        }
        if (buf[1] & GIP_OPT_CHUNK_START) {
            /* The first chunk carries the total length instead of offset 0. */
            s->rx_chunk_total = offset;
            offset = 0;
        }
    }
    received = offset + payload_len;
    if (buf[1] & GIP_OPT_CHUNK && s->rx_chunk_total > received) {
        remaining = s->rx_chunk_total - received;
    }
    stw_le_p(&ack[7], received);
    stw_le_p(&ack[11], remaining);
    xbox_gip_enqueue(s, ack, sizeof(ack));
}

static void xbox_gip_send_power_off(USBXboxGIPState *s)
{
    uint8_t status[] = {
        0x03, 0x20, s->status_sequence++, 0x04,
        0x00, 0x00, 0x00, 0x00,
    };

    if (s->status_sequence == 0) {
        s->status_sequence = 1;
    }
    xbox_gip_enqueue(s, status, sizeof(status));
}

static void xbox_gip_ufu_reply(USBXboxGIPState *s, const uint8_t *payload,
                               size_t len)
{
    uint8_t packet[GIP_PACKET_MAX] = { 0x0c, GIP_OPT_INTERNAL };

    assert(len <= GIP_PACKET_MAX - 4);
    packet[2] = s->sys_sequence++;
    if (s->sys_sequence == 0) {
        s->sys_sequence = 1;
    }
    packet[3] = len;
    memcpy(&packet[4], payload, len);
    xbox_gip_enqueue(s, packet, len + 4);
}

static bool xbox_gip_ufu_range_ok(uint32_t address, uint32_t size)
{
    return address >= UFU_FLASH_BASE &&
           (uint64_t)address + size <= (uint64_t)UFU_FLASH_BASE + UFU_FLASH_SIZE;
}

static void xbox_gip_ufu_dump(USBXboxGIPState *s)
{
    g_autofree char *path = NULL;
    g_autoptr(GError) err = NULL;

    if (!s->fw_dump_dir) {
        return;
    }
    path = g_strdup_printf("%s/ufu-c%u-%08x.bin", s->fw_dump_dir,
                           s->ufu_component, s->ufu_address);
    if (g_file_set_contents(path,
                            (const char *)s->ufu_flash +
                            (s->ufu_address - UFU_FLASH_BASE),
                            s->ufu_size, &err)) {
        fprintf(stderr, "Xbox UFU wrote component %u to %s\n",
                s->ufu_component, path);
    } else {
        fprintf(stderr, "Xbox UFU could not write %s: %s\n", path,
                err->message);
    }
}

/*
 * Handle one reassembled UFU request.  Error replies are padded to the
 * host's minimum response length so that it sees the status.
 */
static void xbox_gip_ufu_command(USBXboxGIPState *s, const uint8_t *req,
                                 size_t len)
{
    uint8_t rsp[60] = { 0 };
    size_t rsp_len = 2;
    uint32_t id, address, size;

    if (len < 1) {
        return;
    }
    rsp[0] = req[0];
    rsp[1] = UFU_OK;

    switch (req[0]) {
    case UFU_GET_INFO:
        fprintf(stderr, "Xbox UFU GetInfo\n");
        rsp[2] = 0x02;  /* protocol: anything but 1 (legacy) */
        stw_le_p(&rsp[4], 0x045e);
        stw_le_p(&rsp[6], 0x0b12);
        stl_le_p(&rsp[8], UFU_MAX_WRITE);
        rsp_len = 60;
        break;
    case UFU_GET_VERSION:
        rsp_len = 14;
        if (len != 5) {
            rsp[1] = UFU_INVALID_ARGUMENT;
            break;
        }
        id = ldl_le_p(&req[1]);
        stl_le_p(&rsp[2], id);
        if (id == 0 || id > UFU_MAX_COMPONENT) {
            rsp[1] = UFU_UNKNOWN_COMPONENT;
        } else {
            for (int i = 0; i < 4; i++) {
                stw_le_p(&rsp[6 + i * 2], s->ufu_versions[id][i]);
            }
            /* Optional tail: magic, 4 unknown bytes, partition size. */
            stl_le_p(&rsp[14], UFU_PARTITION_MAGIC);
            stl_le_p(&rsp[22], ufu_partition_sizes[id]);
            rsp_len = 26;
        }
        fprintf(stderr, "Xbox UFU GetVersion component=%u status=%u\n",
                id, rsp[1]);
        break;
    case UFU_BEGIN_UPDATE:
        if (len != 21) {
            rsp[1] = UFU_INVALID_ARGUMENT;
            break;
        }
        id = ldl_le_p(&req[1]);
        address = ldl_le_p(&req[5]);
        size = ldl_le_p(&req[9]);
        if (id == 0 || id > UFU_MAX_COMPONENT) {
            rsp[1] = UFU_UNKNOWN_COMPONENT;
        } else if (!xbox_gip_ufu_range_ok(address, size)) {
            rsp[1] = UFU_INVALID_RANGE;
        } else if (id == 4 && !s->ufu_begin4_reset_done) {
            /* The physical controller restarts before writing component 4. */
            s->ufu_begin4_reset_done = true;
            rsp[1] = UFU_MUST_RESET;
        } else {
            if (id == 4) {
                s->ufu_begin4_reset_done = false;
            }
            s->ufu_in_progress = true;
            s->ufu_component = id;
            s->ufu_address = address;
            s->ufu_size = size;
            for (int i = 0; i < 4; i++) {
                s->ufu_version[i] = lduw_le_p(&req[13 + i * 2]);
            }
            /* Erase like real flash so that every block is rewritten. */
            memset(s->ufu_flash + (address - UFU_FLASH_BASE), 0xff, size);
        }
        fprintf(stderr, "Xbox UFU BeginUpdate component=%u address=0x%08x "
                "size=0x%x version=%u.%u.%u.%u status=%u\n",
                id, address, size, lduw_le_p(&req[13]), lduw_le_p(&req[15]),
                lduw_le_p(&req[17]), lduw_le_p(&req[19]), rsp[1]);
        break;
    case UFU_GET_BLOCK_HASH: {
        uint8_t *digest = &rsp[2];
        size_t digest_len = 20;

        rsp_len = 22;
        if (len != 9) {
            rsp[1] = UFU_INVALID_ARGUMENT;
            break;
        }
        address = ldl_le_p(&req[1]);
        size = ldl_le_p(&req[5]);
        if (!xbox_gip_ufu_range_ok(address, size) ||
            qcrypto_hash_bytes(QCRYPTO_HASH_ALGO_SHA1,
                               s->ufu_flash + (address - UFU_FLASH_BASE),
                               size, &digest, &digest_len, NULL) < 0) {
            rsp[1] = UFU_INVALID_RANGE;
        }
        fprintf(stderr, "Xbox UFU GetBlockHash address=0x%08x size=0x%x "
                "status=%u\n", address, size, rsp[1]);
        break;
    }
    case UFU_WRITE_BLOCK:
        if (len < 8) {
            rsp[1] = UFU_INVALID_ARGUMENT;
            break;
        }
        address = ldl_le_p(&req[4]);
        size = len - 8;
        if (!s->ufu_in_progress) {
            rsp[1] = UFU_UPDATE_NOT_IN_PROGRESS;
        } else if (address < s->ufu_address ||
                   (uint64_t)address + size >
                   (uint64_t)s->ufu_address + s->ufu_size) {
            rsp[1] = UFU_INVALID_RANGE;
        } else {
            memcpy(s->ufu_flash + (address - UFU_FLASH_BASE), &req[8], size);
        }
        fprintf(stderr, "Xbox UFU WriteBlock address=0x%08x size=0x%x "
                "status=%u\n", address, size, rsp[1]);
        break;
    case UFU_COMPLETE_UPDATE:
        if (!s->ufu_in_progress) {
            rsp[1] = UFU_UPDATE_NOT_IN_PROGRESS;
        } else {
            s->ufu_in_progress = false;
            /*
             * The physical controller answers MustReset for every component;
             * the host then resets it and it restarts on USB before the
             * update continues.
             */
            rsp[1] = UFU_MUST_RESET;
            memcpy(s->ufu_versions[s->ufu_component], s->ufu_version,
                   sizeof(s->ufu_version));
            xbox_gip_ufu_dump(s);
            if (s->ufu_component == 3) {
                /* Component 3 is the application; report its version. */
                s->fw_major = s->ufu_version[0];
                s->fw_minor = s->ufu_version[1];
                s->fw_build = s->ufu_version[2];
                s->fw_revision = s->ufu_version[3];
                stw_le_p(&s->metadata_first[45], s->fw_major);
                stw_le_p(&s->metadata_first[47], s->fw_minor);
                /* Seen by the host when the device re-enumerates. */
                s->desc.id.bcdDevice = ((s->fw_major & 0xff) << 8) |
                                       (s->fw_minor & 0xff);
            }
        }
        fprintf(stderr, "Xbox UFU CompleteUpdate component=%u status=%u\n",
                s->ufu_component, rsp[1]);
        break;
    default:
        fprintf(stderr, "Xbox UFU unknown op 0x%02x\n", req[0]);
        rsp[1] = UFU_PROTOCOL_ERROR;
        break;
    }
    xbox_gip_ufu_reply(s, rsp, rsp_len);
}

/* Reassemble chunked GIP 0x0c messages; WriteBlock is up to 0x1008 bytes. */
static void xbox_gip_ufu_packet(USBXboxGIPState *s, const uint8_t *buf,
                                size_t len)
{
    size_t pos = 3;
    uint32_t payload_len, offset;

    if (!xbox_gip_read_varint(buf, len, &pos, &payload_len)) {
        return;
    }
    if (!(buf[1] & GIP_OPT_CHUNK)) {
        if (pos + payload_len <= len) {
            xbox_gip_ufu_command(s, &buf[pos], payload_len);
        }
        return;
    }
    if (!xbox_gip_read_varint(buf, len, &pos, &offset) ||
        pos + payload_len > len) {
        return;
    }
    if (buf[1] & GIP_OPT_CHUNK_START) {
        /* The first chunk carries the total length instead of offset 0. */
        if (offset > UFU_MAX_MSG) {
            fprintf(stderr, "Xbox UFU message too large: %u bytes\n", offset);
            s->ufu_rx_total = 0;
            return;
        }
        s->ufu_rx_total = offset;
        s->ufu_rx_filled = 0;
        offset = 0;
    }
    if (!s->ufu_rx_total || !payload_len) {
        return;
    }
    if ((uint64_t)offset + payload_len > s->ufu_rx_total) {
        fprintf(stderr, "Xbox UFU chunk outside message: offset=%u len=%u\n",
                offset, payload_len);
        return;
    }
    memcpy(&s->ufu_rx[offset], &buf[pos], payload_len);
    s->ufu_rx_filled = MAX(s->ufu_rx_filled, offset + payload_len);
    if (s->ufu_rx_filled == s->ufu_rx_total) {
        s->ufu_rx_total = 0;
        xbox_gip_ufu_command(s, s->ufu_rx, s->ufu_rx_filled);
    }
}

static void xbox_gip_reboot(void *opaque)
{
    USBXboxGIPState *s = opaque;
    Error *err = NULL;

    if (!s->reboot_detached) {
        fprintf(stderr, "Xbox GIP USB detach\n");
        usb_device_detach(&s->dev);
        s->reboot_detached = true;
        timer_mod(s->reboot_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
        return;
    }
    s->reboot_detached = false;
    s->rebooted = true;
    fprintf(stderr, "Xbox GIP USB attach\n");
    usb_device_attach(&s->dev, &err);
    if (err) {
        error_report_err(err);
    }
}

static void xbox_gip_host_packet(USBXboxGIPState *s,
                                 const uint8_t *buf, size_t len)
{
    if (len < 4 || s->stuck) {
        return;
    }
    if (s->awaiting_start && s->hello_read_ms) {
        /* Record how the host answers a restarted controller. */
        fprintf(stderr, "Xbox GIP first host message after restart Hello, "
                "%" PRId64 " ms after it was read: %02x %02x %02x %02x\n",
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) - s->hello_read_ms,
                buf[0], buf[1], buf[2], buf[3]);
        s->hello_read_ms = 0;
    }
    if (buf[1] & GIP_OPT_ACK && buf[0] != 0x01) {
        xbox_gip_ack(s, buf, len);
    }
    if (buf[0] == 0x0c) {
        xbox_gip_ufu_packet(s, buf, len);
        return;
    }
    if (len < (size_t)buf[3] + 4) {
        return;
    }

    if (buf[0] == 0x04 && buf[3] == 0) {
        s->state = GIP_METADATA;
        s->metadata_ack_phase = 1;
        xbox_gip_enqueue(s, s->metadata_first, metadata_lengths[0]);
    } else if (xbox_gip_is_metadata_ack(buf, len)) {
        if (s->metadata_ack_phase == 1) {
            unsigned int i;
            s->metadata_ack_phase = 2;
            for (i = 1; i <= 5; i++) {
                xbox_gip_enqueue(s, metadata_frames[i], metadata_lengths[i]);
            }
        } else if (s->metadata_ack_phase == 2) {
            s->metadata_ack_phase = 0;
            s->state = GIP_IDLE;
            xbox_gip_enqueue(s, metadata_frames[6], metadata_lengths[6]);
        }
    } else if (buf[0] == 0x05 && buf[3] == 1) {
        switch (buf[4]) {
        case 0x00:
            s->state = GIP_ACTIVE;
            if (s->awaiting_start) {
                s->awaiting_start = false;
                timer_del(s->stuck_timer);
            }
            break;
        case 0x01:
            s->state = GIP_IDLE;
            break;
        case 0x04:
            s->state = GIP_OFF;
            xbox_gip_send_power_off(s);
            break;
        case 0x07:
            /*
             * Reset: the physical controller sends a power-off status (the
             * Windows updater treats it as the disconnect), drops off USB,
             * re-enumerates and sends a single Hello.
             */
            xbox_gip_send_power_off(s);
            s->state = GIP_OFF;
            fprintf(stderr, "Xbox GIP restarting on USB\n");
            /* The physical controller disconnects 1-3.6 s later. */
            timer_mod(s->reboot_timer,
                      qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1500);
            break;
        default:
            break;
        }
    }
}

static void xbox_gip_handle_control(USBDevice *dev, USBPacket *p,
                                    int request, int value, int index,
                                    int length, uint8_t *data)
{
    int ret;

    if (request == 0xc090 && value == 0 && index == 0x0004) {
        p->actual_length = MIN(length, sizeof(xbox_gip_compat_id));
        memcpy(data, xbox_gip_compat_id, p->actual_length);
        ret = 0;
    } else {
        ret = usb_desc_handle_control(dev, p, request, value, index, length,
                                      data);
    }

    fprintf(stderr,
            "Xbox USB control: request=0x%02x value=0x%04x index=0x%04x "
            "length=%d result=%d actual=%d\n",
            request, value, index, length, ret, p->actual_length);
    if (ret >= 0 && p->actual_length > 0 &&
        (request & 0x60) == 0 && (request & 0x0f) == USB_REQ_GET_DESCRIPTOR) {
        xbox_gip_log_packet("USB descriptor", data, p->actual_length);
    }
    if (ret < 0) {
        p->status = USB_RET_STALL;
    }
}

static void xbox_gip_handle_data(USBDevice *dev, USBPacket *p)
{
    USBXboxGIPState *s = USB_XBOX_GIP(dev);

    if (p->ep->nr != GIP_EP_IN) {
        p->status = USB_RET_STALL;
        return;
    }

    if (p->pid == USB_TOKEN_IN) {
        GIPFrame *frame;
        if (!s->tx_count) {
            p->status = USB_RET_NAK;
            return;
        }
        frame = &s->tx[s->tx_head];
        {
            size_t len = MIN(frame->len, p->iov.size);
            usb_packet_copy(p, frame->data, len);
            if (frame->data[0] == 0x02 && s->awaiting_start &&
                !timer_pending(s->stuck_timer)) {
                /* The host has the restart Hello; it must answer in time. */
                s->hello_read_ms = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
                timer_mod(s->stuck_timer, s->hello_read_ms + 10000);
            }
            /* Skip ACKs of UFU messages; the UFU log lines cover them. */
            if (!(frame->data[0] == 0x01 && frame->data[5] == 0x0c)) {
                xbox_gip_log_packet("IN", frame->data, len);
            }
        }
        s->tx_head = (s->tx_head + 1) % GIP_QUEUE_DEPTH;
        s->tx_count--;
    } else if (p->pid == USB_TOKEN_OUT) {
        uint8_t buf[GIP_PACKET_MAX];
        size_t len = MIN(sizeof(buf), p->iov.size);
        usb_packet_copy(p, buf, len);
        /* Skip WriteBlock continuation chunks to keep the log readable. */
        if (!(buf[0] == 0x0c && buf[1] & GIP_OPT_CHUNK &&
              !(buf[1] & GIP_OPT_CHUNK_START))) {
            xbox_gip_log_packet("OUT", buf, len);
        }
        xbox_gip_host_packet(s, buf, len);
    } else {
        p->status = USB_RET_STALL;
    }
}

static void xbox_gip_reset(USBDevice *dev)
{
    USBXboxGIPState *s = USB_XBOX_GIP(dev);

    s->tx_head = 0;
    s->tx_count = 0;
    s->hello_sequence = 0x02;
    s->status_sequence = 0x01;
    s->metadata_ack_phase = 0;
    s->state = GIP_ARRIVAL;
    if (s->rebooted || s->awaiting_start) {
        /*
         * After a restart, and again on every bus reset until the Hello is
         * answered: the reset clears the IN queue, so announce again.
         */
        s->rebooted = false;
        s->awaiting_start = false;
        s->hello_once = true;
        timer_del(s->stuck_timer);
    }
    timer_mod(s->hello_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
}

static void xbox_gip_realize(USBDevice *dev, Error **errp)
{
    USBXboxGIPState *s = USB_XBOX_GIP(dev);

    /*
     * The physical controller reports 5.23 as bcdDevice 0x0517 and as the
     * metadata's major/minor pair; keep both in step with the Hello version.
     */
    s->desc = xbox_gip_desc;
    s->desc.id.bcdDevice = ((s->fw_major & 0xff) << 8) | (s->fw_minor & 0xff);
    dev->usb_desc = &s->desc;
    memcpy(s->metadata_first, metadata_frames[0], sizeof(s->metadata_first));
    stw_le_p(&s->metadata_first[45], s->fw_major);
    stw_le_p(&s->metadata_first[47], s->fw_minor);
    fprintf(stderr, "Xbox GIP firmware version %u.%u.%u.%u\n",
            s->fw_major, s->fw_minor, s->fw_build, s->fw_revision);

    s->ufu_flash = g_malloc(UFU_FLASH_SIZE);
    memset(s->ufu_flash, 0xff, UFU_FLASH_SIZE);
    for (int id = 1; id <= UFU_MAX_COMPONENT; id++) {
        s->ufu_versions[id][0] = s->fw_major;
        s->ufu_versions[id][1] = s->fw_minor;
        s->ufu_versions[id][2] = s->fw_build;
        s->ufu_versions[id][3] = s->fw_revision;
    }
    s->sys_sequence = 0x01;

    usb_desc_init(dev);
    if (dev->serial) {
        usb_desc_create_serial(dev);
    }
    s->intr_in = usb_ep_get(dev, USB_TOKEN_IN, GIP_EP_IN);
    s->hello_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, xbox_gip_hello, s);
    s->reboot_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, xbox_gip_reboot, s);
    s->stuck_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, xbox_gip_stuck, s);
    s->hello_sequence = 0x02;
    s->status_sequence = 0x01;
    s->state = GIP_ARRIVAL;
    timer_mod(s->hello_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1);
}

static void xbox_gip_unrealize(USBDevice *dev)
{
    USBXboxGIPState *s = USB_XBOX_GIP(dev);
    timer_free(s->hello_timer);
    timer_free(s->reboot_timer);
    timer_free(s->stuck_timer);
    g_free(s->ufu_flash);
}

static const VMStateDescription vmstate_usb_xbox_gip = {
    .name = "usb-xbox-gip",
    .unmigratable = 1,
};

static const Property xbox_gip_properties[] = {
    DEFINE_PROP_UINT16("fw-major", USBXboxGIPState, fw_major, 5),
    DEFINE_PROP_UINT16("fw-minor", USBXboxGIPState, fw_minor, 23),
    DEFINE_PROP_UINT16("fw-build", USBXboxGIPState, fw_build, 6),
    DEFINE_PROP_UINT16("fw-revision", USBXboxGIPState, fw_revision, 0),
    DEFINE_PROP_STRING("fw-dump-dir", USBXboxGIPState, fw_dump_dir),
    DEFINE_PROP_BOOL("strict-hello", USBXboxGIPState, strict_hello, false),
};

static void xbox_gip_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);

    uc->product_desc = "Xbox Controller";
    uc->usb_desc = &xbox_gip_desc;
    uc->realize = xbox_gip_realize;
    uc->unrealize = xbox_gip_unrealize;
    uc->handle_reset = xbox_gip_reset;
    uc->handle_control = xbox_gip_handle_control;
    uc->handle_data = xbox_gip_handle_data;
    uc->handle_attach = usb_desc_attach;
    dc->desc = "Experimental Xbox GIP controller";
    dc->vmsd = &vmstate_usb_xbox_gip;
    device_class_set_props(dc, xbox_gip_properties);
}

static const TypeInfo xbox_gip_type_info = {
    .name = TYPE_USB_XBOX_GIP,
    .parent = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBXboxGIPState),
    .class_init = xbox_gip_class_init,
};

static void xbox_gip_register_types(void)
{
    type_register_static(&xbox_gip_type_info);
}

type_init(xbox_gip_register_types)
