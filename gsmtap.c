/*
 * GSMTAP output -- send reassembled IDA frames to Wireshark via UDP
 *
 * GSMTAP is a de-facto standard for feeding GSM protocol data to
 * Wireshark. We wrap Iridium LAPDm frames in a 16-byte GSMTAP header
 * and send them as UDP to port 4729 (Wireshark's default GSMTAP port).
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "gsmtap.h"

/* Packed GSMTAP header (16 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint8_t  hdr_len;
    uint8_t  type;
    uint8_t  timeslot;
    uint16_t arfcn;
    int8_t   signal_dbm;
    int8_t   snr_db;
    uint32_t frame_number;
    uint8_t  sub_type;
    uint8_t  antenna_nr;
    uint8_t  sub_slot;
    uint8_t  res;
} gsmtap_hdr_t;

static int gsmtap_fd = -1;
static struct sockaddr_in gsmtap_addr;

int gsmtap_init(const char *host, int port)
{
    gsmtap_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (gsmtap_fd < 0)
        return -1;

    memset(&gsmtap_addr, 0, sizeof(gsmtap_addr));
    gsmtap_addr.sin_family = AF_INET;
    gsmtap_addr.sin_port = htons(port);
    inet_pton(AF_INET, host ? host : GSMTAP_DEFAULT_HOST,
              &gsmtap_addr.sin_addr);
    return 0;
}

void gsmtap_send(const uint8_t *data, int len,
                 double frequency, ir_direction_t direction,
                 int8_t signal_dbm)
{
    if (gsmtap_fd < 0 || len <= 0)
        return;

    uint16_t fchan = (uint16_t)((frequency - IR_BASE_FREQ) / IR_CHANNEL_WIDTH);
    uint16_t arfcn = fchan;
    if (direction == DIR_UPLINK)
        arfcn |= GSMTAP_ARFCN_F_UPLINK;

    uint8_t pkt[16 + 256];
    if (len > 240) len = 240;

    gsmtap_hdr_t *hdr = (gsmtap_hdr_t *)pkt;
    hdr->version      = GSMTAP_VERSION;
    hdr->hdr_len      = GSMTAP_HDR_LEN;
    hdr->type          = GSMTAP_TYPE_ABIS;
    hdr->timeslot      = 0;
    hdr->arfcn         = htons(arfcn);
    hdr->signal_dbm    = signal_dbm;
    hdr->snr_db        = 0;
    hdr->frame_number  = htonl((uint32_t)frequency);
    hdr->sub_type      = GSMTAP_SUB_BCCH;
    hdr->antenna_nr    = 0;
    hdr->sub_slot      = 0;
    hdr->res           = 0;

    memcpy(pkt + 16, data, len);

    sendto(gsmtap_fd, pkt, 16 + len, 0,
           (struct sockaddr *)&gsmtap_addr, sizeof(gsmtap_addr));
}

void gsmtap_shutdown(void)
{
    if (gsmtap_fd >= 0) {
        close(gsmtap_fd);
        gsmtap_fd = -1;
    }
}
