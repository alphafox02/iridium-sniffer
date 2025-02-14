/*
 * GSMTAP output -- send reassembled IDA frames to Wireshark via UDP
 */

#ifndef __GSMTAP_H__
#define __GSMTAP_H__

#include <stdint.h>
#include "burst_downmix.h"

/* GSMTAP protocol constants */
#define GSMTAP_VERSION          2
#define GSMTAP_HDR_LEN          4       /* 32-bit words = 16 bytes */
#define GSMTAP_TYPE_ABIS        2
#define GSMTAP_SUB_BCCH         1
#define GSMTAP_ARFCN_F_UPLINK   0x4000

#define GSMTAP_DEFAULT_HOST     "127.0.0.1"
#define GSMTAP_DEFAULT_PORT     4729

/* Iridium L-band channelization */
#define IR_BASE_FREQ            1616000000.0
#define IR_CHANNEL_WIDTH        41666.667

/* Initialize GSMTAP UDP socket. Returns 0 on success, -1 on error. */
int gsmtap_init(const char *host, int port);

/* Send a reassembled IDA message as GSMTAP/LAPDm packet. */
void gsmtap_send(const uint8_t *data, int len,
                 double frequency, ir_direction_t direction,
                 int8_t signal_dbm);

/* Close the GSMTAP socket. */
void gsmtap_shutdown(void);

#endif
