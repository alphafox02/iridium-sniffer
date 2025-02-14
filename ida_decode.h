/*
 * IDA (Iridium Data) frame decoder + multi-burst reassembly
 */

#ifndef __IDA_DECODE_H__
#define __IDA_DECODE_H__

#include <stdint.h>
#include "qpsk_demod.h"
#include "burst_downmix.h"

/* LCW (Link Control Word) decoded fields */
typedef struct {
    int ft;             /* frame type: 2=IDA */
    int lcw_ok;         /* all 3 LCW components decoded */
} lcw_t;

/* Single IDA burst (after BCH decode, before reassembly) */
typedef struct {
    uint64_t timestamp;
    double frequency;
    ir_direction_t direction;
    float magnitude;
    int da_ctr;         /* sequence counter 0-7 */
    int da_len;         /* payload length in bytes */
    int cont;           /* continuation expected */
    uint8_t payload[32];
    int payload_len;
    int crc_ok;
} ida_burst_t;

/* Reassembly slot */
typedef struct {
    int active;
    ir_direction_t direction;
    double frequency;
    uint64_t last_timestamp;
    int last_ctr;
    uint8_t data[256];
    int data_len;
} ida_reassembly_t;

#define IDA_MAX_REASSEMBLY 16

/* Reassembly context */
typedef struct {
    ida_reassembly_t slots[IDA_MAX_REASSEMBLY];
} ida_context_t;

/* Callback for completed IDA messages */
typedef void (*ida_message_cb)(const uint8_t *data, int len,
                                uint64_t timestamp, double frequency,
                                ir_direction_t direction, float magnitude,
                                void *user);

/* Initialize IDA BCH syndrome tables. Call once at startup. */
void ida_decode_init(void);

/* Try to decode a demodulated frame as IDA.
 * Returns 1 if IDA detected, fills burst. 0 otherwise. */
int ida_decode(const demod_frame_t *frame, ida_burst_t *burst);

/* Feed a decoded burst into the reassembly engine.
 * Calls cb when a complete message is assembled. Returns 1 if emitted. */
int ida_reassemble(ida_context_t *ctx, const ida_burst_t *burst,
                   ida_message_cb cb, void *user);

/* Flush timed-out reassembly slots (call every frame). */
void ida_reassemble_flush(ida_context_t *ctx, uint64_t now_ns);

#endif
