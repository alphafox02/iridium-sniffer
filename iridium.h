/*
 * Iridium protocol constants
 */

#ifndef __IRIDIUM_H__
#define __IRIDIUM_H__

#define IR_SYMBOLS_PER_SECOND    25000
#define IR_UW_LENGTH             12

#define IR_SIMPLEX_FREQUENCY_MIN 1626000000

#define IR_PREAMBLE_LENGTH_SHORT 16
#define IR_PREAMBLE_LENGTH_LONG  64

#define IR_MIN_FRAME_LENGTH_NORMAL  131  /* IBC frame */
#define IR_MAX_FRAME_LENGTH_NORMAL  191

#define IR_MIN_FRAME_LENGTH_SIMPLEX  80  /* Single page IRA */
#define IR_MAX_FRAME_LENGTH_SIMPLEX 444

/* Unique words (DQPSK symbols, not bits) */
static const int IR_UW_DL[] = { 0, 2, 2, 2, 2, 0, 0, 0, 2, 0, 0, 2 };
static const int IR_UW_UL[] = { 2, 2, 0, 0, 0, 2, 0, 0, 2, 0, 2, 2 };

/* Default center frequency for Iridium L-band */
#define IR_DEFAULT_CENTER_FREQ   1622000000

/* Default burst detection threshold in dB */
#define IR_DEFAULT_THRESHOLD     18.0f

/* Default burst width in Hz */
#define IR_DEFAULT_BURST_WIDTH   40000

/* Default samples per symbol */
#define IR_DEFAULT_SPS           10

/* Default noise floor history size (FFT frames) */
#define IR_DEFAULT_HISTORY_SIZE  512

/* Default burst pre/post lengths as fraction of sample rate */
#define IR_BURST_POST_MS         16  /* ms of signal to keep after burst ends */

/* Maximum burst duration: 90 ms */
#define IR_MAX_BURST_MS          90

#endif
