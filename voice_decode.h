/*
 * Iridium voice decoder: VOC clustering, AMBE decode, call management
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMBE codec: Copyright (c) 2015 Sylvain Munaut <tnt@246tNt.com>
 * Licensed under AGPL-3.0-or-later (see codec/LICENSE)
 */

#ifndef __VOICE_DECODE_H__
#define __VOICE_DECODE_H__

#include <stdint.h>
#include "frame_decode.h"

#define VOICE_MAX_CALLS     100     /* circular buffer size */
#define VOICE_MAX_FRAMES    2000    /* max frames per call (~3 min) */
#define VOICE_CLUSTER_FREQ  20000.0 /* max freq diff to same call (Hz) */
#define VOICE_CLUSTER_TIME  20.0    /* max time gap before new call (sec) */
#define VOICE_SAMPLE_RATE   8000
#define VOICE_SAMPLES_PER_SF 720    /* PCM samples per superframe */

typedef enum {
    VOICE_QUALITY_GOOD = 0,
    VOICE_QUALITY_FAIR,
    VOICE_QUALITY_POOR,
} voice_quality_t;

/* Completed voice call */
typedef struct {
    int valid;
    uint64_t start_time;        /* timestamp of first frame (ns) */
    uint64_t end_time;          /* timestamp of last frame (ns) */
    double frequency;           /* mean frequency (Hz) */
    int n_frames;               /* total VOC frames received */
    voice_quality_t quality;
    int16_t *audio;             /* decoded PCM (8kHz 16-bit mono) */
    int n_samples;              /* total PCM samples */
    int call_id;                /* monotonic call counter */
} voice_call_t;

/* Initialize voice decoder. Call once at startup. */
void voice_decode_init(void);

/* Shutdown and free resources. */
void voice_decode_shutdown(void);

/* Add a VOC frame. Handles clustering and triggers decode on call end. */
void voice_decode_add_frame(const voc_data_t *voc, uint64_t timestamp,
                            double frequency);

/* Flush any in-progress call (e.g., on shutdown). */
void voice_decode_flush(void);

/* Get total number of completed calls (monotonic). */
int voice_decode_total_calls(void);

/* Get total number of VOC frames received. */
int voice_decode_total_frames(void);

/* Copy a completed call's metadata by index (0 = oldest in buffer); audio is
 * left NULL. Returns 0, or -1 if out of range. */
int voice_decode_get_call(int index, voice_call_t *out);

/* Copy a call's audio by call_id into a malloc'd buffer the caller frees.
 * The ring can free the original at any time, so never hold a pointer to it. */
int16_t *voice_decode_copy_audio(int call_id, int *n_samples);

/* Get number of calls currently in the buffer. */
int voice_decode_call_count(void);

#endif
