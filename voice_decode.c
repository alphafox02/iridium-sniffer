/*
 * Iridium voice decoder: VOC clustering, AMBE decode, call management
 *
 * Clusters VOC frames by frequency/time into voice calls, decodes
 * AMBE superframes to PCM audio, and stores completed calls in a
 * circular buffer for web UI playback.
 *
 * Supports multiple concurrent calls on different frequencies via
 * a small array of in-progress call slots.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMBE codec: Copyright (c) 2015 Sylvain Munaut <tnt@246tNt.com>
 * Licensed under AGPL-3.0-or-later (see codec/LICENSE)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "voice_decode.h"
#include "codec/ambe.h"

extern int verbose;

/* ---- In-progress call accumulators ---- */

#define MAX_ACTIVE_CALLS 8

typedef struct {
    uint8_t payload[VOC_PAYLOAD_BYTES];
    uint64_t timestamp;
    double frequency;
} voc_frame_t;

typedef struct {
    voc_frame_t frames[VOICE_MAX_FRAMES];
    int n_frames;
    uint64_t first_time;
    uint64_t last_time;
    double freq_sum;
    int active;
} active_call_t;

static active_call_t active_calls[MAX_ACTIVE_CALLS];

/* ---- Completed calls circular buffer ---- */

static voice_call_t calls[VOICE_MAX_CALLS];
static int call_head = 0;          /* next write position */
static int call_count = 0;         /* entries in buffer */
static int total_calls = 0;
static int total_frames = 0;
static pthread_mutex_t voice_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- AMBE decoder ---- */

static struct ir77_ambe_decoder *ambe_dec = NULL;

/* ---- Internal functions ---- */

static voice_quality_t classify_quality(int n_frames, int duration_ms)
{
    if (duration_ms <= 0) return VOICE_QUALITY_POOR;
    /* Expect ~11 frames/sec (90ms per superframe). Calculate ratio. */
    double expected = (double)duration_ms / 90.0;
    double ratio = (double)n_frames / expected;

    if (ratio > 0.8) return VOICE_QUALITY_GOOD;
    if (ratio > 0.5) return VOICE_QUALITY_FAIR;
    return VOICE_QUALITY_POOR;
}

static void finalize_call(active_call_t *call)
{
    if (!call->active || call->n_frames < 3)
        goto reset;

    /* Allocate audio buffer for decoded PCM */
    int max_samples = call->n_frames * VOICE_SAMPLES_PER_SF;
    int16_t *audio = malloc(max_samples * sizeof(int16_t));
    if (!audio) {
        fprintf(stderr, "VOICE: failed to allocate audio buffer\n");
        goto reset;
    }

    /* Decode each superframe -- only keep frames where FEC succeeded */
    int total_samples = 0;
    int decoded_ok = 0;
    for (int i = 0; i < call->n_frames; i++) {
        int16_t frame_audio[VOICE_SAMPLES_PER_SF];
        int rv = ir77_ambe_decode_superframe(ambe_dec, frame_audio,
                                              VOICE_SAMPLES_PER_SF,
                                              call->frames[i].payload);
        if (rv > 0) {
            memcpy(audio + total_samples, frame_audio,
                   VOICE_SAMPLES_PER_SF * sizeof(int16_t));
            total_samples += VOICE_SAMPLES_PER_SF;
            decoded_ok += rv;
        }
    }
    if (verbose) {
        fprintf(stderr, "VOICE: AMBE decode: %d/%d sub-frames ok\n",
                decoded_ok, call->n_frames * 2);
    }

    if (decoded_ok < 4) {
        /* Need at least 2 superframes (4 sub-frames) for usable audio */
        free(audio);
        goto reset;
    }

    /* Normalize audio volume -- find peak and scale to ~80% of int16 range */
    int16_t peak = 0;
    for (int i = 0; i < total_samples; i++) {
        int16_t v = audio[i] < 0 ? -audio[i] : audio[i];
        if (v > peak) peak = v;
    }
    if (peak > 0 && peak < 16000) {
        /* Only boost if quiet (peak < ~50% of full scale) */
        double gain = 26000.0 / (double)peak;
        if (gain > 8.0) gain = 8.0;  /* cap at 8x */
        for (int i = 0; i < total_samples; i++) {
            int32_t v = (int32_t)(audio[i] * gain);
            if (v > 32767) v = 32767;
            if (v < -32768) v = -32768;
            audio[i] = (int16_t)v;
        }
    }

    /* Compute call metadata */
    int duration_ms = (int)((call->last_time -
                             call->first_time) / 1000000ULL);

    /* Store in circular buffer */
    pthread_mutex_lock(&voice_lock);

    /* Free old audio if overwriting */
    voice_call_t *slot = &calls[call_head];
    if (slot->audio) {
        free(slot->audio);
        slot->audio = NULL;
    }

    slot->valid = 1;
    slot->start_time = call->first_time;
    slot->end_time = call->last_time;
    slot->frequency = call->freq_sum / call->n_frames;
    slot->n_frames = call->n_frames;
    slot->quality = classify_quality(call->n_frames, duration_ms);
    slot->audio = audio;
    slot->n_samples = total_samples;
    slot->call_id = total_calls++;

    call_head = (call_head + 1) % VOICE_MAX_CALLS;
    if (call_count < VOICE_MAX_CALLS)
        call_count++;

    pthread_mutex_unlock(&voice_lock);

    if (verbose) {
        fprintf(stderr, "VOICE: call #%d complete, %d frames, "
                "%.1f sec, %s quality, %.3f MHz\n",
                slot->call_id, slot->n_frames,
                duration_ms / 1000.0,
                slot->quality == VOICE_QUALITY_GOOD ? "good" :
                slot->quality == VOICE_QUALITY_FAIR ? "fair" : "poor",
                slot->frequency / 1e6);
    }

reset:
    call->active = 0;
    call->n_frames = 0;
    call->freq_sum = 0;
}

/* Find the active call slot matching this frequency, or NULL */
static active_call_t *find_call(double frequency)
{
    for (int i = 0; i < MAX_ACTIVE_CALLS; i++) {
        if (!active_calls[i].active) continue;
        double df = frequency - (active_calls[i].freq_sum / active_calls[i].n_frames);
        if (df < 0) df = -df;
        if (df <= VOICE_CLUSTER_FREQ)
            return &active_calls[i];
    }
    return NULL;
}

/* Get a free slot, evicting the oldest if necessary */
static active_call_t *alloc_call(void)
{
    /* First try to find an empty slot */
    for (int i = 0; i < MAX_ACTIVE_CALLS; i++) {
        if (!active_calls[i].active)
            return &active_calls[i];
    }
    /* All full -- finalize and reuse the oldest */
    active_call_t *oldest = &active_calls[0];
    for (int i = 1; i < MAX_ACTIVE_CALLS; i++) {
        if (active_calls[i].first_time < oldest->first_time)
            oldest = &active_calls[i];
    }
    finalize_call(oldest);
    return oldest;
}

/* ---- Public API ---- */

void voice_decode_init(void)
{
    memset(active_calls, 0, sizeof(active_calls));
    memset(calls, 0, sizeof(calls));

    ambe_dec = ir77_ambe_decode_alloc();
    if (!ambe_dec)
        fprintf(stderr, "VOICE: failed to allocate AMBE decoder\n");
}

void voice_decode_shutdown(void)
{
    voice_decode_flush();

    if (ambe_dec) {
        ir77_ambe_decode_release(ambe_dec);
        ambe_dec = NULL;
    }

    pthread_mutex_lock(&voice_lock);
    for (int i = 0; i < VOICE_MAX_CALLS; i++) {
        if (calls[i].audio) {
            free(calls[i].audio);
            calls[i].audio = NULL;
        }
    }
    pthread_mutex_unlock(&voice_lock);
}

void voice_decode_add_frame(const voc_data_t *voc, uint64_t timestamp,
                            double frequency)
{
    if (!ambe_dec) return;

    total_frames++;

    /* Quick AMBE probe for debug */
    if (verbose) {
        int16_t probe_audio[VOICE_SAMPLES_PER_SF];
        int rv = ir77_ambe_decode_superframe(ambe_dec, probe_audio,
                                              VOICE_SAMPLES_PER_SF,
                                              voc->payload);
        fprintf(stderr, "VOICE: VOC frame #%d @ %.3f MHz, AMBE FEC: %d/2 sub-frames ok\n",
                total_frames, frequency / 1e6, rv);
    }

    /* Find matching active call by frequency */
    active_call_t *call = find_call(frequency);

    if (call) {
        /* Check time gap */
        double dt = (double)(timestamp - call->last_time) / 1e9;
        if (dt > VOICE_CLUSTER_TIME) {
            finalize_call(call);
            call = NULL;
        }
    }

    /* Allocate new call slot if needed */
    if (!call) {
        call = alloc_call();
        call->active = 1;
        call->n_frames = 0;
        call->first_time = timestamp;
        call->freq_sum = 0;
    }

    /* Add frame */
    if (call->n_frames < VOICE_MAX_FRAMES) {
        voc_frame_t *f = &call->frames[call->n_frames];
        memcpy(f->payload, voc->payload, VOC_PAYLOAD_BYTES);
        f->timestamp = timestamp;
        f->frequency = frequency;
        call->n_frames++;
    }
    call->last_time = timestamp;
    call->freq_sum += frequency;
}

void voice_decode_flush(void)
{
    for (int i = 0; i < MAX_ACTIVE_CALLS; i++) {
        if (active_calls[i].active)
            finalize_call(&active_calls[i]);
    }
}

int voice_decode_total_calls(void)
{
    return total_calls;
}

int voice_decode_total_frames(void)
{
    return total_frames;
}

int voice_decode_call_count(void)
{
    int n;
    pthread_mutex_lock(&voice_lock);
    n = call_count;
    pthread_mutex_unlock(&voice_lock);
    return n;
}

const voice_call_t *voice_decode_get_call(int index)
{
    const voice_call_t *result = NULL;
    pthread_mutex_lock(&voice_lock);

    if (index >= 0 && index < call_count) {
        /* Index 0 = oldest, call_count-1 = newest */
        int pos = (call_head - call_count + index + VOICE_MAX_CALLS)
                  % VOICE_MAX_CALLS;
        if (calls[pos].valid)
            result = &calls[pos];
    }

    pthread_mutex_unlock(&voice_lock);
    return result;
}
