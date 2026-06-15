/*
 * Epiq Solutions Sidekiq SDR backend for iridium-sniffer
 *
 * Copyright 2025-2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Native libsidekiq backend (AD9361-based SKUs). Ported from the verified
 * blue-dragon crates/sdr/src/sidekiq.rs FFI wrapper -- same SDK call sequence,
 * sample format (12-bit, low-justified in int16), and rf_timestamp gap-based
 * drop detection, adapted to iridium-sniffer's sample_buf_t / push_samples()
 * contract.
 *
 * Device string:  -i sidekiq           first detected card
 *                 -i sidekiq-<serial>   card matching <serial>
 *
 * RX handle A1 / RF port J1 are used by default. Gain is a 0..N hardware index
 * (NOT dB); see --sidekiq-gain.
 */

#include <err.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#include <sidekiq_api.h>

#include "sdr.h"

extern sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern int sidekiq_gain_val;
extern int verbose;

/* libsidekiq is a process-wide singleton: skiq_init_without_cards() must be
 * paired with exactly one skiq_exit(). iridium-sniffer opens a single SDR, so a
 * simple "did we init" flag is enough (blue-dragon needed a refcount only
 * because list_devices() and an open handle could coexist). */
static int sdk_inited = 0;

static int sdk_acquire(void) {
    if (!sdk_inited) {
        int32_t rc = skiq_init_without_cards();
        if (rc != 0)
            return rc;
        sdk_inited = 1;
    }
    return 0;
}

static void sdk_release(void) {
    if (sdk_inited) {
        skiq_exit();
        sdk_inited = 0;
    }
}

/* Opaque context handed back to main.c. */
typedef struct _sidekiq_ctx_t {
    uint8_t card;
    skiq_rx_hdl_t hdl;
    int streaming;
} sidekiq_ctx_t;

/* Header size before the int16_t data[] flexible array. The SDK defines
 * SKIQ_RX_HEADER_SIZE_IN_BYTES; fall back to offsetof for robustness. */
#ifndef SKIQ_RX_HEADER_SIZE_IN_BYTES
#define SKIQ_RX_HEADER_SIZE_IN_BYTES ((uint32_t)offsetof(skiq_rx_block_t, data))
#endif

/* ---- card enumeration --------------------------------------------------- */

void sidekiq_list(void) {
    uint8_t cards[SKIQ_MAX_NUM_CARDS];
    uint8_t num = 0;

    if (sdk_acquire() != 0)
        return;

    if (skiq_get_cards(skiq_xport_type_auto, &num, cards) != 0) {
        sdk_release();
        return;
    }

    for (uint8_t i = 0; i < num; ++i) {
        uint8_t card = cards[i];
        /* Bring the card up at BASIC level just long enough to read serial. */
        if (skiq_enable_cards(&card, 1, skiq_xport_init_level_basic) != 0)
            continue;
        char *serial = NULL;
        char val[64];
        if (skiq_read_serial_string(card, &serial) == 0 && serial != NULL)
            snprintf(val, sizeof(val), "sidekiq-%s", serial);
        else
            snprintf(val, sizeof(val), "sidekiq");
        skiq_disable_cards(&card, 1);
        printf("  %-24s Epiq Sidekiq (card %u)\n", val, card);
    }

    sdk_release();
}

/* ---- device-string parsing ---------------------------------------------- */

/* Returns the serial substring of "sidekiq-<serial>", NULL for bare "sidekiq"
 * (meaning: first detected card). */
static char *sidekiq_parse_serial(char *name) {
    if (strncmp(name, "sidekiq-", 8) == 0 && name[8] != '\0')
        return name + 8;
    return NULL;
}

/* Locate the chosen card id. With a serial we probe each card; otherwise the
 * first card the SDK returns. */
static int sidekiq_pick_card(const char *want_serial, uint8_t *out_card) {
    uint8_t cards[SKIQ_MAX_NUM_CARDS];
    uint8_t num = 0;

    if (skiq_get_cards(skiq_xport_type_auto, &num, cards) != 0)
        return -1;
    if (num == 0)
        return -1;

    if (want_serial == NULL) {
        *out_card = cards[0];
        return 0;
    }

    for (uint8_t i = 0; i < num; ++i) {
        uint8_t card = cards[i];
        if (skiq_enable_cards(&card, 1, skiq_xport_init_level_basic) != 0)
            continue;
        char *serial = NULL;
        int match = (skiq_read_serial_string(card, &serial) == 0 &&
                     serial != NULL && strcasecmp(serial, want_serial) == 0);
        skiq_disable_cards(&card, 1);
        if (match) {
            *out_card = card;
            return 0;
        }
    }
    return -1;
}

/* ---- setup -------------------------------------------------------------- */

void *sidekiq_setup(char *name) {
    char *want_serial = sidekiq_parse_serial(name);
    uint8_t card = 0;
    skiq_rx_hdl_t hdl = skiq_rx_hdl_A1;

    if (sdk_acquire() != 0)
        errx(1, "Sidekiq: skiq_init_without_cards failed");

    if (sidekiq_pick_card(want_serial, &card) != 0) {
        sdk_release();
        if (want_serial)
            errx(1, "Sidekiq: serial '%s' not found", want_serial);
        errx(1, "Sidekiq: no cards present");
    }

    /* Defensive disable to clear any prior partial state, then FULL enable. */
    skiq_disable_cards(&card, 1);
    if (skiq_enable_cards(&card, 1, skiq_xport_init_level_full) != 0) {
        sdk_release();
        errx(1, "Sidekiq: skiq_enable_cards(FULL) failed for card %u", card);
    }

    /* Deliver samples as interleaved I,Q so no swap is needed downstream. */
    skiq_write_iq_order_mode(card, skiq_iq_order_iq);

    /* Default RX1-labeled port. Some SKUs expose only one valid port per
     * handle, in which case this is a no-op. */
    skiq_write_rx_rf_port_for_hdl(card, hdl, skiq_rf_port_J1);

    /* Sample rate + analog bandwidth. Cap BW at the AD9361 analog filter
     * range (~56 MHz); the SDK rounds to the nearest supported setting. */
    uint32_t rate = (uint32_t)samp_rate;
    uint32_t bandwidth = (uint32_t)(samp_rate * 0.8);
    if (bandwidth > 56000000u)
        bandwidth = 56000000u;
    if (skiq_write_rx_sample_rate_and_bandwidth(card, hdl, rate, bandwidth) != 0)
        warnx("Sidekiq: set sample rate/bandwidth (%u/%u) failed, continuing",
              rate, bandwidth);

    /* Read back and warn if the device negotiated a materially different rate;
     * downstream burst timing assumes samp_rate is exact. */
    uint32_t got_rate = 0, got_bw = 0, got_actual_bw = 0;
    double got_actual = 0.0;
    if (skiq_read_rx_sample_rate_and_bandwidth(card, hdl, &got_rate, &got_actual,
                                               &got_bw, &got_actual_bw) == 0) {
        if (verbose)
            fprintf(stderr, "Sidekiq: requested %u Sps, actual %.1f Sps; "
                    "BW req %u actual %u\n", rate, got_actual, bandwidth,
                    got_actual_bw);
        double drift = (got_actual - (double)rate) / (double)rate;
        if (drift < 0) drift = -drift;
        if (drift > 0.001)
            warnx("Sidekiq: device running at %.0f Sps but %u requested "
                  "(%.3f%% off) -- burst timing may degrade",
                  got_actual, rate, drift * 100.0);
    }

    if (skiq_write_rx_LO_freq(card, hdl, (uint64_t)center_freq) != 0) {
        skiq_disable_cards(&card, 1);
        sdk_release();
        errx(1, "Sidekiq: set LO freq %.0f failed", center_freq);
    }

    /* Gain is a 0..N hardware index (NOT dB). Clamp to the device range. */
    uint8_t gmin = 0, gmax = 76;
    skiq_read_rx_gain_index_range(card, hdl, &gmin, &gmax);
    int gi = sidekiq_gain_val;
    if (gi < gmin) gi = gmin;
    if (gi > gmax) gi = gmax;
    skiq_write_rx_gain_mode(card, hdl, skiq_rx_gain_manual);
    if (skiq_write_rx_gain(card, hdl, (uint8_t)gi) != 0)
        warnx("Sidekiq: set gain index %d failed", gi);

    /* FPGA DC offset correction removes residual LO leakage at band center.
     * No-op (warning) on SKUs that do not support it. */
    if (skiq_write_rx_dc_offset_corr(card, hdl, true) == 0) {
        if (verbose)
            fprintf(stderr, "Sidekiq: FPGA DC offset correction enabled\n");
    }

    skiq_write_rx_stream_mode(card, skiq_rx_stream_mode_high_tput);
    skiq_set_rx_transfer_timeout(card, 50);

    if (skiq_start_rx_streaming(card, hdl) != 0) {
        skiq_disable_cards(&card, 1);
        sdk_release();
        errx(1, "Sidekiq: skiq_start_rx_streaming failed");
    }

    if (verbose)
        fprintf(stderr, "Sidekiq: card %u, hdl A1, port J1, %.0f MHz, "
                "%.1f MS/s, gain idx %d (%u..%u)\n", card,
                center_freq / 1e6, samp_rate / 1e6, gi, gmin, gmax);

    sidekiq_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->card = card;
    ctx->hdl = hdl;
    ctx->streaming = 1;
    return ctx;
}

/* ---- stream thread ------------------------------------------------------ */

void *sidekiq_stream_thread(void *arg) {
    sidekiq_ctx_t *ctx = arg;
    uint8_t card = ctx->card;
    skiq_rx_hdl_t hdl = ctx->hdl;

    /* libsidekiq delivers one ~1k-sample block per skiq_receive. Aggregate
     * several blocks into one ~16k-sample buffer so the burst detector sees
     * chunks comparable to the bladeRF / USRP backends. Whole blocks are
     * copied (never split), so the buffer is sized to an exact block multiple. */
    int32_t block_bytes = skiq_read_rx_block_size(card, skiq_rx_stream_mode_high_tput);
    if (block_bytes <= (int32_t)SKIQ_RX_HEADER_SIZE_IN_BYTES)
        errx(1, "Sidekiq: invalid block size %d", block_bytes);
    unsigned block_samps =
        ((uint32_t)block_bytes - SKIQ_RX_HEADER_SIZE_IN_BYTES) / 4u;
    unsigned blocks_per_buf = (16384u + block_samps - 1u) / block_samps;
    unsigned cap_samps = blocks_per_buf * block_samps;

    sample_buf_t *s = NULL;
    unsigned filled = 0;          /* samples (I/Q pairs) accumulated in s */
    unsigned blocks_in_buf = 0;
    int have_prev_ts = 0;
    uint64_t expected_ts = 0;     /* rf_timestamp expected for next block */

    while (running) {
        skiq_rx_hdl_t rcv_hdl = hdl;
        skiq_rx_block_t *p_block = NULL;
        uint32_t len = 0;

        int32_t st = skiq_receive(card, &rcv_hdl, &p_block, &len);
        if (st == skiq_rx_status_no_data)
            continue;
        if (st != skiq_rx_status_success || p_block == NULL ||
            len <= SKIQ_RX_HEADER_SIZE_IN_BYTES) {
            if (verbose)
                warnx("Sidekiq: skiq_receive status=%d len=%u", st, len);
            continue;
        }
        if (rcv_hdl != hdl)
            continue;  /* sample from a handle we are not consuming */

        unsigned blk_pairs = (len - SKIQ_RX_HEADER_SIZE_IN_BYTES) / 4u;

        /* Drop detection: next block's rf_timestamp should equal the previous
         * block's rf_timestamp + its sample count. A gap means dropped samples
         * (host/queue starvation); flush what we have so the demod sees the
         * discontinuity at a buffer boundary, not mid-buffer. */
        if (have_prev_ts && p_block->rf_timestamp != expected_ts) {
            if (verbose)
                warnx("Sidekiq: rf_timestamp gap (expected %llu got %llu)",
                      (unsigned long long)expected_ts,
                      (unsigned long long)p_block->rf_timestamp);
            if (s != NULL && filled > 0) {
                s->num = filled;
                if (running)
                    push_samples(s);
                else
                    free(s);
                s = NULL;
                filled = 0;
                blocks_in_buf = 0;
            }
        }
        expected_ts = p_block->rf_timestamp + blk_pairs;
        have_prev_ts = 1;

        if (s == NULL) {
            s = malloc(sizeof(*s) + cap_samps * 2u * sizeof(float));
            s->format = SAMPLE_FMT_FLOAT;
            s->hw_timestamp_ns = 0;
            filled = 0;
            blocks_in_buf = 0;
        }

        /* 12-bit two's-complement samples, low-justified in int16, interleaved
         * I,Q (iq_order set to skiq_iq_order_iq). Normalize to ~[-1,1] using
         * the same 1/2048 scale as the bladeRF SC16_Q11 backend. */
        const int16_t *d = p_block->data;
        float *out = (float *)s->samples + filled * 2u;
        for (unsigned i = 0; i < blk_pairs * 2u; ++i)
            out[i] = d[i] * (1.0f / 2048.0f);
        filled += blk_pairs;
        ++blocks_in_buf;

        if (blocks_in_buf >= blocks_per_buf) {
            s->num = filled;
            if (running)
                push_samples(s);
            else
                free(s);
            s = NULL;
            filled = 0;
            blocks_in_buf = 0;
        }
    }

    if (s != NULL)
        free(s);

    skiq_stop_rx_streaming(card, hdl);
    ctx->streaming = 0;

    kill(self_pid, SIGINT);
    return NULL;
}

void sidekiq_close(void *arg) {
    sidekiq_ctx_t *ctx = arg;
    if (ctx == NULL)
        return;
    if (ctx->streaming)
        skiq_stop_rx_streaming(ctx->card, ctx->hdl);
    skiq_disable_cards(&ctx->card, 1);
    sdk_release();
    free(ctx);
}
