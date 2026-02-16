/*
 * QPSK/DQPSK demodulator - port of gr-iridium's iridium_qpsk_demod_impl.cc
 *
 * Decimate to 1 sps → First-order PLL (alpha=0.2) → Hard-decision QPSK →
 * Dual-direction unique word verification (DL + UL, Hamming <= 2) →
 * DQPSK differential decode → Symbol-to-bits mapping
 *
 * Original work Copyright 2020 Free Software Foundation, Inc.
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * QPSK/DQPSK demodulator - port of gr-iridium's iridium_qpsk_demod
 *
 * Pipeline: decimate -> PLL -> hard decision -> UW check ->
 *           DQPSK decode -> symbol-to-bits
 *
 * Improvement beyond gr-iridium:
 *   - Soft-decision UW rescue for borderline frames
 */

#include <complex.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

#include "qpsk_demod.h"
#include "iridium.h"

extern char *save_bursts_dir;
extern int use_gardner;

#define PLL_ALPHA           0.2f
#define M_SQRT1_2f          0.70710678118654752f
#define CONFIDENCE_ANGLE    22      /* degrees from ideal constellation */
#define MAGNITUDE_DROP      8.0f    /* end-of-frame: signal < peak/8 */
#define MAX_LOW_COUNT       3       /* consecutive weak symbols = end */
#define UW_MAX_ERRORS       2       /* max Hamming distance for hard UW check */
#define UW_SOFT_THRESHOLD   3.0f    /* soft-decision rescue threshold */

/* DQPSK transition table: maps (new - old) % 4 -> decoded symbol */
static const int dqpsk_map[] = { 0, 2, 3, 1 };

/* Gardner TED loop filter gains.
 * Bn*Ts ~= 0.01 (1% of symbol rate) for moderate convergence speed.
 * Kp (proportional) and Ki (integral) derived from standard 2nd-order loop. */
#define GARDNER_KP  0.02f
#define GARDNER_KI  0.0002f

/* ---- Cubic interpolation of complex samples ---- */

static float complex cubic_interp(const float complex *in, int n_samples,
                                   float pos)
{
    int idx = (int)pos;
    float mu = pos - idx;

    /* Clamp to valid range with enough margin for cubic */
    if (idx < 1) idx = 1;
    if (idx >= n_samples - 2) idx = n_samples - 3;

    float complex s0 = in[idx - 1];
    float complex s1 = in[idx];
    float complex s2 = in[idx + 1];
    float complex s3 = in[idx + 2];

    /* Catmull-Rom spline */
    float mu2 = mu * mu;
    float mu3 = mu2 * mu;

    float complex a = -0.5f*s0 + 1.5f*s1 - 1.5f*s2 + 0.5f*s3;
    float complex b =      s0 - 2.5f*s1 + 2.0f*s2 - 0.5f*s3;
    float complex c = -0.5f*s0           + 0.5f*s2;
    float complex d =                 s1;

    return a*mu3 + b*mu2 + c*mu + d;
}

/* ---- Gardner timing error detector with interpolation ---- */

static int decimate_gardner(const float complex *in, int n_samples,
                            float sps, float complex *out)
{
    int n = 0;
    float pos = 0.0f;           /* current sampling position (fractional) */
    float timing_offset = 0.0f; /* integral accumulator */
    float complex prev_sym = 0; /* previous on-time sample */

    while (pos < n_samples - 3) {
        /* On-time sample via cubic interpolation */
        float complex on_time = cubic_interp(in, n_samples, pos);
        out[n] = on_time;

        if (n > 0) {
            /* Mid-point sample (halfway between previous and current) */
            float mid_pos = pos - sps * 0.5f;
            if (mid_pos >= 1.0f) {
                float complex mid = cubic_interp(in, n_samples, mid_pos);

                /* Gardner TED error: Re{(prev - current) * conj(mid)} */
                float complex diff = prev_sym - on_time;
                float error = crealf(diff * conjf(mid));

                /* Clamp error to prevent instability */
                if (error > 1.0f) error = 1.0f;
                if (error < -1.0f) error = -1.0f;

                /* PI loop filter */
                timing_offset += GARDNER_KI * error;
                float adjust = GARDNER_KP * error + timing_offset;

                /* Limit adjustment to +/- 0.5 samples per symbol */
                if (adjust > 0.5f) adjust = 0.5f;
                if (adjust < -0.5f) adjust = -0.5f;

                pos += adjust;
            }
        }

        prev_sym = on_time;
        n++;
        pos += sps;
    }

    return n;
}

/* ---- Simple decimation (legacy fallback) ---- */

static int decimate_simple(const float complex *in, int n_samples,
                           float sps, float complex *out)
{
    int n = 0;
    for (int i = 0; i < n_samples; i += (int)sps)
        out[n++] = in[i];
    return n;
}

/* ---- First-order PLL for QPSK phase tracking ---- */

static float qpsk_pll(const float complex *in, float complex *out,
                       int n_symbols, float alpha)
{
    float complex phi_hat = 1.0f + 0.0f * I;
    float total_phase = 0.0f;

    for (int i = 0; i < n_symbols; i++) {
        /* Correct phase */
        out[i] = in[i] * phi_hat;

        /* Hard decision: nearest QPSK constellation point */
        float complex x_hat;
        float re = crealf(out[i]);
        float im = cimagf(out[i]);

        if (re >= 0 && im >= 0)
            x_hat = M_SQRT1_2f + M_SQRT1_2f * I;
        else if (re >= 0)
            x_hat = M_SQRT1_2f - M_SQRT1_2f * I;
        else if (im < 0)
            x_hat = -M_SQRT1_2f - M_SQRT1_2f * I;
        else
            x_hat = -M_SQRT1_2f + M_SQRT1_2f * I;

        /* Error signal: rotate by conjugate of ideal */
        float complex er = conjf(x_hat) * out[i];
        float er_mag = cabsf(er);
        if (er_mag < 1e-10f)
            continue;

        /* Normalize to unit magnitude */
        float complex phi_hat_t = er / er_mag;

        /* Loop filter: phi_hat_t^alpha (fractional power of unit complex) */
        float angle = cargf(phi_hat_t);
        float scaled_angle = alpha * angle;
        float complex correction = cosf(scaled_angle) + sinf(scaled_angle) * I;

        total_phase += scaled_angle;

        /* Update phase estimate */
        phi_hat = conjf(correction) * phi_hat;

        /* Normalize to prevent magnitude drift */
        float phi_mag = cabsf(phi_hat);
        if (phi_mag > 0)
            phi_hat /= phi_mag;
    }

    return total_phase;
}

/* ---- Hard-decision QPSK demod with confidence ---- */

static int demod_qpsk(const float complex *burst, int n_symbols,
                      int *symbols, float *level_out, int *confidence_out)
{
    float max_mag = 0;
    int low_count = 0;
    int n = 0;
    float *offsets = malloc(n_symbols * sizeof(float));
    float *magnitudes = malloc(n_symbols * sizeof(float));

    for (int i = 0; i < n_symbols; i++) {
        float re = crealf(burst[i]);
        float im = cimagf(burst[i]);
        float mag = sqrtf(re * re + im * im);

        magnitudes[i] = mag;
        if (mag > max_mag)
            max_mag = mag;

        /* Hard decision */
        if (re >= 0 && im >= 0)
            symbols[i] = 0;
        else if (re < 0 && im >= 0)
            symbols[i] = 1;
        else if (re < 0)
            symbols[i] = 2;
        else
            symbols[i] = 3;

        /* Phase offset from ideal 45/135/225/315 grid */
        float phase = (atan2f(im, re) + (float)M_PI) * 180.0f / (float)M_PI;
        offsets[i] = 45.0f - fmodf(phase, 90.0f);

        n++;

        /* End-of-frame: signal dropped well below peak */
        if (mag < max_mag / MAGNITUDE_DROP) {
            low_count++;
            if (low_count >= MAX_LOW_COUNT) {
                n -= MAX_LOW_COUNT;
                break;
            }
        } else {
            low_count = 0;
        }
    }

    /* Confidence: percentage of symbols within tolerance of ideal */
    int n_ok = 0;
    float sum = 0;
    for (int i = 0; i < n; i++) {
        sum += magnitudes[i];
        if (fabsf(offsets[i]) <= CONFIDENCE_ANGLE)
            n_ok++;
    }

    *level_out = n > 0 ? sum / n : 0;
    *confidence_out = n > 0 ? (100 * n_ok) / n : 0;

    free(offsets);
    free(magnitudes);
    return n;
}

/* ---- DQPSK differential decode ---- */

static void decode_dqpsk(int *symbols, int n)
{
    int old_sym = 0;
    for (int i = 0; i < n; i++) {
        int s = symbols[i];
        int diff = (s - old_sym + 4) % 4;
        old_sym = s;
        symbols[i] = dqpsk_map[diff];
    }
}

/* ---- Hard-decision unique word verification ---- */

static int check_sync_word(const int *symbols, int n, ir_direction_t direction)
{
    if (n < IR_UW_LENGTH)
        return 0;

    const int *uw = (direction == DIR_DOWNLINK) ? IR_UW_DL : IR_UW_UL;
    int diffs = 0;

    for (int i = 0; i < IR_UW_LENGTH; i++) {
        int diff = abs(symbols[i] - uw[i]);
        if (diff == 3)
            diff = 1;  /* wraparound: 3-step = 1-step opposite direction */
        diffs += diff;
    }

    return diffs <= UW_MAX_ERRORS;
}

/* ---- Soft-decision UW check (rescues borderline frames) ---- */

static float soft_check_sync_word(const float complex *pll_out, int n,
                                   ir_direction_t direction)
{
    if (n < IR_UW_LENGTH)
        return 999.0f;

    const int *uw = (direction == DIR_DOWNLINK) ? IR_UW_DL : IR_UW_UL;
    float total_error = 0.0f;

    for (int i = 0; i < IR_UW_LENGTH; i++) {
        /* Expected phase for QPSK symbol s: pi/4 + s * pi/2 */
        float expected = (float)M_PI * 0.25f + uw[i] * (float)M_PI * 0.5f;

        /* Actual phase mapped to [0, 2*pi) */
        float actual = cargf(pll_out[i]);
        if (actual < 0)
            actual += 2.0f * (float)M_PI;

        /* Angular distance wrapped to [-pi, pi] */
        float diff = actual - expected;
        if (diff > (float)M_PI) diff -= 2.0f * (float)M_PI;
        if (diff < -(float)M_PI) diff += 2.0f * (float)M_PI;

        /* Normalize: 90 degrees (one quadrant) = 1.0 error */
        total_error += fabsf(diff) * (float)(2.0 / M_PI);
    }

    return total_error;
}

/* ---- Symbol-to-bits mapping (MSB first) ---- */

static void map_symbols_to_bits(const int *symbols, int n, uint8_t *bits)
{
    for (int i = 0; i < n; i++) {
        bits[2 * i]     = (symbols[i] >> 1) & 1;  /* MSB */
        bits[2 * i + 1] = symbols[i] & 1;          /* LSB */
    }
}

/* ---- Burst IQ sample saving (for research/analysis) ---- */

static void save_burst_iq(downmix_frame_t *in, const char *dir_name)
{
    if (!dir_name) return;

    /* Create directory if it doesn't exist */
    struct stat st = {0};
    if (stat(dir_name, &st) == -1) {
        if (mkdir(dir_name, 0755) == -1 && errno != EEXIST) {
            fprintf(stderr, "Warning: failed to create burst save directory: %s\n",
                    strerror(errno));
            return;
        }
    }

    /* Format: <timestamp>_<freq>_<id>_<direction>.cf32 */
    const char *dir_str = (in->direction == DIR_DOWNLINK) ? "DL" :
                          (in->direction == DIR_UPLINK) ? "UL" : "UN";

    char filename[512];
    snprintf(filename, sizeof(filename), "%s/%020lu_%011.0f_%lu_%s",
             dir_name, in->timestamp, in->center_frequency, in->id, dir_str);

    /* Save IQ samples (cf32 format) */
    char iq_file[520];
    snprintf(iq_file, sizeof(iq_file), "%s.cf32", filename);
    FILE *f = fopen(iq_file, "wb");
    if (!f) {
        fprintf(stderr, "Warning: failed to save burst IQ: %s\n", strerror(errno));
        return;
    }
    fwrite(in->samples, sizeof(float complex), in->num_samples, f);
    fclose(f);

    /* Save metadata */
    char meta_file[520];
    snprintf(meta_file, sizeof(meta_file), "%s.meta", filename);
    f = fopen(meta_file, "w");
    if (!f) return;

    fprintf(f, "burst_id: %lu\n", in->id);
    fprintf(f, "timestamp_ns: %lu\n", in->timestamp);
    fprintf(f, "center_freq_hz: %.0f\n", in->center_frequency);
    fprintf(f, "sample_rate_hz: %.0f\n", in->sample_rate);
    fprintf(f, "samples_per_symbol: %.2f\n", in->samples_per_symbol);
    fprintf(f, "direction: %s\n", dir_str);
    fprintf(f, "magnitude_db: %.2f\n", in->magnitude);
    fprintf(f, "noise_dbfs_hz: %.2f\n", in->noise);
    fprintf(f, "num_samples: %zu\n", in->num_samples);
    fprintf(f, "uw_start_offset: %.2f\n", in->uw_start);
    fclose(f);
}

/* ---- Main demodulation function ---- */

int qpsk_demod(downmix_frame_t *in, demod_frame_t **out)
{
    int sps = (int)(in->samples_per_symbol + 0.5f);
    if (sps < 1) sps = 1;

    int max_symbols = (int)in->num_samples / sps + 1;
    float complex *decimated = malloc(max_symbols * sizeof(float complex));
    float complex *pll_out   = malloc(max_symbols * sizeof(float complex));
    int *symbols             = malloc(max_symbols * sizeof(int));

    if (!decimated || !pll_out || !symbols) {
        free(decimated);
        free(pll_out);
        free(symbols);
        return 0;
    }

    /* Step 1: Decimate to 1 sample per symbol */
    int n_symbols;
    if (use_gardner)
        n_symbols = decimate_gardner(in->samples, (int)in->num_samples,
                                     in->samples_per_symbol, decimated);
    else
        n_symbols = decimate_simple(in->samples, (int)in->num_samples,
                                    in->samples_per_symbol, decimated);

    /* Step 2: PLL phase correction */
    float total_phase = qpsk_pll(decimated, pll_out, n_symbols, PLL_ALPHA);

    /* Step 3: Hard-decision QPSK demod + confidence */
    float level;
    int confidence;
    int actual_symbols = demod_qpsk(pll_out, n_symbols, symbols,
                                     &level, &confidence);

    /* Step 4: Verify unique word (hard check both directions, soft rescue) */
    {
        int dl_ok = check_sync_word(symbols, actual_symbols, DIR_DOWNLINK);
        int ul_ok = check_sync_word(symbols, actual_symbols, DIR_UPLINK);

        if (!dl_ok && !ul_ok) {
            /* Hard check failed -- try soft-decision rescue */
            float dl_err = soft_check_sync_word(pll_out, actual_symbols,
                                                 DIR_DOWNLINK);
            float ul_err = soft_check_sync_word(pll_out, actual_symbols,
                                                 DIR_UPLINK);
            float min_err = (dl_err < ul_err) ? dl_err : ul_err;

            if (min_err > UW_SOFT_THRESHOLD) {
                /* Save failed burst IQ if requested (for demod analysis) */
                if (save_bursts_dir) {
                    in->direction = DIR_UNDEF;
                    save_burst_iq(in, save_bursts_dir);
                }
                free(decimated);
                free(pll_out);
                free(symbols);
                return 0;
            }

            /* Soft rescue succeeded */
            if (ul_err < dl_err)
                in->direction = DIR_UPLINK;
            else
                in->direction = DIR_DOWNLINK;
        } else {
            /* Hard check passed -- update direction */
            if (ul_ok && !dl_ok)
                in->direction = DIR_UPLINK;
            else if (dl_ok && !ul_ok)
                in->direction = DIR_DOWNLINK;
        }
    }

    /* Save burst IQ if requested (for research/analysis) */
    if (save_bursts_dir) {
        save_burst_iq(in, save_bursts_dir);
    }

    /* Step 5: DQPSK differential decode */
    decode_dqpsk(symbols, actual_symbols);

    /* Step 6: Map to bits */
    int n_bits = actual_symbols * 2;
    uint8_t *bits = malloc(n_bits);
    if (!bits) {
        free(decimated);
        free(pll_out);
        free(symbols);
        return 0;
    }
    map_symbols_to_bits(symbols, actual_symbols, bits);

    /* Step 7: Compute per-bit soft reliability (LLR magnitude) from PLL output.
     * For QPSK: MSB reliability = |Re(symbol)|, LSB = |Im(symbol)|.
     * Normalized so average constellation distance = 1.0. */
    float *llr = malloc(n_bits * sizeof(float));
    if (llr) {
        /* Compute average magnitude for normalization */
        float sum_mag = 0;
        for (int i = 0; i < actual_symbols; i++)
            sum_mag += cabsf(pll_out[i]);
        float scale = (actual_symbols > 0 && sum_mag > 0)
                    ? (M_SQRT1_2f / (sum_mag / actual_symbols))
                    : 1.0f;

        for (int i = 0; i < actual_symbols; i++) {
            llr[2 * i]     = fabsf(crealf(pll_out[i])) * scale;
            llr[2 * i + 1] = fabsf(cimagf(pll_out[i])) * scale;
        }
    }

    /* Build output frame */
    demod_frame_t *frame = calloc(1, sizeof(demod_frame_t));
    frame->id = in->id;
    frame->timestamp = in->timestamp;
    frame->direction = in->direction;
    frame->magnitude = in->magnitude;
    frame->noise = in->noise;
    frame->confidence = confidence;
    frame->level = level;
    frame->n_symbols = actual_symbols;
    frame->n_payload_symbols = actual_symbols - IR_UW_LENGTH;
    frame->bits = bits;
    frame->llr = llr;
    frame->n_bits = n_bits;

    /* Refine center frequency with PLL-measured residual CFO */
    if (actual_symbols > 0) {
        double duration = (double)actual_symbols / IR_SYMBOLS_PER_SECOND;
        frame->center_frequency = in->center_frequency +
            total_phase / duration / M_PI / 2.0;
    } else {
        frame->center_frequency = in->center_frequency;
    }

    *out = frame;

    free(decimated);
    free(pll_out);
    free(symbols);
    return 1;
}
