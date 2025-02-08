/*
 * FIR filter with decimation + filter coefficient generation
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "fir_filter.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ---- FIR filter creation/destruction ---- */

fir_filter_t *fir_filter_create(const float *taps, int ntaps) {
    fir_filter_t *f = malloc(sizeof(*f));
    f->ntaps = ntaps;
    f->taps = malloc(sizeof(float) * ntaps);
    memcpy(f->taps, taps, sizeof(float) * ntaps);
    return f;
}

void fir_filter_destroy(fir_filter_t *f) {
    if (!f) return;
    free(f->taps);
    free(f);
}

/* ---- Complex FIR filter ---- */

void fir_filter_ccf(fir_filter_t *f, float complex *out,
                    const float complex *in, int n) {
    for (int i = 0; i < n; i++) {
        float complex acc = 0;
        for (int k = 0; k < f->ntaps; k++)
            acc += f->taps[k] * in[i + k];
        out[i] = acc;
    }
}

/* ---- Complex FIR filter with decimation ---- */

void fir_filter_ccf_dec(fir_filter_t *f, float complex *out,
                        const float complex *in, int n_out, int decimation) {
    for (int i = 0; i < n_out; i++) {
        float complex acc = 0;
        const float complex *p = &in[i * decimation];
        for (int k = 0; k < f->ntaps; k++)
            acc += f->taps[k] * p[k];
        out[i] = acc;
    }
}

/* ---- Real FIR filter ---- */

void fir_filter_fff(fir_filter_t *f, float *out, const float *in, int n) {
    for (int i = 0; i < n; i++) {
        float acc = 0;
        for (int k = 0; k < f->ntaps; k++)
            acc += f->taps[k] * in[i + k];
        out[i] = acc;
    }
}

/* ---- sinc function ---- */

static float sincf(float x) {
    if (fabsf(x) < 1e-10f) return 1.0f;
    return sinf((float)M_PI * x) / ((float)M_PI * x);
}

/* ---- Root Raised Cosine taps ---- */

float *rrc_taps(int *ntaps_out, float gain, float sample_rate,
                float symbol_rate, float alpha, int ntaps) {
    /* Ensure odd number of taps */
    ntaps |= 1;
    *ntaps_out = ntaps;

    float *taps = malloc(sizeof(float) * ntaps);
    float sps = sample_rate / symbol_rate;
    int center = ntaps / 2;

    float energy = 0;
    for (int i = 0; i < ntaps; i++) {
        float t = (i - center) / sps;

        if (fabsf(t) < 1e-10f) {
            /* t = 0 */
            taps[i] = (1.0f - alpha + 4.0f * alpha / (float)M_PI);
        } else if (fabsf(fabsf(t) - 1.0f / (4.0f * alpha)) < 1e-6f) {
            /* t = +/- 1/(4*alpha) */
            taps[i] = alpha / sqrtf(2.0f) *
                ((1.0f + 2.0f / (float)M_PI) * sinf((float)M_PI / (4.0f * alpha)) +
                 (1.0f - 2.0f / (float)M_PI) * cosf((float)M_PI / (4.0f * alpha)));
        } else {
            float num = sinf((float)M_PI * t * (1.0f - alpha)) +
                        4.0f * alpha * t * cosf((float)M_PI * t * (1.0f + alpha));
            float den = (float)M_PI * t * (1.0f - (4.0f * alpha * t) * (4.0f * alpha * t));
            taps[i] = num / den;
        }
        energy += taps[i] * taps[i];
    }

    /* Normalize */
    float scale = gain / sqrtf(energy);
    for (int i = 0; i < ntaps; i++)
        taps[i] *= scale;

    return taps;
}

/* ---- Raised Cosine taps ---- */

float *rc_taps(int *ntaps_out, float sample_rate, float symbol_rate,
               float alpha, int ntaps) {
    ntaps |= 1;
    *ntaps_out = ntaps;

    float *taps = malloc(sizeof(float) * ntaps);
    float sps = sample_rate / symbol_rate;
    int center = ntaps / 2;

    for (int i = 0; i < ntaps; i++) {
        float t = (i - center) / sps;

        if (fabsf(t) < 1e-10f) {
            taps[i] = 1.0f;
        } else if (alpha > 0 && fabsf(fabsf(t) - 1.0f / (2.0f * alpha)) < 1e-6f) {
            taps[i] = (float)M_PI / (4.0f) * sincf(1.0f / (2.0f * alpha));
        } else {
            float cos_term = cosf((float)M_PI * alpha * t);
            float den = 1.0f - (2.0f * alpha * t) * (2.0f * alpha * t);
            taps[i] = sincf(t) * cos_term / den;
        }
    }

    return taps;
}

/* ---- Low-pass filter taps (windowed sinc with Blackman-Harris) ---- */

float *lpf_taps(int *ntaps_out, float gain, float sample_rate,
                float cutoff_freq, float transition_width) {
    /* Estimate filter order from transition width */
    int ntaps = (int)(4.0f / (transition_width / sample_rate));
    ntaps |= 1;
    *ntaps_out = ntaps;

    float *taps = malloc(sizeof(float) * ntaps);
    int center = ntaps / 2;
    float omega_c = 2.0f * (float)M_PI * cutoff_freq / sample_rate;

    float energy = 0;
    for (int i = 0; i < ntaps; i++) {
        float n = i - center;
        /* Sinc */
        float h;
        if (fabsf(n) < 1e-10f)
            h = omega_c / (float)M_PI;
        else
            h = sinf(omega_c * n) / ((float)M_PI * n);

        /* Blackman-Harris window */
        float w = 0.35875f
                - 0.48829f * cosf(2.0f * (float)M_PI * i / (ntaps - 1))
                + 0.14128f * cosf(4.0f * (float)M_PI * i / (ntaps - 1))
                - 0.01168f * cosf(6.0f * (float)M_PI * i / (ntaps - 1));

        taps[i] = h * w;
        energy += taps[i];
    }

    /* Normalize to unity DC gain, then apply desired gain */
    if (fabsf(energy) > 0) {
        float scale = gain / energy;
        for (int i = 0; i < ntaps; i++)
            taps[i] *= scale;
    }

    return taps;
}

/* ---- Box (averaging) filter taps ---- */

float *box_taps(int *ntaps_out, int length) {
    *ntaps_out = length;
    float *taps = malloc(sizeof(float) * length);
    float val = 1.0f / length;
    for (int i = 0; i < length; i++)
        taps[i] = val;
    return taps;
}
