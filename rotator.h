/*
 * Complex frequency rotator
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Complex frequency rotator
 */

#ifndef __ROTATOR_H__
#define __ROTATOR_H__

#include <complex.h>

typedef struct {
    float complex phase;
    float complex phase_incr;
} rotator_t;

static inline void rotator_init(rotator_t *r) {
    r->phase = 1.0f;
    r->phase_incr = 1.0f;
}

static inline void rotator_set_phase(rotator_t *r, float complex phase) {
    r->phase = phase;
}

static inline void rotator_set_phase_incr(rotator_t *r, float complex incr) {
    r->phase_incr = incr;
}

#define ROTATOR_BLOCK 8

/* Rotate n samples: out[i] = in[i] * phase; phase *= phase_incr.
 * Blocks of ROTATOR_BLOCK with precomputed steps break the serial phase
 * dependency so the inner loop vectorizes; phase is renormalized as it goes. */
static inline void rotator_rotate_n(rotator_t *r, float complex *out,
                                     const float complex *in, int n) {
    float sr[ROTATOR_BLOCK], si[ROTATOR_BLOCK];
    float complex p = 1.0f;
    for (int k = 0; k < ROTATOR_BLOCK; k++) {
        sr[k] = crealf(p);
        si[k] = cimagf(p);
        p *= r->phase_incr;
    }
    float complex block_incr = p;

    const float *x = (const float *)in;
    float *y = (float *)out;
    int i = 0;
    for (; i + ROTATOR_BLOCK <= n; i += ROTATOR_BLOCK) {
        float pr = crealf(r->phase), pi = cimagf(r->phase);
        for (int k = 0; k < ROTATOR_BLOCK; k++) {
            float wr = pr * sr[k] - pi * si[k];
            float wi = pr * si[k] + pi * sr[k];
            float xr = x[2 * (i + k)], xi = x[2 * (i + k) + 1];
            y[2 * (i + k)] = xr * wr - xi * wi;
            y[2 * (i + k) + 1] = xr * wi + xi * wr;
        }
        r->phase *= block_incr;
        if ((i & (64 * ROTATOR_BLOCK - 1)) == 0) {
            /* |phase| stays near 1: one Newton step for 1/|phase| */
            float m2 = crealf(r->phase) * crealf(r->phase) +
                       cimagf(r->phase) * cimagf(r->phase);
            r->phase *= 0.5f * (3.0f - m2);
        }
    }
    for (; i < n; i++) {
        out[i] = in[i] * r->phase;
        r->phase *= r->phase_incr;
    }
    float mag = cabsf(r->phase);
    if (mag > 0)
        r->phase /= mag;
}

#endif
