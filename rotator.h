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

#include "simd_kernels.h"

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

/* Rotate n samples: out[i] = in[i] * phase; phase *= phase_incr.
 * The block loop lives in simd_rotate (generic and AVX2 give identical
 * results); the phase is renormalized on return. */
static inline void rotator_rotate_n(rotator_t *r, float complex *out,
                                     const float complex *in, int n) {
    simd_rotate(out, in, n, &r->phase, r->phase_incr);
    float mag = cabsf(r->phase);
    if (mag > 0)
        r->phase /= mag;
}

#endif
