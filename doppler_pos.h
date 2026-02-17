/*
 * Doppler-based receiver positioning from Iridium signals
 *
 * Based on: "New Method for Positioning Using IRIDIUM Satellite Signals
 * of Opportunity" (Tan et al., IEEE Access, 2019)
 *
 * Uses Doppler shift measurements from decoded IRA frames combined with
 * satellite positions to estimate the receiver's geographic location via
 * iterated weighted least squares.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __DOPPLER_POS_H__
#define __DOPPLER_POS_H__

#include <stdint.h>
#include "frame_decode.h"

/* Position solution output */
typedef struct {
    double lat, lon;        /* estimated position (degrees) */
    double alt;             /* estimated altitude (meters) */
    double hdop;            /* horizontal dilution of precision */
    int n_measurements;     /* total measurements used */
    int n_satellites;       /* distinct satellites used */
    int converged;          /* 1 if solver converged */
} doppler_solution_t;

/* Initialize the positioning engine. Call once at startup. */
void doppler_pos_init(void);

/* Feed a decoded IRA frame into the measurement buffer. Thread-safe. */
void doppler_pos_add_measurement(const ira_data_t *ira, double frequency,
                                  uint64_t timestamp);

/* Attempt to compute a position solution.
 * Returns 1 if a valid solution was produced, 0 otherwise. */
int doppler_pos_solve(doppler_solution_t *out);

/* Set assumed receiver height for height aiding (meters above WGS-84).
 * A value of 0 disables height aiding. */
void doppler_pos_set_height(double height_m);

#endif
