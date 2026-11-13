/*
 * Doppler positioning simulator: Iridium-like constellation, known receiver,
 * IRA positions quantized to 4 km, true Doppler plus noise and LO offset.
 * Feeds doppler_pos.c and reports the horizontal error.
 *
 * Usage: doppler_sim [-a lat] [-o lon] [-m minutes] [-n noise_hz]
 *                    [-f lo_offset_hz] [-s seed] [-v]
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "doppler_pos.h"
#include "wgs84.h"

int verbose = 0;

#define RA_FREQ     1626270833.0
#define ORBIT_R     (6378137.0 + 780e3)
#define INCL_DEG    86.4
#define PLANES      6
#define PER_PLANE   11
#define STEP_S      4.0         /* IRA cadence per visible satellite */
#define MIN_ELEV    10.0

static double gauss(void)
{
    double u1 = (rand() + 1.0) / (RAND_MAX + 2.0);
    double u2 = (rand() + 1.0) / (RAND_MAX + 2.0);
    return sqrt(-2.0 * log(u1)) * cos(2 * M_PI * u2);
}

/* Inertial position and velocity of satellite k in plane p at time t */
static void sat_inertial(int p, int k, double t, double r[3], double v[3])
{
    double raan = p * (M_PI / PLANES) * (180.0 / 186.0);
    double inc = INCL_DEG * M_PI / 180.0;
    double n = sqrt(GM_EARTH / pow(ORBIT_R, 3));
    double u = 2 * M_PI * k / PER_PLANE + (p % 2) * M_PI / PER_PLANE + n * t;
    double cu = cos(u), su = sin(u), co = cos(raan), so = sin(raan);
    double ci = cos(inc), si = sin(inc);
    double spd = n * ORBIT_R;
    r[0] = ORBIT_R * (co * cu - so * su * ci);
    r[1] = ORBIT_R * (so * cu + co * su * ci);
    r[2] = ORBIT_R * (su * si);
    v[0] = spd * (-co * su - so * cu * ci);
    v[1] = spd * (-so * su + co * cu * ci);
    v[2] = spd * (cu * si);
}

int main(int argc, char **argv)
{
    double lat = 39.0, lon = -77.0, h = 100.0;
    double minutes = 20, noise_hz = 30, lo_hz = 700;
    int seed = 1, opt;

    while ((opt = getopt(argc, argv, "a:o:m:n:f:s:v")) != -1) {
        switch (opt) {
        case 'a': lat = atof(optarg); break;
        case 'o': lon = atof(optarg); break;
        case 'm': minutes = atof(optarg); break;
        case 'n': noise_hz = atof(optarg); break;
        case 'f': lo_hz = atof(optarg); break;
        case 's': seed = atoi(optarg); break;
        case 'v': verbose = 1; break;
        default:
            fprintf(stderr, "usage: %s [-a lat] [-o lon] [-m min] [-n noise_hz] "
                    "[-f lo_hz] [-s seed] [-v]\n", argv[0]);
            return 2;
        }
    }
    srand(seed);

    double rx[3];
    geodetic_to_ecef(lat, lon, h, rx);
    double rx_n = sqrt(rx[0] * rx[0] + rx[1] * rx[1] + rx[2] * rx[2]);

    doppler_pos_init();
    doppler_pos_set_height(h);

    const uint64_t t0_ns = 1800000000ULL * 1000000000ULL;
    double phase0 = (seed * 0.37) * 2 * M_PI;   /* vary constellation phase */
    int fed = 0, solves = 0;
    doppler_solution_t sol = {0};
    int have = 0;

    for (double t = 0; t < minutes * 60; t += STEP_S) {
        double th = OMEGA_EARTH * t + phase0;
        double c = cos(th), s = sin(th);
        for (int p = 0; p < PLANES; p++) {
            for (int k = 0; k < PER_PLANE; k++) {
                double ri[3], vi[3], re[3], ve[3];
                sat_inertial(p, k, t + phase0 * 1000, ri, vi);
                /* ECEF = Rz(-th) * inertial; v_ecef = Rz(-th) v_i - w x r_ecef */
                re[0] = c * ri[0] + s * ri[1];
                re[1] = -s * ri[0] + c * ri[1];
                re[2] = ri[2];
                ve[0] = c * vi[0] + s * vi[1] + OMEGA_EARTH * re[1];
                ve[1] = -s * vi[0] + c * vi[1] - OMEGA_EARTH * re[0];
                ve[2] = vi[2];

                double los[3] = { re[0] - rx[0], re[1] - rx[1], re[2] - rx[2] };
                double rho = sqrt(los[0] * los[0] + los[1] * los[1] + los[2] * los[2]);
                double up = (los[0] * rx[0] + los[1] * rx[1] + los[2] * rx[2]) / (rho * rx_n);
                if (asin(up) * 180 / M_PI < MIN_ELEV)
                    continue;

                double rr = (los[0] * ve[0] + los[1] * ve[1] + los[2] * ve[2]) / rho;
                double freq = RA_FREQ * (1.0 - rr / C_LIGHT) + lo_hz + noise_hz * gauss();

                ira_data_t ira;
                memset(&ira, 0, sizeof(ira));
                ira.sat_id = (p * PER_PLANE + k) & 0x7f;
                ira.beam_id = 0;
                for (int i = 0; i < 3; i++)
                    ira.pos_xyz[i] = (int)lround(re[i] / 4000.0);
                double rn = sqrt(re[0] * re[0] + re[1] * re[1] + re[2] * re[2]);
                ira.lat = asin(re[2] / rn) * 180 / M_PI;
                ira.lon = atan2(re[1], re[0]) * 180 / M_PI;
                ira.alt = (int)((rn - 6371000.0) / 1000.0);

                doppler_pos_add_measurement(&ira, freq, t0_ns + (uint64_t)(t * 1e9));
                fed++;
            }
        }
        /* Solve every 10 s of data, as main.c does on the wall clock */
        if (fmod(t, 10.0) < STEP_S && t > 0) {
            doppler_solution_t s1;
            if (doppler_pos_solve(&s1)) {
                sol = s1;
                have = 1;
            }
            solves++;
        }
    }
    doppler_solution_t s1;
    if (doppler_pos_solve(&s1)) {
        sol = s1;
        have = 1;
    }

    if (!have) {
        printf("no solution (fed %d measurements, %d solves)\n", fed, solves);
        return 1;
    }
    double est[3];
    geodetic_to_ecef(sol.lat, sol.lon, sol.alt, est);
    double d[3] = { est[0] - rx[0], est[1] - rx[1], est[2] - rx[2] };
    /* horizontal error: remove the local-vertical component */
    double upc = (d[0] * rx[0] + d[1] * rx[1] + d[2] * rx[2]) / rx_n;
    double err3 = sqrt(d[0] * d[0] + d[1] * d[1] + d[2] * d[2]);
    double errh = sqrt(fmax(0, err3 * err3 - upc * upc));
    printf("truth %.4f,%.4f  est %.4f,%.4f  horiz err %.2f km  meas %d sats %d "
           "hdop %.1f conv %d\n", lat, lon, sol.lat, sol.lon, errh / 1000,
           sol.n_measurements, sol.n_satellites, sol.hdop, sol.converged);
    return 0;
}
