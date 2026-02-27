/*
 * WGS-84 geodetic constants and coordinate transforms
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __WGS84_H__
#define __WGS84_H__

#include <math.h>

/* WGS-84 ellipsoid parameters */
#define WGS84_A     6378137.0              /* semi-major axis (m) */
#define WGS84_F     (1.0 / 298.257223563)  /* flattening */
#define WGS84_B     (WGS84_A * (1.0 - WGS84_F))
#define WGS84_E2    (2.0 * WGS84_F - WGS84_F * WGS84_F)

/* Physical constants */
#define GM_EARTH    3.986004418e14         /* gravitational parameter (m^3/s^2) */
#define C_LIGHT     299792458.0            /* speed of light (m/s) */
#define OMEGA_EARTH 7.2921150e-5           /* Earth rotation rate (rad/s) */

/* Iridium L-band */
#define IR_CARRIER_FREQ  1626000000.0      /* nominal carrier frequency (Hz) */
#define IR_LAMBDA        (C_LIGHT / IR_CARRIER_FREQ)

/* Convert geodetic (lat/lon in degrees, alt in meters) to ECEF (meters) */
static inline void geodetic_to_ecef(double lat_deg, double lon_deg,
                                     double alt_m, double ecef[3])
{
    double lat = lat_deg * M_PI / 180.0;
    double lon = lon_deg * M_PI / 180.0;
    double slat = sin(lat), clat = cos(lat);
    double slon = sin(lon), clon = cos(lon);
    double N = WGS84_A / sqrt(1.0 - WGS84_E2 * slat * slat);

    ecef[0] = (N + alt_m) * clat * clon;
    ecef[1] = (N + alt_m) * clat * slon;
    ecef[2] = (N * (1.0 - WGS84_E2) + alt_m) * slat;
}

/* Convert ECEF (meters) to geodetic (lat/lon in degrees, alt in meters).
 * Uses iterative Bowring method (converges in 2-3 iterations). */
static inline void ecef_to_geodetic(const double ecef[3],
                                     double *lat_deg, double *lon_deg,
                                     double *alt_m)
{
    double x = ecef[0], y = ecef[1], z = ecef[2];
    double p = sqrt(x * x + y * y);

    *lon_deg = atan2(y, x) * 180.0 / M_PI;

    /* Iterative latitude computation */
    double lat = atan2(z, p * (1.0 - WGS84_E2));
    for (int i = 0; i < 5; i++) {
        double slat = sin(lat);
        double N = WGS84_A / sqrt(1.0 - WGS84_E2 * slat * slat);
        lat = atan2(z + WGS84_E2 * N * slat, p);
    }

    double slat = sin(lat);
    double N = WGS84_A / sqrt(1.0 - WGS84_E2 * slat * slat);
    *alt_m = p / cos(lat) - N;
    *lat_deg = lat * 180.0 / M_PI;
}

/* Build 3x3 ECEF-to-ENU rotation matrix for a given reference point.
 * R[row][col], applied as: enu = R * ecef_delta */
static inline void ecef_to_enu_matrix(double lat_deg, double lon_deg,
                                       double R[3][3])
{
    double lat = lat_deg * M_PI / 180.0;
    double lon = lon_deg * M_PI / 180.0;
    double slat = sin(lat), clat = cos(lat);
    double slon = sin(lon), clon = cos(lon);

    /* East */
    R[0][0] = -slon;
    R[0][1] =  clon;
    R[0][2] =  0.0;
    /* North */
    R[1][0] = -slat * clon;
    R[1][1] = -slat * slon;
    R[1][2] =  clat;
    /* Up */
    R[2][0] =  clat * clon;
    R[2][1] =  clat * slon;
    R[2][2] =  slat;
}

#endif
