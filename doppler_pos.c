/*
 * Doppler-based receiver positioning from Iridium signals
 *
 * Based on: "New Method for Positioning Using IRIDIUM Satellite Signals
 * of Opportunity" (Tan et al., IEEE Access, 2019)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "doppler_pos.h"
#include "wgs84.h"

extern int verbose;

/* ---- Configuration ---- */

#define MAX_SATELLITES       128
#define MEAS_PER_SAT         200     /* circular buffer depth per satellite */
#define MIN_MEASUREMENTS     8       /* minimum to attempt a solution */
#define MIN_SATELLITES       2       /* need geometry from multiple passes */
#define MAX_ITERATIONS       200     /* WLS iteration limit */
#define CONVERGENCE_M        100.0   /* position correction threshold (m) */
#define OUTLIER_SIGMA        3.0     /* residual rejection threshold */
#define MAX_MEAS_AGE_NS      (30ULL * 60 * 1000000000ULL)  /* 30 min */
#define MIN_VEL_INTERVAL_NS  (2ULL * 1000000000ULL)         /* 2 sec */
#define MAX_SAT_CLUSTER_DIST 8000e3   /* max 3D ECEF distance between visible sats (m) */
#define SAT_GAP_RESET_S      600.0   /* reset sat buffer after 10 min gap (new pass) */
#define MAX_SOLUTION_JUMP    500e3    /* reject solutions >500 km from previous (m) */
#define RA_FREQ              1626270833.0  /* ring-alert channel; IRA is only sent here */
#define RA_ACCEPT_HZ         62500.0  /* Doppler + LO error, half way to the next channel */
#define HEIGHT_WEIGHT        100.0    /* height constraint weight vs (m/s)^2 residuals */
#define START_RING           8        /* extra solver starts around the centroid */
#define START_RING_M         1500e3   /* their distance from the centroid (m) */

/* ---- Internal types ---- */

typedef struct {
    double sat_ecef[3];     /* satellite ECEF position (m) */
    double freq;            /* measured burst frequency (Hz) */
    uint64_t timestamp;     /* nanoseconds */
    int valid;
} sat_meas_t;

typedef struct {
    int sat_id;
    sat_meas_t meas[MEAS_PER_SAT];
    int head;               /* next write index */
    int count;              /* total stored (capped at MEAS_PER_SAT) */
} sat_buffer_t;

/* Flattened measurement for the solver */
typedef struct {
    double sat_ecef[3];
    double sat_vel[3];      /* estimated satellite velocity (m/s) */
    double range_rate;      /* measured range rate (m/s) */
    double weight;
    int sat_idx;            /* index into satellites[] for per-sat residual check */
} solver_meas_t;

/* ---- Module state ---- */

static pthread_mutex_t pos_lock;
static sat_buffer_t satellites[MAX_SATELLITES];
static int n_satellites;
static double height_aiding_m = -1.0;  /* -1 = disabled, >= 0 = altitude in meters */
static int height_aiding_enabled;

/* Persistent solution state (reused between solve calls) */
static double prev_ecef[3] = {0, 0, 0};
static double prev_clock_drift = 0;
static int has_prev_solution = 0;
static int jump_reject_count = 0;

/* ---- Helpers ---- */

static double vec3_dot(const double a[3], const double b[3])
{
    return a[0]*b[0] + a[1]*b[1] + a[2]*b[2];
}

static double vec3_norm(const double v[3])
{
    return sqrt(v[0]*v[0] + v[1]*v[1] + v[2]*v[2]);
}

static void vec3_sub(const double a[3], const double b[3], double out[3])
{
    out[0] = a[0] - b[0];
    out[1] = a[1] - b[1];
    out[2] = a[2] - b[2];
}

static void vec3_cross(const double a[3], const double b[3], double out[3])
{
    out[0] = a[1]*b[2] - a[2]*b[1];
    out[1] = a[2]*b[0] - a[0]*b[2];
    out[2] = a[0]*b[1] - a[1]*b[0];
}

/* a - b in seconds; timestamps are unsigned ns */
static double ns_diff_s(uint64_t a, uint64_t b)
{
    return (double)(int64_t)(a - b) / 1e9;
}

/* Convert IRA-encoded satellite position to ECEF meters.
 * IRA uses 12-bit signed XYZ where 1 unit ~ 4 km of geocentric distance. */
static void ira_xyz_to_ecef(const int pos_xyz[3], double ecef[3])
{
    ecef[0] = (double)pos_xyz[0] * 4000.0;
    ecef[1] = (double)pos_xyz[1] * 4000.0;
    ecef[2] = (double)pos_xyz[2] * 4000.0;
}

/* Find satellite buffer by ID, or allocate a new one */
static sat_buffer_t *find_or_create_sat(int sat_id)
{
    for (int i = 0; i < n_satellites; i++) {
        if (satellites[i].sat_id == sat_id)
            return &satellites[i];
    }
    if (n_satellites >= MAX_SATELLITES)
        return NULL;
    sat_buffer_t *s = &satellites[n_satellites++];
    memset(s, 0, sizeof(*s));
    s->sat_id = sat_id;
    return s;
}

/* Add measurement to a satellite's circular buffer */
static void sat_buf_add(sat_buffer_t *s, const double ecef[3],
                         double freq, uint64_t ts)
{
    sat_meas_t *m = &s->meas[s->head];
    m->sat_ecef[0] = ecef[0];
    m->sat_ecef[1] = ecef[1];
    m->sat_ecef[2] = ecef[2];
    m->freq = freq;
    m->timestamp = ts;
    m->valid = 1;
    s->head = (s->head + 1) % MEAS_PER_SAT;
    if (s->count < MEAS_PER_SAT)
        s->count++;
}

/* Get measurement by index (0 = oldest) */
static sat_meas_t *sat_buf_get(sat_buffer_t *s, int idx)
{
    if (idx < 0 || idx >= s->count) return NULL;
    int start = (s->count < MEAS_PER_SAT) ? 0 :
                (s->head - s->count + MEAS_PER_SAT) % MEAS_PER_SAT;
    return &s->meas[(start + idx) % MEAS_PER_SAT];
}

/* Earth-fixed satellite velocity from two IRA positions, assuming a circular
 * orbit. The partner position is rotated into an inertial frame aligned with
 * ECEF at the current epoch, the orbit plane and inertial velocity come from
 * that, and v_ecef = v_inertial - omega x r. */
static int estimate_velocity(sat_buffer_t *s, int idx, double vel[3])
{
    sat_meas_t *cur = sat_buf_get(s, idx);
    if (!cur) return -1;

    double r_norm = vec3_norm(cur->sat_ecef);
    if (r_norm < 1e6) return -1;

    /* Widest separation gives the best plane despite 4 km quantization */
    sat_meas_t *best_other = NULL;
    double best_dt = 0;

    for (int i = 0; i < s->count; i++) {
        if (i == idx) continue;
        sat_meas_t *m = sat_buf_get(s, i);
        if (!m || !m->valid) continue;
        double dt = fabs(ns_diff_s(m->timestamp, cur->timestamp));
        if (dt >= MIN_VEL_INTERVAL_NS / 1e9 && dt < 600.0 && dt > best_dt) {
            double other_r = vec3_norm(m->sat_ecef);
            if (other_r < 7050e3 || other_r > 7250e3) continue;
            best_dt = dt;
            best_other = m;
        }
    }
    if (!best_other) return -1;

    double dt = ns_diff_s(best_other->timestamp, cur->timestamp);
    double th = OMEGA_EARTH * dt, c = cos(th), sn = sin(th);
    const double *o = best_other->sat_ecef;
    double other_i[3] = { c * o[0] - sn * o[1], sn * o[0] + c * o[1], o[2] };

    double h[3];
    if (dt > 0)
        vec3_cross(cur->sat_ecef, other_i, h);
    else
        vec3_cross(other_i, cur->sat_ecef, h);
    if (vec3_norm(h) < 1e6) return -1;  /* nearly collinear positions */

    double v_dir[3];
    vec3_cross(h, cur->sat_ecef, v_dir);
    double v_norm = vec3_norm(v_dir);
    if (v_norm < 1.0) return -1;

    double speed = sqrt(GM_EARTH / r_norm);
    const double *r = cur->sat_ecef;
    vel[0] = speed * v_dir[0] / v_norm + OMEGA_EARTH * r[1];
    vel[1] = speed * v_dir[1] / v_norm - OMEGA_EARTH * r[0];
    vel[2] = speed * v_dir[2] / v_norm;
    return 0;
}

/* 4x4 matrix inversion via Gauss-Jordan elimination.
 * Operates in-place on A[4][4], stores inverse in inv[4][4].
 * Returns 0 on success, -1 if singular. */
static int mat4_invert(double A[4][4], double inv[4][4])
{
    /* Initialize inv to identity */
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            inv[i][j] = (i == j) ? 1.0 : 0.0;

    for (int col = 0; col < 4; col++) {
        /* Partial pivoting */
        int pivot = col;
        double max_val = fabs(A[col][col]);
        for (int row = col + 1; row < 4; row++) {
            if (fabs(A[row][col]) > max_val) {
                max_val = fabs(A[row][col]);
                pivot = row;
            }
        }
        if (max_val < 1e-30) return -1;

        if (pivot != col) {
            for (int j = 0; j < 4; j++) {
                double tmp;
                tmp = A[col][j]; A[col][j] = A[pivot][j]; A[pivot][j] = tmp;
                tmp = inv[col][j]; inv[col][j] = inv[pivot][j]; inv[pivot][j] = tmp;
            }
        }

        double diag = A[col][col];
        for (int j = 0; j < 4; j++) {
            A[col][j] /= diag;
            inv[col][j] /= diag;
        }

        for (int row = 0; row < 4; row++) {
            if (row == col) continue;
            double factor = A[row][col];
            for (int j = 0; j < 4; j++) {
                A[row][j] -= factor * A[col][j];
                inv[row][j] -= factor * inv[col][j];
            }
        }
    }
    return 0;
}

/* ---- Public API ---- */

void doppler_pos_init(void)
{
    pthread_mutex_init(&pos_lock, NULL);
    n_satellites = 0;
    height_aiding_m = -1.0;
    height_aiding_enabled = 0;
    memset(satellites, 0, sizeof(satellites));
}

void doppler_pos_set_height(double height_m)
{
    height_aiding_m = height_m;
    height_aiding_enabled = 1;
}

void doppler_pos_add_measurement(const ira_data_t *ira, double frequency,
                                  uint64_t timestamp)
{
    static unsigned long dbg_total = 0, dbg_sat0 = 0, dbg_coord = 0,
                         dbg_radius = 0, dbg_ok = 0, dbg_vel_rej = 0,
                         dbg_freq = 0;

    dbg_total++;

    if (ira->sat_id == 0) { dbg_sat0++; goto dbg_print; }
    if (ira->lat < -90 || ira->lat > 90) { dbg_coord++; goto dbg_print; }
    if (ira->lon < -180 || ira->lon > 180) { dbg_coord++; goto dbg_print; }
    if (fabs(frequency - RA_FREQ) > RA_ACCEPT_HZ) { dbg_freq++; goto dbg_print; }

    /* Convert IRA satellite position to ECEF */
    double sat_ecef[3];
    ira_xyz_to_ecef(ira->pos_xyz, sat_ecef);

    /* Sanity: Iridium orbit radius ~7158 km (780 km altitude).
     * Accept 7050-7250 km (altitude 672-872 km) to reject false positives. */
    double r = vec3_norm(sat_ecef);
    if (r < 7050e3 || r > 7250e3) {
        dbg_radius++;
        goto dbg_print;
    }

    pthread_mutex_lock(&pos_lock);
    sat_buffer_t *s = find_or_create_sat(ira->sat_id);
    if (s) {
        if (s->count > 0) {
            int last = (s->head - 1 + MEAS_PER_SAT) % MEAS_PER_SAT;
            double dt = ns_diff_s(timestamp, s->meas[last].timestamp);

            /* Long gap: likely a different physical satellite reusing
             * this 7-bit sat_id. Reset the buffer to avoid mixing
             * measurements from different orbital planes. */
            if (dt > SAT_GAP_RESET_S) {
                if (verbose)
                    fprintf(stderr, "DOPPLER: sat=%d gap=%.0fs, "
                            "resetting buffer (likely new pass)\n",
                            ira->sat_id, dt);
                s->count = 0;
                s->head = 0;
            } else {
                /* Short gap: verify position consistency.
                 * At ~7.5 km/s, speed > 10 km/s is impossible. */
                double dx = sat_ecef[0] - s->meas[last].sat_ecef[0];
                double dy = sat_ecef[1] - s->meas[last].sat_ecef[1];
                double dz = sat_ecef[2] - s->meas[last].sat_ecef[2];
                double dist = sqrt(dx*dx + dy*dy + dz*dz);
                if (dt > 0 && dt < 120 && dist / dt > 10000.0) {
                    dbg_vel_rej++;
                    pthread_mutex_unlock(&pos_lock);
                    goto dbg_print;
                }
            }
        }
        sat_buf_add(s, sat_ecef, frequency, timestamp);
    }
    pthread_mutex_unlock(&pos_lock);

    if (verbose) {
        double slat, slon, salt;
        ecef_to_geodetic(sat_ecef, &slat, &slon, &salt);
        fprintf(stderr, "DOPPLER: accepted sat=%d pos=%.1f,%.1f "
                "alt=%.0fkm freq=%.0f\n",
                ira->sat_id, slat, slon, salt/1000.0, frequency);
    }
    dbg_ok++;

dbg_print:
    if (verbose && dbg_total % 50 == 0)
        fprintf(stderr, "DOPPLER: ira_total=%lu ok=%lu "
                "reject_sat0=%lu reject_coord=%lu reject_radius=%lu "
                "reject_vel=%lu reject_freq=%lu\n",
                dbg_total, dbg_ok, dbg_sat0, dbg_coord, dbg_radius,
                dbg_vel_rej, dbg_freq);
}

/* Range rate in ECEF (receiver fixed, sat_vel Earth-fixed) and its gradient
 * with respect to receiver position. NAN when degenerate. */
static double model_range_rate(const solver_meas_t *m, const double rx[3],
                               double grad[3])
{
    double los[3];
    vec3_sub(m->sat_ecef, rx, los);
    double rho = vec3_norm(los);
    if (rho < 1.0) return NAN;
    double rr = vec3_dot(los, m->sat_vel) / rho;
    if (grad)
        for (int i = 0; i < 3; i++)
            grad[i] = (-m->sat_vel[i] + los[i] * rr / rho) / rho;
    return rr;
}

static double meas_residual(const solver_meas_t *m, const double rx[3],
                            double clk)
{
    return m->range_rate - (model_range_rate(m, rx, NULL) + clk);
}

/* Height-aiding residual (m); grad gets d(alt)/d(rx), the radial unit vector */
static double height_residual(const double rx[3], double grad[3])
{
    double r0 = vec3_norm(rx);
    double lat, lon, alt;
    ecef_to_geodetic(rx, &lat, &lon, &alt);
    for (int i = 0; i < 3; i++)
        grad[i] = rx[i] / r0;
    return height_aiding_m - alt;
}

static double solve_cost(const solver_meas_t *meas, int n, const double rx[3],
                         double clk, int use_height)
{
    double cost = 0;
    for (int i = 0; i < n; i++) {
        if (meas[i].weight <= 0) continue;
        double r = meas_residual(&meas[i], rx, clk);
        if (!isnan(r))
            cost += meas[i].weight * r * r;
    }
    if (use_height) {
        double g[3];
        double h = height_residual(rx, g);
        cost += HEIGHT_WEIGHT * h * h;
    }
    return cost;
}

/* Levenberg-Marquardt over [x, y, z, clock]. A step is kept only if it lowers
 * the cost; converged once an accepted step moves less than CONVERGENCE_M. */
static int wls_solve(const solver_meas_t *meas, int n, double rx[3],
                     double *clk, int use_height)
{
    double lambda = 1e-3;

    for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
        double A[4][4] = {{0}}, g[4] = {0};

        for (int i = 0; i < n; i++) {
            const solver_meas_t *m = &meas[i];
            if (m->weight <= 0) continue;
            double H[4];
            double rr = model_range_rate(m, rx, H);
            if (isnan(rr)) continue;
            H[3] = 1.0;
            double dy = m->range_rate - (rr + *clk);
            for (int r = 0; r < 4; r++) {
                for (int c = 0; c < 4; c++)
                    A[r][c] += H[r] * m->weight * H[c];
                g[r] += H[r] * m->weight * dy;
            }
        }
        if (use_height) {
            double H[4];
            double dy = height_residual(rx, H);
            H[3] = 0.0;
            for (int r = 0; r < 4; r++) {
                for (int c = 0; c < 4; c++)
                    A[r][c] += H[r] * HEIGHT_WEIGHT * H[c];
                g[r] += H[r] * HEIGHT_WEIGHT * dy;
            }
        }
        double cost = solve_cost(meas, n, rx, *clk, use_height);

        for (;;) {
            double M[4][4], inv[4][4], d[4] = {0};
            memcpy(M, A, sizeof(M));
            for (int i = 0; i < 4; i++)
                M[i][i] += lambda * A[i][i] + 1e-9;
            if (mat4_invert(M, inv) != 0) {
                lambda *= 10;
                if (lambda > 1e8) return 0;
                continue;
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    d[i] += inv[i][j] * g[j];

            double step = sqrt(d[0]*d[0] + d[1]*d[1] + d[2]*d[2]);
            if (step > 500e3) {
                for (int i = 0; i < 4; i++)
                    d[i] *= 500e3 / step;
                step = 500e3;
            }

            double cand[3] = { rx[0] + d[0], rx[1] + d[1], rx[2] + d[2] };
            double cand_clk = *clk + d[3];
            if (solve_cost(meas, n, cand, cand_clk, use_height) <= cost) {
                memcpy(rx, cand, sizeof(cand));
                *clk = cand_clk;
                lambda = fmax(lambda * 0.1, 1e-9);
                if (step < CONVERGENCE_M)
                    return 1;
                break;
            }
            lambda *= 10;
            if (lambda > 1e8)
                return 1;   /* no downhill step left: at the minimum */
        }
    }
    return 0;
}

int doppler_pos_solve(doppler_solution_t *out)
{
    memset(out, 0, sizeof(*out));

    pthread_mutex_lock(&pos_lock);

    /* Collect valid measurements with velocity estimates */
    static solver_meas_t all_meas[MAX_SATELLITES * MEAS_PER_SAT];
    int n_meas = 0;
    int sats_used = 0;
    uint64_t now = 0;

    /* Find latest timestamp as reference */
    for (int s = 0; s < n_satellites; s++) {
        for (int i = 0; i < satellites[s].count; i++) {
            sat_meas_t *m = sat_buf_get(&satellites[s], i);
            if (m && m->valid && m->timestamp > now)
                now = m->timestamp;
        }
    }

    /* Spatial visibility filter: cluster satellites by proximity.
     * All satellites visible from a single receiver are within ~6000 km
     * ground distance, which corresponds to ~8000 km in 3D ECEF at orbit
     * altitude. Corrupted IRA positions (valid altitude, wrong lat/lon)
     * place satellites on the opposite side of the planet (>12000 km away).
     *
     * Key insight: only consider satellites with demonstrated orbital motion
     * (valid velocity estimates). Real satellites move at ~7.5 km/s so their
     * positions change between IRA frames. Corrupted decodes tend to report
     * the same wrong position repeatedly (zero apparent motion), which fails
     * the velocity estimation. This filters them before clustering. */
    int sat_keep[MAX_SATELLITES] = {0};
    {
        double sat_pos[MAX_SATELLITES][3];
        int sat_has_motion[MAX_SATELLITES] = {0};
        int n_with_motion = 0;
        int vel_usable[MAX_SATELLITES] = {0};  /* count of velocity-valid meas */

        for (int s = 0; s < n_satellites; s++) {
            if (satellites[s].count < 2) continue;

            /* Check if this satellite has any measurement with a valid
             * velocity estimate (proves it's actually moving in orbit) */
            int latest_vel_idx = -1;
            for (int i = satellites[s].count - 1; i >= 0; i--) {
                sat_meas_t *m = sat_buf_get(&satellites[s], i);
                if (!m || !m->valid) continue;
                if (now > 0 && now - m->timestamp > MAX_MEAS_AGE_NS) continue;
                double vel[3];
                if (estimate_velocity(&satellites[s], i, vel) == 0) {
                    vel_usable[s]++;
                    if (latest_vel_idx < 0) latest_vel_idx = i;
                }
            }

            if (latest_vel_idx >= 0) {
                sat_meas_t *m = sat_buf_get(&satellites[s], latest_vel_idx);
                sat_pos[s][0] = m->sat_ecef[0];
                sat_pos[s][1] = m->sat_ecef[1];
                sat_pos[s][2] = m->sat_ecef[2];
                sat_has_motion[s] = 1;
                n_with_motion++;
            }
        }

        if (n_with_motion >= 3) {
            /* Count mutual neighbors among motion-validated satellites */
            int neighbors[MAX_SATELLITES] = {0};
            for (int i = 0; i < n_satellites; i++) {
                if (!sat_has_motion[i]) continue;
                for (int j = i + 1; j < n_satellites; j++) {
                    if (!sat_has_motion[j]) continue;
                    double d[3];
                    vec3_sub(sat_pos[i], sat_pos[j], d);
                    if (vec3_norm(d) < MAX_SAT_CLUSTER_DIST) {
                        neighbors[i]++;
                        neighbors[j]++;
                    }
                }
            }

            /* Find cluster core: most neighbors, break ties by number
             * of velocity-usable measurements (not raw buffer count) */
            int core = -1;
            int max_nb = -1;
            int max_vel = -1;
            for (int s = 0; s < n_satellites; s++) {
                if (!sat_has_motion[s]) continue;
                if (neighbors[s] > max_nb ||
                    (neighbors[s] == max_nb &&
                     vel_usable[s] > max_vel)) {
                    max_nb = neighbors[s];
                    max_vel = vel_usable[s];
                    core = s;
                }
            }

            /* Keep all motion-validated satellites within threshold of core.
             * Also keep satellites without motion proof if they have recent
             * measurements (newcomers that haven't accumulated enough for
             * velocity yet) and are near the cluster. */
            if (core >= 0) {
                sat_keep[core] = 1;
                for (int s = 0; s < n_satellites; s++) {
                    if (s == core) continue;
                    if (!sat_has_motion[s]) {
                        /* Newcomer: get its latest position and check distance */
                        for (int i = satellites[s].count - 1; i >= 0; i--) {
                            sat_meas_t *m = sat_buf_get(&satellites[s], i);
                            if (!m || !m->valid) continue;
                            if (now > 0 && now - m->timestamp > MAX_MEAS_AGE_NS)
                                continue;
                            double d[3];
                            vec3_sub(m->sat_ecef, sat_pos[core], d);
                            if (vec3_norm(d) < MAX_SAT_CLUSTER_DIST)
                                sat_keep[s] = 1;
                            break;
                        }
                        continue;
                    }
                    double d[3];
                    vec3_sub(sat_pos[s], sat_pos[core], d);
                    double dist = vec3_norm(d);
                    if (dist < MAX_SAT_CLUSTER_DIST) {
                        sat_keep[s] = 1;
                    } else if (verbose) {
                        double slat, slon, salt;
                        ecef_to_geodetic(sat_pos[s], &slat, &slon, &salt);
                        fprintf(stderr, "DOPPLER: visibility reject "
                                "sat=%d pos=%.1f,%.1f (%.0fkm from core "
                                "sat=%d)\n", satellites[s].sat_id, slat, slon,
                                dist / 1000.0, satellites[core].sat_id);
                    }
                }
            }
        } else {
            /* Not enough motion-validated satellites to cluster;
             * keep all that have recent measurements */
            for (int s = 0; s < n_satellites; s++) {
                if (satellites[s].count == 0) continue;
                for (int i = satellites[s].count - 1; i >= 0; i--) {
                    sat_meas_t *m = sat_buf_get(&satellites[s], i);
                    if (m && m->valid &&
                        (now == 0 || now - m->timestamp <= MAX_MEAS_AGE_NS)) {
                        sat_keep[s] = 1;
                        break;
                    }
                }
            }
        }
    }

    for (int s = 0; s < n_satellites; s++) {
        if (!sat_keep[s]) continue;
        int sat_contributed = 0;

        for (int i = 0; i < satellites[s].count; i++) {
            sat_meas_t *m = sat_buf_get(&satellites[s], i);
            if (!m || !m->valid) continue;

            /* Skip old measurements */
            if (now - m->timestamp > MAX_MEAS_AGE_NS) continue;

            /* Estimate satellite velocity */
            double vel[3];
            if (estimate_velocity(&satellites[s], i, vel) != 0)
                continue;

            double range_rate = -(C_LIGHT / RA_FREQ) * (m->freq - RA_FREQ);

            solver_meas_t *sm = &all_meas[n_meas];
            memcpy(sm->sat_ecef, m->sat_ecef, sizeof(sm->sat_ecef));
            memcpy(sm->sat_vel, vel, sizeof(sm->sat_vel));
            sm->range_rate = range_rate;
            sm->weight = 1.0;
            sm->sat_idx = s;
            n_meas++;
            sat_contributed = 1;

            if (n_meas >= MAX_SATELLITES * MEAS_PER_SAT)
                goto done_collect;
        }

        if (sat_contributed)
            sats_used++;
    }
done_collect:

    /* Debug: show buffer state vs usable measurements */
    if (verbose) {
        int total_buf = 0;
        for (int s = 0; s < n_satellites; s++)
            total_buf += satellites[s].count;
        static int solve_dbg_cnt = 0;
        if (solve_dbg_cnt++ % 6 == 0)
            fprintf(stderr, "DOPPLER: buffers=%d stored=%d usable=%d "
                    "from %d sats\n",
                    n_satellites, total_buf, n_meas, sats_used);
    }

    pthread_mutex_unlock(&pos_lock);

    /* Check minimum data requirements */
    if (n_meas < MIN_MEASUREMENTS || sats_used < MIN_SATELLITES) {
        out->n_measurements = n_meas;
        out->n_satellites = sats_used;
        return 0;
    }

    /* Start points: the previous fix, the centroid of the sub-satellite
     * points (weighted by measurement count), and a ring around it. With few
     * passes Doppler has a mirror solution across the ground track, so a
     * single start can settle in the wrong basin; keep the lowest cost. */
    double centroid[3] = {0, 0, 0};
    double total_weight = 0;
    for (int s = 0; s < n_satellites; s++) {
        if (!sat_keep[s] || satellites[s].count == 0) continue;
        sat_meas_t *latest = NULL;
        for (int i = satellites[s].count - 1; i >= 0; i--) {
            sat_meas_t *m = sat_buf_get(&satellites[s], i);
            if (m && m->valid) { latest = m; break; }
        }
        if (!latest) continue;
        double r = vec3_norm(latest->sat_ecef);
        if (r <= 0) continue;
        double scale = WGS84_A / r;
        double w = (double)satellites[s].count;
        for (int k = 0; k < 3; k++)
            centroid[k] += latest->sat_ecef[k] * scale * w;
        total_weight += w;
    }
    if (total_weight > 0)
        for (int k = 0; k < 3; k++)
            centroid[k] /= total_weight;

    double clat, clon, calt;
    ecef_to_geodetic(centroid, &clat, &clon, &calt);
    double start_h = height_aiding_enabled ? height_aiding_m : 0.0;

    double starts[2 + START_RING][3];
    int n_starts = 0;
    if (has_prev_solution)
        memcpy(starts[n_starts++], prev_ecef, sizeof(prev_ecef));
    geodetic_to_ecef(clat, clon, start_h, starts[n_starts++]);
    for (int k = 0; k < START_RING; k++) {
        double brg = 2 * M_PI * k / START_RING;
        double dlat = START_RING_M * cos(brg) / 6371e3 * 180 / M_PI;
        double dlon = START_RING_M * sin(brg) /
                      (6371e3 * fmax(cos(clat * M_PI / 180), 0.1)) * 180 / M_PI;
        double slat = fmax(-89.0, fmin(89.0, clat + dlat));
        geodetic_to_ecef(slat, remainder(clon + dlon, 360.0), start_h,
                         starts[n_starts++]);
    }

    int use_height = height_aiding_enabled;
    double rx_ecef[3] = {0, 0, 0};
    double clock_drift = 0;
    double best_cost = INFINITY, prev_basin_cost = INFINITY;

    for (int k = 0; k < n_starts; k++) {
        double x[3], clk = has_prev_solution ? prev_clock_drift : 0;
        memcpy(x, starts[k], sizeof(x));
        if (!wls_solve(all_meas, n_meas, x, &clk, use_height))
            continue;
        double cost = solve_cost(all_meas, n_meas, x, clk, use_height);
        if (has_prev_solution && k == 0)
            prev_basin_cost = cost;
        if (cost < best_cost) {
            best_cost = cost;
            memcpy(rx_ecef, x, sizeof(x));
            clock_drift = clk;
        }
    }

    if (verbose) {
        double lat0, lon0, alt0;
        ecef_to_geodetic(rx_ecef, &lat0, &lon0, &alt0);
        fprintf(stderr, "DOPPLER: best of %d starts pos=%.4f,%.4f cost=%.3g "
                "n_meas=%d n_sats=%d\n", n_starts, lat0, lon0, best_cost,
                n_meas, sats_used);
    }

    if (isinf(best_cost)) {
        out->n_measurements = n_meas;
        out->n_satellites = sats_used;
        has_prev_solution = 0;
        return 0;
    }

    /* Outlier rejection: drop measurements beyond OUTLIER_SIGMA of the fit */
    int n_active = n_meas;
    if (n_meas > 4) {
        double sum_res2 = 0;
        for (int i = 0; i < n_meas; i++) {
            double res = meas_residual(&all_meas[i], rx_ecef, clock_drift);
            if (isnan(res)) {
                all_meas[i].weight = 0;
                continue;
            }
            sum_res2 += res * res;
        }
        double sigma = sqrt(sum_res2 / (n_meas - 4));
        int rejected = 0;
        for (int i = 0; i < n_meas; i++) {
            if (all_meas[i].weight == 0) continue;
            double res = meas_residual(&all_meas[i], rx_ecef, clock_drift);
            if (fabs(res) > OUTLIER_SIGMA * sigma) {
                all_meas[i].weight = 0;
                rejected++;
            }
        }
        if (rejected > 0 && n_meas - rejected >= MIN_MEASUREMENTS) {
            n_active = n_meas - rejected;
            if (!wls_solve(all_meas, n_meas, rx_ecef, &clock_drift, use_height)) {
                if (verbose)
                    fprintf(stderr, "DOPPLER: re-solve FAIL - did not converge\n");
                return 0;
            }
        } else if (rejected > 0) {
            for (int i = 0; i < n_meas; i++)
                all_meas[i].weight = 1.0;
        }
    }

    /* Per-satellite screening: a satellite whose mean residual is far above
     * the others has bad orbit data or a bad decode. Drop it and re-solve. */
    {
        double sat_res_sum[MAX_SATELLITES] = {0};
        int sat_res_count[MAX_SATELLITES] = {0};

        for (int i = 0; i < n_meas; i++) {
            solver_meas_t *m = &all_meas[i];
            if (m->weight == 0) continue;
            if (m->sat_idx < 0 || m->sat_idx >= MAX_SATELLITES) continue;
            double res = meas_residual(m, rx_ecef, clock_drift);
            if (isnan(res)) continue;
            sat_res_sum[m->sat_idx] += fabs(res);
            sat_res_count[m->sat_idx]++;
        }

        double sat_mean_res[MAX_SATELLITES];
        int active_sats[MAX_SATELLITES];
        int n_sats_active = 0;
        for (int s = 0; s < MAX_SATELLITES; s++) {
            if (sat_res_count[s] == 0) continue;
            sat_mean_res[s] = sat_res_sum[s] / sat_res_count[s];
            active_sats[n_sats_active++] = s;
        }

        if (n_sats_active >= 3) {
            double sorted_res[MAX_SATELLITES];
            for (int i = 0; i < n_sats_active; i++)
                sorted_res[i] = sat_mean_res[active_sats[i]];
            for (int i = 1; i < n_sats_active; i++) {
                double key = sorted_res[i];
                int j = i - 1;
                while (j >= 0 && sorted_res[j] > key) {
                    sorted_res[j + 1] = sorted_res[j];
                    j--;
                }
                sorted_res[j + 1] = key;
            }
            double median_res = sorted_res[n_sats_active / 2];

            int sat_dropped = 0;
            for (int i = 0; i < n_sats_active; i++) {
                int s = active_sats[i];
                if (median_res > 0 && sat_mean_res[s] > 3.0 * median_res) {
                    if (verbose)
                        fprintf(stderr, "DOPPLER: dropping sat_idx=%d "
                                "(sat_id=%d) residual=%.1f vs median=%.1f\n",
                                s, satellites[s].sat_id,
                                sat_mean_res[s], median_res);
                    for (int j = 0; j < n_meas; j++)
                        if (all_meas[j].sat_idx == s)
                            all_meas[j].weight = 0;
                    sat_dropped++;
                    sats_used--;
                }
            }

            if (sat_dropped > 0) {
                n_active = 0;
                for (int i = 0; i < n_meas; i++)
                    if (all_meas[i].weight > 0) n_active++;
                if (n_active < MIN_MEASUREMENTS || sats_used < MIN_SATELLITES) {
                    if (verbose)
                        fprintf(stderr, "DOPPLER: per-sat screening left "
                                "too few measurements (%d meas, %d sats)\n",
                                n_active, sats_used);
                    return 0;
                }
                if (!wls_solve(all_meas, n_meas, rx_ecef, &clock_drift,
                               use_height)) {
                    if (verbose)
                        fprintf(stderr, "DOPPLER: per-sat re-solve "
                                "FAIL - did not converge\n");
                    return 0;
                }
            }
        }
    }

    /* HDOP from the final geometry */
    double hdop = 99.9;
    {
        double HtH[4][4] = {{0}};
        int count = 0;

        for (int i = 0; i < n_meas; i++) {
            solver_meas_t *m = &all_meas[i];
            if (m->weight == 0) continue;
            double H[4];
            if (isnan(model_range_rate(m, rx_ecef, H))) continue;
            H[3] = 1.0;
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 4; c++)
                    HtH[r][c] += H[r] * H[c];
            count++;
        }

        if (count >= 4) {
            double HtH_copy[4][4];
            memcpy(HtH_copy, HtH, sizeof(HtH));
            double Q[4][4];
            if (mat4_invert(HtH_copy, Q) == 0) {
                double lat, lon, alt;
                ecef_to_geodetic(rx_ecef, &lat, &lon, &alt);
                double R[3][3];
                ecef_to_enu_matrix(lat, lon, R);

                /* Q_enu = R * Q_xyz * R^T (3x3 position block) */
                double Q_enu[3][3] = {{0}};
                for (int i = 0; i < 3; i++)
                    for (int j = 0; j < 3; j++)
                        for (int k = 0; k < 3; k++)
                            for (int l = 0; l < 3; l++)
                                Q_enu[i][j] += R[i][k] * Q[k][l] * R[j][l];

                if (Q_enu[0][0] + Q_enu[1][1] > 0)
                    hdop = sqrt(Q_enu[0][0] + Q_enu[1][1]);
            }
        }
    }
    n_meas = n_active;

    /* Note: HDOP is reported in the solution for the caller to assess.
     * With few satellite passes (early operation), HDOP can be 100+
     * but the position is still useful for approximate location. */

    /* Solution jump guard: reject solutions that jump too far from
     * the previous established position. A stationary receiver should
     * not move >500km between solves. Allow override after 5 consecutive
     * rejections (the old position was probably wrong). */
    if (has_prev_solution) {
        double dx = rx_ecef[0] - prev_ecef[0];
        double dy = rx_ecef[1] - prev_ecef[1];
        double dz = rx_ecef[2] - prev_ecef[2];
        double jump = sqrt(dx*dx + dy*dy + dz*dz);

        if (jump > MAX_SOLUTION_JUMP && !(best_cost < 0.5 * prev_basin_cost)) {
            jump_reject_count++;
            if (jump_reject_count < 5) {
                if (verbose) {
                    double jlat, jlon, jalt;
                    ecef_to_geodetic(rx_ecef, &jlat, &jlon, &jalt);
                    fprintf(stderr, "DOPPLER: rejecting %.0fkm jump to "
                            "%.4f,%.4f (reject #%d)\n",
                            jump / 1000.0, jlat, jlon, jump_reject_count);
                }
                /* Return the previous solution instead */
                ecef_to_geodetic(prev_ecef, &out->lat, &out->lon, &out->alt);
                out->hdop = hdop;
                out->n_measurements = n_meas;
                out->n_satellites = sats_used;
                out->converged = 1;
                return 1;
            } else {
                if (verbose)
                    fprintf(stderr, "DOPPLER: accepting jump after %d "
                            "consecutive rejections (resetting)\n",
                            jump_reject_count);
                jump_reject_count = 0;
            }
        } else {
            jump_reject_count = 0;
        }
    }

    /* Save solution for next iteration */
    prev_ecef[0] = rx_ecef[0];
    prev_ecef[1] = rx_ecef[1];
    prev_ecef[2] = rx_ecef[2];
    prev_clock_drift = clock_drift;
    has_prev_solution = 1;

    /* Convert ECEF to geodetic for output */
    ecef_to_geodetic(rx_ecef, &out->lat, &out->lon, &out->alt);
    out->hdop = hdop;
    out->n_measurements = n_meas;
    out->n_satellites = sats_used;
    out->converged = 1;

    return 1;
}
