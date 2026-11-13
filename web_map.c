/*
 * Built-in web map server for Iridium ring alerts and satellites
 *
 * Minimal HTTP server with SSE (Server-Sent Events) for real-time
 * map updates. Uses Leaflet.js + OpenStreetMap for visualization.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Built-in web map server for Iridium ring alerts and satellites
 *
 * Minimal HTTP server with SSE (Server-Sent Events) for real-time
 * map updates. Uses Leaflet.js + OpenStreetMap for visualization.
 *
 * Two endpoints:
 *   GET /           → embedded HTML/JS map page
 *   GET /api/events → SSE stream (1 Hz JSON updates)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "web_map.h"
#include "ida_decode.h"
#ifdef HAVE_VOICE
#include "voice_decode.h"
extern int voice_enabled;
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ---- Configuration ---- */

#define MAX_RA_POINTS    2000
#define MAX_BEAM_POINTS  2000
#define MAX_MT_POINTS    500
#define MAX_SATELLITES   100
#define MAX_AIRCRAFT     32
#define MAX_AIRCRAFT_FIXES 8
#define MAX_SSE_CLIENTS  8
#define MAX_CLIENT_THREADS 64
#define MAX_ACARS_MSGS   100
#define ACARS_TEXT_MAX   256
#define HTTP_BUF_SIZE    4096

/* ---- SSE client count ---- */
static atomic_int sse_client_count = 0;
static atomic_int client_threads = 0;

/* ---- Shared state ---- */

typedef struct {
    double lat, lon;
    int alt;
    int sat_id, beam_id;
    int n_pages;
    uint32_t tmsi;
    double frequency;
    uint64_t timestamp;
} ra_point_t;

/* Ground beam center position (alt < 100 from IRA frames) */
typedef struct {
    double lat, lon;
    int alt;
    int sat_id, beam_id;
    int n_pages;
    uint32_t tmsi;
    double frequency;
    uint64_t timestamp;
} beam_point_t;

/* MT phone/terminal position from IDA reassembly */
typedef struct {
    double lat, lon;
    int alt;
    uint16_t msg_type;
    uint64_t timestamp;
    double frequency;
} mt_point_t;

typedef struct {
    int sat_id;
    int beam_id;
    uint64_t last_seen;
    int count;
} sat_entry_t;

/* ACARS aircraft position (one entry per tail number) */
typedef struct {
    char reg[16];    /* registration / tail number */
    char flight[8];  /* flight number, may be empty */
    char oooi[8];    /* last OOOI event: "OUT","OFF","ON","IN", or empty */
    int sat_id, beam_id;
    double fix_lat[MAX_AIRCRAFT_FIXES];
    double fix_lon[MAX_AIRCRAFT_FIXES];
    uint64_t fix_t[MAX_AIRCRAFT_FIXES];  /* seconds since epoch */
    int fix_alt[MAX_AIRCRAFT_FIXES];     /* altitude in feet, -99999 if unknown */
    uint8_t fix_adsc[MAX_AIRCRAFT_FIXES]; /* 1=ADS-C GPS position, 0=beam estimate */
    int n_fixes;
    double frequency;
    uint64_t last_seen;  /* ns, for eviction */
} aircraft_entry_t;

/* Recent ACARS message entry for the chronological feed tab */
typedef struct {
    char reg[16];
    char flight[8];
    char label[4];
    char text[ACARS_TEXT_MAX];
    int ul;
    uint64_t timestamp;
} acars_msg_t;

static struct {
    pthread_mutex_t lock;
    ra_point_t ra[MAX_RA_POINTS];
    int ra_head;
    int ra_count;
    beam_point_t beams[MAX_BEAM_POINTS];
    int beam_head;
    int beam_count;
    mt_point_t mt[MAX_MT_POINTS];
    int mt_head;
    int mt_count;
    sat_entry_t sats[MAX_SATELLITES];
    int n_sats;
    aircraft_entry_t aircraft[MAX_AIRCRAFT];
    int n_aircraft;
    acars_msg_t acars[MAX_ACARS_MSGS];
    int acars_head;
    int acars_count;
    unsigned long total_ira;
    unsigned long total_ibc;
    unsigned long total_pages;
    unsigned long total_beams;
    unsigned long total_mt;
    unsigned long total_aircraft;
    unsigned long total_acars_msgs;
    /* Doppler positioning receiver estimate */
    double rx_lat, rx_lon;
    double rx_hdop;
    int rx_valid;
} state;

/* ---- Server state ---- */

static int server_fd = -1;
static pthread_t server_thread;
static volatile int server_running = 0;

/* ---- State update functions (thread-safe) ---- */

static void add_beam_locked(const ira_data_t *ra, uint64_t timestamp,
                             double frequency)
{
    /* Deduplication: skip if same sat_id already has this lat/lon recently */
    int search = (state.beam_count < 20) ? state.beam_count : 20;
    for (int i = 0; i < search; i++) {
        int idx = (state.beam_head - 1 - i + MAX_BEAM_POINTS) % MAX_BEAM_POINTS;
        beam_point_t *b = &state.beams[idx];
        if (b->sat_id == ra->sat_id &&
            fabs(b->lat - ra->lat) < 0.001 &&
            fabs(b->lon - ra->lon) < 0.001) {
            /* Duplicate -- update timestamp and page info */
            b->timestamp = timestamp;
            if (ra->n_pages > 0) {
                b->n_pages = ra->n_pages;
                b->tmsi = ra->pages[0].tmsi;
                state.total_pages++;
            }
            state.total_beams++;
            return;
        }
    }

    beam_point_t *p = &state.beams[state.beam_head];
    p->lat = ra->lat;
    p->lon = ra->lon;
    p->alt = ra->alt;
    p->sat_id = ra->sat_id;
    p->beam_id = ra->beam_id;
    p->n_pages = ra->n_pages;
    p->tmsi = (ra->n_pages > 0) ? ra->pages[0].tmsi : 0;
    p->frequency = frequency;
    p->timestamp = timestamp;

    state.beam_head = (state.beam_head + 1) % MAX_BEAM_POINTS;
    if (state.beam_count < MAX_BEAM_POINTS)
        state.beam_count++;
    state.total_beams++;
    if (ra->n_pages > 0)
        state.total_pages++;
}

void web_map_add_ra(const ira_data_t *ra, uint64_t timestamp,
                     double frequency)
{
    /* Sanity check coordinates */
    if (ra->lat < -90 || ra->lat > 90 || ra->lon < -180 || ra->lon > 180)
        return;
    if (ra->sat_id == 0 && ra->beam_id == 0 && ra->lat == 0 && ra->lon == 0)
        return;

    /* Ground beam position: alt < 100 km (beam center on earth surface) */
    if (ra->alt >= 0 && ra->alt < 100) {
        pthread_mutex_lock(&state.lock);
        state.total_ira++;
        add_beam_locked(ra, timestamp, frequency);
        pthread_mutex_unlock(&state.lock);
        return;
    }

    /* Satellite orbital position: 700-900 km */
    if (ra->alt < 700 || ra->alt > 900)
        return;

    pthread_mutex_lock(&state.lock);

    ra_point_t *p = &state.ra[state.ra_head];
    p->lat = ra->lat;
    p->lon = ra->lon;
    p->alt = ra->alt;
    p->sat_id = ra->sat_id;
    p->beam_id = ra->beam_id;
    p->n_pages = ra->n_pages;
    p->tmsi = (ra->n_pages > 0) ? ra->pages[0].tmsi : 0;
    p->frequency = frequency;
    p->timestamp = timestamp;

    state.ra_head = (state.ra_head + 1) % MAX_RA_POINTS;
    if (state.ra_count < MAX_RA_POINTS)
        state.ra_count++;
    state.total_ira++;
    if (ra->n_pages > 0)
        state.total_pages++;

    pthread_mutex_unlock(&state.lock);
}

void web_map_add_sat(const ibc_data_t *ibc, uint64_t timestamp)
{
    if (ibc->sat_id == 0) return;

    pthread_mutex_lock(&state.lock);

    /* Find or create satellite entry */
    int idx = -1;
    for (int i = 0; i < state.n_sats; i++) {
        if (state.sats[i].sat_id == ibc->sat_id) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        if (state.n_sats < MAX_SATELLITES) {
            idx = state.n_sats++;
        } else {
            /* Full: reuse the entry seen longest ago, or new satellites
             * would never appear on a long run */
            idx = 0;
            for (int i = 1; i < state.n_sats; i++)
                if (state.sats[i].last_seen < state.sats[idx].last_seen)
                    idx = i;
        }
        state.sats[idx].sat_id = ibc->sat_id;
        state.sats[idx].count = 0;
    }

    if (idx >= 0) {
        state.sats[idx].beam_id = ibc->beam_id;
        state.sats[idx].last_seen = timestamp;
        state.sats[idx].count++;
    }
    state.total_ibc++;

    pthread_mutex_unlock(&state.lock);
}

void web_map_set_position(double lat, double lon, double hdop)
{
    pthread_mutex_lock(&state.lock);
    state.rx_lat = lat;
    state.rx_lon = lon;
    state.rx_hdop = hdop;
    state.rx_valid = 1;
    pthread_mutex_unlock(&state.lock);
}

void web_map_add_mt(double lat, double lon, int alt, uint16_t msg_type,
                     uint64_t timestamp, double frequency)
{
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180)
        return;

    pthread_mutex_lock(&state.lock);

    mt_point_t *p = &state.mt[state.mt_head];
    p->lat = lat;
    p->lon = lon;
    p->alt = alt;
    p->msg_type = msg_type;
    p->timestamp = timestamp;
    p->frequency = frequency;

    state.mt_head = (state.mt_head + 1) % MAX_MT_POINTS;
    if (state.mt_count < MAX_MT_POINTS)
        state.mt_count++;
    state.total_mt++;

    pthread_mutex_unlock(&state.lock);
}

/* ---- MT position extraction from IDA messages ---- */

/* Extract 12-bit signed XYZ from 5 bytes (two's complement encoding).
 * Matches iridium-toolkit util.py xyz() function. */
static int mtpos_xyz(const uint8_t *bytes, int skip,
                      double *lat, double *lon, int *alt)
{
    uint64_t val = 0;
    for (int i = 0; i < 5; i++)
        val = (val << 8) | bytes[i];

    int sb = 4 - skip;

    int x = (int)((val >> (24 + sb)) & 0xFFF);
    int y = (int)((val >> (12 + sb)) & 0xFFF);
    int z = (int)((val >> (0  + sb)) & 0xFFF);

    /* Two's complement sign extension */
    if (x > 0x7FF) x -= 0x1000;
    if (y > 0x7FF) y -= 0x1000;
    if (z > 0x7FF) z -= 0x1000;

    if (x == 0 && y == 0 && z == 0) return 0;

    double xy = sqrt((double)x * x + (double)y * y);
    *lat = atan2((double)z, xy) * 180.0 / M_PI;
    *lon = atan2((double)y, (double)x) * 180.0 / M_PI;

    /* radius is Earth-center distance in km (each unit ~4km) */
    double radius_km = sqrt((double)x * x + (double)y * y +
                            (double)z * z) * 4.0;
    *alt = (int)(radius_km - 6371.0);

    if (*lat < -90 || *lat > 90) return 0;
    /* reject positions with unreasonable Earth-center distance */
    if (radius_km < 5000.0 || radius_km > 7000.0) return 0;
    return 1;
}

void mtpos_ida_cb(const uint8_t *data, int len,
                   uint64_t timestamp, double frequency,
                   ir_direction_t direction, float magnitude,
                   void *user)
{
    (void)magnitude;
    (void)user;

    if (len < 5) return;

    uint16_t msg_type = ((uint16_t)data[0] << 8) | data[1];
    double lat, lon;
    int alt;
    int valid = 0;

    switch (msg_type) {
    case 0x0605:
        /* GSM paging with position at offset 36, marker 0x1b */
        if (len >= 42 && data[36] == 0x1b)
            valid = mtpos_xyz(data + 37, 0, &lat, &lon, &alt);
        break;

    case 0x7605:
        /* SBD paging with position */
        if (len >= 8 && data[2] == 0x00 && (data[3] & 0xf0) == 0x40)
            valid = mtpos_xyz(data + 3, 4, &lat, &lon, &alt);
        break;

    case 0x0600:
        /* Uplink with position */
        if (direction == DIR_UPLINK && len >= 24 &&
            (data[2] == 0x10 || data[2] == 0x40 || data[2] == 0x70) &&
            data[18] == 0x01)
            valid = mtpos_xyz(data + 19, 0, &lat, &lon, &alt);
        break;

    default:
        return;
    }

    if (valid)
        web_map_add_mt(lat, lon, alt, msg_type, timestamp, frequency);
}

/* ---- Aircraft beam-based position ---- */

/* Haversine great-circle distance in km */
static double aircraft_dist_km(double lat1, double lon1,
                                double lat2, double lon2)
{
    const double R = 6371.0;
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dlat/2)*sin(dlat/2) +
               cos(lat1*M_PI/180.0)*cos(lat2*M_PI/180.0)*
               sin(dlon/2)*sin(dlon/2);
    return R * 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
}

void web_map_add_aircraft(const char *reg, const char *flight,
                           double lat, double lon,
                           int sat_id, int beam_id,
                           uint64_t timestamp_ns, double frequency,
                           int alt_ft, int adsc_pos,
                           const char *oooi)
{
    if (!reg || !reg[0]) return;

    pthread_mutex_lock(&state.lock);

    /* Find existing entry for this registration */
    int idx = -1;
    for (int i = 0; i < state.n_aircraft; i++) {
        if (strncmp(state.aircraft[i].reg, reg, 15) == 0) {
            idx = i;
            break;
        }
    }

    /* If not found, create new or evict the oldest entry */
    if (idx < 0) {
        if (state.n_aircraft < MAX_AIRCRAFT) {
            idx = state.n_aircraft++;
        } else {
            uint64_t oldest = UINT64_MAX;
            for (int i = 0; i < MAX_AIRCRAFT; i++) {
                if (state.aircraft[i].last_seen < oldest) {
                    oldest = state.aircraft[i].last_seen;
                    idx = i;
                }
            }
            memset(&state.aircraft[idx], 0, sizeof(state.aircraft[idx]));
        }
        strncpy(state.aircraft[idx].reg, reg, 15);
        state.aircraft[idx].reg[15] = '\0';
        state.aircraft[idx].n_fixes = 0;
    }

    aircraft_entry_t *ac = &state.aircraft[idx];

    if (flight && flight[0]) {
        strncpy(ac->flight, flight, 7);
        ac->flight[7] = '\0';
    }

    if (oooi && oooi[0]) {
        strncpy(ac->oooi, oooi, 7);
        ac->oooi[7] = '\0';
    }

    /* Speed plausibility check: reject beam-estimate fixes that would require
     * flying faster than 1200 km/h (commercial max + supersonic buffer).
     * ADS-C GPS positions bypass this check since they're not beam guesses. */
    if (!adsc_pos && ac->n_fixes > 0) {
        int last = ac->n_fixes - 1;
        double dt_s = (double)(timestamp_ns - ac->last_seen) / 1e9;
        if (dt_s > 0.0 && dt_s < 7200.0) {
            double max_km = (dt_s / 3600.0) * 1200.0;
            double dist = aircraft_dist_km(ac->fix_lat[last], ac->fix_lon[last],
                                           lat, lon);
            if (dist > max_km) {
                /* Implausible jump - beam from wrong satellite, discard */
                pthread_mutex_unlock(&state.lock);
                return;
            }
        }
    }

    /* Append fix; shift out oldest when the history is full */
    int nf = ac->n_fixes;
    if (nf >= MAX_AIRCRAFT_FIXES) {
        memmove(&ac->fix_lat[0],  &ac->fix_lat[1],
                (MAX_AIRCRAFT_FIXES - 1) * sizeof(ac->fix_lat[0]));
        memmove(&ac->fix_lon[0],  &ac->fix_lon[1],
                (MAX_AIRCRAFT_FIXES - 1) * sizeof(ac->fix_lon[0]));
        memmove(&ac->fix_t[0],    &ac->fix_t[1],
                (MAX_AIRCRAFT_FIXES - 1) * sizeof(ac->fix_t[0]));
        memmove(&ac->fix_alt[0],  &ac->fix_alt[1],
                (MAX_AIRCRAFT_FIXES - 1) * sizeof(ac->fix_alt[0]));
        memmove(&ac->fix_adsc[0], &ac->fix_adsc[1],
                (MAX_AIRCRAFT_FIXES - 1) * sizeof(ac->fix_adsc[0]));
        nf = MAX_AIRCRAFT_FIXES - 1;
    }
    ac->fix_lat[nf]  = lat;
    ac->fix_lon[nf]  = lon;
    ac->fix_t[nf]    = timestamp_ns / 1000000000ULL;
    ac->fix_alt[nf]  = alt_ft;
    ac->fix_adsc[nf] = (uint8_t)adsc_pos;
    ac->n_fixes = nf + 1;
    ac->sat_id    = sat_id;
    ac->beam_id   = beam_id;
    ac->frequency = frequency;
    ac->last_seen = timestamp_ns;
    state.total_aircraft++;

    pthread_mutex_unlock(&state.lock);
}

void web_map_add_acars_message(const char *reg, const char *flight,
                                const char *label, const char *text,
                                int ul, uint64_t timestamp_ns)
{
    if (!reg || !label || !text || !text[0]) return;

    pthread_mutex_lock(&state.lock);

    acars_msg_t *m = &state.acars[state.acars_head];

    /* Strip leading dots from registration */
    const char *r = reg;
    while (*r == '.') r++;
    strncpy(m->reg, r, sizeof(m->reg) - 1);
    m->reg[sizeof(m->reg) - 1] = '\0';

    m->flight[0] = '\0';
    if (flight && flight[0]) {
        strncpy(m->flight, flight, sizeof(m->flight) - 1);
        m->flight[sizeof(m->flight) - 1] = '\0';
    }

    strncpy(m->label, label, sizeof(m->label) - 1);
    m->label[sizeof(m->label) - 1] = '\0';

    strncpy(m->text, text, sizeof(m->text) - 1);
    m->text[sizeof(m->text) - 1] = '\0';

    m->ul = ul ? 1 : 0;
    m->timestamp = timestamp_ns;

    state.acars_head = (state.acars_head + 1) % MAX_ACARS_MSGS;
    if (state.acars_count < MAX_ACARS_MSGS)
        state.acars_count++;
    state.total_acars_msgs++;

    pthread_mutex_unlock(&state.lock);
}

/* ---- JSON serialization ---- */

/* Growable output buffer: appends never truncate or overrun */
typedef struct {
    char *p;
    size_t len, cap;
    int oom;
} jbuf_t;

static void jb_reserve(jbuf_t *j, size_t extra)
{
    if (j->oom || j->len + extra < j->cap) return;
    size_t cap = j->cap ? j->cap : 65536;
    while (cap <= j->len + extra) cap *= 2;
    char *np = realloc(j->p, cap);
    if (!np) { j->oom = 1; return; }
    j->p = np;
    j->cap = cap;
}

static void jb_printf(jbuf_t *j, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void jb_printf(jbuf_t *j, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    jb_reserve(j, (size_t)n + 1);
    if (j->oom) return;
    va_start(ap, fmt);
    vsnprintf(j->p + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);
    j->len += n;
}

/* Quoted JSON string; text decoded off the air may contain anything */
static void jb_str(jbuf_t *j, const char *s)
{
    jb_reserve(j, strlen(s) * 6 + 3);
    if (j->oom) return;
    char *o = j->p + j->len;
    *o++ = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            *o++ = '\\';
            *o++ = c;
        } else if (c < 0x20 || c >= 0x7f) {
            o += sprintf(o, "\\u%04x", c);
        } else {
            *o++ = c;
        }
    }
    *o++ = '"';
    *o = '\0';
    j->len = o - j->p;
}

static void build_json(jbuf_t *j)
{
    j->len = 0;
    j->oom = 0;
    pthread_mutex_lock(&state.lock);

    jb_printf(j,
                    "{\"total_ira\":%lu,\"total_ibc\":%lu,\"total_pages\":%lu,"
                    "\"total_beams\":%lu,\"total_mt\":%lu,\"total_aircraft\":%lu,",
                    state.total_ira, state.total_ibc, state.total_pages,
                    state.total_beams, state.total_mt, state.total_aircraft);

    /* Satellite orbital positions (most recent first, max 500) */
    jb_printf(j, "\"ra\":[");
    int n_out = 0;
    for (int i = 0; i < state.ra_count && n_out < 500; i++) {
        int idx = (state.ra_head - 1 - i + MAX_RA_POINTS) % MAX_RA_POINTS;
        ra_point_t *p = &state.ra[idx];
        if (n_out > 0) jb_printf(j, ",");
        jb_printf(j,
            "{\"lat\":%.4f,\"lon\":%.4f,\"alt\":%d,"
            "\"sat\":%d,\"beam\":%d,\"pages\":%d,"
            "\"tmsi\":%u,\"freq\":%.0f,\"t\":%llu}",
            p->lat, p->lon, p->alt,
            p->sat_id, p->beam_id, p->n_pages,
            p->tmsi, p->frequency,
            (unsigned long long)(p->timestamp / 1000000000ULL));
        n_out++;
    }
    jb_printf(j, "],");

    /* Ground beam positions (most recent first, max 300) */
    jb_printf(j, "\"beams\":[");
    n_out = 0;
    for (int i = 0; i < state.beam_count && n_out < 300; i++) {
        int idx = (state.beam_head - 1 - i + MAX_BEAM_POINTS) % MAX_BEAM_POINTS;
        beam_point_t *p = &state.beams[idx];
        if (n_out > 0) jb_printf(j, ",");
        jb_printf(j,
            "{\"lat\":%.4f,\"lon\":%.4f,\"alt\":%d,"
            "\"sat\":%d,\"beam\":%d,\"pages\":%d,"
            "\"tmsi\":%u,\"freq\":%.0f,\"t\":%llu}",
            p->lat, p->lon, p->alt,
            p->sat_id, p->beam_id, p->n_pages,
            p->tmsi, p->frequency,
            (unsigned long long)(p->timestamp / 1000000000ULL));
        n_out++;
    }
    jb_printf(j, "],");

    /* MT phone/terminal positions (most recent first, max 200) */
    jb_printf(j, "\"mt\":[");
    n_out = 0;
    for (int i = 0; i < state.mt_count && n_out < 200; i++) {
        int idx = (state.mt_head - 1 - i + MAX_MT_POINTS) % MAX_MT_POINTS;
        mt_point_t *p = &state.mt[idx];
        if (n_out > 0) jb_printf(j, ",");
        jb_printf(j,
            "{\"lat\":%.4f,\"lon\":%.4f,\"alt\":%d,"
            "\"type\":%u,\"freq\":%.0f,\"t\":%llu}",
            p->lat, p->lon, p->alt,
            (unsigned)p->msg_type, p->frequency,
            (unsigned long long)(p->timestamp / 1000000000ULL));
        n_out++;
    }
    jb_printf(j, "],");

    /* Active satellites (only those seen in last 15 minutes) */
    uint64_t max_ts = 0;
    for (int i = 0; i < state.n_sats; i++) {
        if (state.sats[i].last_seen > max_ts)
            max_ts = state.sats[i].last_seen;
    }
    uint64_t sat_window = 15ULL * 60 * 1000000000ULL;  /* 15 minutes in ns */

    jb_printf(j, "\"sats\":[");
    int first_sat = 1;
    for (int i = 0; i < state.n_sats; i++) {
        if (max_ts > sat_window && state.sats[i].last_seen < max_ts - sat_window)
            continue;
        if (!first_sat) jb_printf(j, ",");
        jb_printf(j,
            "{\"id\":%d,\"beam\":%d,\"count\":%d}",
            state.sats[i].sat_id, state.sats[i].beam_id,
            state.sats[i].count);
        first_sat = 0;
    }
    jb_printf(j, "]");

    /* ACARS aircraft positions (ADS-C or beam-based) */
    jb_printf(j, ",\"aircraft\":[");
    int first_ac = 1;
    for (int i = 0; i < state.n_aircraft; i++) {
        aircraft_entry_t *ac = &state.aircraft[i];
        if (ac->n_fixes == 0) continue;
        if (!first_ac) jb_printf(j, ",");
        first_ac = 0;
        jb_printf(j, "{\"reg\":");
        jb_str(j, ac->reg);
        jb_printf(j, ",\"flight\":");
        jb_str(j, ac->flight);
        jb_printf(j, ",\"oooi\":");
        jb_str(j, ac->oooi);
        jb_printf(j, ",\"sat\":%d,\"beam\":%d,\"freq\":%.0f,\"fixes\":[",
            ac->sat_id, ac->beam_id, ac->frequency);
        for (int f = 0; f < ac->n_fixes; f++) {
            if (f > 0) jb_printf(j, ",");
            jb_printf(j,
                "{\"lat\":%.5f,\"lon\":%.5f,\"t\":%llu,\"alt\":%d,\"adsc\":%d}",
                ac->fix_lat[f], ac->fix_lon[f],
                (unsigned long long)ac->fix_t[f],
                ac->fix_alt[f], (int)ac->fix_adsc[f]);
        }
        jb_printf(j, "]}");
    }
    jb_printf(j, "]");

    /* Receiver position estimate (Doppler positioning) */
    if (state.rx_valid) {
        jb_printf(j,
            ",\"rx\":{\"lat\":%.6f,\"lon\":%.6f,\"hdop\":%.1f}",
            state.rx_lat, state.rx_lon, state.rx_hdop);
    }

    /* Recent ACARS messages (chronological feed) */
    jb_printf(j,
        ",\"total_acars_msgs\":%lu,\"acars\":[", state.total_acars_msgs);
    int n_msgs = state.acars_count;
    int n_emit = 0;
    for (int i = n_msgs - 1; i >= 0; i--) {
        int idx = (state.acars_head - 1 - (n_msgs - 1 - i) + MAX_ACARS_MSGS)
                  % MAX_ACARS_MSGS;
        const acars_msg_t *m = &state.acars[idx];
        if (n_emit > 0)
            jb_printf(j, ",");
        jb_printf(j, "{\"t\":%llu,\"reg\":",
            (unsigned long long)(m->timestamp / 1000000000ULL));
        jb_str(j, m->reg);
        jb_printf(j, ",\"flt\":");
        jb_str(j, m->flight);
        jb_printf(j, ",\"lbl\":");
        jb_str(j, m->label);
        jb_printf(j, ",\"ul\":%d,\"txt\":", m->ul);
        jb_str(j, m->text);
        jb_printf(j, "}");
        n_emit++;
    }
    jb_printf(j, "]");

    pthread_mutex_unlock(&state.lock);

#ifdef HAVE_VOICE
    /* Voice stats (uses separate lock, safe outside state.lock) */
    if (voice_enabled)
        jb_printf(j,
            ",\"voice\":1,\"total_voc\":%d,\"total_voice_calls\":%d",
            voice_decode_total_frames(), voice_decode_total_calls());
#endif

    jb_printf(j, "}");

}

/* ---- Embedded HTML/JS ---- */

static const char HTML_PAGE[] =
"<!DOCTYPE html>\n"
"<html><head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>iridium-sniffer</title>\n"
"<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\">\n"
"<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\"></script>\n"
"<style>\n"
"*{margin:0;padding:0;box-sizing:border-box}\n"
"body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a}\n"
"#map{width:100vw;height:calc(100vh - 44px)}\n"
"#bar{height:44px;background:#1e293b;color:#e2e8f0;display:flex;\n"
"  align-items:center;padding:0 16px;gap:20px;font-size:13px;\n"
"  border-bottom:1px solid #334155}\n"
"#bar .title{font-weight:600;color:#f8fafc;letter-spacing:0.5px}\n"
".stat{color:#94a3b8}\n"
".val{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums}\n"
"#status{margin-left:auto;font-size:12px}\n"
".leaflet-popup-content{font-family:'SF Mono',Consolas,monospace;\n"
"  font-size:12px;line-height:1.6}\n"
".popup-title{font-weight:700;font-size:13px;margin-bottom:4px;\n"
"  padding-bottom:4px;border-bottom:1px solid #e2e8f0}\n"
".popup-page{color:#dc2626;font-weight:600}\n"
".popup-mt{color:#f59e0b;font-weight:600}\n"
".popup-ac{font-weight:600}\n"
".legend{position:absolute;bottom:28px;right:10px;z-index:1000;\n"
"  background:rgba(15,23,42,0.92);color:#e2e8f0;padding:10px 14px;\n"
"  border-radius:6px;font-size:12px;line-height:2;\n"
"  border:1px solid #334155;pointer-events:auto}\n"
".legend-title{font-weight:700;font-size:11px;text-transform:uppercase;\n"
"  letter-spacing:1px;color:#94a3b8;margin-bottom:2px}\n"
".legend-row{display:flex;align-items:center;gap:8px}\n"
".legend-swatch{display:inline-block}\n"
".leaflet-container{background:#0f172a}\n"
".leaflet-control-layers{background:rgba(15,23,42,0.92)!important;\n"
"  color:#e2e8f0!important;border:1px solid #334155!important}\n"
".leaflet-control-layers label{color:#e2e8f0}\n"
".tab{cursor:pointer;padding:0 12px;line-height:42px;color:#64748b;\n"
"  border-bottom:2px solid transparent;margin-bottom:-1px}\n"
".tab.active{color:#38bdf8;border-bottom-color:#38bdf8}\n"
".tab:hover{color:#94a3b8}\n"
".badge{background:#38bdf8;color:#0f172a;font-size:11px;\n"
"  padding:1px 7px;border-radius:10px;margin-left:4px;font-weight:600}\n"
"#calls-panel{width:100vw;height:calc(100vh - 44px);overflow-y:auto;\n"
"  padding:16px 24px;background:#0f172a;display:none}\n"
".ct{width:100%;max-width:1200px;margin:0 auto;border-collapse:collapse}\n"
".ct th{text-align:left;padding:10px 16px;color:#64748b;font-size:12px;\n"
"  text-transform:uppercase;letter-spacing:.5px;\n"
"  border-bottom:1px solid #1e293b;font-weight:500}\n"
".ct td{padding:12px 16px;border-bottom:1px solid #1e293b;\n"
"  font-size:14px;color:#e2e8f0}\n"
".ct tr:hover{background:#1e293b;cursor:pointer}\n"
".ct tr.playing{background:#1e3a5f}\n"
".qb{padding:3px 10px;border-radius:12px;font-size:12px;font-weight:500}\n"
".qb.good{background:#064e3b;color:#34d399}\n"
".qb.fair{background:#422006;color:#fbbf24}\n"
".qb.poor{background:#450a0a;color:#f87171}\n"
".pbtn{width:32px;height:32px;border-radius:50%;border:none;\n"
"  background:#38bdf8;color:#0f172a;cursor:pointer;font-size:14px;\n"
"  display:flex;align-items:center;justify-content:center}\n"
".pbtn:hover{background:#7dd3fc}\n"
".pbtn.on{background:#22c55e}\n"
"#pbar{position:fixed;bottom:0;left:0;right:0;background:#1e293b;\n"
"  border-top:1px solid #334155;padding:12px 24px;display:none;\n"
"  align-items:center;gap:16px;z-index:2000}\n"
".pi{flex:1}.pt{font-size:14px;color:#e2e8f0}\n"
".ps{font-size:12px;color:#64748b}\n"
".pp{flex:3;height:4px;background:#334155;border-radius:2px;\n"
"  cursor:pointer;position:relative}\n"
".pf{height:100%;background:#38bdf8;border-radius:2px;width:0}\n"
".ptm{font-size:12px;color:#64748b;min-width:80px;text-align:right}\n"
".no-calls{text-align:center;color:#64748b;padding:48px 0;font-size:14px}\n"
".freq{color:#94a3b8;font-variant-numeric:tabular-nums;font-size:13px}\n"
".dur{font-variant-numeric:tabular-nums}\n"
"#main{display:flex;width:100vw;height:calc(100vh - 44px)}\n"
"#map{flex:1;height:100%;width:auto;position:relative}\n"
"#acars-side{width:380px;height:100%;background:#0f172a;\n"
"  border-left:1px solid #334155;overflow-y:auto;color:#e2e8f0;\n"
"  font-family:'SF Mono',Consolas,monospace;font-size:11px}\n"
"#acars-side .header{padding:8px 12px;background:#1e293b;\n"
"  border-bottom:1px solid #334155;font-size:11px;\n"
"  text-transform:uppercase;letter-spacing:1px;color:#94a3b8;\n"
"  font-weight:600;position:sticky;top:0;z-index:10}\n"
"#acars-side .header .hint{display:block;font-size:9px;\n"
"  text-transform:none;letter-spacing:0;color:#64748b;\n"
"  font-weight:400;margin-top:2px}\n"
".amsg{padding:6px 10px;border-bottom:1px solid #1e293b;line-height:1.5}\n"
".amsg:hover{background:#1e293b}\n"
".amsg .row1{display:flex;gap:8px;color:#64748b;font-size:10px;\n"
"  margin-bottom:2px}\n"
".amsg .reg{color:#38bdf8;font-weight:600}\n"
".amsg .flt{color:#94a3b8}\n"
".amsg .lbl{color:#fbbf24}\n"
".amsg .dir{color:#475569}\n"
".amsg .txt{color:#e2e8f0;white-space:pre-wrap;word-break:break-word}\n"
".no-msgs{text-align:center;color:#64748b;padding:32px 12px;font-size:11px}\n"
".btn-bar{background:#334155;color:#e2e8f0;border:1px solid #475569;\n"
"  border-radius:4px;padding:2px 8px;cursor:pointer;font-size:11px;\n"
"  margin-left:4px}\n"
"#theme-toggle{background:transparent;color:inherit;\n"
"  border:1px solid currentColor;border-radius:4px;padding:0 8px;\n"
"  cursor:pointer;font-size:14px;line-height:24px;height:26px;\n"
"  opacity:0.6;margin-left:4px}\n"
"#theme-toggle:hover{opacity:1}\n"
/* ---- Light theme overrides (gated by html.light, dark stays default) ---- */
"html.light body{background:#f8fafc;color:#1e293b}\n"
"html.light #bar{background:#ffffff;color:#1e293b;\n"
"  border-bottom-color:#cbd5e1}\n"
"html.light #bar .title{color:#0f172a}\n"
"html.light .stat{color:#475569}\n"
"html.light .val{color:#0284c7}\n"
"html.light .leaflet-container{background:#f8fafc}\n"
"html.light .leaflet-control-layers{background:rgba(255,255,255,0.95)!important;\n"
"  color:#1e293b!important;border-color:#cbd5e1!important}\n"
"html.light .leaflet-control-layers label{color:#1e293b}\n"
"html.light .legend{background:rgba(255,255,255,0.95);color:#1e293b;\n"
"  border-color:#cbd5e1}\n"
"html.light .legend-title{color:#475569}\n"
"html.light .popup-title{border-bottom-color:#cbd5e1}\n"
"html.light #acars-side{background:#ffffff;color:#1e293b;\n"
"  border-left-color:#cbd5e1}\n"
"html.light #acars-side .header{background:#f1f5f9;color:#475569;\n"
"  border-bottom-color:#cbd5e1}\n"
"html.light #acars-side .header .hint{color:#64748b}\n"
"html.light .amsg{border-bottom-color:#e2e8f0}\n"
"html.light .amsg:hover{background:#f1f5f9}\n"
"html.light .amsg .row1{color:#64748b}\n"
"html.light .amsg .reg{color:#0284c7}\n"
"html.light .amsg .flt{color:#475569}\n"
"html.light .amsg .lbl{color:#b45309}\n"
"html.light .amsg .dir{color:#94a3b8}\n"
"html.light .amsg .txt{color:#1e293b}\n"
"html.light .no-msgs{color:#94a3b8}\n"
"html.light .btn-bar{background:#e2e8f0;color:#1e293b;\n"
"  border-color:#cbd5e1}\n"
"</style></head><body>\n"
"<div id=\"bar\">\n"
"  <span class=\"title\">iridium-sniffer</span>\n"
"  <span class=\"tab active\" id=\"tab-map\" onclick=\"showTab('map')\">Map</span>\n"
"  <span class=\"tab\" id=\"tab-calls\" style=\"display:none\" onclick=\"showTab('calls')\">Calls"
"<span id=\"cbadge\" class=\"badge\" style=\"display:none\">0</span></span>\n"
"  <span class=\"stat\">Beams <span id=\"n-beams\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">MT <span id=\"n-mt\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">Aircraft <span id=\"n-ac\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">Pages <span id=\"n-pages\" class=\"val\">0</span></span>\n"
"  <button id=\"btn-export\" class=\"btn-bar\" onclick=\"exportPages()\">Export Pages CSV</button>\n"
"  <span class=\"stat\">Sats <span id=\"n-sats\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">IRA <span id=\"n-ira\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\" id=\"voc-stat\" style=\"display:none\">"
"VOC <span id=\"n-voc\" class=\"val\">0</span></span>\n"
"  <span class=\"stat\">ACARS <span id=\"n-acars\" class=\"val\">0</span></span>\n"
"  <button id=\"theme-toggle\" onclick=\"toggleTheme()\" title=\"Toggle light/dark\">\\u263E</button>\n"
"  <span id=\"status\" style=\"color:#64748b\">connecting...</span>\n"
"</div>\n"
"<div id=\"main\">\n"
"  <div id=\"map\">\n"
"<div class=\"legend\" id=\"legend\">\n"
"  <div class=\"legend-title\">Map</div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:16px;height:16px;\n"
"      border-radius:50%;border:1px solid #3b82f6;\n"
"      background:rgba(59,130,246,0.12)\"></span>\n"
"    Beam footprint\n"
"  </div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:10px;height:10px;\n"
"      border-radius:50%;background:#f59e0b\"></span>\n"
"    MT position\n"
"  </div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:10px;height:10px;\n"
"      border-radius:50%;background:#22d3ee\"></span>\n"
"    Aircraft (ACARS beam)\n"
"  </div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:10px;height:10px;\n"
"      border-radius:50%;background:#ef4444\"></span>\n"
"    Paging event\n"
"  </div>\n"
"  <div class=\"legend-row\">\n"
"    <span class=\"legend-swatch\" style=\"width:10px;height:10px;\n"
"      border-radius:50%;background:#22c55e\"></span>\n"
"    Receiver position\n"
"  </div>\n"
"</div>\n"
"  </div>\n"
"  <div id=\"acars-side\">\n"
"    <div class=\"header\">Recent ACARS<span class=\"hint\">heartbeats filtered</span></div>\n"
"    <div id=\"acars-list\">\n"
"      <div class=\"no-msgs\">No ACARS messages yet<br>(heartbeats filtered)</div>\n"
"    </div>\n"
"  </div>\n"
"</div>\n"
"<div id=\"calls-panel\">\n"
"  <table class=\"ct\"><thead><tr>\n"
"    <th style=\"width:50px\"></th>\n"
"    <th>Time</th><th>Duration</th><th>Frequency</th>\n"
"    <th>Frames</th><th>Quality</th>\n"
"  </tr></thead>\n"
"  <tbody id=\"calls-tbody\">\n"
"    <tr><td colspan=\"6\" class=\"no-calls\">"
"No voice calls detected yet</td></tr>\n"
"  </tbody></table>\n"
"</div>\n"
"<div id=\"pbar\">\n"
"  <button class=\"pbtn on\" id=\"pb-btn\" onclick=\"togglePlay()\""
" style=\"width:36px;height:36px;font-size:16px\">&#9654;</button>\n"
"  <div class=\"pi\">\n"
"    <div class=\"pt\" id=\"pb-title\"></div>\n"
"    <div class=\"ps\" id=\"pb-sub\"></div>\n"
"  </div>\n"
"  <div class=\"pp\" onclick=\"seekAudio(event)\">"
"<div class=\"pf\" id=\"pb-fill\"></div></div>\n"
"  <div class=\"ptm\" id=\"pb-time\">0:00 / 0:00</div>\n"
"</div>\n"
"<script>\n"
"var map=L.map('map',{zoomControl:true}).setView([20,0],2);\n"
"var tileLayer=null;\n"
"function setTheme(name){\n"
"  var html=document.documentElement;\n"
"  if(name==='light'){html.classList.add('light')}else{html.classList.remove('light')}\n"
"  try{localStorage.setItem('theme',name)}catch(e){}\n"
"  if(tileLayer)map.removeLayer(tileLayer);\n"
"  var url=(name==='light')?'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'\n"
"                          :'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';\n"
"  tileLayer=L.tileLayer(url,{attribution:'CartoDB',maxZoom:18,\n"
"    subdomains:'abcd'}).addTo(map);\n"
"  var btn=document.getElementById('theme-toggle');\n"
"  if(btn)btn.textContent=(name==='light')?'\\u263C':'\\u263E';\n"
"}\n"
"function toggleTheme(){\n"
"  var cur=document.documentElement.classList.contains('light')?'light':'dark';\n"
"  setTheme(cur==='light'?'dark':'light');\n"
"}\n"
"setTheme((function(){try{return localStorage.getItem('theme')||'dark'}catch(e){return 'dark'}})());\n"
"\n"
"var C=[\n"
"  '#3b82f6','#22d3ee','#10b981','#a78bfa','#f472b6',\n"
"  '#fb923c','#facc15','#4ade80','#818cf8','#f87171',\n"
"  '#2dd4bf','#c084fc','#38bdf8','#fb7185','#a3e635'];\n"
"function sc(id){return C[id%C.length]}\n"
"\n"
"function fmtTime(t){\n"
"  var d=new Date(t*1000);\n"
"  var h=String(d.getUTCHours()).padStart(2,'0');\n"
"  var m=String(d.getUTCMinutes()).padStart(2,'0');\n"
"  var s=String(d.getUTCSeconds()).padStart(2,'0');\n"
"  return h+':'+m+':'+s+'Z';\n"
"}\n"
"\n"
"function esc(s){\n"
"  return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;')\n"
"    .replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;');\n"
"}\n"
"\n"
"function renderAcars(msgs){\n"
"  var box=document.getElementById('acars-list');\n"
"  if(!msgs||msgs.length===0){\n"
"    box.innerHTML='<div class=\"no-msgs\">No ACARS messages yet<br>(heartbeats filtered)</div>';\n"
"    return;\n"
"  }\n"
"  var html='';\n"
"  msgs.forEach(function(m){\n"
"    var txt=esc(m.txt);\n"
"    html+='<div class=\"amsg\">'+\n"
"      '<div class=\"row1\">'+\n"
"      '<span>'+fmtTime(m.t)+'</span>'+\n"
"      '<span class=\"reg\">'+esc(m.reg)+'</span>'+\n"
"      (m.flt?'<span class=\"flt\">'+esc(m.flt)+'</span>':'')+\n"
"      '<span class=\"lbl\">'+esc(m.lbl)+'</span>'+\n"
"      '<span class=\"dir\">'+(m.ul?'UL':'DL')+'</span>'+\n"
"      '</div>'+\n"
"      '<div class=\"txt\">'+txt+'</div></div>';\n"
"  });\n"
"  box.innerHTML=html;\n"
"}\n"
"\n"
"var allPages=[];\n"
"function exportPages(){\n"
"  if(allPages.length===0){alert('No paging events collected yet.');return;}\n"
"  var csv='timestamp,tmsi_hex,satellite,beam,lat,lon\\n';\n"
"  allPages.forEach(function(p){\n"
"    var d=new Date(p.t*1000);\n"
"    csv+=d.toISOString()+',0x'+(p.tmsi>>>0).toString(16).toUpperCase()\n"
"      +','+p.sat+','+p.beam+','+p.lat.toFixed(4)+','+p.lon.toFixed(4)+'\\n';\n"
"  });\n"
"  var blob=new Blob([csv],{type:'text/csv'});\n"
"  var a=document.createElement('a');\n"
"  a.href=URL.createObjectURL(blob);\n"
"  a.download='iridium_pages_'+Date.now()+'.csv';\n"
"  a.click();\n"
"}\n"
"\n"
"var beamLy=L.layerGroup().addTo(map);\n"
"var mtLy=L.layerGroup().addTo(map);\n"
"var acarsLy=L.layerGroup();\n"
"var pageLy=L.layerGroup().addTo(map);\n"
"var rxLy=L.layerGroup().addTo(map);\n"
"var satLy=L.layerGroup();\n"
"var coverLy=L.layerGroup();\n"
"L.control.layers(null,{\n"
"  'Beam footprints':beamLy,'MT positions':mtLy,\n"
"  'Aircraft (ACARS)':acarsLy,\n"
"  'Paging events':pageLy,'Receiver':rxLy,\n"
"  'Satellite tracks':satLy,'Sat coverage':coverLy\n"
"},{collapsed:false}).addTo(map);\n"
"\n"
"var centered=false;\n"
"var TW=300;\n"
"var popupOpen=false;\n"
"map.on('popupopen',function(){popupOpen=true});\n"
"map.on('popupclose',function(){popupOpen=false});\n"
"\n"
"var activeTab='map';\n"
"function showTab(t){\n"
"  activeTab=t;\n"
"  document.getElementById('main').style.display=t==='map'?'flex':'none';\n"
"  document.getElementById('calls-panel').style.display=t==='calls'?'block':'none';\n"
"  document.getElementById('tab-map').className=t==='map'?'tab active':'tab';\n"
"  document.getElementById('tab-calls').className=t==='calls'?'tab active':'tab';\n"
"  if(t==='map')map.invalidateSize();\n"
"  if(t==='calls')fetchCalls();\n"
"}\n"
"\n"
"var callsData=[];\n"
"var curPlay=-1;\n"
"var au=new Audio();\n"
"\n"
"function fetchCalls(){\n"
"  fetch('/api/calls').then(function(r){return r.json()}).then(function(d){\n"
"    callsData=d.calls||[];\n"
"    var b=document.getElementById('cbadge');\n"
"    if(d.total_calls>0){b.textContent=d.total_calls;b.style.display='';}\n"
"    if(d.total_voc_frames>0){\n"
"      document.getElementById('voc-stat').style.display='';\n"
"      document.getElementById('n-voc').textContent=d.total_voc_frames;\n"
"    }\n"
"    renderCalls();\n"
"  }).catch(function(){});\n"
"}\n"
"\n"
"function fmtD(ms){\n"
"  var s=Math.floor(ms/1000);var m=Math.floor(s/60);s=s%60;\n"
"  return m>0?m+'m '+s+'s':s+'s';\n"
"}\n"
"function fmtT(ts){\n"
"  var d=new Date(ts*1000);\n"
"  var h=d.getHours(),m=d.getMinutes(),s=d.getSeconds();\n"
"  return ('0'+h).slice(-2)+':'+('0'+m).slice(-2)+':'+('0'+s).slice(-2);\n"
"}\n"
"function fmtF(hz){return (hz/1e6).toFixed(3)+' MHz'}\n"
"\n"
"function renderCalls(){\n"
"  var tb=document.getElementById('calls-tbody');\n"
"  if(!callsData.length){\n"
"    tb.innerHTML='<tr><td colspan=\"6\" class=\"no-calls\">'"
"+'No voice calls detected yet</td></tr>';\n"
"    return;\n"
"  }\n"
"  var h='';\n"
"  for(var i=0;i<callsData.length;i++){\n"
"    var c=callsData[i];\n"
"    var p=curPlay===c.id;\n"
"    var pa=p&&!au.paused;\n"
"    var q=['good','fair','poor'][c.quality]||'poor';\n"
"    var ql=['Good','Fair','Poor'][c.quality]||'Poor';\n"
"    h+='<tr class=\"'+(p?'playing':'')+'\" onclick=\"playCall('+c.id+')\">';\n"
"    h+='<td><button class=\"pbtn '+(pa?'on':'')+'\">';\n"
"    h+=(pa?'&#9646;&#9646;':'&#9654;')+'</button></td>';\n"
"    h+='<td>'+fmtT(c.t)+'</td>';\n"
"    var aDur=Math.round(c.samples/8);\n"
"    h+='<td class=\"dur\">'+fmtD(aDur)+'</td>';\n"
"    h+='<td class=\"freq\">'+fmtF(c.freq)+'</td>';\n"
"    h+='<td>'+c.frames+'</td>';\n"
"    h+='<td><span class=\"qb '+q+'\">'+ql+'</span></td>';\n"
"    h+='</tr>';\n"
"  }\n"
"  tb.innerHTML=h;\n"
"}\n"
"\n"
"function playCall(id){\n"
"  var bar=document.getElementById('pbar');\n"
"  if(curPlay===id){\n"
"    if(au.paused)au.play();else au.pause();\n"
"    renderCalls();return;\n"
"  }\n"
"  curPlay=id;au.src='/api/calls/'+id+'/audio';au.play();\n"
"  bar.style.display='flex';\n"
"  var c=null;\n"
"  for(var i=0;i<callsData.length;i++){"
"if(callsData[i].id===id){c=callsData[i];break;}}\n"
"  if(c){\n"
"    document.getElementById('pb-title').textContent="
"'Call #'+c.id+' - '+fmtF(c.freq);\n"
"    document.getElementById('pb-sub').textContent="
"fmtT(c.t)+' - '+c.frames+' frames, '\n"
"      +['Good','Fair','Poor'][c.quality]+' quality';\n"
"  }\n"
"  renderCalls();\n"
"}\n"
"\n"
"function togglePlay(){if(au.paused)au.play();else au.pause()}\n"
"function seekAudio(e){\n"
"  if(!au.duration)return;\n"
"  var r=e.currentTarget.getBoundingClientRect();\n"
"  au.currentTime=(e.clientX-r.left)/r.width*au.duration;\n"
"}\n"
"\n"
"au.addEventListener('timeupdate',function(){\n"
"  if(!au.duration)return;\n"
"  document.getElementById('pb-fill').style.width=\n"
"    (au.currentTime/au.duration*100)+'%';\n"
"  var c=Math.floor(au.currentTime),t=Math.floor(au.duration);\n"
"  document.getElementById('pb-time').textContent=\n"
"    Math.floor(c/60)+':'+('0'+c%60).slice(-2)+' / '+\n"
"    Math.floor(t/60)+':'+('0'+t%60).slice(-2);\n"
"});\n"
"au.addEventListener('ended',function(){\n"
"  curPlay=-1;document.getElementById('pbar').style.display='none';\n"
"  renderCalls();\n"
"});\n"
"au.addEventListener('pause',function(){\n"
"  document.getElementById('pb-btn').innerHTML='&#9654;';renderCalls();\n"
"});\n"
"au.addEventListener('play',function(){\n"
"  document.getElementById('pb-btn').innerHTML='&#9646;&#9646;';renderCalls();\n"
"});\n"
"\n"
"setInterval(function(){if(activeTab==='calls')fetchCalls()},5000);\n"
"\n"
"function update(d){\n"
"  document.getElementById('n-ira').textContent=d.total_ira;\n"
"  document.getElementById('n-beams').textContent=d.total_beams||0;\n"
"  document.getElementById('n-mt').textContent=d.total_mt||0;\n"
"  document.getElementById('n-ac').textContent=d.total_aircraft||0;\n"
"  document.getElementById('n-pages').textContent=d.total_pages;\n"
"  document.getElementById('n-acars').textContent=d.total_acars_msgs||0;\n"
"  document.getElementById('status').style.color='#22c55e';\n"
"  document.getElementById('status').textContent='live';\n"
"  renderAcars(d.acars||[]);\n"
"\n"
"  if(d.total_voc>0){\n"
"    document.getElementById('voc-stat').style.display='';\n"
"    document.getElementById('n-voc').textContent=d.total_voc;\n"
"  }\n"
"  if(d.voice)document.getElementById('tab-calls').style.display='';\n"
"  var cb=document.getElementById('cbadge');\n"
"  if(d.total_voice_calls>0){cb.textContent=d.total_voice_calls;cb.style.display='';}\n"
"\n"
"  if(popupOpen)return;\n"
"\n"
"  beamLy.clearLayers();\n"
"  mtLy.clearLayers();\n"
"  acarsLy.clearLayers();\n"
"  pageLy.clearLayers();\n"
"  satLy.clearLayers();\n"
"  coverLy.clearLayers();\n"
"\n"
"  var now=0;\n"
"  if(d.beams)d.beams.forEach(function(p){if(p.t>now)now=p.t});\n"
"  if(d.ra)d.ra.forEach(function(p){if(p.t>now)now=p.t});\n"
"  if(d.mt)d.mt.forEach(function(p){if(p.t>now)now=p.t});\n"
"  if(d.aircraft)d.aircraft.forEach(function(ac){\n"
"    if(ac.fixes)ac.fixes.forEach(function(f){if(f.t>now)now=f.t});\n"
"  });\n"
"  var cut=now-TW;\n"
"\n"
"  /* --- Ground beam footprints (primary) --- */\n"
"  var nBeamSat=0;\n"
"  if(d.beams&&d.beams.length>0){\n"
"    var bySat={};\n"
"    d.beams.forEach(function(p){\n"
"      if(p.t<cut)return;\n"
"      if(!bySat[p.sat])bySat[p.sat]=[];\n"
"      bySat[p.sat].push(p);\n"
"      if(p.pages>0){\n"
"        var isDup=allPages.some(function(e){return e.t===p.t&&e.tmsi===p.tmsi&&e.sat===p.sat});\n"
"        if(!isDup)allPages.push({t:p.t,tmsi:p.tmsi,sat:p.sat,beam:p.beam,lat:p.lat,lon:p.lon});\n"
"        var pm=L.circleMarker([p.lat,p.lon],{\n"
"          radius:7,color:'#ef4444',fillColor:'#ef4444',\n"
"          fillOpacity:0.8,weight:2\n"
"        });\n"
"        pm.bindPopup('<div class=\"popup-title popup-page\">Paging</div>'\n"
"          +'Satellite: '+p.sat+'<br>'\n"
"          +'Beam: '+p.beam+'<br>'\n"
"          +'TMSI: 0x'+(p.tmsi>>>0).toString(16).toUpperCase()+'<br>'\n"
"          +'Position: '+p.lat.toFixed(4)+', '+p.lon.toFixed(4));\n"
"        pm.addTo(pageLy);\n"
"      }\n"
"    });\n"
"    Object.keys(bySat).forEach(function(sid){\n"
"      var pts=bySat[sid].sort(function(a,b){return a.t-b.t});\n"
"      if(!pts.length)return;\n"
"      nBeamSat++;\n"
"      var col=sc(parseInt(sid));\n"
"      pts.forEach(function(pt){\n"
"        var age=(now-pt.t)/TW;\n"
"        L.circle([pt.lat,pt.lon],{radius:200000,\n"
"          stroke:true,color:col,weight:1,\n"
"          fillColor:col,fillOpacity:0.10*(1-age)\n"
"        }).addTo(beamLy);\n"
"      });\n"
"      var last=pts[pts.length-1];\n"
"      var m=L.circleMarker([last.lat,last.lon],{\n"
"        radius:5,color:col,fillColor:col,fillOpacity:0.9,weight:2\n"
"      });\n"
"      m.bindTooltip('Sat '+sid+' B'+last.beam,\n"
"        {direction:'top',offset:[0,-8]});\n"
"      m.bindPopup('<div class=\"popup-title\">Beam Center</div>'\n"
"        +'Satellite: '+sid+'<br>'\n"
"        +'Beam: '+last.beam+'<br>'\n"
"        +'Position: '+last.lat.toFixed(4)+', '+last.lon.toFixed(4)+'<br>'\n"
"        +'Frequency: '+last.freq.toFixed(0)+' Hz');\n"
"      m.addTo(beamLy);\n"
"    });\n"
"  }\n"
"  document.getElementById('n-sats').textContent=nBeamSat;\n"
"\n"
"  /* --- MT phone/terminal positions --- */\n"
"  if(d.mt&&d.mt.length>0){\n"
"    d.mt.forEach(function(p){\n"
"      if(p.t<cut)return;\n"
"      var age=(now-p.t)/TW;\n"
"      var ts=p.type==0x0605?'GSM Page':\n"
"             p.type==0x7605?'SBD Page':\n"
"             p.type==0x0600?'Uplink':'Unknown';\n"
"      var pm=L.circleMarker([p.lat,p.lon],{\n"
"        radius:5,color:'#f59e0b',fillColor:'#f59e0b',\n"
"        fillOpacity:0.8*(1-age*0.5),weight:2\n"
"      });\n"
"      pm.bindPopup('<div class=\"popup-title popup-mt\">MT Position</div>'\n"
"        +'Type: '+ts+'<br>'\n"
"        +'Position: '+p.lat.toFixed(4)+', '+p.lon.toFixed(4)+'<br>'\n"
"        +'Frequency: '+p.freq.toFixed(0)+' Hz');\n"
"      pm.addTo(mtLy);\n"
"    });\n"
"  }\n"
"\n"
"  /* --- Aircraft beam-based positions (ACARS) --- */\n"
"  var TW_AC=3600;\n"
"  function hav(a,b){\n"
"    var R=6371,dr=(b.lat-a.lat)*Math.PI/180,dl=(b.lon-a.lon)*Math.PI/180;\n"
"    var s=Math.sin(dr/2)*Math.sin(dr/2)+Math.cos(a.lat*Math.PI/180)*Math.cos(b.lat*Math.PI/180)*Math.sin(dl/2)*Math.sin(dl/2);\n"
"    return R*2*Math.atan2(Math.sqrt(s),Math.sqrt(1-s));\n"
"  }\n"
"  if(d.aircraft&&d.aircraft.length>0){\n"
"    d.aircraft.forEach(function(ac,idx){\n"
"      if(!ac.fixes||ac.fixes.length===0)return;\n"
"      var last=ac.fixes[ac.fixes.length-1];\n"
"      if(now-last.t>TW_AC)return;\n"
"      var col=sc(idx);\n"
"      if(ac.fixes.length>1){\n"
"        /* Split track into segments; skip any jump > 2500 km (satellite beam shift) */\n"
"        var segs=[],cur=[ac.fixes[0]];\n"
"        for(var i=1;i<ac.fixes.length;i++){\n"
"          if(hav(ac.fixes[i-1],ac.fixes[i])<2500){\n"
"            cur.push(ac.fixes[i]);\n"
"          }else{\n"
"            if(cur.length>1)segs.push(cur);\n"
"            cur=[ac.fixes[i]];\n"
"          }\n"
"        }\n"
"        if(cur.length>1)segs.push(cur);\n"
"        segs.forEach(function(seg){\n"
"          L.polyline(seg.map(function(f){return[f.lat,f.lon];}),\n"
"            {color:col,weight:2,opacity:0.5,dashArray:'6,4'}).addTo(acarsLy);\n"
"        });\n"
"      }\n"
"      var label=esc(ac.reg)+(ac.flight?' / '+esc(ac.flight):'')+(ac.oooi?' ['+esc(ac.oooi)+']':'');\n"
"      var m=L.circleMarker([last.lat,last.lon],{\n"
"        radius:7,color:col,fillColor:col,fillOpacity:0.9,weight:2\n"
"      });\n"
"      m.bindTooltip(label,{direction:'top',offset:[0,-8]});\n"
"      var ts=new Date(last.t*1000).toUTCString().replace(/.*?([0-9]{2}:[0-9]{2}:[0-9]{2}).*/,'$1')+' UTC';\n"
"      var altStr=last.alt>-99999?'<b>Altitude:</b> '+(last.alt).toLocaleString()+' ft<br>':'';\n"
"      var posStr=last.adsc?'<span style=\"color:#22c55e;font-size:11px\">ADS-C GPS position</span>':'<span style=\"color:#94a3b8;font-size:11px\">~200 km beam estimate</span>';\n"
"      var ooiStr=ac.oooi?'<b>Event:</b> <span style=\"color:#f59e0b;font-weight:600\">'+esc(ac.oooi)+'</span><br>':'';\n"
"      m.bindPopup('<div class=\"popup-title popup-ac\" style=\"color:'+col+'\">Aircraft</div>'\n"
"        +'<b>Reg:</b> '+esc(ac.reg)+'<br>'\n"
"        +(ac.flight?'<b>Flight:</b> '+esc(ac.flight)+'<br>':'')\n"
"        +ooiStr\n"
"        +altStr\n"
"        +'<b>Sat:</b> '+ac.sat+'  Beam: '+ac.beam+'<br>'\n"
"        +'<b>Position:</b> '+last.lat.toFixed(last.adsc?4:2)+', '+last.lon.toFixed(last.adsc?4:2)+'<br>'\n"
"        +'<b>Last msg:</b> '+ts+'<br>'\n"
"        +posStr);\n"
"      m.addTo(acarsLy);\n"
"    });\n"
"  }\n"
"\n"
"  /* --- Satellite orbital tracks (toggleable, off by default) --- */\n"
"  if(d.ra&&d.ra.length>0){\n"
"    var satBySat={};\n"
"    d.ra.forEach(function(p){\n"
"      if(p.t<cut)return;\n"
"      if(!satBySat[p.sat])satBySat[p.sat]=[];\n"
"      satBySat[p.sat].push(p);\n"
"    });\n"
"    Object.keys(satBySat).forEach(function(sid){\n"
"      var pts=satBySat[sid].sort(function(a,b){return a.t-b.t});\n"
"      if(!pts.length)return;\n"
"      var col=sc(parseInt(sid));\n"
"      pts.forEach(function(pt){\n"
"        var age=(now-pt.t)/TW;\n"
"        L.circle([pt.lat,pt.lon],{radius:400000,\n"
"          stroke:false,fillColor:col,fillOpacity:0.08*(1-age)\n"
"        }).addTo(coverLy);\n"
"      });\n"
"      var last=pts[pts.length-1];\n"
"      var m=L.circleMarker([last.lat,last.lon],{\n"
"        radius:4,color:'#64748b',fillColor:'#64748b',\n"
"        fillOpacity:0.7,weight:1\n"
"      });\n"
"      m.bindTooltip('Sat '+sid+' (orbit)',\n"
"        {direction:'top',offset:[0,-8]});\n"
"      m.bindPopup('<div class=\"popup-title\">Satellite '+sid+'</div>'\n"
"        +'Beam: '+last.beam+'<br>'\n"
"        +'Position: '+last.lat.toFixed(2)+', '+last.lon.toFixed(2)+'<br>'\n"
"        +'Altitude: '+last.alt+' km<br>'\n"
"        +'Frequency: '+last.freq.toFixed(0)+' Hz');\n"
"      m.addTo(satLy);\n"
"    });\n"
"  }\n"
"\n"
"  /* --- Receiver position --- */\n"
"  rxLy.clearLayers();\n"
"  if(d.rx){\n"
"    var rm=L.circleMarker([d.rx.lat,d.rx.lon],{\n"
"      radius:8,color:'#22c55e',fillColor:'#22c55e',\n"
"      fillOpacity:0.9,weight:3\n"
"    });\n"
"    rm.bindPopup('<div class=\"popup-title\">Receiver Position</div>'\n"
"      +'Estimated: '+d.rx.lat.toFixed(6)+', '+d.rx.lon.toFixed(6)+'<br>'\n"
"      +'HDOP: '+d.rx.hdop.toFixed(1));\n"
"    rm.addTo(rxLy);\n"
"    if(d.rx.hdop<50){\n"
"      L.circle([d.rx.lat,d.rx.lon],{radius:d.rx.hdop*20,\n"
"        color:'#22c55e',fillColor:'#22c55e',\n"
"        fillOpacity:0.1,weight:1,dashArray:'4'}).addTo(rxLy);\n"
"    }\n"
"  }\n"
"\n"
"  /* --- Auto-center --- */\n"
"  if(!centered){\n"
"    if(d.rx){\n"
"      map.setView([d.rx.lat,d.rx.lon],8);\n"
"      centered=true;\n"
"    }else if(d.beams&&d.beams.length>0){\n"
"      map.setView([d.beams[0].lat,d.beams[0].lon],8);\n"
"      centered=true;\n"
"    }else if(d.ra&&d.ra.length>0){\n"
"      map.setView([d.ra[0].lat,d.ra[0].lon],3);\n"
"      centered=true;\n"
"    }\n"
"  }\n"
"}\n"
"\n"
"function connect(){\n"
"  var base=window.location.href.split('#')[0].split('?')[0].replace(/\\/?$/,'/');\n"
"  var es=new EventSource(base+'api/events');\n"
"  es.addEventListener('update',function(e){\n"
"    try{update(JSON.parse(e.data))}catch(err){}\n"
"  });\n"
"  es.onerror=function(){\n"
"    document.getElementById('status').style.color='#ef4444';\n"
"    document.getElementById('status').textContent='reconnecting...';\n"
"    es.close();\n"
"    setTimeout(connect,2000);\n"
"  };\n"
"}\n"
"connect();\n"
"</script></body></html>\n";

/* ---- HTTP request handling ---- */

static void send_response(int fd, const char *status, const char *content_type,
                            const char *body, int body_len)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n", status, content_type, body_len);
    if (write(fd, header, hlen) < 0) return;
    if (body_len > 0) {
        if (write(fd, body, body_len) < 0) return;
    }
}

static void handle_sse(int fd)
{
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "X-Accel-Buffering: no\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n");
    if (write(fd, header, hlen) < 0) return;

    jbuf_t json = {0};

    while (server_running) {
        usleep(1000000);  /* 1 Hz updates */
        if (!server_running) break;

        build_json(&json);
        if (json.oom) break;

        char prefix[] = "event: update\ndata: ";
        char suffix[] = "\n\n";

        struct iovec iov[3];
        iov[0].iov_base = prefix;
        iov[0].iov_len = sizeof(prefix) - 1;
        iov[1].iov_base = json.p;
        iov[1].iov_len = json.len;
        iov[2].iov_base = suffix;
        iov[2].iov_len = sizeof(suffix) - 1;

        /* Use writev for atomic write */
        if (writev(fd, iov, 3) < 0) break;
    }

    free(json.p);
}

static void handle_client(int fd)
{

    char buf[HTTP_BUF_SIZE];
    int n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(fd); return; }
    buf[n] = '\0';

    /* Parse GET path */
    if (strncmp(buf, "GET ", 4) != 0) {
        send_response(fd, "405 Method Not Allowed", "text/plain", "405", 3);
        close(fd);
        return;
    }

    char *path = buf + 4;
    char *end = strchr(path, ' ');
    if (end) *end = '\0';

    /* Strip query string — reverse proxies may append ?... parameters */
    char *qs = strchr(path, '?');
    if (qs) *qs = '\0';

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        send_response(fd, "200 OK", "text/html",
                       HTML_PAGE, sizeof(HTML_PAGE) - 1);
        close(fd);
    } else if (strcmp(path, "/api/events") == 0) {
        if (atomic_fetch_add(&sse_client_count, 1) >= MAX_SSE_CLIENTS) {
            atomic_fetch_sub(&sse_client_count, 1);
            send_response(fd, "503 Service Unavailable", "text/plain",
                          "too many clients", 16);
        } else {
            handle_sse(fd);
            atomic_fetch_sub(&sse_client_count, 1);
        }
        close(fd);
    } else if (strcmp(path, "/api/state") == 0) {
        jbuf_t json = {0};
        build_json(&json);
        if (!json.oom)
            send_response(fd, "200 OK", "application/json", json.p, (int)json.len);
        free(json.p);
        close(fd);
#ifdef HAVE_VOICE
    } else if (voice_enabled && strcmp(path, "/api/calls") == 0) {
        /* Voice calls JSON list */
        int n_calls = voice_decode_call_count();
        jbuf_t json = {0};
        jb_printf(&json, "{\"total_calls\":%d,\"total_voc_frames\":%d,\"calls\":[",
                  voice_decode_total_calls(), voice_decode_total_frames());
        int n_emit = 0;
        for (int i = n_calls - 1; i >= 0; i--) {
            voice_call_t c;
            if (voice_decode_get_call(i, &c) != 0) continue;
            int dur_ms = (int)((c.end_time - c.start_time) / 1000000ULL);
            jb_printf(&json, "%s{\"id\":%d,\"t\":%lu,\"dur\":%d,"
                "\"freq\":%.0f,\"frames\":%d,\"quality\":%d,\"samples\":%d}",
                n_emit++ ? "," : "", c.call_id,
                (unsigned long)(c.start_time / 1000000000ULL),
                dur_ms, c.frequency, c.n_frames, (int)c.quality, c.n_samples);
        }
        jb_printf(&json, "]}");
        if (!json.oom)
            send_response(fd, "200 OK", "application/json", json.p, (int)json.len);
        free(json.p);
        close(fd);
    } else if (voice_enabled && strncmp(path, "/api/calls/", 11) == 0) {
        /* Voice call audio: /api/calls/N/audio */
        int call_id = -1;
        if (sscanf(path + 11, "%d/audio", &call_id) == 1 && call_id >= 0) {
            int n_samples = 0;
            int16_t *audio = voice_decode_copy_audio(call_id, &n_samples);
            if (audio) {
                /* Build WAV file in memory */
                int data_size = n_samples * 2;
                int wav_size = 44 + data_size;
                uint8_t *wav = malloc(wav_size);
                if (wav) {
                    /* RIFF header */
                    memcpy(wav, "RIFF", 4);
                    uint32_t chunk_size = wav_size - 8;
                    memcpy(wav + 4, &chunk_size, 4);
                    memcpy(wav + 8, "WAVE", 4);
                    /* fmt subchunk */
                    memcpy(wav + 12, "fmt ", 4);
                    uint32_t fmt_size = 16;
                    memcpy(wav + 16, &fmt_size, 4);
                    uint16_t audio_fmt = 1; /* PCM */
                    memcpy(wav + 20, &audio_fmt, 2);
                    uint16_t channels = 1;
                    memcpy(wav + 22, &channels, 2);
                    uint32_t sample_rate = VOICE_SAMPLE_RATE;
                    memcpy(wav + 24, &sample_rate, 4);
                    uint32_t byte_rate = VOICE_SAMPLE_RATE * 2;
                    memcpy(wav + 28, &byte_rate, 4);
                    uint16_t block_align = 2;
                    memcpy(wav + 32, &block_align, 2);
                    uint16_t bits_per_sample = 16;
                    memcpy(wav + 34, &bits_per_sample, 2);
                    /* data subchunk */
                    memcpy(wav + 36, "data", 4);
                    uint32_t data_sz = data_size;
                    memcpy(wav + 40, &data_sz, 4);
                    memcpy(wav + 44, audio, data_size);

                    send_response(fd, "200 OK", "audio/wav",
                                  (char *)wav, wav_size);
                    free(wav);
                } else {
                    send_response(fd, "500 Internal Server Error",
                                  "text/plain", "OOM", 3);
                }
                free(audio);
            } else {
                send_response(fd, "404 Not Found", "text/plain",
                              "call not found", 14);
            }
        } else {
            send_response(fd, "400 Bad Request", "text/plain",
                          "bad call id", 11);
        }
        close(fd);
#endif
    } else {
        send_response(fd, "404 Not Found", "text/plain", "404", 3);
        close(fd);
    }
}

static void *client_thread(void *arg)
{
    handle_client((int)(intptr_t)arg);
    atomic_fetch_sub(&client_threads, 1);
    return NULL;
}

/* ---- Server thread ---- */

static void *server_thread_fn(void *arg)
{
    (void)arg;

    while (server_running) {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        int client = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client < 0) {
            if (server_running) usleep(10000);
            continue;
        }

        if (atomic_fetch_add(&client_threads, 1) >= MAX_CLIENT_THREADS) {
            atomic_fetch_sub(&client_threads, 1);
            close(client);
            continue;
        }

        /* Keepalive for SSE; timeouts so idle or non-reading clients
         * can't hold a thread or an SSE slot forever */
        int keepalive = 1;
        setsockopt(client, SOL_SOCKET, SO_KEEPALIVE,
                    &keepalive, sizeof(keepalive));
        struct timeval rto = { .tv_sec = 5 }, sto = { .tv_sec = 10 };
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));

        /* Spawn client handler thread (detached) */
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, client_thread,
                            (void *)(intptr_t)client) != 0) {
            atomic_fetch_sub(&client_threads, 1);
            close(client);
        }
        pthread_attr_destroy(&attr);
    }

    return NULL;
}

/* ---- Public interface ---- */

int web_map_init(int port)
{
    memset(&state, 0, sizeof(state));
    pthread_mutex_init(&state.lock, NULL);

    /* Ignore SIGPIPE (broken SSE connections) */
    signal(SIGPIPE, SIG_IGN);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("web_map: socket");
        return -1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port),
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("web_map: bind");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    if (listen(server_fd, 16) < 0) {
        perror("web_map: listen");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    server_running = 1;
    if (pthread_create(&server_thread, NULL, server_thread_fn, NULL) != 0) {
        perror("web_map: pthread_create");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    fprintf(stderr, "Web map: http://localhost:%d/\n", port);
    return 0;
}

void web_map_shutdown(void)
{
    if (!server_running) return;
    server_running = 0;

    if (server_fd >= 0) {
        shutdown(server_fd, SHUT_RDWR);
        close(server_fd);
        server_fd = -1;
    }

    pthread_join(server_thread, NULL);
    pthread_mutex_destroy(&state.lock);
}
