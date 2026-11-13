/*
 * SBD/ACARS reassembly from IDA messages
 *
 * Extracts SBD (Short Burst Data) packets from reassembled IDA payloads,
 * handles multi-packet SBD reassembly, and parses ACARS messages.
 *
 * When libacars-2 is available (HAVE_LIBACARS), decodes ARINC-622 application
 * payloads including ADS-C position reports, CPDLC datalink, and more.
 *
 * Protocol details derived from iridium-toolkit reassembler/sbd.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include "basestation.h"
#include "waypoint_db.h"
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "net_util.h"
#include "sbd_acars.h"
#include "web_map.h"

#ifdef HAVE_LIBACARS
#include <libacars/libacars.h>
#include <libacars/acars.h>
#include <libacars/reassembly.h>
#include <libacars/vstring.h>
#include <libacars/version.h>
#endif

/* ---- Configuration ---- */

int acars_json = 0;
extern int acars_enabled;
extern int web_enabled;
extern int basestation_enabled;
extern int basestation_beam;
static const char *station = NULL;

/* Beam cache lookup from main.c -- provides approximate aircraft position
 * by correlating the ACARS message timestamp with the most recent IRA ground
 * beam position.  Returns 1 on success, 0 if no match within 10 seconds. */
extern int beam_cache_lookup(uint64_t ts_ns, double *lat, double *lon,
                              int *sat_id, int *beam_id);

/* ---- UDP JSON streaming (up to 4 endpoints) ---- */

#define UDP_MAX 4
static int udp_count = 0;
static int udp_fds[UDP_MAX];
static struct sockaddr_in udp_addrs[UDP_MAX];

/* ---- Aggregator feed endpoints (iridium-toolkit format, mixed UDP/TCP) ---- */

#define FEED_MAX 4
typedef struct {
    int fd;
    int is_tcp;
    struct sockaddr_in udp_addr;   /* UDP only */
    char *tcp_host;                /* TCP only (for reconnect) */
    int tcp_port;                  /* TCP only */
    time_t retry_at;               /* TCP only: next reconnect attempt */
} feed_ep_t;
static feed_ep_t feeds[FEED_MAX];
static int n_feeds = 0;

/* JSON output buffer -- used to build JSON for dual stdout/UDP dispatch */
#define JSON_BUF_SIZE 8192
static char json_buf[JSON_BUF_SIZE];
static int json_pos = 0;

static void json_buf_reset(void) { json_pos = 0; json_buf[0] = '\0'; }

static void json_buf_append(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void json_buf_append(const char *fmt, ...)
{
    if (json_pos >= JSON_BUF_SIZE - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(json_buf + json_pos, JSON_BUF_SIZE - json_pos, fmt, ap);
    va_end(ap);
    if (n > 0) json_pos += n;
    if (json_pos >= JSON_BUF_SIZE) json_pos = JSON_BUF_SIZE - 1;
}

static void json_buf_emit(void)
{
    if (json_pos == 0) return;

    /* stdout (--acars-json) */
    if (acars_json) {
        fwrite(json_buf, 1, json_pos, stdout);
        putchar('\n');
        fflush(stdout);
    }

    /* UDP streams (--acars-udp, one or more endpoints) */
    for (int i = 0; i < udp_count; i++) {
        if (udp_fds[i] >= 0) {
            if (sendto(udp_fds[i], json_buf, json_pos, 0,
                       (struct sockaddr *)&udp_addrs[i],
                       sizeof(udp_addrs[i])) < 0) {
                static int warned;
                if (!warned) { warn("acars-udp: sendto"); warned = 1; }
            }
        }
    }
}

/* Forward declarations */
static void format_timestamp(uint64_t ts_ns, char *buf, int bufsz);
static double ts_to_unix(uint64_t ts_ns);

/* ---- acarshub JSON buffer (iridium-toolkit compat format) ---- */

static char hub_buf[JSON_BUF_SIZE];
static int hub_pos = 0;

static void hub_buf_reset(void) { hub_pos = 0; hub_buf[0] = '\0'; }

static void hub_buf_append(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void hub_buf_append(const char *fmt, ...)
{
    if (hub_pos >= JSON_BUF_SIZE - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(hub_buf + hub_pos, JSON_BUF_SIZE - hub_pos, fmt, ap);
    va_end(ap);
    if (n > 0) hub_pos += n;
    if (hub_pos >= JSON_BUF_SIZE) hub_pos = JSON_BUF_SIZE - 1;
}

/* Check if any feed endpoint is configured */
static int feed_any_active(void) { return n_feeds > 0; }

/* Attempt TCP connection (hostname resolved via getaddrinfo) */
static int feed_tcp_connect(const char *host, int port)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return -1;

    int fd = tcp_connect_timeout(res->ai_addr, res->ai_addrlen, 3000);
    freeaddrinfo(res);
    if (fd < 0)
        return -1;

    /* Disable Nagle for low-latency sends; a peer that stops reading must
     * not block the output thread */
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct timeval sto = { .tv_sec = 2 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));

    return fd;
}

/* Whole buffer or failure; send() may write only part of it */
static int send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t r = send(fd, buf, len, MSG_NOSIGNAL);
        if (r <= 0)
            return -1;
        buf += r;
        len -= (size_t)r;
    }
    return 0;
}

static void hub_buf_emit(void)
{
    if (hub_pos == 0) return;

    for (int i = 0; i < n_feeds; i++) {
        feed_ep_t *f = &feeds[i];

        if (!f->is_tcp) {
            /* UDP feed */
            if (f->fd >= 0) {
                if (sendto(f->fd, hub_buf, hub_pos, 0,
                           (struct sockaddr *)&f->udp_addr,
                           sizeof(f->udp_addr)) < 0) {
                    static int warned;
                    if (!warned) { warn("feed-udp: sendto"); warned = 1; }
                }
            }
        } else {
            /* TCP feed -- reconnect at most every 10 s, not per message */
            if (f->fd < 0 && f->tcp_host && time(NULL) >= f->retry_at) {
                f->fd = feed_tcp_connect(f->tcp_host, f->tcp_port);
                if (f->fd >= 0)
                    fprintf(stderr, "ACARS: reconnected to %s:%d\n",
                            f->tcp_host, f->tcp_port);
                else
                    f->retry_at = time(NULL) + 10;
            }

            if (f->fd >= 0) {
                if (send_all(f->fd, hub_buf, hub_pos) != 0 ||
                    send_all(f->fd, "\n", 1) != 0) {
                    close(f->fd);
                    f->fd = -1;
                    f->retry_at = time(NULL) + 10;
                }
            }
        }
    }
}

/* JSON string escaping for acarshub output */
static void hub_json_escape(const char *in, int inlen, char *out, int outsz)
{
    int o = 0;
    for (int i = 0; i < inlen && o < outsz - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = '"';
        } else if (c == '\\') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = '\\';
        } else if (c == '\n') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 'n';
        } else if (c == '\r') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 'r';
        } else if (c == '\t') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 't';
        } else if (c < 0x20 || c == 0x7f) {
            if (o + 6 >= outsz) break;
            o += snprintf(out + o, outsz - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* Emit iridium-toolkit compatible JSON to acarshub endpoint.
 * Called from both libacars and fallback paths with pre-extracted fields. */
static void hub_emit_acars(const char *mode, const char *reg, char ack,
                            const char *label, char blk_id, int block_end,
                            int ul, const char *text, int text_len,
                            const char *flight, const char *msg_num,
                            char msg_num_seq, int errors,
                            uint64_t timestamp, double frequency,
                            float magnitude, const uint8_t *hdr, int hdr_len)
{
    if (!feed_any_active()) return;

    /* Timestamp as ISO-8601 -- use wall clock for feed output so
     * aggregators (acars_router) don't reject messages as stale
     * when processing backlog causes sample-derived time to lag. */
    char ts_buf[32];
    {
        time_t now = time(NULL);
        struct tm tm;
        gmtime_r(&now, &tm);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    }

    /* Escape strings */
    char esc_reg[64], esc_label[16], esc_text[2048];
    hub_json_escape(reg ? reg : "", reg ? (int)strlen(reg) : 0,
                    esc_reg, sizeof(esc_reg));
    hub_json_escape(label ? label : "", label ? (int)strlen(label) : 0,
                    esc_label, sizeof(esc_label));
    if (text && text_len > 0)
        hub_json_escape(text, text_len, esc_text, sizeof(esc_text));
    else
        esc_text[0] = '\0';

    /* Header as hex string */
    char hdr_hex[64] = "";
    if (hdr && hdr_len > 0) {
        int hp = 0;
        for (int i = 0; i < hdr_len && hp < (int)sizeof(hdr_hex) - 3; i++)
            hp += snprintf(hdr_hex + hp, sizeof(hdr_hex) - hp, "%02x", hdr[i]);
    }

    hub_buf_reset();

    /* app block -- must say "iridium-toolkit" for acarshub detection */
    hub_buf_append("{\"app\":{\"name\":\"iridium-toolkit\",\"version\":\"0.0.1\"}");

    /* source block */
    hub_buf_append(",\"source\":{\"transport\":\"iridium\","
                   "\"protocol\":\"acars\"");
    if (station)
        hub_buf_append(",\"station_id\":\"%s\"", station);
    hub_buf_append("}");

    /* acars block */
    hub_buf_append(",\"acars\":{\"timestamp\":\"%s\"", ts_buf);
    hub_buf_append(",\"errors\":%d", errors);
    hub_buf_append(",\"link_direction\":\"%s\"", ul ? "uplink" : "downlink");
    hub_buf_append(",\"block_end\":%s", block_end ? "true" : "false");
    hub_buf_append(",\"mode\":\"%s\"", mode ? mode : "");
    hub_buf_append(",\"tail\":\"%s\"", esc_reg);
    hub_buf_append(",\"label\":\"%s\"", esc_label);
    hub_buf_append(",\"block_id\":\"%c\"", blk_id);
    hub_buf_append(",\"ack\":\"%c\"", (ack == 0x15) ? '!' : ack);

    if (flight && flight[0]) {
        char esc_flt[32];
        hub_json_escape(flight, (int)strlen(flight), esc_flt, sizeof(esc_flt));
        hub_buf_append(",\"flight\":\"%s\"", esc_flt);
    }
    if (msg_num && msg_num[0]) {
        char esc_mn[16];
        hub_json_escape(msg_num, (int)strlen(msg_num), esc_mn, sizeof(esc_mn));
        hub_buf_append(",\"message_number\":\"%s\"", esc_mn);
    }

    hub_buf_append(",\"text\":\"%s\"", esc_text);
    hub_buf_append("}");

    /* top-level freq, level, header */
    hub_buf_append(",\"freq\":%.1f", frequency);
    hub_buf_append(",\"level\":%.2f", (double)magnitude);
    hub_buf_append(",\"header\":\"%s\"", hdr_hex);

    hub_buf_append("}");
    hub_buf_emit();
}

/* ---- Stats counters ---- */

static int stat_ida_total = 0;      /* total IDA messages received */
static int stat_sbd_total = 0;      /* SBD packets identified */
static int stat_sbd_short = 0;      /* short/mboxcheck messages */
static int stat_sbd_single = 0;     /* single-packet messages */
static int stat_sbd_multi_ok = 0;   /* completed multi-packet messages */
static int stat_sbd_multi_frag = 0; /* multi-packet fragments processed */
static int stat_sbd_broken = 0;     /* orphan/expired fragments */
static int stat_acars_total = 0;    /* ACARS messages decoded */
static int stat_acars_errors = 0;   /* ACARS with CRC/parity errors */
static int stat_pos_adsc = 0;       /* positions from ADS-C */
static int stat_pos_text = 0;       /* positions from free text coords */
static int stat_pos_waypoint = 0;   /* positions from waypoint lookup */
static int stat_pos_beam = 0;       /* positions from beam estimate */
static int stat_bs_sent = 0;        /* positions sent via basestation */

/* ---- Timestamp handling ---- */

static struct timespec wall_t0;
static uint64_t first_ts_ns = 0;
static pthread_once_t ts_once = PTHREAD_ONCE_INIT;

/* Called exactly once via pthread_once -- captures wall clock baseline.
 * first_ts_ns must be set before calling pthread_once. */
static void ts_do_init(void)
{
    clock_gettime(CLOCK_REALTIME, &wall_t0);
}

static void ts_ensure_init(uint64_t ts_ns)
{
    if (first_ts_ns == 0)
        first_ts_ns = ts_ns;
    pthread_once(&ts_once, ts_do_init);
}

static void format_timestamp(uint64_t ts_ns, char *buf, int bufsz)
{
    ts_ensure_init(ts_ns);
    double elapsed = (double)(ts_ns - first_ts_ns) / 1e9;
    time_t wall_sec = wall_t0.tv_sec + (time_t)elapsed;
    struct tm tm;
    gmtime_r(&wall_sec, &tm);
    strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static double ts_to_unix(uint64_t ts_ns)
{
    ts_ensure_init(ts_ns);
    return (double)wall_t0.tv_sec +
           (double)wall_t0.tv_nsec / 1e9 +
           (double)(ts_ns - first_ts_ns) / 1e9;
}

/* ---- CRC-16/Kermit (reflected, poly=0x8408, init=0) ---- */

static uint16_t crc16_table[256];
static int crc_initialized = 0;

static void crc16_init(void)
{
    for (int i = 0; i < 256; i++) {
        uint16_t crc = (uint16_t)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x8408;
            else
                crc >>= 1;
        }
        crc16_table[i] = crc;
    }
    crc_initialized = 1;
}

#ifndef HAVE_LIBACARS
static uint16_t crc16_kermit(const uint8_t *data, int len)
{
    uint16_t crc = 0;
    for (int i = 0; i < len; i++)
        crc = crc16_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc;
}
#endif

/* ---- SBD multi-packet reassembly ---- */

#define SBD_MAX_MULTI    8
#define SBD_MAX_DATA     1024
#define SBD_TIMEOUT_NS   5000000000ULL  /* 5 seconds */

typedef struct {
    int active;
    int msgno;          /* last received message number */
    int msgcnt;         /* total expected messages */
    int ul;             /* direction: 1=uplink, 0=downlink */
    uint64_t timestamp; /* timestamp of last fragment */
    double frequency;
    float magnitude;
    uint8_t data[SBD_MAX_DATA];
    int data_len;
} sbd_multi_t;

static sbd_multi_t sbd_multi[SBD_MAX_MULTI];

/*
 * Extract aircraft position from ACARS free text body.
 *
 * Parses known position formats embedded in message text, gated by label
 * to avoid extracting destination waypoints or flight plan coordinates.
 * Only labels where embedded coordinates are known to represent the
 * aircraft's current position are accepted.
 *
 * Returns 1 if position was extracted, 0 otherwise.
 */
static int acars_extract_text_position(const char *label, const char *text,
                                        double *lat, double *lon)
{
    if (!label || !text || !text[0])
        return 0;

    /* Labels known to carry current aircraft position in text:
     *   H1  - position/met report (POS preamble)
     *   20  - position report (POS preamble)
     *   44  - OOOI + position
     *   4J  - position and weather
     *   15  - general aviation position report
     *   SA  - in-range/fuel status (some carriers include position)
     *
     * NOT included (carry waypoints/destinations, not current position):
     *   H1/FPN - flight plan (future route)
     *   5Z     - too variable, airline-specific
     */
    int label_ok = 0;
    if (label[0] == 'H' && label[1] == '1') label_ok = 1;
    else if (label[0] == '2' && label[1] == '0') label_ok = 1;
    else if (label[0] == '4' && label[1] == '4') label_ok = 1;
    else if (label[0] == '4' && label[1] == 'J') label_ok = 1;
    else if (label[0] == '1' && label[1] == '5') label_ok = 1;
    else if (label[0] == 'S' && label[1] == 'A') label_ok = 1;

    if (!label_ok)
        return 0;

    /* Skip H1 flight plan messages (FPN preamble = future route, not
     * current position) */
    if (label[0] == 'H' && label[1] == '1') {
        if (strncmp(text, "FPN", 3) == 0)
            return 0;
    }

    /*
     * Format 1: POS[NS]ddddd[EW]dddddd  (degrees * 1000)
     *   Example: POSN43312W123174 = 43.312N, 123.174W
     *   Used in H1/POS and label 20/POS messages.
     */
    const char *p = strstr(text, "POS");
    if (p) {
        p += 3;
        char lat_dir = *p;
        if (lat_dir == 'N' || lat_dir == 'S') {
            p++;
            /* Parse 5-digit latitude (degrees * 1000) */
            int lat_digits = 0;
            const char *lp = p;
            while (*p >= '0' && *p <= '9' && lat_digits < 5) {
                lat_digits++;
                p++;
            }
            if (lat_digits == 5) {
                char lon_dir = *p;
                if (lon_dir == 'E' || lon_dir == 'W') {
                    p++;
                    int lon_digits = 0;
                    const char *lop = p;
                    while (*p >= '0' && *p <= '9' && lon_digits < 6) {
                        lon_digits++;
                        p++;
                    }
                    if (lon_digits == 6) {
                        char lat_buf[6], lon_buf[7];
                        memcpy(lat_buf, lp, 5); lat_buf[5] = '\0';
                        memcpy(lon_buf, lop, 6); lon_buf[6] = '\0';
                        double la = atof(lat_buf) / 1000.0;
                        double lo = atof(lon_buf) / 1000.0;
                        if (la >= 0 && la <= 90 && lo >= 0 && lo <= 180) {
                            *lat = (lat_dir == 'S') ? -la : la;
                            *lon = (lon_dir == 'W') ? -lo : lo;
                            return 1;
                        }
                    }
                }
            }
        }
    }

    /*
     * Format 2: [NS]dddmm[EW]dddmm  (degrees + minutes, no decimal)
     *   Example: N33521W084123 = 33d52.1'N, 084d12.3'W = 33.868N, 84.205W
     *   Common across many ACARS labels and carriers.
     *   Latitude: 2 digits degrees + 3 digits (minutes * 10)
     *   Longitude: 3 digits degrees + 3 digits (minutes * 10)
     */
    for (const char *s = text; *s; s++) {
        if ((*s == 'N' || *s == 'S') && s[1] >= '0' && s[1] <= '9') {
            char lat_dir = *s;
            s++;
            /* Need 5 digits for lat (DDmmm) then [EW] then 6 digits for lon */
            int n = 0;
            const char *lat_start = s;
            while (s[n] >= '0' && s[n] <= '9') n++;
            if (n == 5 && (s[n] == 'E' || s[n] == 'W')) {
                char lon_dir = s[n];
                const char *lon_start = s + n + 1;
                int m = 0;
                while (lon_start[m] >= '0' && lon_start[m] <= '9') m++;
                if (m == 6) {
                    /* Parse lat: DD + mmm (minutes * 10) */
                    int lat_deg = (lat_start[0] - '0') * 10 +
                                  (lat_start[1] - '0');
                    int lat_min10 = (lat_start[2] - '0') * 100 +
                                    (lat_start[3] - '0') * 10 +
                                    (lat_start[4] - '0');
                    /* Parse lon: DDD + mmm (minutes * 10) */
                    int lon_deg = (lon_start[0] - '0') * 100 +
                                  (lon_start[1] - '0') * 10 +
                                  (lon_start[2] - '0');
                    int lon_min10 = (lon_start[3] - '0') * 100 +
                                    (lon_start[4] - '0') * 10 +
                                    (lon_start[5] - '0');

                    if (lat_deg <= 90 && lat_min10 < 600 &&
                        lon_deg <= 180 && lon_min10 < 600) {
                        double la = lat_deg + lat_min10 / 600.0;
                        double lo = lon_deg + lon_min10 / 600.0;
                        *lat = (lat_dir == 'S') ? -la : la;
                        *lon = (lon_dir == 'W') ? -lo : lo;
                        return 1;
                    }
                }
            }
            /* Reset scan position if this wasn't a match */
            s = lat_start - 1;
        }
    }

    /*
     * Format 3: LAT [NS] dd.ddd/LON [EW] ddd.ddd  (decimal degrees, tagged)
     *   Example: LAT N 33.917/LON W 77.988
     *   Used in some structured position reports.
     */
    p = strstr(text, "LAT");
    if (p) {
        p += 3;
        while (*p == ' ') p++;
        char lat_dir = *p;
        if (lat_dir == 'N' || lat_dir == 'S') {
            p++;
            while (*p == ' ') p++;
            char *end;
            double la = strtod(p, &end);
            if (end != p && la >= 0 && la <= 90) {
                /* Find LON */
                const char *lp = strstr(end, "LON");
                if (lp) {
                    lp += 3;
                    while (*lp == ' ') lp++;
                    char lon_dir = *lp;
                    if (lon_dir == 'E' || lon_dir == 'W') {
                        lp++;
                        while (*lp == ' ') lp++;
                        double lo = strtod(lp, &end);
                        if (end != lp && lo >= 0 && lo <= 180) {
                            *lat = (lat_dir == 'S') ? -la : la;
                            *lon = (lon_dir == 'W') ? -lo : lo;
                            return 1;
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * Extract aircraft position from waypoint name in ACARS text.
 * Only uses the FIRST waypoint reference (current position fix),
 * not subsequent ones (which are "next" or destination waypoints).
 *
 * Scans for 5-letter uppercase sequences that match the waypoint database.
 * Returns 1 if a valid waypoint was found and resolved, 0 otherwise.
 */
static int acars_extract_waypoint_position(const char *label, const char *text,
                                            double *lat, double *lon)
{
    if (!label || !text || !text[0])
        return 0;

    /* Same label gate as coordinate extraction */
    int label_ok = 0;
    if (label[0] == 'H' && label[1] == '1') label_ok = 1;
    else if (label[0] == '2' && label[1] == '0') label_ok = 1;
    else if (label[0] == '4' && label[1] == '4') label_ok = 1;
    else if (label[0] == '4' && label[1] == 'J') label_ok = 1;
    else if (label[0] == '1' && label[1] == '5') label_ok = 1;
    else if (label[0] == 'S' && label[1] == 'A') label_ok = 1;
    if (!label_ok) return 0;

    /* Skip FPN (flight plan) preamble */
    if (label[0] == 'H' && label[1] == '1' && strncmp(text, "FPN", 3) == 0)
        return 0;

    /* In POS messages, the waypoint after the coordinate block is the
     * current fix. Format: POS[coords],WAYPOINT,time,...
     * If we get here, coordinate extraction already failed, so look for
     * the first comma-separated 5-letter token after "POS". */
    const char *scan = text;

    /* If text starts with POS, skip past it to find waypoint fields */
    if (strncmp(scan, "POS", 3) == 0)
        scan += 3;

    /* Scan for 5-letter uppercase tokens (comma or space delimited) */
    while (*scan) {
        /* Skip to next potential start of a token */
        while (*scan && *scan != ',' && *scan != ' ' && *scan != '/')
            scan++;
        while (*scan == ',' || *scan == ' ' || *scan == '/')
            scan++;

        /* Check if we have a 5-letter uppercase sequence */
        if (scan[0] >= 'A' && scan[0] <= 'Z' &&
            scan[1] >= 'A' && scan[1] <= 'Z' &&
            scan[2] >= 'A' && scan[2] <= 'Z' &&
            scan[3] >= 'A' && scan[3] <= 'Z' &&
            scan[4] >= 'A' && scan[4] <= 'Z' &&
            (scan[5] == ',' || scan[5] == ' ' || scan[5] == '/' ||
             scan[5] == '\0' || scan[5] == '\r' || scan[5] == '\n')) {

            char ident[6];
            memcpy(ident, scan, 5);
            ident[5] = '\0';

            /* Look up in waypoint database */
            if (waypoint_db_lookup(ident, lat, lon))
                return 1;
        }

        /* Move past this token */
        while (*scan && *scan != ',' && *scan != ' ' && *scan != '/')
            scan++;
    }

    return 0;
}

/* ================================================================
 * libacars path -- full ARINC-622/ADS-C/CPDLC decoding
 *
 * JSON output follows the dumpvdl2/dumphfdl envelope format:
 *   {"iridium":{"app":{"name":"...","ver":"..."},"station":"...",
 *     "t":{"sec":N,"usec":N},"freq":N,"sig_level":N.N,
 *     "acars":{...libacars fields...}}}
 * ================================================================ */

#ifdef HAVE_LIBACARS

#include <libacars/json.h>
#include <libacars/adsc.h>

static la_reasm_ctx *reasm_ctx = NULL;

/* Iridium message metadata for the JSON envelope */
typedef struct {
    const char *station;
    struct timeval tv;
    int64_t freq;
    double sig_level;
    const uint8_t *ir_hdr;
    int ir_hdr_len;
} iridium_metadata_t;

/* la_type_descriptor format_json callback -- writes the iridium envelope
 * fields in the same style as dumpvdl2's la_vdl2_format_json */
static void iridium_format_json(la_vstring *vstr, void const *data)
{
    const iridium_metadata_t *m = data;

    la_json_object_start(vstr, "app");
    la_json_append_string(vstr, "name", "iridium-sniffer");
    la_json_append_string(vstr, "ver", "1.0");
    la_json_object_end(vstr);

    if (m->station)
        la_json_append_string(vstr, "station", m->station);

    la_json_object_start(vstr, "t");
    la_json_append_int64(vstr, "sec", (int64_t)m->tv.tv_sec);
    la_json_append_int64(vstr, "usec", (int64_t)m->tv.tv_usec);
    la_json_object_end(vstr);

    la_json_append_int64(vstr, "freq", m->freq);
    la_json_append_double(vstr, "sig_level", m->sig_level);

    if (m->ir_hdr && m->ir_hdr_len > 0)
        la_json_append_octet_string(vstr, "header",
                                    m->ir_hdr, m->ir_hdr_len);
}

/* Type descriptor: json_key "iridium" wraps the entire message,
 * matching the pattern of "vdl2" in dumpvdl2 and "hfdl" in dumphfdl */
static la_type_descriptor const la_DEF_iridium_message = {
    .format_text = NULL,
    .destroy = NULL,
    .format_json = iridium_format_json,
    .json_key = "iridium",
};

static void acars_parse_libacars(const uint8_t *data, int len, int ul,
                                  uint64_t timestamp, double frequency,
                                  float magnitude)
{
    if (len == 0 || data[0] != 0x01)
        return;

    /* Strip SOH marker (0x01) -- libacars expects data after SOH */
    data++;
    len--;

    /* Strip Iridium-specific 0x03 header (8 bytes of unknown meaning) */
    const uint8_t *ir_hdr = NULL;
    int ir_hdr_len = 0;
    if (len > 0 && data[0] == 0x03 && len >= 8) {
        ir_hdr = data;
        ir_hdr_len = 8;
        data += 8;
        len -= 8;
    }

    if (len < 13)
        return;

    la_msg_dir dir = ul ? LA_MSG_DIR_AIR2GND : LA_MSG_DIR_GND2AIR;

    /* Convert timestamp to struct timeval for libacars reassembly */
    double unix_time = ts_to_unix(timestamp);
    struct timeval tv;
    tv.tv_sec = (time_t)unix_time;
    tv.tv_usec = (long)((unix_time - (double)tv.tv_sec) * 1000000.0);

    la_proto_node *tree = la_acars_parse_and_reassemble(
        data, len, dir, reasm_ctx, tv);
    if (!tree)
        return;

    /* Find the ACARS message node */
    la_proto_node *acars_node = la_proto_tree_find_acars(tree);
    if (!acars_node || !acars_node->data) {
        la_proto_tree_destroy(tree);
        return;
    }

    la_acars_msg *msg = (la_acars_msg *)acars_node->data;

    /* Skip in-progress reassembly (multi-block ACARS) */
    if (msg->reasm_status == LA_REASM_IN_PROGRESS) {
        la_proto_tree_destroy(tree);
        return;
    }

    stat_acars_total++;
    if (msg->err)
        stat_acars_errors++;

    if (acars_json || udp_count > 0) {
        if (msg->err) {
            la_proto_tree_destroy(tree);
            return;
        }

        /* Build dumpvdl2/dumphfdl-style JSON via libacars tree formatter.
         * Prepend an iridium metadata node to the ACARS tree, then let
         * la_proto_tree_format_json render the entire tree. */
        iridium_metadata_t meta = {
            .station = station,
            .tv = tv,
            .freq = (int64_t)frequency,
            .sig_level = (double)magnitude,
            .ir_hdr = ir_hdr,
            .ir_hdr_len = ir_hdr_len,
        };

        la_proto_node *ir_node = la_proto_node_new();
        ir_node->td = &la_DEF_iridium_message;
        ir_node->data = &meta;
        ir_node->next = tree;

        la_vstring *vstr = la_proto_tree_format_json(NULL, ir_node);
        if (vstr && vstr->str) {
            json_buf_reset();
            json_buf_append("%.*s", (int)vstr->len, vstr->str);
            json_buf_emit();
        }
        if (vstr)
            la_vstring_destroy(vstr, true);

        /* Detach before freeing -- meta is on the stack, tree is freed below */
        ir_node->data = NULL;
        ir_node->next = NULL;
        free(ir_node);
    }

    if (!acars_json) {
        /* Text mode: timestamp + direction header, then libacars text */
        char ts_buf[32];
        format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

        printf("ACARS: %s %s ", ts_buf, ul ? "UL" : "DL");
        if (ir_hdr && ir_hdr_len > 0) {
            printf("[hdr:%s] ", "iridium");
        }

        la_vstring *vstr = la_proto_tree_format_text(NULL, tree);
        if (vstr && vstr->str) {
            /* Print the full decoded output from libacars */
            printf("\n%s", vstr->str);
        }
        if (vstr)
            la_vstring_destroy(vstr, true);

        fflush(stdout);
    }

    /* Web map ACARS feed sidebar (filter heartbeats and empty-text messages) */
    if (web_enabled && !msg->err && msg->reg[0] && msg->txt && msg->txt[0]) {
        int is_heartbeat = (msg->label[0] == '_' && msg->label[1] == 'd');
        if (!is_heartbeat) {
            const char *tail = msg->reg;
            while (*tail == '.') tail++;
            web_map_add_acars_message(tail, msg->flight_id,
                                       msg->label, msg->txt, ul, timestamp);
        }
    }

    /* acarshub/airframes compat output (iridium-toolkit format) */
    if (feed_any_active() &&
        !msg->err) {
        char mode_str[2] = { msg->mode, '\0' };

        /* Strip leading dots from registration for tail field */
        const char *tail = msg->reg;
        while (*tail == '.') tail++;

        /* Determine block_end from more flag */
        int block_end = !msg->final_block ? 0 : 1;

        /* Extract text from libacars msg */
        const char *txt = msg->txt ? msg->txt : "";
        int txt_len = msg->txt ? (int)strlen(msg->txt) : 0;

        hub_emit_acars(mode_str, tail, msg->ack, msg->label, msg->block_id,
                       block_end, ul, txt, txt_len,
                       msg->flight_id, msg->msg_num, msg->msg_num_seq,
                       0, timestamp, frequency, magnitude,
                       ir_hdr, ir_hdr_len);
    }

    /* Aircraft position (ADS-C GPS if available, else beam estimate) */
    if (web_enabled && !msg->err && msg->reg[0]) {
        double pos_lat = 0.0, pos_lon = 0.0;
        int pos_sat = 0, pos_beam = 0;
        int adsc_alt = -99999;
        int adsc_pos = 0;
        char adsc_flt[10] = {0};
        char oooi_str[8] = {0};

        /* Walk ADS-C proto tree for exact position, altitude, flight ID */
        la_proto_node *an = la_proto_tree_find_adsc(tree);
        if (an && an->data) {
            la_adsc_msg_t *am = (la_adsc_msg_t *)an->data;
            if (!am->err && am->tag_list) {
                for (la_list *l = am->tag_list; l; l = l->next) {
                    la_adsc_tag_t *t = (la_adsc_tag_t *)l->data;
                    if (!t || !t->data) continue;
                    /* Basic position report (downlink tags 7,9,10,18,19,20) */
                    if (t->tag == 7  || t->tag == 9  || t->tag == 10 ||
                        t->tag == 18 || t->tag == 19 || t->tag == 20) {
                        la_adsc_basic_report_t *br =
                            (la_adsc_basic_report_t *)t->data;
                        pos_lat  = br->lat;
                        pos_lon  = br->lon;
                        adsc_alt = br->alt;  /* feet */
                        adsc_pos = 1;
                    }
                    /* Flight ID (tag 12) -- use when msg->flight_id is empty */
                    if (t->tag == 12) {
                        la_adsc_flight_id_t *fi =
                            (la_adsc_flight_id_t *)t->data;
                        strncpy(adsc_flt, fi->id, 9);
                        adsc_flt[9] = '\0';
                    }
                }
            }
        }

        /* Detect OOOI events: Q0 label with OUT/OFF/ON/IN in text */
        if (msg->label[0] == 'Q' && msg->label[1] == '0' && msg->txt) {
            if      (strstr(msg->txt, "OUT")) strncpy(oooi_str, "OUT", 4);
            else if (strstr(msg->txt, "OFF")) strncpy(oooi_str, "OFF", 4);
            else if (strstr(msg->txt, " IN")) strncpy(oooi_str, "IN",  3);
            else if (strstr(msg->txt, " ON")) strncpy(oooi_str, "ON",  3);
        }

        /* Extract position from ACARS free text when ADS-C is absent.
         * Only attempt on labels known to carry current aircraft position
         * (not destination waypoints or flight plan coordinates). */
        int text_pos = 0;
        int wp_pos = 0;
        if (!adsc_pos && msg->txt && msg->txt[0]) {
            text_pos = acars_extract_text_position(msg->label, msg->txt,
                                                    &pos_lat, &pos_lon);
            if (!text_pos)
                wp_pos = acars_extract_waypoint_position(msg->label, msg->txt,
                                                          &pos_lat, &pos_lon);
        }

        /* Position source priority:
         *   1. ADS-C GPS (structured, highest confidence)
         *   2. Free text coordinates (aircraft-reported, label-gated)
         *   3. Waypoint name lookup (first/current fix from message)
         *   4. Beam cache estimate (~200 km accuracy) */
        int have_pos;
        if (adsc_pos) {
            have_pos = 1;
            stat_pos_adsc++;
            double bx, by;
            beam_cache_lookup(timestamp, &bx, &by, &pos_sat, &pos_beam);
        } else if (text_pos) {
            have_pos = 1;
            stat_pos_text++;
            adsc_pos = 1;
            double bx, by;
            beam_cache_lookup(timestamp, &bx, &by, &pos_sat, &pos_beam);
        } else if (wp_pos) {
            have_pos = 1;
            stat_pos_waypoint++;
            adsc_pos = 1;
            double bx, by;
            beam_cache_lookup(timestamp, &bx, &by, &pos_sat, &pos_beam);
        } else {
            have_pos = beam_cache_lookup(timestamp, &pos_lat, &pos_lon,
                                         &pos_sat, &pos_beam);
            if (have_pos) stat_pos_beam++;
        }

        if (have_pos) {
            const char *tail = msg->reg;
            while (*tail == '.') tail++;
            const char *flt = adsc_flt[0] ? adsc_flt :
                              (msg->flight_id[0] ? msg->flight_id : "");
            if (*tail) {
                web_map_add_aircraft(tail, flt, pos_lat, pos_lon,
                                     pos_sat, pos_beam, timestamp, frequency,
                                     adsc_alt, adsc_pos,
                                     oooi_str[0] ? oooi_str : NULL);
                if (basestation_enabled && (adsc_pos || basestation_beam)) {
                    basestation_send_position(tail, flt, pos_lat, pos_lon,
                                              adsc_alt, timestamp);
                    stat_bs_sent++;
                }
            }
        }
    }

    la_proto_tree_destroy(tree);
}

#else /* !HAVE_LIBACARS */

/* ================================================================
 * Fallback path -- basic ACARS field extraction (no ARINC-622)
 * Same dumpvdl2/dumphfdl JSON envelope, but ACARS fields are parsed
 * manually without libacars (no ARINC-622/ADS-C/CPDLC decoding).
 * ================================================================ */

/* ---- JSON string escaping (only needed in fallback path) ---- */

static void json_escape(const char *in, int inlen, char *out, int outsz)
{
    int o = 0;
    for (int i = 0; i < inlen && o < outsz - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = '"';
        } else if (c == '\\') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = '\\';
        } else if (c == '\n') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 'n';
        } else if (c == '\r') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 'r';
        } else if (c == '\t') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 't';
        } else if (c < 0x20 || c == 0x7f) {
            if (o + 6 >= outsz) break;
            o += snprintf(out + o, outsz - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* Fallback JSON: same dumpvdl2/dumphfdl envelope as the libacars path,
 * but ACARS fields are manually extracted (no ARINC-622 decoding).
 * Field names match libacars' la_acars_format_json output:
 *   err, crc_ok, more, reg, mode, label, blk_id, ack,
 *   flight, msg_num, msg_num_seq, sublabel, mfi, msg_text */
static void acars_output_json(const uint8_t *data, int len, int ul,
                               uint64_t timestamp, double frequency,
                               float magnitude, const uint8_t *hdr, int hdr_len)
{
    if (len < 13)
        return;

    char mode = (char)data[0];

    /* Registration: keep leading dots (libacars does) */
    char reg[8] = {0};
    memcpy(reg, data + 1, 7);
    reg[7] = '\0';

    char ack = (char)data[8];

    char label[4] = {0};
    label[0] = (char)data[9];
    label[1] = (char)data[10];
    if (data[9] == '_' && data[10] == 0x7f) label[1] = 'd';

    char blk_id = (char)data[11];

    const uint8_t *rest = data + 12;
    int rest_len = len - 12;

    int cont = 0;
    if (rest_len > 0) {
        if (rest[rest_len - 1] == 0x03) {
            rest_len--;
        } else if (rest[rest_len - 1] == 0x17) {
            cont = 1;
            rest_len--;
        }
    }

    /* Extract flight, msg_num, msg_num_seq for uplink blocks */
    char flight[8] = {0};
    char msg_num[4] = {0};
    char msg_num_seq = 0;
    const uint8_t *txt = NULL;
    int txt_len = 0;

    if (rest_len > 0 && rest[0] == 0x02) {
        if (ul && rest_len >= 11) {
            memcpy(msg_num, rest + 1, 3); msg_num[3] = '\0';
            msg_num_seq = (char)rest[4];
            memcpy(flight, rest + 5, 6); flight[6] = '\0';
            txt = rest + 11;
            txt_len = rest_len - 11;
        } else {
            txt = rest + 1;
            txt_len = rest_len - 1;
        }
    }

    /* Timestamp as unix sec/usec */
    double unix_time = ts_to_unix(timestamp);
    long tv_sec = (long)unix_time;
    long tv_usec = (long)((unix_time - (double)tv_sec) * 1000000.0);

    /* Escape text for JSON */
    char esc_text[2048];
    if (txt && txt_len > 0)
        json_escape((const char *)txt, txt_len, esc_text, sizeof(esc_text));
    else
        esc_text[0] = '\0';

    char esc_reg[64], esc_label[16], esc_flight[32], esc_msgnum[16];
    json_escape(reg, (int)strlen(reg), esc_reg, sizeof(esc_reg));
    json_escape(label, (int)strlen(label), esc_label, sizeof(esc_label));
    json_escape(flight, (int)strlen(flight), esc_flight, sizeof(esc_flight));
    json_escape(msg_num, (int)strlen(msg_num), esc_msgnum, sizeof(esc_msgnum));

    json_buf_reset();

    /* Iridium envelope (matches dumpvdl2 "vdl2" / dumphfdl "hfdl") */
    json_buf_append("{\"iridium\":{\"app\":{\"name\":\"iridium-sniffer\","
                    "\"ver\":\"1.0\"}");
    if (station)
        json_buf_append(",\"station\":\"%s\"", station);
    json_buf_append(",\"t\":{\"sec\":%ld,\"usec\":%ld}", tv_sec, tv_usec);
    json_buf_append(",\"freq\":%lld", (long long)(int64_t)frequency);
    json_buf_append(",\"sig_level\":%.2f", (double)magnitude);

    if (hdr && hdr_len > 0) {
        json_buf_append(",\"header\":\"");
        for (int i = 0; i < hdr_len; i++)
            json_buf_append("%02x", hdr[i]);
        json_buf_append("\"");
    }

    /* ACARS fields -- match libacars la_acars_format_json field names */
    json_buf_append(",\"acars\":{\"err\":false,\"crc_ok\":true");
    json_buf_append(",\"more\":%s", cont ? "true" : "false");
    json_buf_append(",\"reg\":\"%s\"", esc_reg);
    json_buf_append(",\"mode\":\"%c\"", mode);
    json_buf_append(",\"label\":\"%s\"", esc_label);
    json_buf_append(",\"blk_id\":\"%c\"", blk_id);
    json_buf_append(",\"ack\":\"%c\"", ack);

    if (ul && flight[0]) {
        json_buf_append(",\"flight\":\"%s\"", esc_flight);
        json_buf_append(",\"msg_num\":\"%s\"", esc_msgnum);
        if (msg_num_seq)
            json_buf_append(",\"msg_num_seq\":\"%c\"", msg_num_seq);
    }

    if (esc_text[0])
        json_buf_append(",\"msg_text\":\"%s\"", esc_text);

    json_buf_append("}}}");
    json_buf_emit();
}

static void acars_output_text(const uint8_t *data, int len, int ul,
                               uint64_t timestamp, double frequency,
                               float magnitude, const uint8_t *hdr, int hdr_len,
                               int errors)
{
    if (len < 13)
        return;

    char ts_buf[32];
    format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

    char mode = (char)data[0];

    char reg[8] = {0};
    int reg_start = 1;
    while (reg_start < 8 && data[reg_start] == '.')
        reg_start++;
    int rlen = 8 - reg_start;
    if (rlen > 0)
        memcpy(reg, data + reg_start, rlen);
    reg[rlen] = '\0';

    int is_nak = (data[8] == 0x15);
    char ack = (char)data[8];

    char label[4] = {0};
    if (data[9] == '_' && data[10] == 0x7f) {
        label[0] = '_'; label[1] = '?';
    } else {
        label[0] = (char)data[9];
        label[1] = (char)data[10];
    }

    char bid = (char)data[11];

    const uint8_t *rest = data + 12;
    int rest_len = len - 12;

    int cont = 0;
    if (rest_len > 0) {
        if (rest[rest_len - 1] == 0x03)
            rest_len--;
        else if (rest[rest_len - 1] == 0x17) {
            cont = 1;
            rest_len--;
        }
    }

    printf("ACARS: %s %s Mode:%c REG:%-7s ",
           ts_buf, ul ? "UL" : "DL", mode, reg);

    if (is_nak)
        printf("NAK  ");
    else
        printf("ACK:%c ", ack);

    printf("Label:%s bID:%c ", label, bid);

    if (rest_len > 0 && rest[0] == 0x02) {
        if (ul && rest_len >= 11) {
            printf("SEQ:%.4s FNO:%.6s ", rest + 1, rest + 5);
            if (rest_len > 11) {
                printf("[");
                for (int i = 11; i < rest_len; i++) {
                    char c = (char)rest[i];
                    if (c >= 0x20 && c < 0x7f)
                        putchar(c);
                    else
                        putchar('.');
                }
                printf("]");
            }
        } else {
            if (rest_len > 1) {
                printf("[");
                for (int i = 1; i < rest_len; i++) {
                    char c = (char)rest[i];
                    if (c >= 0x20 && c < 0x7f)
                        putchar(c);
                    else
                        putchar('.');
                }
                printf("]");
            }
        }
    }

    if (cont)
        printf(" CONT'd");

    if (errors > 0)
        printf(" ERRORS");

    printf("\n");
    fflush(stdout);
}

static void acars_parse_fallback(const uint8_t *data, int len, int ul,
                                  uint64_t timestamp, double frequency,
                                  float magnitude)
{
    if (len == 0 || data[0] != 0x01)
        return;

    if (len <= 2)
        return;

    data++;
    len--;

    uint8_t csum[2] = {0};
    int has_crc = 0;
    if (len >= 3 && data[len - 1] == 0x7f) {
        csum[0] = data[len - 3];
        csum[1] = data[len - 2];
        len -= 3;
        has_crc = 1;
    }

    const uint8_t *hdr = NULL;
    int hdr_len = 0;
    if (len > 0 && data[0] == 0x03) {
        if (len >= 8) {
            hdr = data;
            hdr_len = 8;
            data += 8;
            len -= 8;
        }
    }

    int crc_errors = 0;
    if (has_crc) {
        uint8_t crc_buf[SBD_MAX_DATA];
        int crc_len = len + 2;
        if (crc_len <= (int)sizeof(crc_buf)) {
            memcpy(crc_buf, data, len);
            crc_buf[len] = csum[0];
            crc_buf[len + 1] = csum[1];
            if (crc16_kermit(crc_buf, crc_len) != 0)
                crc_errors = 1;
        }
    } else {
        crc_errors = 1;
    }

    if (len < 13)
        return;

    uint8_t stripped[SBD_MAX_DATA];
    int parity_ok = 1;
    for (int i = 0; i < len; i++) {
        int bits = 0;
        uint8_t c = data[i];
        for (uint8_t b = c; b; b >>= 1)
            bits += b & 1;
        if ((bits % 2) == 0)
            parity_ok = 0;
        stripped[i] = c & 0x7F;
    }

    int errors = crc_errors + (!parity_ok);

    stat_acars_total++;
    if (errors > 0)
        stat_acars_errors++;

    if ((acars_json || udp_count > 0) && errors > 0)
        return;

    if (acars_json || udp_count > 0)
        acars_output_json(stripped, len, ul, timestamp, frequency, magnitude,
                          hdr, hdr_len);
    if (!acars_json)
        acars_output_text(stripped, len, ul, timestamp, frequency, magnitude,
                          hdr, hdr_len, errors);

    /* acarshub/airframes compat output (iridium-toolkit format) */
    if (feed_any_active() &&
        errors == 0) {
        char mode_str[2] = { (char)stripped[0], '\0' };

        /* Strip leading dots from registration */
        char reg[8] = {0};
        int rstart = 1;
        while (rstart < 8 && stripped[rstart] == '.')
            rstart++;
        int rlen = 8 - rstart;
        if (rlen > 0) memcpy(reg, stripped + rstart, rlen);
        reg[rlen] = '\0';

        char ack_c = (char)stripped[8];
        char label[3] = { (char)stripped[9], (char)stripped[10], '\0' };
        if (stripped[9] == '_' && stripped[10] == 0x7f) label[1] = 'd';
        char bid = (char)stripped[11];

        const uint8_t *rest = stripped + 12;
        int rest_len = len - 12;

        int cont = 0;
        if (rest_len > 0) {
            if (rest[rest_len - 1] == 0x03)
                rest_len--;
            else if (rest[rest_len - 1] == 0x17) {
                cont = 1;
                rest_len--;
            }
        }
        int block_end = !cont;

        char flight[8] = {0};
        char msg_num[4] = {0};
        char msg_num_seq = 0;
        const char *txt = NULL;
        int txt_len = 0;

        if (rest_len > 0 && rest[0] == 0x02) {
            if (ul && rest_len >= 11) {
                memcpy(msg_num, rest + 1, 3); msg_num[3] = '\0';
                msg_num_seq = (char)rest[4];
                memcpy(flight, rest + 5, 6); flight[6] = '\0';
                txt = (const char *)(rest + 11);
                txt_len = rest_len - 11;
            } else {
                txt = (const char *)(rest + 1);
                txt_len = rest_len - 1;
            }
        }

        hub_emit_acars(mode_str, reg, ack_c, label, bid, block_end,
                       ul, txt, txt_len, flight, msg_num, msg_num_seq,
                       errors, timestamp, frequency, magnitude,
                       hdr, hdr_len);

        /* Web map ACARS feed sidebar (filter heartbeats + empty text) */
        if (web_enabled && reg[0] && txt && txt_len > 0) {
            int is_heartbeat = (label[0] == '_' && label[1] == 'd');
            if (!is_heartbeat) {
                char txt_z[256];
                int zlen = txt_len < (int)sizeof(txt_z) - 1 ?
                           txt_len : (int)sizeof(txt_z) - 1;
                memcpy(txt_z, txt, zlen);
                txt_z[zlen] = '\0';
                web_map_add_acars_message(reg, flight, label, txt_z,
                                           ul, timestamp);
            }
        }
    }

    /* Aircraft position (requires --web, no errors) */
    if (web_enabled && errors == 0 && len >= 13) {
        /* Extract registration (strip leading dots) */
        char reg_f[8] = {0};
        int rstart = 1;
        while (rstart < 8 && stripped[rstart] == '.')
            rstart++;
        int rlen = 8 - rstart;
        if (rlen > 0) {
            memcpy(reg_f, stripped + rstart, rlen);
            reg_f[rlen] = '\0';
        }
        if (reg_f[0]) {
            char label_f[3] = { (char)stripped[9], (char)stripped[10], '\0' };

            /* Extract text body for position parsing */
            const uint8_t *rest_f = stripped + 12;
            int rest_f_len = len - 12;
            if (rest_f_len > 0 && (rest_f[rest_f_len-1] == 0x03 ||
                                    rest_f[rest_f_len-1] == 0x17))
                rest_f_len--;
            const char *txt_f = NULL;
            int txt_f_len = 0;
            if (rest_f_len > 0 && rest_f[0] == 0x02) {
                if (ul && rest_f_len >= 11) {
                    txt_f = (const char *)(rest_f + 11);
                    txt_f_len = rest_f_len - 11;
                } else {
                    txt_f = (const char *)(rest_f + 1);
                    txt_f_len = rest_f_len - 1;
                }
            }

            /* Try free text position extraction, then waypoint fallback */
            double pos_lat = 0, pos_lon = 0;
            int have_text_pos = 0;
            if (txt_f && txt_f_len > 0) {
                char txt_z[2048];
                int zlen = txt_f_len < (int)sizeof(txt_z) - 1 ?
                           txt_f_len : (int)sizeof(txt_z) - 1;
                memcpy(txt_z, txt_f, zlen);
                txt_z[zlen] = '\0';
                have_text_pos = acars_extract_text_position(label_f, txt_z,
                                                             &pos_lat, &pos_lon);
                if (!have_text_pos)
                    have_text_pos = acars_extract_waypoint_position(
                                        label_f, txt_z, &pos_lat, &pos_lon);
            }

            int bc_sat = 0, bc_beam = 0;
            if (have_text_pos) {
                stat_pos_text++;
                double bx, by;
                beam_cache_lookup(timestamp, &bx, &by, &bc_sat, &bc_beam);
                web_map_add_aircraft(reg_f, "", pos_lat, pos_lon,
                                     bc_sat, bc_beam, timestamp, frequency,
                                     -99999, 1, NULL);
                if (basestation_enabled) {
                    basestation_send_position(reg_f, "", pos_lat, pos_lon,
                                              -99999, timestamp);
                    stat_bs_sent++;
                }
            } else {
                double bc_lat, bc_lon;
                if (beam_cache_lookup(timestamp, &bc_lat, &bc_lon,
                                      &bc_sat, &bc_beam)) {
                    stat_pos_beam++;
                    web_map_add_aircraft(reg_f, "", bc_lat, bc_lon,
                                         bc_sat, bc_beam, timestamp, frequency,
                                         -99999, 0, NULL);
                    /* Beam estimates only sent if --basestation-beam */
                    if (basestation_enabled && basestation_beam)
                        basestation_send_position(reg_f, "", bc_lat, bc_lon,
                                                  -99999, timestamp);
                }
            }
        }
    }
}

#endif /* !HAVE_LIBACARS */

/* ---- SBD extraction ---- */

static void sbd_output_raw(const uint8_t *data, int len, int ul,
                            uint64_t timestamp, double frequency)
{
    if (acars_enabled)
        return;

    char ts_buf[32];
    format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

    printf("SBD: %s %s ", ts_buf, ul ? "UL" : "DL");
    for (int i = 0; i < len && i < 64; i++)
        printf("%02x", data[i]);
    if (len > 64)
        printf("...");
    printf(" | ");
    for (int i = 0; i < len && i < 64; i++) {
        char c = (char)data[i];
        printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    printf("\n");
    fflush(stdout);
}

static void sbd_process(const uint8_t *sbd_data, int sbd_len, int ul,
                         uint64_t timestamp, double frequency,
                         float magnitude)
{
    /* Try ACARS first (marker byte 0x01) */
    if (sbd_len > 2 && sbd_data[0] == 0x01) {
#ifdef HAVE_LIBACARS
        acars_parse_libacars(sbd_data, sbd_len, ul, timestamp,
                             frequency, magnitude);
#else
        acars_parse_fallback(sbd_data, sbd_len, ul, timestamp,
                             frequency, magnitude);
#endif
        return;
    }

    /* Non-ACARS SBD: show raw in text mode */
    if (sbd_len > 0)
        sbd_output_raw(sbd_data, sbd_len, ul, timestamp, frequency);
}

static void sbd_expire(uint64_t now_ns)
{
    for (int i = 0; i < SBD_MAX_MULTI; i++) {
        if (sbd_multi[i].active &&
            now_ns > sbd_multi[i].timestamp + SBD_TIMEOUT_NS) {
            sbd_multi[i].active = 0;
        }
    }
}

static void sbd_extract(const uint8_t *data, int len, int ul,
                          uint64_t timestamp, double frequency,
                          float magnitude)
{
    if (len < 5)
        return;

    /* Check for SBD markers */
    int is_sbd = 0;
    if (data[0] == 0x76 && data[1] != 5) {
        if (ul) {
            if (data[1] >= 0x0c && data[1] <= 0x0e)
                is_sbd = 1;
        } else {
            if (data[1] >= 0x08 && data[1] <= 0x0b)
                is_sbd = 1;
        }
    } else if (data[0] == 0x06 && data[1] == 0x00) {
        if (data[2] == 0x00 || data[2] == 0x10 || data[2] == 0x20 ||
            data[2] == 0x40 || data[2] == 0x50 || data[2] == 0x70)
            is_sbd = 1;
    }

    if (!is_sbd)
        return;

    stat_sbd_total++;

    uint8_t typ0 = data[0];
    uint8_t typ1 = data[1];
    data += 2;
    len -= 2;

    int msgno = 0;
    int msgcnt = 0;
    const uint8_t *sbd_data = NULL;
    int sbd_len = 0;

    if (typ0 == 0x06 && typ1 == 0x00) {
        if (len < 30 || data[0] != 0x20)
            return;

        msgcnt = data[15];
        msgno = (msgcnt == 0) ? 0 : 1;
        sbd_data = data + 29;
        sbd_len = len - 29;
    } else {
        if (typ1 == 0x08) {
            if (len < 5)
                return;
            int prehdr_len;
            if (data[0] == 0x26)
                prehdr_len = 7;
            else if (data[0] == 0x20)
                prehdr_len = 5;
            else
                prehdr_len = 7;

            if (len < prehdr_len)
                return;

            msgcnt = data[3];
            data += prehdr_len;
            len -= prehdr_len;
        } else {
            msgcnt = -1;
        }

        if (ul && len >= 3 && (data[0] == 0x50 || data[0] == 0x51)) {
            data += 3;
            len -= 3;
        }

        if (len == 0) {
            msgno = 0;
            sbd_data = data;
            sbd_len = 0;
        } else if (len > 3 && data[0] == 0x10) {
            int pkt_len = data[1];
            msgno = data[2];
            data += 3;
            len -= 3;

            if (len < pkt_len)
                return;
            if (len > pkt_len)
                len = pkt_len;

            sbd_data = data;
            sbd_len = len;
        } else {
            msgno = 0;
            sbd_data = data;
            sbd_len = len;
        }
    }

    sbd_expire(timestamp);

    if (msgno == 0) {
        stat_sbd_short++;
        if (sbd_len > 0)
            sbd_process(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
    } else if (msgcnt == 1 && msgno == 1) {
        stat_sbd_single++;
        sbd_process(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
    } else if (msgcnt > 1) {
        int idx = -1;
        for (int i = 0; i < SBD_MAX_MULTI; i++) {
            if (!sbd_multi[i].active) { idx = i; break; }
        }
        if (idx < 0) {
            uint64_t oldest = UINT64_MAX;
            for (int i = 0; i < SBD_MAX_MULTI; i++) {
                if (sbd_multi[i].timestamp < oldest) {
                    oldest = sbd_multi[i].timestamp;
                    idx = i;
                }
            }
        }
        if (idx < 0) idx = 0;

        sbd_multi_t *s = &sbd_multi[idx];
        s->active = 1;
        s->msgno = msgno;
        s->msgcnt = msgcnt;
        s->ul = ul;
        s->timestamp = timestamp;
        s->frequency = frequency;
        s->magnitude = magnitude;
        s->data_len = (sbd_len > (int)sizeof(s->data)) ?
                      (int)sizeof(s->data) : sbd_len;
        memcpy(s->data, sbd_data, s->data_len);
    } else if (msgno > 1) {
        for (int i = SBD_MAX_MULTI - 1; i >= 0; i--) {
            sbd_multi_t *s = &sbd_multi[i];
            if (!s->active) continue;
            if (s->ul != ul) continue;
            if (msgno != s->msgno + 1) continue;

            int space = (int)sizeof(s->data) - s->data_len;
            int copy = (sbd_len > space) ? space : sbd_len;
            if (copy > 0) {
                memcpy(s->data + s->data_len, sbd_data, copy);
                s->data_len += copy;
            }
            s->msgno = msgno;
            s->timestamp = timestamp;

            stat_sbd_multi_frag++;
            if (msgno == s->msgcnt) {
                stat_sbd_multi_ok++;
                sbd_process(s->data, s->data_len, ul, timestamp,
                            s->frequency, s->magnitude);
                s->active = 0;
            }
            return;
        }
        stat_sbd_broken++;
    }
}

/* ---- Public API ---- */

void acars_init(const char *station_id, const char **udp_hosts,
                const int *udp_ports, int n_udp,
                const char **f_hosts, const int *f_ports,
                const int *f_tcp, int nf)
{
    station = station_id;
    memset(sbd_multi, 0, sizeof(sbd_multi));
    if (!crc_initialized)
        crc16_init();

    /* UDP JSON streaming endpoints (dumpvdl2 format) */
    udp_count = 0;
    for (int i = 0; i < n_udp && i < UDP_MAX; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            perror("acars_init: UDP socket");
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(udp_ports[i]);
        if (resolve_host_ipv4(udp_hosts[i], &addr.sin_addr) < 0) {
            fprintf(stderr, "acars_init: cannot resolve UDP host '%s'\n",
                    udp_hosts[i]);
            close(fd);
            continue;
        }
        udp_fds[udp_count] = fd;
        udp_addrs[udp_count] = addr;
        udp_count++;
        fprintf(stderr, "ACARS: UDP JSON stream -> %s:%d\n",
                udp_hosts[i], udp_ports[i]);
    }

    /* Aggregator feed endpoints (iridium-toolkit format, mixed UDP/TCP) */
    n_feeds = 0;
    for (int i = 0; i < nf && i < FEED_MAX; i++) {
        feed_ep_t *f = &feeds[n_feeds];
        memset(f, 0, sizeof(*f));
        f->fd = -1;
        f->is_tcp = f_tcp[i];

        if (!f->is_tcp) {
            /* UDP feed */
            f->fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (f->fd < 0) {
                perror("acars_init: feed UDP socket");
                continue;
            }
            memset(&f->udp_addr, 0, sizeof(f->udp_addr));
            f->udp_addr.sin_family = AF_INET;
            f->udp_addr.sin_port = htons(f_ports[i]);
            if (resolve_host_ipv4(f_hosts[i], &f->udp_addr.sin_addr) < 0) {
                fprintf(stderr, "acars_init: cannot resolve feed host '%s'\n",
                        f_hosts[i]);
                close(f->fd);
                f->fd = -1;
                continue;
            }
            fprintf(stderr, "ACARS: feed UDP -> %s:%d\n",
                    f_hosts[i], f_ports[i]);
        } else {
            /* TCP feed */
            f->tcp_host = strdup(f_hosts[i]);
            f->tcp_port = f_ports[i];
            f->fd = feed_tcp_connect(f_hosts[i], f_ports[i]);
            if (f->fd >= 0)
                fprintf(stderr, "ACARS: feed TCP -> %s:%d\n",
                        f_hosts[i], f_ports[i]);
            else
                fprintf(stderr, "ACARS: feed TCP %s:%d connect failed "
                        "(will retry on first message)\n",
                        f_hosts[i], f_ports[i]);
        }
        n_feeds++;
    }

#ifdef HAVE_LIBACARS
    la_config_set_int("acars_bearer", LA_ACARS_BEARER_SATCOM);
    reasm_ctx = la_reasm_ctx_new();
    fprintf(stderr, "ACARS: libacars %s (ARINC-622/ADS-C/CPDLC decoding)\n",
            LA_VERSION);
#endif
}

void acars_shutdown(void)
{
    for (int i = 0; i < udp_count; i++) {
        if (udp_fds[i] >= 0) {
            close(udp_fds[i]);
            udp_fds[i] = -1;
        }
    }
    udp_count = 0;
    for (int i = 0; i < n_feeds; i++) {
        if (feeds[i].fd >= 0) {
            close(feeds[i].fd);
            feeds[i].fd = -1;
        }
        free(feeds[i].tcp_host);
        feeds[i].tcp_host = NULL;
    }
    n_feeds = 0;
#ifdef HAVE_LIBACARS
    if (reasm_ctx) {
        la_reasm_ctx_destroy(reasm_ctx);
        reasm_ctx = NULL;
    }
    la_config_destroy();
#endif
}

void acars_ida_cb(const uint8_t *data, int len,
                  uint64_t timestamp, double frequency,
                  ir_direction_t direction, float magnitude,
                  void *user)
{
    (void)user;
    stat_ida_total++;
    int ul = (direction == DIR_UPLINK) ? 1 : 0;
    sbd_extract(data, len, ul, timestamp, frequency, magnitude);
}

void acars_print_stats(void)
{
    fprintf(stderr, "SBD: %d packets from %d IDA messages "
            "(%d short, %d single, %d multi-pkt)\n",
            stat_sbd_total, stat_ida_total,
            stat_sbd_short, stat_sbd_single, stat_sbd_multi_ok);
    if (stat_sbd_multi_frag > 0 || stat_sbd_broken > 0)
        fprintf(stderr, "SBD: %d multi-pkt fragments, %d broken/orphan\n",
                stat_sbd_multi_frag, stat_sbd_broken);
    fprintf(stderr, "ACARS: %d messages decoded", stat_acars_total);
    if (stat_acars_errors > 0)
        fprintf(stderr, " (%d with errors)", stat_acars_errors);
    fprintf(stderr, "\n");
    if (stat_pos_adsc || stat_pos_text || stat_pos_waypoint || stat_pos_beam)
        fprintf(stderr, "Positions: %d ADS-C, %d text, %d waypoint, %d beam\n",
                stat_pos_adsc, stat_pos_text, stat_pos_waypoint, stat_pos_beam);
    if (stat_bs_sent > 0)
        fprintf(stderr, "BaseStation: %d positions sent\n", stat_bs_sent);
}
