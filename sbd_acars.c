/*
 * SBD/ACARS reassembly from IDA messages
 *
 * Extracts SBD (Short Burst Data) packets from reassembled IDA payloads,
 * handles multi-packet SBD reassembly, and parses ACARS messages.
 *
 * Protocol details derived from iridium-toolkit reassembler/sbd.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sbd_acars.h"

/* ---- Configuration ---- */

int acars_json = 0;
static const char *station = NULL;

/* ---- Timestamp handling ---- */

static struct timespec wall_t0;
static uint64_t first_ts_ns = 0;
static int ts_initialized = 0;

static void format_timestamp(uint64_t ts_ns, char *buf, int bufsz)
{
    if (!ts_initialized) {
        clock_gettime(CLOCK_REALTIME, &wall_t0);
        first_ts_ns = ts_ns;
        ts_initialized = 1;
    }

    double elapsed = (double)(ts_ns - first_ts_ns) / 1e9;
    time_t wall_sec = wall_t0.tv_sec + (time_t)elapsed;
    struct tm tm;
    gmtime_r(&wall_sec, &tm);
    strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
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

static uint16_t crc16_kermit(const uint8_t *data, int len)
{
    uint16_t crc = 0;
    for (int i = 0; i < len; i++)
        crc = crc16_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc;
}

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

/* ---- ACARS output ---- */

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

static void acars_output_json(const uint8_t *data, int len, int ul,
                               uint64_t timestamp, double frequency,
                               float magnitude, const uint8_t *hdr, int hdr_len)
{
    /* ACARS fields (already parity-stripped) */
    if (len < 13)
        return;

    char mode[4] = {0};
    mode[0] = (char)data[0];

    /* Registration: bytes 1-7, strip leading dots */
    char reg[8] = {0};
    int reg_start = 1;
    while (reg_start < 8 && data[reg_start] == '.')
        reg_start++;
    int rlen = 8 - reg_start;
    if (rlen > 0)
        memcpy(reg, data + reg_start, rlen);
    reg[rlen] = '\0';

    char ack[4] = {0};
    if (data[8] == 0x15)
        ack[0] = '!';
    else
        ack[0] = (char)data[8];

    char label[4] = {0};
    label[0] = (char)data[9];
    label[1] = (char)data[10];
    /* Replace _DEL with _d (iridium-toolkit convention) */
    if (data[9] == '_' && data[10] == 0x7f) {
        label[0] = '_'; label[1] = 'd';
    }

    char block_id[4] = {0};
    block_id[0] = (char)data[11];

    const uint8_t *rest = data + 12;
    int rest_len = len - 12;

    int cont = 0;
    if (rest_len > 0) {
        if (rest[rest_len - 1] == 0x03) {
            rest_len--;  /* ETX */
        } else if (rest[rest_len - 1] == 0x17) {
            cont = 1;
            rest_len--;  /* ETB */
        }
    }

    /* Extract sequence, flight, text based on STX marker */
    char seq[8] = {0};
    char flight[8] = {0};
    const uint8_t *txt = NULL;
    int txt_len = 0;

    if (rest_len > 0 && rest[0] == 0x02) {
        if (ul) {
            /* Uplink: seq(4) + flight(6) + text */
            if (rest_len >= 11) {
                memcpy(seq, rest + 1, 4); seq[4] = '\0';
                memcpy(flight, rest + 5, 6); flight[6] = '\0';
                txt = rest + 11;
                txt_len = rest_len - 11;
            } else {
                txt = rest + 1;
                txt_len = rest_len - 1;
            }
        } else {
            /* Downlink: text */
            txt = rest + 1;
            txt_len = rest_len - 1;
        }
    }

    char ts_buf[32];
    format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

    /* Escaped strings for JSON */
    char esc_reg[64], esc_mode[16], esc_label[16], esc_bid[16];
    char esc_ack[16], esc_seq[32], esc_flight[32], esc_text[2048];
    char esc_hdr[64];

    json_escape(mode, (int)strlen(mode), esc_mode, sizeof(esc_mode));
    json_escape(reg, (int)strlen(reg), esc_reg, sizeof(esc_reg));
    json_escape(ack, (int)strlen(ack), esc_ack, sizeof(esc_ack));
    json_escape(label, (int)strlen(label), esc_label, sizeof(esc_label));
    json_escape(block_id, (int)strlen(block_id), esc_bid, sizeof(esc_bid));
    json_escape(seq, (int)strlen(seq), esc_seq, sizeof(esc_seq));
    json_escape(flight, (int)strlen(flight), esc_flight, sizeof(esc_flight));
    if (txt && txt_len > 0)
        json_escape((const char *)txt, txt_len, esc_text, sizeof(esc_text));
    else
        esc_text[0] = '\0';

    /* Header hex string */
    esc_hdr[0] = '\0';
    if (hdr && hdr_len > 0) {
        int pos = 0;
        for (int i = 0; i < hdr_len && pos < (int)sizeof(esc_hdr) - 3; i++)
            pos += snprintf(esc_hdr + pos, sizeof(esc_hdr) - pos, "%02x", hdr[i]);
    }

    /* Build JSON -- match iridium-toolkit format */
    printf("{\"app\":{\"name\":\"iridium-sniffer\",\"version\":\"1.0\"},"
           "\"source\":{\"transport\":\"iridium\",\"protocol\":\"acars\"");
    if (station)
        printf(",\"station_id\":\"%s\"", station);
    printf("},\"acars\":{\"timestamp\":\"%s\","
           "\"errors\":0,"
           "\"link_direction\":\"%s\","
           "\"block_end\":%s,"
           "\"mode\":\"%s\","
           "\"tail\":\"%s\"",
           ts_buf,
           ul ? "uplink" : "downlink",
           cont ? "false" : "true",
           esc_mode,
           esc_reg);
    if (ack[0])
        printf(",\"ack\":\"%s\"", esc_ack);
    printf(",\"label\":\"%s\",\"block_id\":\"%s\"",
           esc_label, esc_bid);
    if (ul && seq[0])
        printf(",\"message_number\":\"%s\"", esc_seq);
    if (ul && flight[0])
        printf(",\"flight\":\"%s\"", esc_flight);
    if (esc_text[0])
        printf(",\"text\":\"%s\"", esc_text);
    printf("},\"freq\":%.0f,\"level\":%.2f,\"header\":\"%s\"}\n",
           frequency, magnitude, esc_hdr);
    fflush(stdout);
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

    /* Registration */
    char reg[8] = {0};
    int reg_start = 1;
    while (reg_start < 8 && data[reg_start] == '.')
        reg_start++;
    int rlen = 8 - reg_start;
    if (rlen > 0)
        memcpy(reg, data + reg_start, rlen);
    reg[rlen] = '\0';

    /* Ack */
    int is_nak = (data[8] == 0x15);
    char ack = (char)data[8];

    /* Label */
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

/* ---- ACARS parsing ---- */

static void acars_parse(const uint8_t *data, int len, int ul,
                         uint64_t timestamp, double frequency,
                         float magnitude)
{
    if (len == 0 || data[0] != 0x01)
        return;

    if (len <= 2)
        return;

    /* Strip ACARS marker */
    data++;
    len--;

    /* Check for CRC suffix: last byte == 0x7F */
    uint8_t csum[2] = {0};
    int has_crc = 0;
    if (len >= 3 && data[len - 1] == 0x7f) {
        csum[0] = data[len - 3];
        csum[1] = data[len - 2];
        len -= 3;
        has_crc = 1;
    }

    /* Check for unknown header (0x03 prefix) */
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

    /* CRC verification */
    int crc_errors = 0;
    if (has_crc) {
        /* CRC is computed over data + csum bytes */
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

    /* Strip parity bit 7, verify odd parity */
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

    /* Skip messages with errors unless we're doing text output (show everything) */
    if (acars_json && errors > 0)
        return;

    if (acars_json)
        acars_output_json(stripped, len, ul, timestamp, frequency, magnitude,
                          hdr, hdr_len);
    else
        acars_output_text(stripped, len, ul, timestamp, frequency, magnitude,
                          hdr, hdr_len, errors);
}

/* ---- SBD extraction ---- */

static void sbd_process(const uint8_t *sbd_data, int sbd_len, int ul,
                         uint64_t timestamp, double frequency,
                         float magnitude)
{
    acars_parse(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
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

    uint8_t typ0 = data[0];
    uint8_t typ1 = data[1];
    data += 2;
    len -= 2;

    int msgno = 0;
    int msgcnt = 0;
    const uint8_t *sbd_data = NULL;
    int sbd_len = 0;

    if (typ0 == 0x06 && typ1 == 0x00) {
        /* Hello/SBD packet */
        if (len < 30 || data[0] != 0x20)
            return;

        /* 29-byte prehdr, msgcnt at offset 15 */
        msgcnt = data[15];
        msgno = (msgcnt == 0) ? 0 : 1;
        sbd_data = data + 29;
        sbd_len = len - 29;
    } else {
        /* 76xx data packet */
        if (typ1 == 0x08) {
            /* Downlink data: variable prehdr */
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
            /* Other 76xx types: no prehdr */
            msgcnt = -1;
        }

        /* Uplink ack/nack marker */
        if (ul && len >= 3 && (data[0] == 0x50 || data[0] == 0x51)) {
            data += 3;
            len -= 3;
        }

        /* Data header: 0x10 len msgno */
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

    /* Expire old multi-packet slots */
    sbd_expire(timestamp);

    if (msgno == 0) {
        /* Short/mboxcheck message */
        if (sbd_len > 0)
            sbd_process(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
    } else if (msgcnt == 1 && msgno == 1) {
        /* Single complete message */
        sbd_process(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
    } else if (msgcnt > 1) {
        /* First packet of multi-packet message -- store */
        int idx = -1;
        for (int i = 0; i < SBD_MAX_MULTI; i++) {
            if (!sbd_multi[i].active) { idx = i; break; }
        }
        if (idx < 0) {
            /* Evict oldest */
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
        s->data_len = (sbd_len > (int)sizeof(s->data)) ? (int)sizeof(s->data) : sbd_len;
        memcpy(s->data, sbd_data, s->data_len);
    } else if (msgno > 1) {
        /* Continuation packet -- find matching slot */
        for (int i = SBD_MAX_MULTI - 1; i >= 0; i--) {
            sbd_multi_t *s = &sbd_multi[i];
            if (!s->active) continue;
            if (s->ul != ul) continue;
            if (msgno != s->msgno + 1) continue;

            /* Append data */
            int space = (int)sizeof(s->data) - s->data_len;
            int copy = (sbd_len > space) ? space : sbd_len;
            if (copy > 0) {
                memcpy(s->data + s->data_len, sbd_data, copy);
                s->data_len += copy;
            }
            s->msgno = msgno;
            s->timestamp = timestamp;

            if (msgno == s->msgcnt) {
                /* Complete -- process and free slot */
                sbd_process(s->data, s->data_len, ul, timestamp,
                            s->frequency, s->magnitude);
                s->active = 0;
            }
            return;
        }
        /* No matching slot -- orphan fragment, discard */
    }
}

/* ---- Public API ---- */

void acars_init(const char *station_id)
{
    station = station_id;
    memset(sbd_multi, 0, sizeof(sbd_multi));
    if (!crc_initialized)
        crc16_init();
}

void acars_ida_cb(const uint8_t *data, int len,
                  uint64_t timestamp, double frequency,
                  ir_direction_t direction, float magnitude,
                  void *user)
{
    (void)user;
    int ul = (direction == DIR_UPLINK) ? 1 : 0;
    sbd_extract(data, len, ul, timestamp, frequency, magnitude);
}
