/*
 * IDA (Iridium Data) frame decoder
 *
 * Detects IDA frames via LCW (Link Control Word) extraction,
 * descrambles payload using 124-bit block de-interleaving,
 * BCH decodes with poly=3545, verifies CRC-CCITT, and
 * reassembles multi-burst packets.
 *
 * Reference: iridium-toolkit bitsparser.py + ida.py (muccc)
 */

#include <math.h>
#include <string.h>
#include <stdio.h>

#include "ida_decode.h"
#include "frame_decode.h"

/* BCH polynomial for IDA/ACCH payload blocks */
#define BCH_POLY_DA    3545     /* BCH(31,20) t=2 */
#define BCH_DA_SYN     11      /* syndrome bits (bit_length(3545)-1) */
#define BCH_DA_DATA    20      /* 31 - 11 = 20 data bits per block */
#define BCH_DA_TABLE   2048    /* 2^11 */

/* BCH polynomials for LCW components */
#define BCH_POLY_LCW1  29      /* 7-bit, 4-bit syndrome */
#define BCH_POLY_LCW2  465     /* 14-bit input (13+pad), 8-bit syndrome */
#define BCH_POLY_LCW3  41      /* 26-bit, 5-bit syndrome */

/* Syndrome tables */
static struct { int errs; uint32_t locator; } syn_da[BCH_DA_TABLE];
static struct { int errs; uint32_t locator; } syn_lcw1[16];
static struct { int errs; uint32_t locator; } syn_lcw2[256];
static struct { int errs; uint32_t locator; } syn_lcw3[32];

/* Access codes (same as frame_decode.c) */
static const uint8_t access_dl[24] = {
    0,0,1,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,1,0,0,1,1
};
static const uint8_t access_ul[24] = {
    1,1,0,0,1,1,0,0,0,0,1,1,1,1,0,0,1,1,1,1,1,1,0,0
};

/* LCW de-interleave permutation table (1-indexed, from iridium-toolkit) */
static const int lcw_perm[46] = {
    40, 39, 36, 35, 32, 31, 28, 27, 24, 23,
    20, 19, 16, 15, 12, 11,  8,  7,  4,  3,
    41, 38, 37, 34, 33, 30, 29, 26, 25, 22,
    21, 18, 17, 14, 13, 10,  9,  6,  5,  2,
     1, 46, 45, 44, 43, 42
};

/* ---- Build syndrome tables ---- */

static void build_syn(uint32_t poly, int nbits, int max_errors,
                      void *table, int table_size)
{
    struct { int errs; uint32_t locator; } *syn = table;

    for (int i = 0; i < table_size; i++) {
        syn[i].errs = -1;
        syn[i].locator = 0;
    }

    for (int b = 0; b < nbits; b++) {
        uint32_t r = gf2_remainder(poly, 1u << b);
        if (r < (uint32_t)table_size) {
            syn[r].errs = 1;
            syn[r].locator = 1u << b;
        }
    }

    if (max_errors >= 2) {
        for (int b1 = 0; b1 < nbits; b1++) {
            for (int b2 = b1 + 1; b2 < nbits; b2++) {
                uint32_t val = (1u << b1) | (1u << b2);
                uint32_t r = gf2_remainder(poly, val);
                if (r < (uint32_t)table_size && syn[r].errs < 0) {
                    syn[r].errs = 2;
                    syn[r].locator = val;
                }
            }
        }
    }
}

void ida_decode_init(void)
{
    build_syn(BCH_POLY_DA, 31, 2, syn_da, BCH_DA_TABLE);
    build_syn(BCH_POLY_LCW1, 7, 1, syn_lcw1, 16);
    build_syn(BCH_POLY_LCW2, 14, 1, syn_lcw2, 256);
    build_syn(BCH_POLY_LCW3, 26, 2, syn_lcw3, 32);
}

/* ---- LCW extraction ---- */

static int decode_lcw(const uint8_t *data, int data_len, lcw_t *lcw)
{
    if (data_len < 46)
        return 0;

    /* Apply pair-swap (symbol_reverse) to LCW bits.
     * iridium-toolkit applies symbol_reverse globally, and the LCW
     * permutation table expects swapped input. Since we don't pre-swap,
     * we swap here before applying the permutation. */
    uint8_t swapped[46];
    for (int i = 0; i < 46; i += 2) {
        swapped[i]     = data[i + 1];
        swapped[i + 1] = data[i];
    }

    /* Apply permutation table (1-indexed) */
    uint8_t lcw_bits[46];
    for (int i = 0; i < 46; i++)
        lcw_bits[i] = swapped[lcw_perm[i] - 1];

    /* lcw1: bits 0-6, BCH(7,3), poly=29 */
    uint32_t v1 = bits_to_uint(lcw_bits, 7);
    uint32_t s1 = gf2_remainder(BCH_POLY_LCW1, v1);
    if (s1 != 0) {
        if (s1 >= 16 || syn_lcw1[s1].errs < 0) return 0;
        v1 ^= syn_lcw1[s1].locator;
    }
    int ft = (int)(v1 >> 4) & 0x7;  /* top 3 data bits */

    /* lcw2: bits 7-19 + padding zero = 14 bits, poly=465 */
    uint32_t v2 = (bits_to_uint(lcw_bits + 7, 13) << 1);  /* 13 bits + trailing 0 */
    uint32_t s2 = gf2_remainder(BCH_POLY_LCW2, v2);
    if (s2 != 0) {
        if (s2 >= 256 || syn_lcw2[s2].errs < 0) return 0;
        v2 ^= syn_lcw2[s2].locator;
    }

    /* lcw3: bits 20-45, 26 bits, poly=41 */
    uint32_t v3 = bits_to_uint(lcw_bits + 20, 26);
    uint32_t s3 = gf2_remainder(BCH_POLY_LCW3, v3);
    if (s3 != 0) {
        if (s3 >= 32 || syn_lcw3[s3].errs < 0) return 0;
        v3 ^= syn_lcw3[s3].locator;
    }

    lcw->ft = ft;
    lcw->lcw_ok = 1;
    return 1;
}

/* ---- Generalized 2-way de-interleave ----
 * n_sym symbols (2*n_sym input bits) → 2 output arrays of n_sym bits each.
 * No pair-swap (cancelled by not pre-applying symbol_reverse). */

static void de_interleave_n(const uint8_t *in, int n_sym,
                             uint8_t *out1, uint8_t *out2)
{
    int p = 0;
    for (int s = n_sym - 1; s >= 1; s -= 2) {
        out1[p++] = in[2 * s];
        out1[p++] = in[2 * s + 1];
    }
    p = 0;
    for (int s = n_sym - 2; s >= 0; s -= 2) {
        out2[p++] = in[2 * s];
        out2[p++] = in[2 * s + 1];
    }
}

/* ---- IDA payload descramble + BCH decode ---- */

static int descramble_payload(const uint8_t *data, int data_len,
                               uint8_t *bch_stream, int max_bch)
{
    int bch_len = 0;

    /* Process full 124-bit blocks */
    int n_full = data_len / 124;
    int remain = data_len % 124;

    for (int blk = 0; blk < n_full; blk++) {
        const uint8_t *block = data + blk * 124;

        /* De-interleave 62 symbols → 2 × 62 bits */
        uint8_t half1[62], half2[62];
        de_interleave_n(block, 62, half1, half2);

        /* Concatenate → 124 bits, split into 4 × 31 bits */
        uint8_t combined[124];
        memcpy(combined, half1, 62);
        memcpy(combined + 62, half2, 62);

        uint8_t chunks[4][31];
        memcpy(chunks[0], combined +  0, 31);
        memcpy(chunks[1], combined + 31, 31);
        memcpy(chunks[2], combined + 62, 31);
        memcpy(chunks[3], combined + 93, 31);

        /* Reorder: b4, b2, b3, b1 → chunks[3], chunks[1], chunks[2], chunks[0] */
        int order[4] = {3, 1, 2, 0};

        for (int c = 0; c < 4; c++) {
            if (bch_len + BCH_DA_DATA > max_bch) break;

            uint32_t val = bits_to_uint(chunks[order[c]], 31);
            uint32_t syn = gf2_remainder(BCH_POLY_DA, val);

            if (syn != 0) {
                if (syn >= BCH_DA_TABLE || syn_da[syn].errs < 0)
                    goto done;  /* uncorrectable → stop */
                val ^= syn_da[syn].locator;
            }

            /* Extract 20 data bits */
            uint_to_bits(val >> BCH_DA_SYN, bch_stream + bch_len, BCH_DA_DATA);
            bch_len += BCH_DA_DATA;
        }
    }

    /* Last partial block */
    if (remain >= 4 && bch_len + 2 * (remain / 2 - 1) <= max_bch) {
        int n_sym_last = remain / 2;
        uint8_t h1[64], h2[64];
        de_interleave_n(data + n_full * 124, n_sym_last, h1, h2);

        /* Drop first bit of each half (per iridium-toolkit) */
        int half_len = n_sym_last;  /* bits per half */
        if (half_len > 1 && bch_len + BCH_DA_DATA <= max_bch) {
            /* Process as 31-bit BCH blocks if long enough */
            uint8_t combined[128];
            int clen = 0;
            for (int i = 1; i < half_len && clen < 128; i++)
                combined[clen++] = h2[i];
            for (int i = 1; i < half_len && clen < 128; i++)
                combined[clen++] = h1[i];

            int pos = 0;
            while (pos + 31 <= clen && bch_len + BCH_DA_DATA <= max_bch) {
                uint32_t val = bits_to_uint(combined + pos, 31);
                uint32_t syn = gf2_remainder(BCH_POLY_DA, val);
                if (syn != 0) {
                    if (syn >= BCH_DA_TABLE || syn_da[syn].errs < 0)
                        break;
                    val ^= syn_da[syn].locator;
                }
                uint_to_bits(val >> BCH_DA_SYN, bch_stream + bch_len, BCH_DA_DATA);
                bch_len += BCH_DA_DATA;
                pos += 31;
            }
        }
    }

done:
    return bch_len;
}

/* ---- CRC-CCITT-FALSE (poly=0x1021, init=0xFFFF) ---- */

static uint16_t crc_ccitt(const uint8_t *data, int len)
{
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc = crc << 1;
        }
    }
    return crc;
}

/* ---- Main IDA decode ---- */

int ida_decode(const demod_frame_t *frame, ida_burst_t *burst)
{
    memset(burst, 0, sizeof(*burst));

    if (frame->n_bits < 24 + 46 + 124)
        return 0;

    /* Check access code */
    int is_dl = (memcmp(frame->bits, access_dl, 24) == 0);
    int is_ul = (memcmp(frame->bits, access_ul, 24) == 0);
    if (!is_dl && !is_ul)
        return 0;

    const uint8_t *data = frame->bits + 24;
    int data_len = frame->n_bits - 24;

    /* Extract LCW */
    lcw_t lcw;
    if (!decode_lcw(data, data_len, &lcw))
        return 0;
    if (lcw.ft != 2)
        return 0;

    /* Descramble + BCH decode payload (skip 46 LCW bits) */
    const uint8_t *payload_data = data + 46;
    int payload_len = data_len - 46;
    if (payload_len < 124)
        return 0;

    uint8_t bch_stream[512];
    int bch_len = descramble_payload(payload_data, payload_len, bch_stream, sizeof(bch_stream));

    /* Need at least 196 bits: 20 header + 160 payload + 16 CRC */
    if (bch_len < 196)
        return 0;

    /* Extract IDA fields from bitstream_bch */
    int cont    = bch_stream[3];           /* bit 3: continuation */
    int da_ctr  = (bch_stream[5] << 2) | (bch_stream[6] << 1) | bch_stream[7];
    int da_len  = (bch_stream[11] << 4) | (bch_stream[12] << 3) |
                  (bch_stream[13] << 2) | (bch_stream[14] << 1) | bch_stream[15];
    int zero1   = (bch_stream[17] << 2) | (bch_stream[18] << 1) | bch_stream[19];

    if (zero1 != 0)
        return 0;
    if (da_len > 20)
        return 0;

    /* Extract payload bytes (bits 20-179 → 20 bytes) */
    uint8_t payload[20];
    for (int i = 0; i < 20; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++)
            byte = (byte << 1) | bch_stream[20 + i * 8 + b];
        payload[i] = byte;
    }

    /* CRC verification (if da_len > 0) */
    int crc_ok = 0;
    if (da_len > 0 && bch_len >= 196) {
        /* CRC input: bits 0-19 + 12 zero bits + bits 20 to (end-4) */
        int crc_bits = 20 + 12 + (bch_len - 20 - 4);
        int crc_bytes = crc_bits / 8;
        uint8_t crc_buf[64];
        if (crc_bytes <= (int)sizeof(crc_buf)) {
            /* Pack bits into bytes for CRC */
            memset(crc_buf, 0, sizeof(crc_buf));
            int bit_pos = 0;

            /* First 20 bits (header) */
            for (int i = 0; i < 20; i++) {
                crc_buf[bit_pos / 8] |= bch_stream[i] << (7 - (bit_pos % 8));
                bit_pos++;
            }

            /* 12 zero padding bits */
            bit_pos += 12;

            /* Bits 20 to (bch_len - 4) */
            for (int i = 20; i < bch_len - 4; i++) {
                crc_buf[bit_pos / 8] |= bch_stream[i] << (7 - (bit_pos % 8));
                bit_pos++;
            }

            crc_ok = (crc_ccitt(crc_buf, (bit_pos + 7) / 8) == 0);
        }
    }

    /* Fill burst output */
    burst->timestamp = frame->timestamp;
    burst->frequency = frame->center_frequency;
    burst->direction = frame->direction;
    burst->magnitude = frame->magnitude;
    burst->da_ctr = da_ctr;
    burst->da_len = da_len;
    burst->cont = cont;
    burst->crc_ok = crc_ok;
    burst->payload_len = (da_len > 0) ? da_len : 20;
    memcpy(burst->payload, payload, burst->payload_len);

    return 1;
}

/* ---- Multi-burst reassembly ---- */

int ida_reassemble(ida_context_t *ctx, const ida_burst_t *burst,
                   ida_message_cb cb, void *user)
{
    /* Only process CRC-verified bursts */
    if (!burst->crc_ok || burst->da_len == 0)
        return 0;

    /* Try to match existing reassembly slot */
    for (int i = 0; i < IDA_MAX_REASSEMBLY; i++) {
        ida_reassembly_t *s = &ctx->slots[i];
        if (!s->active) continue;
        if (s->direction != burst->direction) continue;
        if (fabs(s->frequency - burst->frequency) > 260.0) continue;
        if (burst->timestamp < s->last_timestamp) continue;
        if (burst->timestamp - s->last_timestamp > 280000000ULL) continue;
        if ((s->last_ctr + 1) % 8 != burst->da_ctr) continue;

        /* Match -- append payload */
        if (s->data_len + burst->da_len <= (int)sizeof(s->data)) {
            memcpy(s->data + s->data_len, burst->payload, burst->da_len);
            s->data_len += burst->da_len;
        }
        s->last_timestamp = burst->timestamp;
        s->last_ctr = burst->da_ctr;

        if (!burst->cont) {
            /* Message complete */
            cb(s->data, s->data_len, burst->timestamp,
               s->frequency, s->direction, burst->magnitude, user);
            s->active = 0;
            return 1;
        }
        return 0;
    }

    /* Single-burst message (ctr==0, no continuation) */
    if (burst->da_ctr == 0 && !burst->cont) {
        cb(burst->payload, burst->da_len, burst->timestamp,
           burst->frequency, burst->direction, burst->magnitude, user);
        return 1;
    }

    /* Start new multi-burst message (ctr==0, continuation expected) */
    if (burst->da_ctr == 0 && burst->cont) {
        /* Find free slot (or evict oldest) */
        int idx = -1;
        uint64_t oldest = UINT64_MAX;
        for (int i = 0; i < IDA_MAX_REASSEMBLY; i++) {
            if (!ctx->slots[i].active) { idx = i; break; }
            if (ctx->slots[i].last_timestamp < oldest) {
                oldest = ctx->slots[i].last_timestamp;
                idx = i;
            }
        }
        if (idx < 0) idx = 0;

        ida_reassembly_t *s = &ctx->slots[idx];
        s->active = 1;
        s->direction = burst->direction;
        s->frequency = burst->frequency;
        s->last_timestamp = burst->timestamp;
        s->last_ctr = burst->da_ctr;
        memcpy(s->data, burst->payload, burst->da_len);
        s->data_len = burst->da_len;
        return 0;
    }

    /* Orphan fragment (ctr>0, no matching slot) -- discard */
    return 0;
}

void ida_reassemble_flush(ida_context_t *ctx, uint64_t now_ns)
{
    for (int i = 0; i < IDA_MAX_REASSEMBLY; i++) {
        ida_reassembly_t *s = &ctx->slots[i];
        if (s->active && now_ns > s->last_timestamp + 1000000000ULL) {
            s->active = 0;
        }
    }
}
