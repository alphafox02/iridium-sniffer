/*
 * IDA (Iridium Data) frame decoder
 *
 * Detects IDA frames via LCW (Link Control Word) extraction,
 * descrambles payload using 124-bit block de-interleaving,
 * BCH decodes with poly=3545, verifies CRC-CCITT, and
 * reassembles multi-burst packets.
 *
 * Based on iridium-toolkit bitsparser.py + ida.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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
/* Access codes no longer checked here -- direction comes from demodulator UW match */

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

/* Chase decoder: flip up to N least-reliable bits, retry BCH */
#define CHASE_FLIP_BITS 5

static int chase_bch_da(const uint8_t *block31, const float *llr31,
                        uint8_t *out_data, int *fixed)
{
    uint32_t val = bits_to_uint(block31, 31);
    uint32_t syndrome = gf2_remainder(BCH_POLY_DA, val);

    if (syndrome == 0) {
        uint_to_bits(val >> BCH_DA_SYN, out_data, BCH_DA_DATA);
        *fixed = 0;
        return 0;
    }

    if (syndrome < BCH_DA_TABLE && syn_da[syndrome].errs >= 0) {
        val ^= syn_da[syndrome].locator;
        uint_to_bits(val >> BCH_DA_SYN, out_data, BCH_DA_DATA);
        *fixed = 1;
        return syn_da[syndrome].errs;
    }

    /* Standard BCH failed -- Chase decode with soft info */
    if (!llr31)
        return -1;

    /* Find CHASE_FLIP_BITS least-reliable positions */
    int pos[31];
    for (int i = 0; i < 31; i++)
        pos[i] = i;

    for (int i = 0; i < CHASE_FLIP_BITS; i++) {
        int min_idx = i;
        for (int j = i + 1; j < 31; j++) {
            if (llr31[pos[j]] < llr31[pos[min_idx]])
                min_idx = j;
        }
        int tmp = pos[i];
        pos[i] = pos[min_idx];
        pos[min_idx] = tmp;
    }

    uint32_t flip_mask[CHASE_FLIP_BITS];
    for (int i = 0; i < CHASE_FLIP_BITS; i++)
        flip_mask[i] = 1u << (30 - pos[i]);

    uint32_t base_val = bits_to_uint(block31, 31);
    for (int mask = 1; mask < (1 << CHASE_FLIP_BITS); mask++) {
        uint32_t flipped = base_val;
        for (int b = 0; b < CHASE_FLIP_BITS; b++) {
            if (mask & (1 << b))
                flipped ^= flip_mask[b];
        }

        syndrome = gf2_remainder(BCH_POLY_DA, flipped);
        if (syndrome == 0) {
            uint_to_bits(flipped >> BCH_DA_SYN, out_data, BCH_DA_DATA);
            *fixed = 1;
            return 0;
        }
        if (syndrome < BCH_DA_TABLE && syn_da[syndrome].errs >= 0) {
            flipped ^= syn_da[syndrome].locator;
            uint_to_bits(flipped >> BCH_DA_SYN, out_data, BCH_DA_DATA);
            *fixed = 1;
            return syn_da[syndrome].errs;
        }
    }

    return -1;
}

/* Soft de-interleave: LLR follows same permutation as bits */
static void de_interleave_llr_n(const float *in, int n_sym,
                                  float *out1, float *out2)
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

/* ---- LCW extraction ---- */

int decode_lcw(const uint8_t *data, int data_len, lcw_t *lcw)
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

    /* Extract data fields from corrected codewords.
     * lcw1 (7 bits) → top 3 bits are data → ft (frame type)
     * lcw2 (14 bits, poly degree 8) → top 6 bits are data
     *   top 2 bits = lcw_ft, bottom 4 bits = lcw_code
     * lcw3 (26 bits, poly degree 5) → top 21 bits are data */
    int lcw2_data = (int)(v2 >> 8) & 0x3F;   /* 6 data bits from lcw2 */
    int lcw3_data = (int)(v3 >> 5);           /* 21 data bits from lcw3 */

    lcw->ft = ft;
    lcw->lcw_ok = 1;
    lcw->lcw_ft = (lcw2_data >> 4) & 0x3;    /* top 2 bits of lcw2 data */
    lcw->lcw_code = lcw2_data & 0xF;         /* bottom 4 bits of lcw2 data */
    lcw->lcw3_val = (uint32_t)lcw3_data;
    lcw->ec_lcw = (s1 != 0) + (s2 != 0) + (s3 != 0);
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

/* ---- IDA payload descramble + Chase BCH decode ---- */

static int descramble_payload(const uint8_t *data, const float *llr,
                               int data_len,
                               uint8_t *bch_stream, int max_bch,
                               int *fixederrs)
{
    int bch_len = 0;
    *fixederrs = 0;

    /* Process full 124-bit blocks */
    int n_full = data_len / 124;
    int remain = data_len % 124;

    for (int blk = 0; blk < n_full; blk++) {
        const uint8_t *block = data + blk * 124;
        const float *block_llr = llr ? llr + blk * 124 : NULL;

        /* De-interleave 62 symbols → 2 × 62 bits */
        uint8_t half1[62], half2[62];
        de_interleave_n(block, 62, half1, half2);

        float lhalf1[62], lhalf2[62];
        if (block_llr)
            de_interleave_llr_n(block_llr, 62, lhalf1, lhalf2);

        /* Concatenate → 124 bits, split into 4 × 31 bits */
        uint8_t combined[124];
        float lcombined[124];
        memcpy(combined, half1, 62);
        memcpy(combined + 62, half2, 62);
        if (block_llr) {
            memcpy(lcombined, lhalf1, 62 * sizeof(float));
            memcpy(lcombined + 62, lhalf2, 62 * sizeof(float));
        }

        /* Reorder: b4, b2, b3, b1 → chunks[3], chunks[1], chunks[2], chunks[0] */
        int order[4] = {3, 1, 2, 0};

        for (int c = 0; c < 4; c++) {
            if (bch_len + BCH_DA_DATA > max_bch) break;

            int off = order[c] * 31;
            uint8_t out_data[BCH_DA_DATA];
            int fixed = 0;
            int errs = chase_bch_da(combined + off,
                                     block_llr ? lcombined + off : NULL,
                                     out_data, &fixed);
            if (errs < 0)
                goto done;

            *fixederrs += fixed;
            memcpy(bch_stream + bch_len, out_data, BCH_DA_DATA);
            bch_len += BCH_DA_DATA;
        }
    }

    /* Last partial block */
    if (remain >= 4 && bch_len + 2 * (remain / 2 - 1) <= max_bch) {
        int n_sym_last = remain / 2;
        uint8_t h1[64], h2[64];
        de_interleave_n(data + n_full * 124, n_sym_last, h1, h2);

        float lh1[64], lh2[64];
        const float *last_llr = llr ? llr + n_full * 124 : NULL;
        if (last_llr)
            de_interleave_llr_n(last_llr, n_sym_last, lh1, lh2);

        /* Drop first bit of each half (per iridium-toolkit) */
        int half_len = n_sym_last;
        if (half_len > 1 && bch_len + BCH_DA_DATA <= max_bch) {
            uint8_t combined[128];
            float lcombined[128];
            int clen = 0;
            for (int i = 1; i < half_len && clen < 128; i++) {
                combined[clen] = h2[i];
                if (last_llr) lcombined[clen] = lh2[i];
                clen++;
            }
            for (int i = 1; i < half_len && clen < 128; i++) {
                combined[clen] = h1[i];
                if (last_llr) lcombined[clen] = lh1[i];
                clen++;
            }

            int pos = 0;
            while (pos + 31 <= clen && bch_len + BCH_DA_DATA <= max_bch) {
                uint8_t out_data[BCH_DA_DATA];
                int fixed = 0;
                int errs = chase_bch_da(combined + pos,
                                         last_llr ? lcombined + pos : NULL,
                                         out_data, &fixed);
                if (errs < 0) break;
                *fixederrs += fixed;
                memcpy(bch_stream + bch_len, out_data, BCH_DA_DATA);
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

/* ---- LCW pretty-print (matches iridium-toolkit bitsparser.py pretty_lcw) ---- */

static void lcw3_to_bits(uint32_t val, char *out, int nbits)
{
    for (int i = 0; i < nbits; i++)
        out[i] = '0' + ((val >> (nbits - 1 - i)) & 1);
    out[nbits] = '\0';
}

static void format_lcw_header(int ft, const lcw_t *lcw, char *out, int outsz)
{
    char lcw3bits[32];
    lcw3_to_bits(lcw->lcw3_val, lcw3bits, 21);

    const char *ty;
    char code[128];
    char remain[64];

    switch (lcw->lcw_ft) {
    case 0:
        ty = "maint";
        switch (lcw->lcw_code) {
        case 0: {
            int status = (lcw3bits[1] - '0');
            int dtoa = 0, dfoa = 0;
            for (int i = 3; i < 13; i++) dtoa = (dtoa << 1) | (lcw3bits[i] - '0');
            for (int i = 13; i < 21; i++) dfoa = (dfoa << 1) | (lcw3bits[i] - '0');
            snprintf(code, sizeof(code), "sync[status:%d,dtoa:%d,dfoa:%d]", status, dtoa, dfoa);
            snprintf(remain, sizeof(remain), "%c|%c", lcw3bits[0], lcw3bits[2]);
            break;
        }
        case 1: {
            int dtoa = 0, dfoa = 0;
            for (int i = 3; i < 13; i++) dtoa = (dtoa << 1) | (lcw3bits[i] - '0');
            for (int i = 13; i < 21; i++) dfoa = (dfoa << 1) | (lcw3bits[i] - '0');
            snprintf(code, sizeof(code), "switch[dtoa:%d,dfoa:%d]", dtoa, dfoa);
            snprintf(remain, sizeof(remain), "%.3s", lcw3bits);
            break;
        }
        case 3: {
            int lqi = (lcw3bits[1] - '0') * 2 + (lcw3bits[2] - '0');
            int power = 0;
            for (int i = 3; i < 6; i++) power = (power << 1) | (lcw3bits[i] - '0');
            int f_dtoa = 0, f_dfoa = 0;
            for (int i = 6; i < 13; i++) f_dtoa = (f_dtoa << 1) | (lcw3bits[i] - '0');
            for (int i = 13; i < 20; i++) f_dfoa = (f_dfoa << 1) | (lcw3bits[i] - '0');
            snprintf(code, sizeof(code), "maint[2][lqi:%d,power:%d,f_dtoa:%d,f_dfoa:%d]",
                     lqi, power, f_dtoa, f_dfoa);
            snprintf(remain, sizeof(remain), "%c|%c", lcw3bits[0], lcw3bits[20]);
            break;
        }
        case 6:
            snprintf(code, sizeof(code), "geoloc");
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
            break;
        case 12: {
            int lqi = (lcw3bits[19] - '0') * 2 + (lcw3bits[20] - '0');
            int power = 0;
            for (int i = 16; i < 19; i++) power = (power << 1) | (lcw3bits[i] - '0');
            snprintf(code, sizeof(code), "maint[1][lqi:%d,power:%d]", lqi, power);
            lcw3bits[16] = '\0';
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
            break;
        }
        case 15:
            snprintf(code, sizeof(code), "<silent>");
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
            break;
        default:
            snprintf(code, sizeof(code), "rsrvd(%d)", lcw->lcw_code);
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
            break;
        }
        break;
    case 1:
        ty = "acchl";
        if (lcw->lcw_code == 1) {
            int msg_type = 0, bloc_num, sapi_code = 0;
            for (int i = 1; i < 4; i++) msg_type = (msg_type << 1) | (lcw3bits[i] - '0');
            bloc_num = lcw3bits[4] - '0';
            for (int i = 5; i < 8; i++) sapi_code = (sapi_code << 1) | (lcw3bits[i] - '0');
            char segm[16];
            memcpy(segm, lcw3bits + 8, 8); segm[8] = '\0';
            snprintf(code, sizeof(code),
                     "acchl[msg_type:%01x,bloc_num:%01x,sapi_code:%01x,segm_list:%s]",
                     msg_type, bloc_num, sapi_code, segm);
            int tail = 0;
            for (int i = 16; i < 21; i++) tail = (tail << 1) | (lcw3bits[i] - '0');
            snprintf(remain, sizeof(remain), "%c,%02x", lcw3bits[0], tail);
        } else {
            snprintf(code, sizeof(code), "rsrvd(%d)", lcw->lcw_code);
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
        }
        break;
    case 2:
        ty = "hndof";
        switch (lcw->lcw_code) {
        case 3: {
            char cand = ((lcw3bits[2] - '0') == 0) ? 'P' : 'S';
            int denied = lcw3bits[3] - '0';
            int ref = lcw3bits[4] - '0';
            int slot = 1 + (lcw3bits[6] - '0') * 2 + (lcw3bits[7] - '0');
            int sband_up = 0, sband_dn = 0, access = 0;
            for (int i = 8; i < 13; i++) sband_up = (sband_up << 1) | (lcw3bits[i] - '0');
            for (int i = 13; i < 18; i++) sband_dn = (sband_dn << 1) | (lcw3bits[i] - '0');
            for (int i = 18; i < 21; i++) access = (access << 1) | (lcw3bits[i] - '0');
            access += 1;
            snprintf(code, sizeof(code),
                     "handoff_resp[cand:%c,denied:%d,ref:%d,slot:%d,sband_up:%d,sband_dn:%d,access:%d]",
                     cand, denied, ref, slot, sband_up, sband_dn, access);
            snprintf(remain, sizeof(remain), "%.2s,%c", lcw3bits, lcw3bits[5]);
            break;
        }
        case 12: {
            char first[12], second[11];
            memcpy(first, lcw3bits, 11); first[11] = '\0';
            memcpy(second, lcw3bits + 11, 10); second[10] = '\0';
            snprintf(code, sizeof(code), "handoff_cand");
            snprintf(remain, sizeof(remain), "%s,%s", first, second);
            break;
        }
        case 15:
            snprintf(code, sizeof(code), "<silent>");
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
            break;
        default:
            snprintf(code, sizeof(code), "rsrvd(%d)", lcw->lcw_code);
            snprintf(remain, sizeof(remain), "%s", lcw3bits);
            break;
        }
        break;
    case 3:
    default:
        ty = "rsrvd";
        snprintf(code, sizeof(code), "<%d>", lcw->lcw_code);
        snprintf(remain, sizeof(remain), "%s", lcw3bits);
        break;
    }

    /* Format: LCW(%d,T:%s,C:%s,%s) padded to 110 chars + 1 space */
    char raw[128];
    snprintf(raw, sizeof(raw), "LCW(%d,T:%s,C:%s,%s)", ft, ty, code, remain);
    snprintf(out, outsz, "%-110s ", raw);
}

/* ---- Main IDA decode ---- */

int ida_decode(const demod_frame_t *frame, ida_burst_t *burst)
{
    memset(burst, 0, sizeof(*burst));

    if (frame->n_bits < 24 + 46 + 124)
        return 0;

    /* Direction already determined by demodulator UW check */
    if (frame->direction != DIR_DOWNLINK && frame->direction != DIR_UPLINK)
        return 0;

    const uint8_t *data = frame->bits + 24;
    const float *data_llr = frame->llr ? frame->llr + 24 : NULL;
    int data_len = frame->n_bits - 24;

    /* Extract LCW */
    lcw_t lcw;
    if (!decode_lcw(data, data_len, &lcw))
        return 0;
    if (lcw.ft != 2)
        return 0;

    /* Descramble + Chase BCH decode payload (skip 46 LCW bits) */
    const uint8_t *payload_data = data + 46;
    const float *payload_llr = data_llr ? data_llr + 46 : NULL;
    int payload_len = data_len - 46;
    if (payload_len < 124)
        return 0;

    uint8_t bch_stream[512];
    int fixederrs = 0;
    int bch_len = descramble_payload(payload_data, payload_llr, payload_len,
                                      bch_stream, sizeof(bch_stream),
                                      &fixederrs);

    /* Need at least 196 bits: 20 header + 160 payload + 16 CRC */
    if (bch_len < 196)
        return 0;

    /* Extract IDA fields from bitstream_bch */
    int cont    = bch_stream[3];
    int da_ctr  = (bch_stream[5] << 2) | (bch_stream[6] << 1) | bch_stream[7];
    int da_len  = (bch_stream[11] << 4) | (bch_stream[12] << 3) |
                  (bch_stream[13] << 2) | (bch_stream[14] << 1) | bch_stream[15];
    int zero1   = (bch_stream[17] << 2) | (bch_stream[18] << 1) | bch_stream[19];

    if (zero1 != 0)
        return 0;
    if (da_len > 20)
        return 0;

    /* Extract payload bytes (bits 20-179 -> 20 bytes) */
    uint8_t payload[20];
    for (int i = 0; i < 20; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++)
            byte = (byte << 1) | bch_stream[20 + i * 8 + b];
        payload[i] = byte;
    }

    /* CRC verification (if da_len > 0) */
    int crc_ok = 0;
    uint16_t stored_crc = 0;
    uint16_t computed_crc = 0;
    if (da_len > 0 && bch_len >= 196) {
        /* Stored CRC at bits[9*20 .. 9*20+16] */
        stored_crc = 0;
        for (int i = 0; i < 16; i++)
            stored_crc = (stored_crc << 1) | bch_stream[9 * 20 + i];

        /* CRC input: bits 0-19 + 12 zero bits + bits 20 to (end-4) */
        int crc_bits = 20 + 12 + (bch_len - 20 - 4);
        int crc_bytes = (crc_bits + 7) / 8;
        uint8_t crc_buf[64];
        if (crc_bytes <= (int)sizeof(crc_buf)) {
            memset(crc_buf, 0, sizeof(crc_buf));
            int bit_pos = 0;

            for (int i = 0; i < 20; i++) {
                crc_buf[bit_pos / 8] |= bch_stream[i] << (7 - (bit_pos % 8));
                bit_pos++;
            }
            bit_pos += 12;
            for (int i = 20; i < bch_len - 4; i++) {
                crc_buf[bit_pos / 8] |= bch_stream[i] << (7 - (bit_pos % 8));
                bit_pos++;
            }

            computed_crc = crc_ccitt(crc_buf, (bit_pos + 7) / 8);
            crc_ok = (computed_crc == 0);
        }
    }

    /* Fill burst output */
    burst->timestamp = frame->timestamp;
    burst->frequency = frame->center_frequency;
    burst->direction = frame->direction;
    burst->magnitude = frame->magnitude;
    burst->noise = frame->noise;
    burst->level = frame->level;
    burst->confidence = frame->confidence;
    burst->n_symbols = frame->n_payload_symbols;
    burst->da_ctr = da_ctr;
    burst->da_len = da_len;
    burst->cont = cont;
    burst->crc_ok = crc_ok;
    burst->stored_crc = stored_crc;
    burst->computed_crc = computed_crc;
    burst->fixederrs = fixederrs;
    burst->payload_len = (da_len > 0) ? da_len : 20;
    memcpy(burst->payload, payload, burst->payload_len);

    /* Store full BCH stream and LCW for parsed output */
    burst->bch_len = bch_len;
    memcpy(burst->bch_stream, bch_stream,
           bch_len < (int)sizeof(burst->bch_stream) ? bch_len : (int)sizeof(burst->bch_stream));
    burst->lcw = lcw;

    /* Format LCW header string */
    format_lcw_header(lcw.ft, &lcw, burst->lcw_header, sizeof(burst->lcw_header));

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
        if (s->active && now_ns > s->last_timestamp + 280000000ULL) {
            s->active = 0;
        }
    }
}
