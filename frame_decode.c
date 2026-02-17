/*
 * Iridium frame decoder
 *
 * Parses demodulated bits into IRA (ring alert) and IBC (broadcast)
 * frames for web map display. Implements de-interleaving and BCH
 * syndrome checking per the Iridium air interface.
 *
 * Based on iridium-toolkit bitsparser.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Iridium frame decoder
 *
 * Parses demodulated bits into IRA (ring alert) and IBC (broadcast)
 * frames for web map display. Implements de-interleaving and BCH
 * syndrome checking per the Iridium air interface.
 *
 * Reference: iridium-toolkit/bitsparser.py (muccc)
 */

#include <math.h>
#include <string.h>
#include <stdio.h>

#include "frame_decode.h"
#include "iridium.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* BCH polynomials */
#define BCH_POLY_RA   1207   /* BCH(31,21) t=2, for IRA/IBC data blocks */
#define BCH_POLY_HDR  29     /* BCH(7,3) t=1, for IBC header */

/* BCH polynomial bit lengths */
#define BCH_POLY_RA_BITS  11  /* bit_length(1207) = 11, syndrome = 10 bits */
#define BCH_POLY_HDR_BITS 5   /* bit_length(29) = 5, syndrome = 4 bits */

/* BCH data bits per block */
#define BCH_RA_DATA   21     /* 31 - 10 = 21 data bits */
#define BCH_HDR_DATA  3      /* 7 - 4 = 3 data bits */

/* Chase decoder: flip up to N least-reliable bits, retry BCH */
#define CHASE_FLIP_BITS 5    /* 2^5 = 32 combinations per failed block */

/* Access codes (24 bits after UW) */
static const uint8_t access_dl[] = {
    0,0,1,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,1,0,0,1,1
};
static const uint8_t access_ul[] = {
    1,1,0,0,1,1,0,0,0,0,1,1,1,1,0,0,1,1,1,1,1,1,0,0
};

/* Syndrome lookup tables for BCH error correction */
/* poly=1207: 1024 entries (10-bit syndrome), each stores error locator XOR mask */
static struct { int errs; uint32_t locator; } syn_ra[1024];
/* poly=29: 16 entries (4-bit syndrome) */
static struct { int errs; uint32_t locator; } syn_hdr[16];

/* ---- GF(2) polynomial remainder (BCH syndrome) ---- */

uint32_t bits_to_uint(const uint8_t *bits, int n)
{
    uint32_t val = 0;
    for (int i = 0; i < n; i++)
        val = (val << 1) | (bits[i] & 1);
    return val;
}

void uint_to_bits(uint32_t val, uint8_t *bits, int n)
{
    for (int i = n - 1; i >= 0; i--) {
        bits[i] = val & 1;
        val >>= 1;
    }
}

uint32_t gf2_remainder(uint32_t poly, uint32_t val)
{
    if (val == 0) return 0;
    int poly_bits = 32 - __builtin_clz(poly);
    for (int i = 31; i >= poly_bits - 1; i--) {
        if (val & (1u << i))
            val ^= poly << (i - poly_bits + 1);
    }
    return val;
}

/* ---- Build BCH syndrome lookup tables ---- */

static void build_syndrome_table(uint32_t poly, int nbits, int synbits,
                                  int max_errors, void *table, int table_size)
{
    struct { int errs; uint32_t locator; } *syn = table;

    /* Initialize all entries as uncorrectable */
    for (int i = 0; i < table_size; i++) {
        syn[i].errs = -1;
        syn[i].locator = 0;
    }

    /* Single-bit errors */
    for (int b1 = 0; b1 < nbits; b1++) {
        uint32_t val = 1u << b1;
        uint32_t r = gf2_remainder(poly, val);
        if (r < (uint32_t)table_size) {
            syn[r].errs = 1;
            syn[r].locator = val;
        }
    }

    /* Two-bit errors */
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

void frame_decode_init(void)
{
    build_syndrome_table(BCH_POLY_RA, 31, 10, 2, syn_ra, 1024);
    build_syndrome_table(BCH_POLY_HDR, 7, 4, 1, syn_hdr, 16);
}

int bch_31_21_correct(uint32_t syndrome, uint32_t *locator)
{
    if (syndrome == 0) { *locator = 0; return 0; }
    if (syndrome < 1024 && syn_ra[syndrome].errs >= 0) {
        *locator = syn_ra[syndrome].locator;
        return syn_ra[syndrome].errs;
    }
    return -1;
}

/* ---- De-interleaving ----
 *
 * Iridium interleaving: pair-swap bits, then distribute symbols
 * to output streams in reverse order with stride.
 *
 * de_interleave: 64 input bits → 2 × 32 output bits
 * de_interleave3: 96 input bits → 3 × 32 output bits
 */

static void de_interleave(const uint8_t *in, uint8_t *out1, uint8_t *out2)
{
    /* iridium-toolkit applies symbol_reverse (pair-swap) to the raw bitstream
     * BEFORE de_interleave, and de_interleave has its own internal pair-swap.
     * The two swaps cancel out. Since we don't pre-swap, we skip the internal
     * pair-swap too, achieving the same net result. */

    /* Odd symbol indices in reverse → out1 (32 bits) */
    int p = 0;
    for (int s = 31; s >= 1; s -= 2) {
        out1[p++] = in[2 * s];
        out1[p++] = in[2 * s + 1];
    }

    /* Even symbol indices in reverse → out2 (32 bits) */
    p = 0;
    for (int s = 30; s >= 0; s -= 2) {
        out2[p++] = in[2 * s];
        out2[p++] = in[2 * s + 1];
    }
}

static void de_interleave3(const uint8_t *in,
                             uint8_t *out1, uint8_t *out2, uint8_t *out3)
{
    /* Same as de_interleave: no pair-swap needed since we don't pre-swap.
     * Three-way split with reverse stride-3:
     * first:  symbols[47, 44, 41, ..., 2]  → 16 symbols = 32 bits
     * second: symbols[46, 43, 40, ..., 1]  → 16 symbols = 32 bits
     * third:  symbols[45, 42, 39, ..., 0]  → 16 symbols = 32 bits */
    int p1 = 0, p2 = 0, p3 = 0;
    for (int s = 47; s >= 2; s -= 3) {
        out1[p1++] = in[2 * s];
        out1[p1++] = in[2 * s + 1];
    }
    for (int s = 46; s >= 1; s -= 3) {
        out2[p2++] = in[2 * s];
        out2[p2++] = in[2 * s + 1];
    }
    for (int s = 45; s >= 0; s -= 3) {
        out3[p3++] = in[2 * s];
        out3[p3++] = in[2 * s + 1];
    }
}

/* ---- Soft de-interleaving (LLR follows same permutation as bits) ---- */

static void de_interleave_llr(const float *in, float *out1, float *out2)
{
    int p = 0;
    for (int s = 31; s >= 1; s -= 2) {
        out1[p++] = in[2 * s];
        out1[p++] = in[2 * s + 1];
    }
    p = 0;
    for (int s = 30; s >= 0; s -= 2) {
        out2[p++] = in[2 * s];
        out2[p++] = in[2 * s + 1];
    }
}

/* ---- Chase BCH(31,21) decoder ----
 *
 * When standard BCH fails (>2 errors), flip the least-reliable bit
 * positions (guided by LLR) and retry. With CHASE_FLIP_BITS=5 and
 * BCH t=2, can correct up to 7 errors if the right positions are flipped.
 */

static int chase_bch_decode_p(const uint8_t *block32, const float *llr32,
                                uint8_t *out_data, uint8_t *out_check)
{
    /* Try standard BCH first */
    uint32_t val = bits_to_uint(block32, 31);
    uint32_t syndrome = gf2_remainder(BCH_POLY_RA, val);

    if (syndrome == 0) {
        uint_to_bits(val >> 10, out_data, BCH_RA_DATA);
        uint_to_bits(val & 0x3FF, out_check, 10);
        return 0;
    }

    if (syndrome < 1024 && syn_ra[syndrome].errs >= 0) {
        val ^= syn_ra[syndrome].locator;
        uint_to_bits(val >> 10, out_data, BCH_RA_DATA);
        uint_to_bits(val & 0x3FF, out_check, 10);
        return syn_ra[syndrome].errs;
    }

    /* Standard BCH failed -- Chase decode with soft info */
    if (!llr32)
        return -1;

    /* Find CHASE_FLIP_BITS least-reliable positions within the 31-bit codeword.
     * Simple partial selection sort (N=5 from 31 elements). */
    int pos[31];
    for (int i = 0; i < 31; i++)
        pos[i] = i;

    for (int i = 0; i < CHASE_FLIP_BITS; i++) {
        int min_idx = i;
        for (int j = i + 1; j < 31; j++) {
            if (llr32[pos[j]] < llr32[pos[min_idx]])
                min_idx = j;
        }
        int tmp = pos[i];
        pos[i] = pos[min_idx];
        pos[min_idx] = tmp;
    }

    /* Pre-compute flip masks for each candidate position.
     * bits_to_uint puts bit[0] at bit position 30, bit[k] at position (30-k). */
    uint32_t flip_mask[CHASE_FLIP_BITS];
    for (int i = 0; i < CHASE_FLIP_BITS; i++)
        flip_mask[i] = 1u << (30 - pos[i]);

    /* Try all 2^CHASE_FLIP_BITS - 1 non-zero combinations */
    uint32_t base_val = bits_to_uint(block32, 31);
    for (int mask = 1; mask < (1 << CHASE_FLIP_BITS); mask++) {
        uint32_t flipped = base_val;
        for (int b = 0; b < CHASE_FLIP_BITS; b++) {
            if (mask & (1 << b))
                flipped ^= flip_mask[b];
        }

        syndrome = gf2_remainder(BCH_POLY_RA, flipped);
        if (syndrome == 0) {
            uint_to_bits(flipped >> 10, out_data, BCH_RA_DATA);
            uint_to_bits(flipped & 0x3FF, out_check, 10);
            return 0;
        }
        if (syndrome < 1024 && syn_ra[syndrome].errs >= 0) {
            flipped ^= syn_ra[syndrome].locator;
            uint_to_bits(flipped >> 10, out_data, BCH_RA_DATA);
            uint_to_bits(flipped & 0x3FF, out_check, 10);
            return syn_ra[syndrome].errs;
        }
    }

    return -1;
}

/* ---- IRA field extraction ---- */

static int extract_signed12(const uint8_t *bits)
{
    /* 12-bit signed: bit[0] is sign, bits[1:12] are magnitude */
    int sign = bits[0];
    int mag = 0;
    for (int i = 1; i < 12; i++)
        mag = (mag << 1) | bits[i];
    return sign ? (mag - (1 << 11)) : mag;
}

static int extract_uint(const uint8_t *bits, int n)
{
    int val = 0;
    for (int i = 0; i < n; i++)
        val = (val << 1) | bits[i];
    return val;
}

static void parse_ira(const uint8_t *bch_data, int n_bits, ira_data_t *ira)
{
    memset(ira, 0, sizeof(*ira));

    if (n_bits < 63)
        return;

    /* IRA header: 63 bits */
    ira->sat_id  = extract_uint(&bch_data[0], 7);
    ira->beam_id = extract_uint(&bch_data[7], 6);

    int pos_x = extract_signed12(&bch_data[13]);
    int pos_y = extract_signed12(&bch_data[25]);
    int pos_z = extract_signed12(&bch_data[37]);

    /* Store raw XYZ for Doppler positioning */
    ira->pos_xyz[0] = pos_x;
    ira->pos_xyz[1] = pos_y;
    ira->pos_xyz[2] = pos_z;

    /* Convert XYZ to lat/lon/alt */
    double xy = sqrt((double)pos_x * pos_x + (double)pos_y * pos_y);
    ira->lat = atan2((double)pos_z, xy) * 180.0 / M_PI;
    ira->lon = atan2((double)pos_y, (double)pos_x) * 180.0 / M_PI;
    ira->alt = (int)(sqrt((double)pos_x * pos_x + (double)pos_y * pos_y +
                           (double)pos_z * pos_z) * 4.0) - 6378 + 23;

    /* Paging blocks (42 bits each, starting at bit 63) */
    ira->n_pages = 0;
    int offset = 63;
    while (offset + 42 <= n_bits && ira->n_pages < 12) {
        const uint8_t *page = &bch_data[offset];

        /* Check for all-1s terminator */
        int all_ones = 1;
        for (int i = 0; i < 42; i++) {
            if (!page[i]) { all_ones = 0; break; }
        }
        if (all_ones) break;

        uint32_t tmsi = 0;
        for (int i = 0; i < 32; i++)
            tmsi = (tmsi << 1) | page[i];

        ira->pages[ira->n_pages].tmsi = tmsi;
        ira->pages[ira->n_pages].msc_id = extract_uint(&page[34], 5);
        ira->n_pages++;
        offset += 42;
    }
}

static void parse_ibc(const uint8_t *bch_data, int n_bits,
                        int hdr_type, ibc_data_t *ibc)
{
    memset(ibc, 0, sizeof(*ibc));
    ibc->bc_type = hdr_type;

    if (n_bits < 42)
        return;

    /* Block 1: satellite/beam info (first 42 data bits) */
    ibc->sat_id      = extract_uint(&bch_data[0], 7);
    ibc->beam_id     = extract_uint(&bch_data[7], 6);
    ibc->timeslot    = bch_data[14];
    ibc->sv_blocking = bch_data[15];

    /* Block 2: type-dependent (next 42 data bits, if available) */
    if (n_bits >= 84) {
        int type = extract_uint(&bch_data[42], 6);
        if (type == 1) {
            /* LBFC (Iridium time counter) */
            ibc->iri_time = 0;
            for (int i = 52; i < 84; i++)
                ibc->iri_time = (ibc->iri_time << 1) | bch_data[i];
        }
    }
}

/* ---- Parity check for a 32-bit de-interleaved block ----
 * The 32nd bit is an overall parity bit. After BCH correction,
 * data + bch + parity must have even weight. */

static int check_parity32(const uint8_t *block32, const uint8_t *bch_data,
                            int n_data, const uint8_t *bch_check, int n_check)
{
    int ones = 0;
    for (int i = 0; i < n_data; i++) ones += bch_data[i];
    for (int i = 0; i < n_check; i++) ones += bch_check[i];
    ones += block32[31];  /* parity bit */
    return (ones % 2) == 0;
}

/* bch_decode_p: superseded by chase_bch_decode_p which includes
 * the same standard BCH decode as its first step. */

/* ---- Main decode function ---- */

int frame_decode(const demod_frame_t *frame, decoded_frame_t *out)
{
    memset(out, 0, sizeof(*out));
    out->type = FRAME_UNKNOWN;
    out->timestamp = frame->timestamp;
    out->frequency = frame->center_frequency;

    /* Bits layout: [access code 24 bits][frame data...]
     * After DQPSK decode, the UW symbols become the access code bits.
     * The access code is the first 24 bits in the demodulated output. */
    if (frame->n_bits < 24)
        return 0;

    /* Verify access code */
    int is_dl = (memcmp(frame->bits, access_dl, 24) == 0);
    int is_ul = (memcmp(frame->bits, access_ul, 24) == 0);
    if (!is_dl && !is_ul)
        return 0;

    /* Frame data starts after the access code */
    const uint8_t *data = frame->bits + 24;
    const float *data_llr = frame->llr ? frame->llr + 24 : NULL;
    int data_len = frame->n_bits - 24;

    /* ---- Try IBC detection ----
     * Header: 6 bits BCH(7,3), then 64-bit de-interleaved data blocks.
     * Detection: BCH correction on header + first data blocks. */
    if (data_len >= 6 + 64) {
        /* Check IBC header (BCH(7,3) with error correction) */
        uint32_t hdr_val = bits_to_uint(data, 6);
        uint32_t hdr_syn = gf2_remainder(BCH_POLY_HDR, hdr_val);
        int hdr_ok = 0;

        if (hdr_syn == 0) {
            hdr_ok = 1;
        } else if (hdr_syn < 16 && syn_hdr[hdr_syn].errs >= 0) {
            hdr_val ^= syn_hdr[hdr_syn].locator;
            hdr_ok = 1;
        }

        if (hdr_ok) {
            uint8_t hdr_data[3];
            uint_to_bits(hdr_val >> 4, hdr_data, 3);

            /* De-interleave first 64-bit block after header */
            uint8_t di1[32], di2[32];
            float li1[32], li2[32];
            de_interleave(data + 6, di1, di2);
            if (data_llr && data_len >= 6 + 64)
                de_interleave_llr(data_llr + 6, li1, li2);

            /* BCH correction on first data blocks */
            uint8_t d1[BCH_RA_DATA], d2[BCH_RA_DATA];
            uint8_t rc1[10], rc2[10];
            int e1 = chase_bch_decode_p(di1,
                        data_llr ? li1 : NULL, d1, rc1);
            int e2 = chase_bch_decode_p(di2,
                        data_llr ? li2 : NULL, d2, rc2);

            if (e1 >= 0 && e2 >= 0 &&
                check_parity32(di1, d1, BCH_RA_DATA, rc1, 10) &&
                check_parity32(di2, d2, BCH_RA_DATA, rc2, 10)) {
                /* IBC confirmed -- decode all blocks */
                int bc_type = extract_uint(hdr_data, 3);
                int ibc_max = 262;
                if (data_len < ibc_max) ibc_max = data_len;

                uint8_t bch_stream[256];
                int bch_len = 0;

                memcpy(bch_stream + bch_len, d1, BCH_RA_DATA);
                bch_len += BCH_RA_DATA;
                memcpy(bch_stream + bch_len, d2, BCH_RA_DATA);
                bch_len += BCH_RA_DATA;

                /* Remaining 64-bit blocks with Chase BCH + parity */
                int offset = 6 + 64;
                while (offset + 64 <= ibc_max && bch_len + 2 * BCH_RA_DATA <= (int)sizeof(bch_stream)) {
                    de_interleave(data + offset, di1, di2);
                    if (data_llr && offset + 64 <= data_len)
                        de_interleave_llr(data_llr + offset, li1, li2);
                    int ea = chase_bch_decode_p(di1,
                                data_llr ? li1 : NULL, d1, rc1);
                    int eb = chase_bch_decode_p(di2,
                                data_llr ? li2 : NULL, d2, rc2);
                    if (ea < 0 || eb < 0) break;
                    if (!check_parity32(di1, d1, BCH_RA_DATA, rc1, 10)) break;
                    if (!check_parity32(di2, d2, BCH_RA_DATA, rc2, 10)) break;
                    memcpy(bch_stream + bch_len, d1, BCH_RA_DATA);
                    bch_len += BCH_RA_DATA;
                    memcpy(bch_stream + bch_len, d2, BCH_RA_DATA);
                    bch_len += BCH_RA_DATA;
                    offset += 64;
                }

                out->type = FRAME_IBC;
                parse_ibc(bch_stream, bch_len, bc_type, &out->ibc);
                return 1;
            }
        }
    }

    /* ---- Try IRA detection ----
     * First 96 bits: de_interleave3 → 3 × 32-bit blocks.
     * Detection: Chase BCH correction on all 3 header blocks + parity.
     * BCH(31,21) t=2 corrects up to 2 errors per block; Chase extends
     * this with soft info. Three-block parity gate keeps false-positive
     * rate negligible even with correction enabled. */
    if (data_len >= 96) {
        uint8_t ra1[32], ra2[32], ra3[32];
        float la1[32], la2[32], la3[32];
        de_interleave3(data, ra1, ra2, ra3);

        /* De-interleave LLR if available (for Chase decoder) */
        if (data_llr) {
            int p1 = 0, p2 = 0, p3 = 0;
            for (int s = 47; s >= 2; s -= 3) {
                la1[p1++] = data_llr[2 * s];
                la1[p1++] = data_llr[2 * s + 1];
            }
            for (int s = 46; s >= 1; s -= 3) {
                la2[p2++] = data_llr[2 * s];
                la2[p2++] = data_llr[2 * s + 1];
            }
            for (int s = 45; s >= 0; s -= 3) {
                la3[p3++] = data_llr[2 * s];
                la3[p3++] = data_llr[2 * s + 1];
            }
        }

        /* Chase BCH correction on all 3 header blocks */
        uint8_t d1[BCH_RA_DATA], d2[BCH_RA_DATA], d3[BCH_RA_DATA];
        uint8_t c1[10], c2[10], c3[10];
        int e1 = chase_bch_decode_p(ra1, data_llr ? la1 : NULL, d1, c1);
        int e2 = chase_bch_decode_p(ra2, data_llr ? la2 : NULL, d2, c2);
        int e3 = chase_bch_decode_p(ra3, data_llr ? la3 : NULL, d3, c3);

        if (e1 >= 0 && e2 >= 0 && e3 >= 0 &&
            check_parity32(ra1, d1, BCH_RA_DATA, c1, 10) &&
            check_parity32(ra2, d2, BCH_RA_DATA, c2, 10) &&
            check_parity32(ra3, d3, BCH_RA_DATA, c3, 10)) {

            /* IRA confirmed -- assemble decoded data */
            uint8_t bch_stream[512];
            int bch_len = 0;

            memcpy(bch_stream + bch_len, d1, BCH_RA_DATA);
            bch_len += BCH_RA_DATA;
            memcpy(bch_stream + bch_len, d2, BCH_RA_DATA);
            bch_len += BCH_RA_DATA;
            memcpy(bch_stream + bch_len, d3, BCH_RA_DATA);
            bch_len += BCH_RA_DATA;

            /* Remaining 64-bit blocks with Chase BCH + parity */
            uint8_t di1[32], di2[32];
            float li1[32], li2[32];
            uint8_t rd1[BCH_RA_DATA], rd2[BCH_RA_DATA];
            uint8_t rc1[10], rc2[10];
            int offset = 96;
            while (offset + 64 <= data_len && bch_len + 2 * BCH_RA_DATA <= (int)sizeof(bch_stream)) {
                de_interleave(data + offset, di1, di2);
                if (data_llr)
                    de_interleave_llr(data_llr + offset, li1, li2);
                int ea = chase_bch_decode_p(di1,
                            data_llr ? li1 : NULL, rd1, rc1);
                int eb = chase_bch_decode_p(di2,
                            data_llr ? li2 : NULL, rd2, rc2);
                if (ea < 0 || eb < 0) break;
                if (!check_parity32(di1, rd1, BCH_RA_DATA, rc1, 10)) break;
                if (!check_parity32(di2, rd2, BCH_RA_DATA, rc2, 10)) break;
                memcpy(bch_stream + bch_len, rd1, BCH_RA_DATA);
                bch_len += BCH_RA_DATA;
                memcpy(bch_stream + bch_len, rd2, BCH_RA_DATA);
                bch_len += BCH_RA_DATA;
                offset += 64;
            }

            out->type = FRAME_IRA;
            parse_ira(bch_stream, bch_len, &out->ira);
            return 1;
        }
    }

    return 0;
}
