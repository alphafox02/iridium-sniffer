/*
 * Run the native IRA/IBC decoder over iridium-toolkit RAW lines and print
 * one verdict per line, for comparison against iridium-parser.py.
 *
 * Usage: raw_decode < file.raw
 * Output: <line> <IRA|IBC|VOC|-> <freq> [sat beam ...]
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frame_decode.h"

int use_chase = 0;
int verbose = 0;

int main(void)
{
    char *line = NULL;
    size_t cap = 0;
    long lineno = 0;
    static uint8_t bits[4096];

    frame_decode_init();

    while (getline(&line, &cap, stdin) > 0) {
        lineno++;
        if (strncmp(line, "RAW:", 4) != 0)
            continue;

        char name[128], nfield[64], ifield[64], bitstr[4096];
        double ts_ms, freq, level;
        int conf, nsym;
        if (sscanf(line, "RAW: %127s %lf %lf %63s %63s %d%% %lf %d %4095s",
                   name, &ts_ms, &freq, nfield, ifield, &conf, &level,
                   &nsym, bitstr) != 9)
            continue;

        int n = 0;
        for (char *c = bitstr; *c && n < (int)sizeof(bits); c++)
            if (*c == '0' || *c == '1')
                bits[n++] = *c - '0';

        demod_frame_t f;
        memset(&f, 0, sizeof(f));
        f.timestamp = (uint64_t)(ts_ms * 1e6);
        f.center_frequency = freq;
        f.confidence = conf;
        f.level = (float)level;
        f.n_symbols = nsym;
        f.bits = bits;
        f.n_bits = n;

        decoded_frame_t d;
        int ok = frame_decode(&f, &d);
        if (ok && d.type == FRAME_IRA)
            printf("%ld IRA %.0f sat:%d beam:%d alt:%d\n", lineno, freq,
                   d.ira.sat_id, d.ira.beam_id, d.ira.alt);
        else if (ok && d.type == FRAME_IBC)
            printf("%ld IBC %.0f sat:%d beam:%d bc:%d\n", lineno, freq,
                   d.ibc.sat_id, d.ibc.beam_id, d.ibc.bc_type);
        else if (ok && d.type == FRAME_VOC)
            printf("%ld VOC %.0f\n", lineno, freq);
        else
            printf("%ld - %.0f\n", lineno, freq);
    }
    free(line);
    return 0;
}
