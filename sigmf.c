/*
 * SigMF metadata reader for auto-configuring from .sigmf-meta files
 *
 * Parses .sigmf-meta JSON to extract core:datatype, core:sample_rate,
 * and captures[0].core:frequency for automatic IQ file configuration.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "sigmf.h"

/* IQ format enum values (must match main.c / options.c) */
#define FMT_CI8  0
#define FMT_CI16 1
#define FMT_CF32 2
#define FMT_CU8  3

/*
 * Map SigMF core:datatype string to internal IQ format.
 * Returns format enum or -1 if unsupported.
 *
 * SigMF datatype format: [c|r][f|i|u][bits]_[le|be]
 *   c = complex, r = real
 *   f = float, i = signed int, u = unsigned int
 *   bits = per-component bit width
 *   _le = little-endian, _be = big-endian (omitted for 8-bit)
 *
 * iridium-sniffer only supports complex formats on little-endian (x86).
 */
static int sigmf_parse_datatype(const char *dt)
{
    if (!dt)
        return -1;

    /* Complex float 32-bit little-endian */
    if (strcmp(dt, "cf32_le") == 0)
        return FMT_CF32;

    /* Complex signed int 16-bit little-endian */
    if (strcmp(dt, "ci16_le") == 0)
        return FMT_CI16;

    /* Complex signed int 8-bit (no endianness suffix for single-byte) */
    if (strcmp(dt, "ci8") == 0)
        return FMT_CI8;

    /* Complex unsigned int 8-bit, offset 128 */
    if (strcmp(dt, "cu8") == 0)
        return FMT_CU8;

    return -1;
}

int sigmf_read_meta(const char *meta_path,
                    double *sample_rate,
                    double *center_freq,
                    int *iq_format)
{
    /* Read entire file into memory */
    FILE *f = fopen(meta_path, "r");
    if (!f) {
        fprintf(stderr, "sigmf: cannot open %s\n", meta_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 1024 * 1024) {
        fprintf(stderr, "sigmf: metadata file too large or empty\n");
        fclose(f);
        return -1;
    }
    fseek(f, 0, SEEK_SET);

    char *json_str = malloc(fsize + 1);
    if (!json_str) {
        fclose(f);
        return -1;
    }
    size_t nread = fread(json_str, 1, fsize, f);
    fclose(f);
    if (nread == 0) {
        free(json_str);
        fprintf(stderr, "sigmf: failed to read %s\n", meta_path);
        return -1;
    }
    json_str[nread] = '\0';

    /* Parse JSON */
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) {
        fprintf(stderr, "sigmf: failed to parse JSON in %s\n", meta_path);
        return -1;
    }

    /* Extract global.core:datatype (required by SigMF spec) */
    cJSON *global = cJSON_GetObjectItemCaseSensitive(root, "global");
    if (global) {
        cJSON *datatype = cJSON_GetObjectItemCaseSensitive(global,
                                                            "core:datatype");
        if (cJSON_IsString(datatype) && datatype->valuestring) {
            int fmt = sigmf_parse_datatype(datatype->valuestring);
            if (fmt >= 0) {
                *iq_format = fmt;
            } else {
                fprintf(stderr, "sigmf: unsupported datatype '%s'\n",
                        datatype->valuestring);
            }
        }

        /* Extract global.core:sample_rate (optional) */
        cJSON *sr = cJSON_GetObjectItemCaseSensitive(global,
                                                      "core:sample_rate");
        if (cJSON_IsNumber(sr))
            *sample_rate = sr->valuedouble;
    }

    /* Extract captures[0].core:frequency (optional) */
    cJSON *captures = cJSON_GetObjectItemCaseSensitive(root, "captures");
    if (cJSON_IsArray(captures)) {
        cJSON *cap0 = cJSON_GetArrayItem(captures, 0);
        if (cap0) {
            cJSON *freq = cJSON_GetObjectItemCaseSensitive(cap0,
                                                            "core:frequency");
            if (cJSON_IsNumber(freq))
                *center_freq = freq->valuedouble;
        }
    }

    cJSON_Delete(root);
    return 0;
}
