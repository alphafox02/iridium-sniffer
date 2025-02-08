/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#ifndef __SDR_H__
#define __SDR_H__

#include <stdint.h>

#define SAMPLE_FMT_INT8   0
#define SAMPLE_FMT_FLOAT  1

typedef struct _sample_buf_t {
    unsigned num;
    int format;           /* SAMPLE_FMT_INT8 or SAMPLE_FMT_FLOAT */
    int8_t samples[];     /* for SAMPLE_FMT_FLOAT: cast to float* (4x larger) */
} sample_buf_t;

void push_samples(sample_buf_t *buf);

#endif
