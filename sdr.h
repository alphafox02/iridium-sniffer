/*
 * Copyright (c) 2022 ICE9 Consulting LLC
 */

#ifndef __SDR_H__
#define __SDR_H__

#include <stdint.h>

#define SAMPLE_FMT_INT8   0
#define SAMPLE_FMT_FLOAT  1

/* Clock/time source configuration for SDR backends */
#define CLOCK_SRC_INTERNAL  0
#define CLOCK_SRC_EXTERNAL  1
#define CLOCK_SRC_GPSDO     2

typedef struct _sample_buf_t {
    unsigned num;
    int format;           /* SAMPLE_FMT_INT8 or SAMPLE_FMT_FLOAT */
    uint64_t hw_timestamp_ns;  /* hardware timestamp in ns (0 = not available) */
    int8_t samples[];     /* for SAMPLE_FMT_FLOAT: cast to float* (4x larger) */
} sample_buf_t;

void push_samples(sample_buf_t *buf);

#endif
