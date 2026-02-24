/*
 * SBD/ACARS reassembly from IDA messages
 *
 * Extracts SBD (Short Burst Data) packets from reassembled IDA payloads,
 * handles multi-packet SBD reassembly, and parses ACARS messages.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __SBD_ACARS_H__
#define __SBD_ACARS_H__

#include <stdint.h>
#include "burst_downmix.h"

/* Initialize ACARS subsystem. station_id may be NULL. */
void acars_init(const char *station_id);

/* IDA message callback for ACARS processing.
 * Pass this to ida_reassemble() as the callback function. */
void acars_ida_cb(const uint8_t *data, int len,
                  uint64_t timestamp, double frequency,
                  ir_direction_t direction, float magnitude,
                  void *user);

/* Output mode (set before first callback) */
extern int acars_json;

#endif
