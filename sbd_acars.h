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

/* Initialize ACARS subsystem. station_id may be NULL.
 * udp_hosts/udp_ports are parallel arrays of length udp_count for
 * JSON streaming to one or more remote endpoints (dumpvdl2 format).
 * hub_host/hub_port is the optional --feed UDP endpoint (iridium-toolkit format).
 * af_host/af_port is the optional --feed TCP endpoint (iridium-toolkit format). */
void acars_init(const char *station_id, const char **udp_hosts,
                const int *udp_ports, int udp_count,
                const char *hub_host, int hub_port,
                const char *af_host, int af_port);

/* IDA message callback for ACARS processing.
 * Pass this to ida_reassemble() as the callback function. */
void acars_ida_cb(const uint8_t *data, int len,
                  uint64_t timestamp, double frequency,
                  ir_direction_t direction, float magnitude,
                  void *user);

/* Shut down ACARS subsystem (free libacars resources). */
void acars_shutdown(void);

/* Print SBD/ACARS stats summary to stderr. */
void acars_print_stats(void);

/* Output mode (set before first callback) */
extern int acars_json;

#endif
