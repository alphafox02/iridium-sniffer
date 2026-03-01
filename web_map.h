/*
 * Built-in web map server for Iridium ring alerts and satellites
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Built-in web map for Iridium beam tracking, MT positions, and satellites
 *
 * Runs a minimal HTTP server with SSE for real-time map updates.
 * Enable with --web[=PORT] (default port 8888).
 */

#ifndef __WEB_MAP_H__
#define __WEB_MAP_H__

#include <stdint.h>
#include "frame_decode.h"
#include "ida_decode.h"

/* Initialize and start the web map HTTP server on the given port.
 * Spawns a background thread. Returns 0 on success. */
int web_map_init(int port);

/* Shut down the web map server and free resources. */
void web_map_shutdown(void);

/* Add a decoded IRA (ring alert) to the map state. Thread-safe.
 * Routes to beam storage (alt < 100) or satellite storage (700-900). */
void web_map_add_ra(const ira_data_t *ra, uint64_t timestamp,
                     double frequency);

/* Add/update a satellite from a decoded IBC frame. Thread-safe. */
void web_map_add_sat(const ibc_data_t *ibc, uint64_t timestamp);

/* Set estimated receiver position from Doppler positioning. Thread-safe. */
void web_map_set_position(double lat, double lon, double hdop);

/* Add an MT (mobile terminal) position. Thread-safe. */
void web_map_add_mt(double lat, double lon, int alt, uint16_t msg_type,
                     uint64_t timestamp, double frequency);

/* IDA message callback for MT position extraction.
 * Pass to ida_reassemble() when --web is active. */
void mtpos_ida_cb(const uint8_t *data, int len, uint64_t timestamp,
                   double frequency, ir_direction_t direction,
                   float magnitude, void *user);

/* Add a beam-based aircraft position fix from an ACARS message.
 * reg: aircraft registration (tail number, no leading dots).
 * flight: flight number or empty string if unknown.
 * lat/lon: beam center from the IRA ground beam that carried the message.
 * Thread-safe. */
void web_map_add_aircraft(const char *reg, const char *flight,
                           double lat, double lon,
                           int sat_id, int beam_id,
                           uint64_t timestamp_ns, double frequency);

#endif
