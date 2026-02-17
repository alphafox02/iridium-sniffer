/*
 * Built-in web map server for Iridium ring alerts and satellites
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Built-in web map for Iridium ring alerts and satellite tracking
 *
 * Runs a minimal HTTP server with SSE for real-time map updates.
 * Enable with --web[=PORT] (default port 8888).
 */

#ifndef __WEB_MAP_H__
#define __WEB_MAP_H__

#include <stdint.h>
#include "frame_decode.h"

/* Initialize and start the web map HTTP server on the given port.
 * Spawns a background thread. Returns 0 on success. */
int web_map_init(int port);

/* Shut down the web map server and free resources. */
void web_map_shutdown(void);

/* Add a decoded IRA (ring alert) to the map state. Thread-safe. */
void web_map_add_ra(const ira_data_t *ra, uint64_t timestamp,
                     double frequency);

/* Add/update a satellite from a decoded IBC frame. Thread-safe. */
void web_map_add_sat(const ibc_data_t *ibc, uint64_t timestamp);

/* Set estimated receiver position from Doppler positioning. Thread-safe. */
void web_map_set_position(double lat, double lon, double hdop);

#endif
