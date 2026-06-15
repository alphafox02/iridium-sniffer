/*
 * Epiq Solutions Sidekiq SDR backend for iridium-sniffer
 *
 * Copyright 2025-2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Native libsidekiq backend (AD9361-based SKUs: Stretch, m.2, Z2, Z3u, X40, ...).
 * Ported from the verified blue-dragon crates/sdr/src/sidekiq.rs FFI wrapper.
 */

#ifndef __SIDEKIQ_H__
#define __SIDEKIQ_H__

void sidekiq_list(void);
/* Returns an opaque handle (heap-allocated card context) or exits on failure. */
void *sidekiq_setup(char *serial);
void *sidekiq_stream_thread(void *arg);
void sidekiq_close(void *ctx);

#endif
