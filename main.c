/*
 * iridium-sniffer: Standalone Iridium satellite burst detector and demodulator
 * Outputs iridium-toolkit compatible RAW format to stdout
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * iridium-sniffer: Standalone Iridium satellite burst detector and demodulator
 * Outputs iridium-toolkit compatible RAW format to stdout
 */

#define _GNU_SOURCE
#include <err.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_HACKRF
#include "hackrf.h"
#endif
#ifdef HAVE_BLADERF
#include "bladerf.h"
#endif
#ifdef HAVE_UHD
#include "usrp.h"
#endif
#ifdef HAVE_SOAPYSDR
#include "soapysdr.h"
#endif
#ifdef HAVE_SDRPLAY
#include "sdrplay.h"
#endif
#ifdef HAVE_SIDEKIQ
#include "sidekiq.h"
#endif

#include "sdr.h"
#include "iridium.h"
#include "burst_detect.h"
#include "burst_downmix.h"
#include "qpsk_demod.h"
#include "frame_output.h"
#include "frame_decode.h"
#include "web_map.h"
#include "vita49.h"
#include "ida_decode.h"
#include "doppler_pos.h"
#include "voice_decode.h"
#include "gsmtap.h"
#include "sbd_acars.h"
#include "fftw_lock.h"
#include "simd_kernels.h"
#include "aircraft_db.h"
#include "basestation.h"
#include "waypoint_db.h"
#include <fftw3.h>

/* FFTW planner mutex (defined here, declared in fftw_lock.h) */
pthread_mutex_t fftw_planner_mutex;

/* FFTW wisdom file path */
#define FFTW_WISDOM_FILE ".iridium-sniffer-fftw-wisdom"

static void fftw_load_wisdom(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", home, FFTW_WISDOM_FILE);
    if (fftwf_import_wisdom_from_filename(path))
        fprintf(stderr, "FFTW: loaded wisdom from %s\n", path);
}

static void fftw_save_wisdom(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", home, FFTW_WISDOM_FILE);
    if (fftwf_export_wisdom_to_filename(path))
        fprintf(stderr, "FFTW: saved wisdom to %s\n", path);
}

#define C_FEK_BLOCKING_QUEUE_IMPLEMENTATION
#define C_FEK_FAIR_LOCK_IMPLEMENTATION
#include "blocking_queue.h"

#include "pthread_barrier.h"

/* IQ sample format */
typedef enum {
    FMT_CI8 = 0,   /* interleaved int8 (default, SDR native) */
    FMT_CI16,       /* interleaved int16 */
    FMT_CF32,       /* interleaved float32 */
} iq_format_t;

/* ---- Global configuration ---- */
double samp_rate = 10000000;
double center_freq = IR_DEFAULT_CENTER_FREQ;
int verbose = 0;
int live = 0;
char *file_info = NULL;
double threshold_db = IR_DEFAULT_THRESHOLD;
iq_format_t iq_format = FMT_CI8;

/* SDR selection */
char *serial = NULL;
#ifdef HAVE_BLADERF
int bladerf_num = -1;
#endif
#ifdef HAVE_UHD
char *usrp_serial = NULL;
#endif
#ifdef HAVE_SOAPYSDR
int soapy_num = -1;
char *soapy_args = NULL;
#define SOAPY_SETTINGS_MAX 8
char *soapy_setting_keys[SOAPY_SETTINGS_MAX];
char *soapy_setting_vals[SOAPY_SETTINGS_MAX];
int soapy_setting_count = 0;
#define SOAPY_GAINS_MAX 8
char *soapy_gain_elem_names[SOAPY_GAINS_MAX];
double soapy_gain_elem_vals[SOAPY_GAINS_MAX];
int soapy_gain_elem_count = 0;
#endif
#ifdef HAVE_SDRPLAY
char *sdrplay_serial = NULL;
#endif
#ifdef HAVE_SIDEKIQ
char *sidekiq_dev = NULL;
#endif

/* Per-SDR gain settings (defaults from gr-iridium example configs) */
int hackrf_lna_gain = 40;
int hackrf_vga_gain = 20;
int hackrf_amp_enable = 0;
int bladerf_gain_val = 40;
int usrp_gain_val = 40;
double soapy_gain_val = 30.0;
int sdrplay_gain_val = -1;  /* -1 = AGC (default), 0-59 = manual */
int sidekiq_gain_val = 50;  /* hardware gain index (not dB), 0..~76 */
int bias_tee = 0;
int web_enabled = 0;
int web_port = 8888;
int gsmtap_enabled = 0;
char *gsmtap_host = NULL;
int gsmtap_port = GSMTAP_DEFAULT_PORT;

/* GPU acceleration: enabled by default, loaded via dlopen plugin at runtime */
int use_gpu = 1;

int simd_mode = 0;  /* SIMD_AUTO */
char *save_bursts_dir = NULL;
int diagnostic_mode = 0;
int use_gardner = 1;
int parsed_mode = 0;
int use_chase = 0;
int position_enabled = 0;
double position_height = 0;
int acars_enabled = 0;
int voice_enabled = 0;
char *station_id = NULL;

/* Multiple UDP endpoints for ACARS JSON streaming */
#define ACARS_UDP_MAX 4
char *acars_udp_hosts[ACARS_UDP_MAX];
int acars_udp_ports[ACARS_UDP_MAX];
int acars_udp_count = 0;

/* Aggregator feed endpoints (iridium-toolkit JSON format, repeatable) */
#define FEED_MAX 4
char *feed_hosts[FEED_MAX];
int feed_ports[FEED_MAX];
int feed_is_tcp[FEED_MAX];
int feed_count = 0;

/* ZMQ PUB output for multi-consumer iridium-toolkit compatibility */
int zmq_enabled = 0;
char *zmq_endpoint = NULL;
#define ZMQ_DEFAULT_ENDPOINT "tcp://*:7006"

/* ZMQ SUB input for receiving IQ samples over network */
int zmq_sub_enabled = 0;
char *zmq_sub_endpoint = NULL;
#define ZMQ_SUB_DEFAULT_ENDPOINT "tcp://127.0.0.1:5555"

/* VITA 49 (VRT) UDP input */
int vita49_enabled = 0;
char *vita49_endpoint = NULL;

/* BaseStation (SBS) output */
int basestation_enabled = 0;
int basestation_beam = 0;
char *basestation_endpoint = NULL;
char *aircraft_db_path = NULL;

/* Track whether -r, -c, --format were explicitly set (for VITA 49 auto-config) */
int samp_rate_explicit = 0;
int center_freq_explicit = 0;
int iq_format_explicit = 0;

/* VITA 49 context synchronization: vita49 thread signals when context is received */
pthread_mutex_t vita49_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t vita49_ctx_cond = PTHREAD_COND_INITIALIZER;
int vita49_ctx_ready = 0;

/* ---- Beam cache for ACARS aircraft position correlation ---- */
/* Stores recent IRA ground beam positions (alt < 100) so the ACARS
 * callback can correlate a received message with the beam it arrived on. */

#define BEAM_CACHE_SIZE 64

typedef struct {
    double lat, lon;
    int sat_id, beam_id;
    uint64_t timestamp_ns;  /* 0 = empty slot */
} beam_cache_t;

static beam_cache_t beam_cache[BEAM_CACHE_SIZE];
static int beam_cache_head = 0;
static pthread_mutex_t beam_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* Look up the most recent ground beam position within 10 s before ts_ns.
 * Returns 1 and fills out-params on success, 0 if no match found. */
int beam_cache_lookup(uint64_t ts_ns, double *lat, double *lon,
                      int *sat_id, int *beam_id)
{
    int found = 0;
    pthread_mutex_lock(&beam_cache_lock);
    for (int i = 0; i < BEAM_CACHE_SIZE; i++) {
        int idx = (beam_cache_head - 1 - i + BEAM_CACHE_SIZE) % BEAM_CACHE_SIZE;
        beam_cache_t *e = &beam_cache[idx];
        if (e->timestamp_ns == 0) break;           /* empty -- stop */
        if (e->timestamp_ns > ts_ns) continue;    /* future entry */
        if (ts_ns - e->timestamp_ns > 10000000000ULL) break; /* > 10 s */
        *lat    = e->lat;
        *lon    = e->lon;
        *sat_id = e->sat_id;
        *beam_id = e->beam_id;
        found = 1;
        break;
    }
    pthread_mutex_unlock(&beam_cache_lock);
    return found;
}

/* Clock/time source (CLOCK_SRC_INTERNAL/EXTERNAL/GPSDO from sdr.h) */
int clock_source = CLOCK_SRC_INTERNAL;
int time_source = CLOCK_SRC_INTERNAL;

/* Threading state */
volatile sig_atomic_t running = 1;
pid_t self_pid;

/* Queues */
#define SAMPLES_QUEUE_SIZE 4096
#define BURST_QUEUE_SIZE   2048
#define FRAME_QUEUE_SIZE   512
#define OUTPUT_QUEUE_SIZE  1024
#define MAX_DOWNMIX_WORKERS 32
int num_downmix_workers = 0;  /* 0 = auto-detect from CPU cores */
Blocking_Queue samples_queue;
Blocking_Queue burst_queue;
Blocking_Queue frame_queue;
Blocking_Queue output_queue;

/* Atomic stats counters (for gr-iridium compatible status line) */
atomic_ulong stat_n_detected = 0;
atomic_ulong stat_n_handled = 0;
atomic_ulong stat_n_ok_bursts = 0;
atomic_ulong stat_n_ok_sub = 0;
atomic_ulong stat_n_dropped = 0;
atomic_ulong stat_n_frame_drops = 0;
atomic_ulong stat_n_output_drops = 0;
atomic_ulong stat_sample_count = 0;

/* Global detector pointer for diagnostic stats (set by detector thread) */
burst_detector_t *global_detector = NULL;

/* Input file */
FILE *in_file = NULL;

void parse_options(int argc, char **argv);

/* ---- Sample buffer management ---- */

void push_samples(sample_buf_t *buf) {
    atomic_fetch_add(&stat_sample_count, buf->num);
    if (blocking_queue_add(&samples_queue, buf) == BQ_FULL) {
        if (verbose)
            fprintf(stderr, "WARNING: dropped samples\n");
        free(buf);
    }
}

/* ---- Utility ---- */

static unsigned long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL;
}

/* ---- File spewer thread ---- */

static inline int8_t clamp8(float v) {
    if (v > 127.0f) return 127;
    if (v < -128.0f) return -128;
    return (int8_t)v;
}

static void *spewer_thread(void *arg) {
    FILE *f = (FILE *)arg;
    size_t block = 32768;  /* samples per read (each sample = I + Q) */

    while (running) {
        sample_buf_t *s;
        size_t r;

        switch (iq_format) {
        case FMT_CI8:
            /* Native: 2 bytes per sample */
            s = malloc(sizeof(*s) + block * 2);
            s->format = SAMPLE_FMT_INT8;
            r = fread(s->samples, 2, block, f);
            break;

        case FMT_CI16: {
            /* 4 bytes per sample -> convert to int8 */
            s = malloc(sizeof(*s) + block * 2);
            s->format = SAMPLE_FMT_INT8;
            int16_t *tmp = malloc(block * 4);
            r = fread(tmp, 4, block, f);
            for (size_t i = 0; i < r * 2; i++)
                s->samples[i] = (int8_t)(tmp[i] >> 8);
            free(tmp);
            break;
        }

        case FMT_CF32: {
            /* Pass float32 samples directly (no int8 quantization) */
            s = malloc(sizeof(*s) + block * 8);
            s->format = SAMPLE_FMT_FLOAT;
            r = fread(s->samples, 8, block, f);
            break;
        }

        default:
            s = malloc(sizeof(*s));
            s->format = SAMPLE_FMT_INT8;
            r = 0;
            break;
        }

        if (r == 0) {
            free(s);
            break;
        }
        s->num = r;
        s->hw_timestamp_ns = 0;
        if (blocking_queue_put(&samples_queue, s) != 0) {
            free(s);
            break;
        }
    }

    /* Wait for queue to drain */
    while (running && samples_queue.queue_size > 0)
        usleep(10000);

    running = 0;
    kill(self_pid, SIGINT);
    return NULL;
}

/* ---- ZMQ SUB input thread ---- */
#ifdef HAVE_ZMQ
#include <zmq.h>

static void *zmq_sub_ctx = NULL;
static void *zmq_sub_socket = NULL;

static void *zmq_sub_thread(void *arg) {
    (void)arg;

    zmq_sub_ctx = zmq_ctx_new();
    if (!zmq_sub_ctx) {
        warnx("zmq-sub: cannot create context");
        running = 0;
        kill(self_pid, SIGINT);
        return NULL;
    }

    zmq_sub_socket = zmq_socket(zmq_sub_ctx, ZMQ_SUB);
    if (!zmq_sub_socket) {
        warnx("zmq-sub: cannot create socket");
        zmq_ctx_destroy(zmq_sub_ctx);
        zmq_sub_ctx = NULL;
        running = 0;
        kill(self_pid, SIGINT);
        return NULL;
    }

    /* Subscribe to all messages */
    zmq_setsockopt(zmq_sub_socket, ZMQ_SUBSCRIBE, "", 0);

    const char *ep = zmq_sub_endpoint ? zmq_sub_endpoint
                                      : ZMQ_SUB_DEFAULT_ENDPOINT;
    if (zmq_connect(zmq_sub_socket, ep) != 0) {
        warnx("zmq-sub: cannot connect to %s: %s", ep, zmq_strerror(errno));
        zmq_close(zmq_sub_socket);
        zmq_ctx_destroy(zmq_sub_ctx);
        zmq_sub_socket = NULL;
        zmq_sub_ctx = NULL;
        running = 0;
        kill(self_pid, SIGINT);
        return NULL;
    }

    fprintf(stderr, "zmq-sub: connected to %s (format=%s)\n", ep,
            iq_format == FMT_CF32 ? "cf32" :
            iq_format == FMT_CI16 ? "cs16" : "cs8");

    while (running) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);

        int rc = zmq_msg_recv(&msg, zmq_sub_socket, 0);
        if (rc < 0) {
            zmq_msg_close(&msg);
            if (errno == EINTR)
                continue;
            break;
        }

        size_t len = zmq_msg_size(&msg);
        void *data = zmq_msg_data(&msg);

        sample_buf_t *s;
        size_t num_samples;

        switch (iq_format) {
        case FMT_CF32:
            /* 8 bytes per sample (2 x float32) */
            num_samples = len / 8;
            if (num_samples == 0) { zmq_msg_close(&msg); continue; }
            s = malloc(sizeof(*s) + num_samples * 8);
            s->format = SAMPLE_FMT_FLOAT;
            memcpy(s->samples, data, num_samples * 8);
            break;

        case FMT_CI16: {
            /* 4 bytes per sample -> convert to int8 */
            num_samples = len / 4;
            if (num_samples == 0) { zmq_msg_close(&msg); continue; }
            s = malloc(sizeof(*s) + num_samples * 2);
            s->format = SAMPLE_FMT_INT8;
            int16_t *src = (int16_t *)data;
            for (size_t i = 0; i < num_samples * 2; i++)
                s->samples[i] = (int8_t)(src[i] >> 8);
            break;
        }

        case FMT_CI8:
        default:
            /* 2 bytes per sample (native int8) */
            num_samples = len / 2;
            if (num_samples == 0) { zmq_msg_close(&msg); continue; }
            s = malloc(sizeof(*s) + num_samples * 2);
            s->format = SAMPLE_FMT_INT8;
            memcpy(s->samples, data, num_samples * 2);
            break;
        }

        zmq_msg_close(&msg);

        s->num = num_samples;
        s->hw_timestamp_ns = 0;
        push_samples(s);
    }

    zmq_close(zmq_sub_socket);
    zmq_ctx_destroy(zmq_sub_ctx);
    zmq_sub_socket = NULL;
    zmq_sub_ctx = NULL;

    running = 0;
    kill(self_pid, SIGINT);
    return NULL;
}
#endif /* HAVE_ZMQ */

/* ---- IDA/GSMTAP state ---- */

static ida_context_t ida_ctx;
static ida_context_t acars_ida_ctx;
static ida_context_t mtpos_ida_ctx;

static atomic_ulong gsmtap_sent_count = 0;

static void gsmtap_ida_cb(const uint8_t *data, int len,
                           uint64_t timestamp, double frequency,
                           ir_direction_t direction, float magnitude,
                           void *user)
{
    (void)timestamp; (void)user;
    int8_t dbm = (magnitude > 0) ? (int8_t)(20.0f * log10f(magnitude)) : -128;
    gsmtap_send(data, len, frequency, direction, dbm);
    atomic_fetch_add(&gsmtap_sent_count, 1);
}

/* ---- Output item: passed from consumer to output thread ---- */

typedef struct {
    /* Demodulated frame fields needed for frame_decode */
    demod_frame_t demod;        /* shallow copy -- bits/llr ownership transferred */
    /* IDA decode result */
    int ida_ok;
    ida_burst_t burst;
} output_item_t;

/* ---- Frame consumer: QPSK demod + IDA decode + stdout (fast path) ---- */

static void *frame_consumer_thread(void *arg) {
    (void)arg;
    while (1) {
        downmix_frame_t *frame;
        if (blocking_queue_take(&frame_queue, &frame) != 0)
            break;

        atomic_fetch_add(&stat_n_handled, 1);

        demod_frame_t *demod = NULL;
        if (qpsk_demod(frame, &demod)) {
            atomic_fetch_add(&stat_n_ok_bursts, 1);
            atomic_fetch_add(&stat_n_ok_sub, 1);

            /* Try IDA decode if parsed output or GSMTAP is active */
            int ida_ok = 0;
            ida_burst_t burst;
            if (parsed_mode || gsmtap_enabled || acars_enabled || web_enabled)
                ida_ok = ida_decode(demod, &burst);

            /* Output: parsed IDA line if available, otherwise RAW */
            if (parsed_mode && ida_ok)
                frame_output_print_ida(&burst);
            else
                frame_output_print(demod);

            /* Hand off to output thread for slow work (web map, ACARS, GSMTAP) */
            if (web_enabled || position_enabled || gsmtap_enabled || acars_enabled) {
                output_item_t *item = malloc(sizeof(output_item_t));
                if (item) {
                    item->demod = *demod;   /* shallow copy */
                    item->ida_ok = ida_ok;
                    item->burst = burst;
                    /* Transfer bits/llr ownership to output thread */
                    if (blocking_queue_add(&output_queue, item) == BQ_FULL) {
                        free(demod->bits);
                        free(demod->llr);
                        free(item);
                        atomic_fetch_add(&stat_n_output_drops, 1);
                    }
                } else {
                    free(demod->bits);
                    free(demod->llr);
                }
            } else {
                free(demod->bits);
                free(demod->llr);
            }
            free(demod);
        } else if (verbose) {
            fprintf(stderr, "demod: UW check failed id=%lu freq=%.0f Hz dir=%s\n",
                    (unsigned long)frame->id, frame->center_frequency,
                    frame->direction == DIR_DOWNLINK ? "DL" :
                    frame->direction == DIR_UPLINK ? "UL" : "??");
        }

        free(frame->samples);
        free(frame);
    }
    return NULL;
}

/* ---- Output thread: frame decode, web map, ACARS, GSMTAP (slow path) ---- */

static void *output_thread_fn(void *arg) {
    (void)arg;
    while (1) {
        output_item_t *item;
        if (blocking_queue_take(&output_queue, &item) != 0)
            break;

        demod_frame_t *demod = &item->demod;

        if (web_enabled || position_enabled || voice_enabled) {
            decoded_frame_t decoded;
            if (frame_decode(demod, &decoded)) {
                if (decoded.type == FRAME_IRA) {
                    if (web_enabled) {
                        web_map_add_ra(&decoded.ira, decoded.timestamp,
                                        decoded.frequency);
                        if (decoded.ira.alt >= 0 && decoded.ira.alt < 100) {
                            pthread_mutex_lock(&beam_cache_lock);
                            beam_cache[beam_cache_head % BEAM_CACHE_SIZE] =
                                (beam_cache_t){
                                    .lat = decoded.ira.lat,
                                    .lon = decoded.ira.lon,
                                    .sat_id = decoded.ira.sat_id,
                                    .beam_id = decoded.ira.beam_id,
                                    .timestamp_ns = decoded.timestamp
                                };
                            beam_cache_head++;
                            pthread_mutex_unlock(&beam_cache_lock);
                        }
                    }
                    if (position_enabled)
                        doppler_pos_add_measurement(&decoded.ira,
                                                     decoded.frequency,
                                                     decoded.timestamp);
                } else if (decoded.type == FRAME_IBC) {
                    if (web_enabled)
                        web_map_add_sat(&decoded.ibc, decoded.timestamp);
                } else if (decoded.type == FRAME_VOC) {
                    if (voice_enabled)
                        voice_decode_add_frame(&decoded.voc,
                                                decoded.timestamp,
                                                decoded.frequency);
                }
            }
        }

        if (gsmtap_enabled) {
            if (item->ida_ok)
                ida_reassemble(&ida_ctx, &item->burst, gsmtap_ida_cb, NULL);
            ida_reassemble_flush(&ida_ctx, demod->timestamp);
        }

        if (acars_enabled) {
            if (item->ida_ok)
                ida_reassemble(&acars_ida_ctx, &item->burst,
                               acars_ida_cb, NULL);
            ida_reassemble_flush(&acars_ida_ctx, demod->timestamp);
        }

        if (web_enabled) {
            if (item->ida_ok)
                ida_reassemble(&mtpos_ida_ctx, &item->burst,
                               mtpos_ida_cb, NULL);
            ida_reassemble_flush(&mtpos_ida_ctx, demod->timestamp);
        }

        free(demod->bits);
        free(demod->llr);
        free(item);
    }
    return NULL;
}

/* ---- Stats thread (gr-iridium/iridium-extractor compatible format) ---- */
/*
 * Output format (to stderr, once per second):
 *   timestamp | i: N/s | i_avg: N/s | q_max: N | i_ok: N% |
 *   o: N/s | ok: N% | ok: N/s | ok_avg: N% | ok: TOTAL | ok_avg: N/s | d: N
 *
 * In offline (file) mode, "i: N/s" is replaced with "srr: N%" (sample rate ratio).
 */

static void *stats_thread_fn(void *arg) {
    (void)arg;
    unsigned long t0 = now_ms();
    unsigned long prev_t = t0;
    unsigned long prev_det = 0, prev_ok = 0, prev_sub = 0;
    unsigned long prev_handled = 0, prev_samples = 0;
    unsigned q_max = 0;

    while (running) {
        usleep(1000000);
        if (!running) break;

        unsigned long now = now_ms();
        double dt = (now - prev_t) / 1000.0;
        double elapsed = (now - t0) / 1000.0;
        if (dt < 0.01 || elapsed < 0.01) { prev_t = now; continue; }
        prev_t = now;

        unsigned long det     = atomic_load(&stat_n_detected);
        unsigned long handled = atomic_load(&stat_n_handled);
        unsigned long ok      = atomic_load(&stat_n_ok_bursts);
        unsigned long sub     = atomic_load(&stat_n_ok_sub);
        unsigned long dropped = atomic_load(&stat_n_dropped);
        unsigned long samp    = atomic_load(&stat_sample_count);

        /* Per-interval deltas */
        unsigned long dd    = det     - prev_det;
        unsigned long dk    = ok      - prev_ok;
        unsigned long ds    = sub     - prev_sub;
        unsigned long dh    = handled - prev_handled;
        unsigned long dsamp = samp    - prev_samples;

        /* Track max queue depth */
        unsigned qsz = (unsigned)samples_queue.queue_size;
        if (qsz > q_max) q_max = qsz;

        /* Rates */
        double in_rate     = dd / dt;
        double in_rate_avg = det / elapsed;
        double out_rate    = dh / dt;
        double ok_rate     = ds / dt;
        double ok_rate_avg = sub / elapsed;

        /* Ratios */
        double in_ok_pct  = dd > 0  ? 100.0 * dk  / dd  : 0;
        double out_ok_pct = dd > 0  ? 100.0 * ds  / dd  : 0;
        double ok_avg_pct = det > 0 ? 100.0 * sub / det : 0;

        if (diagnostic_mode) {
            /* Diagnostic mode display */
            int runtime_sec = (int)elapsed;
            int hours = runtime_sec / 3600;
            int mins = (runtime_sec % 3600) / 60;
            int secs = runtime_sec % 60;

            /* Bursts per minute */
            double burst_per_min = (elapsed > 0) ? (det * 60.0 / elapsed) : 0;

            /* Get noise floor and peak signal from detector */
            float noise_floor = global_detector ? burst_detector_noise_floor(global_detector) : -120.0f;
            float peak_signal = global_detector ? burst_detector_peak_signal(global_detector) : 0.0f;
            float signal_gap = peak_signal - noise_floor;

            fprintf(stderr, "Runtime: %02d:%02d:%02d  |  "
                           "Bursts: %lu detected (%.1f/min)  |  "
                           "Decoded: %lu (ok_avg: %.0f%%)  |  "
                           "Noise: %.1f dBFS/Hz  |  "
                           "Peak: %.1f dB  ",
                           hours, mins, secs,
                           det, burst_per_min,
                           sub, ok_avg_pct,
                           noise_floor, peak_signal);

            /* Simple status guidance */
            if (det == 0 && elapsed > 120) {
                fprintf(stderr, "| No bursts detected - check antenna");
            } else if (ok_avg_pct >= 70 && burst_per_min >= 3) {
                fprintf(stderr, "| Setup looks good (gap: %.1f dB)", signal_gap);
            } else if (ok_avg_pct < 70 && det > 10) {
                fprintf(stderr, "| Low decode rate - try adjusting gain");
            } else if (ok_avg_pct >= 70 && burst_per_min < 3 && elapsed > 60) {
                fprintf(stderr, "| Good decode rate but low burst count");
            }

            fprintf(stderr, "\n");
        } else {
            /* Print in gr-iridium format */
            fprintf(stderr, "%ld", (long)time(NULL));
            if (!live) {
                double srr = (samp_rate > 0 && dt > 0) ? dsamp / (samp_rate * dt) * 100 : 0;
                fprintf(stderr, " | srr: %5.1f%%", srr);
            } else {
                fprintf(stderr, " | i: %3.0f/s", in_rate);
            }
            fprintf(stderr, " | i_avg: %3.0f/s", in_rate_avg);
            fprintf(stderr, " | q_max: %4u", q_max);
            fprintf(stderr, " | i_ok: %3.0f%%", in_ok_pct);
            fprintf(stderr, " | o: %4.0f/s", out_rate);
            fprintf(stderr, " | ok: %3.0f%%", out_ok_pct);
            fprintf(stderr, " | ok: %3.0f/s", ok_rate);
            fprintf(stderr, " | ok_avg: %3.0f%%", ok_avg_pct);
            fprintf(stderr, " | ok: %10lu", sub);
            fprintf(stderr, " | ok_avg: %3.0f/s", ok_rate_avg);
            fprintf(stderr, " | d: %lu", dropped);
            {
                unsigned long fd = atomic_load(&stat_n_frame_drops);
                unsigned long od = atomic_load(&stat_n_output_drops);
                if (fd > 0 || od > 0)
                    fprintf(stderr, " | fd: %lu/%lu", fd, od);
            }
            fprintf(stderr, "\n");
        }

        /* Suppress unused variable warning */
        (void)dsamp;

        /* Doppler positioning: attempt solve every 10 seconds */
        if (position_enabled && (int)elapsed % 10 == 0 && elapsed > 5) {
            doppler_solution_t sol;
            if (doppler_pos_solve(&sol)) {
                fprintf(stderr, "POSITION: %.6f, %.6f (HDOP=%.1f, %d sats, %d meas)\n",
                        sol.lat, sol.lon, sol.hdop, sol.n_satellites,
                        sol.n_measurements);
                if (web_enabled)
                    web_map_set_position(sol.lat, sol.lon, sol.hdop);
            } else if ((int)elapsed % 60 == 0) {
                fprintf(stderr, "POSITION: waiting (%d sats, %d meas)\n",
                        sol.n_satellites, sol.n_measurements);
            }
        }

        /* Reset per-interval tracking */
        q_max = 0;
        prev_det     = det;
        prev_ok      = ok;
        prev_sub     = sub;
        prev_handled = handled;
        prev_samples = samp;
    }
    return NULL;
}

/* ---- Signal handling ---- */

static void sig_handler(int signo) {
    (void)signo;
    running = 0;
}

/* ---- Main ---- */

int main(int argc, char **argv) {
    pthread_t detector, spewer, stats;
#ifdef HAVE_HACKRF
    hackrf_device *hackrf = NULL;
#endif
#ifdef HAVE_BLADERF
    struct bladerf *bladerf_dev = NULL;
    pthread_t bladerf_thread;
#endif
#ifdef HAVE_UHD
    uhd_usrp_handle usrp = NULL;
    pthread_t usrp_thread;
#endif
#ifdef HAVE_SOAPYSDR
    SoapySDRDevice *soapy = NULL;
    pthread_t soapy_thread;
#endif
#ifdef HAVE_SDRPLAY
    void *sdrplay_ctx = NULL;
    pthread_t sdrplay_thread;
#endif
#ifdef HAVE_SIDEKIQ
    void *sidekiq_ctx = NULL;
    pthread_t sidekiq_thread;
#endif

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    self_pid = getpid();

    parse_options(argc, argv);

    /* Initialize SIMD dispatch (must be before any DSP) */
    simd_init(simd_mode);

    fprintf(stderr, "iridium-sniffer: center_freq=%.0f Hz, sample_rate=%.0f Hz, threshold=%.1f dB\n",
            center_freq, samp_rate, threshold_db);

    if (diagnostic_mode) {
        fprintf(stderr, "\nDiagnostic Mode - Setup Verification (RAW output suppressed)\n");
        fprintf(stderr, "Target: ok_avg >70%% for good performance\n");
        fprintf(stderr, "Press Ctrl+C to exit\n\n");
    }

    fftw_lock_init();
    fftw_load_wisdom();
    frame_output_init(file_info);

#ifdef HAVE_ZMQ
    if (zmq_enabled) {
        const char *ep = zmq_endpoint ? zmq_endpoint : ZMQ_DEFAULT_ENDPOINT;
        if (frame_output_zmq_init(ep) != 0)
            errx(1, "Failed to bind ZMQ PUB socket on %s", ep);
        fprintf(stderr, "ZMQ: publishing on %s\n", ep);
    }
#endif

    if (web_enabled || gsmtap_enabled || position_enabled || voice_enabled)
        frame_decode_init();

    if (voice_enabled)
        voice_decode_init();

    if (parsed_mode || gsmtap_enabled || acars_enabled || web_enabled || voice_enabled)
        ida_decode_init();

    if (position_enabled) {
        doppler_pos_init();
        /* Height aiding defaults to 0m (sea level) unless user specifies
         * a value.  Required to prevent solver diverging to extreme altitude
         * when satellite geometry is poor. */
        doppler_pos_set_height(position_height);
        fprintf(stderr, "Doppler positioning: enabled (height aiding: %.0f m)\n",
                position_height);
    }

    if (web_enabled) {
        if (web_map_init(web_port) != 0)
            errx(1, "Failed to start web map server on port %d", web_port);
    }

    if (basestation_enabled) {
        /* Load aircraft database */
        const char *dbpath = aircraft_db_path ? aircraft_db_path
                                               : aircraft_db_default_path();
        if (!dbpath || aircraft_db_load(dbpath) < 0) {
            fprintf(stderr, "basestation: no aircraft database found\n"
                    "  Run: iridium-sniffer --update-db\n"
                    "  Or specify: --aircraft-db=PATH\n");
            /* Continue without database -- positions will be skipped */
        }
        if (basestation_init(basestation_endpoint) != 0)
            errx(1, "Failed to start basestation output");
    }

    if (gsmtap_enabled) {
        if (gsmtap_init(gsmtap_host, gsmtap_port) != 0)
            errx(1, "Failed to initialize GSMTAP socket");
    }

    /* Load waypoint database for ACARS position extraction fallback.
     * Look next to executable first, then in data/ relative to exe. */
    if (acars_enabled || basestation_enabled) {
        char wp_path[512];
        ssize_t exe_len = readlink("/proc/self/exe", wp_path, sizeof(wp_path) - 1);
        if (exe_len > 0) {
            wp_path[exe_len] = '\0';
            char *slash = strrchr(wp_path, '/');
            if (slash) {
                /* Try ../data/waypoints.csv (source tree) */
                snprintf(slash + 1, sizeof(wp_path) - (slash + 1 - wp_path),
                         "../data/waypoints.csv");
                if (waypoint_db_load(wp_path) < 0) {
                    /* Try data/waypoints.csv next to exe */
                    snprintf(slash + 1, sizeof(wp_path) - (slash + 1 - wp_path),
                             "data/waypoints.csv");
                    waypoint_db_load(wp_path);
                }
            }
        }
    }

    if (acars_enabled) {
        acars_init(station_id, (const char **)acars_udp_hosts,
                   acars_udp_ports, acars_udp_count,
                   (const char **)feed_hosts, feed_ports,
                   feed_is_tcp, feed_count);
        fprintf(stderr, "ACARS: enabled (%s output%s",
                acars_json ? "JSON" : "text",
                station_id ? ", station set" : "");
        if (acars_udp_count == 1)
            fprintf(stderr, ", UDP stream");
        else if (acars_udp_count > 1)
            fprintf(stderr, ", %d UDP streams", acars_udp_count);
        for (int i = 0; i < feed_count; i++)
            fprintf(stderr, ", feed %s://%s:%d",
                    feed_is_tcp[i] ? "tcp" : "udp",
                    feed_hosts[i], feed_ports[i]);
        fprintf(stderr, ")\n");
    }

    blocking_queue_init(&samples_queue, SAMPLES_QUEUE_SIZE);
    blocking_queue_init(&burst_queue, BURST_QUEUE_SIZE);
    blocking_queue_init(&frame_queue, FRAME_QUEUE_SIZE);
    blocking_queue_init(&output_queue, OUTPUT_QUEUE_SIZE);

    /* VITA 49 auto-config: start the listener thread early so context packets
     * can provide sample rate, center frequency, and data format before the
     * burst detector is created (which needs those values at init time). */
    if (vita49_enabled) {
        pthread_create(&spewer, NULL, vita49_thread, NULL);
#ifdef __linux__
        pthread_setname_np(spewer, "vita49");
#endif
        /* Wait up to 5 seconds for the first context packet */
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;

        pthread_mutex_lock(&vita49_ctx_mutex);
        while (!vita49_ctx_ready) {
            if (pthread_cond_timedwait(&vita49_ctx_cond, &vita49_ctx_mutex,
                                        &deadline) != 0)
                break;  /* timeout */
        }
        int got_ctx = vita49_ctx_ready;
        pthread_mutex_unlock(&vita49_ctx_mutex);

        if (got_ctx) {
            fprintf(stderr, "vita49: configured from context packet\n");
        } else {
            fprintf(stderr, "vita49: no context packet received within 5s, "
                    "using command-line values\n");
            /* Validate that we have usable values */
            if (samp_rate <= 0)
                errx(1, "VITA 49: no context received and no -r specified");
            if (center_freq <= 0)
                errx(1, "VITA 49: no context received and no -c specified");
        }
    }

    /* Create burst detector and all downmix workers here in the main thread,
     * before the SDR starts. FFTW_MEASURE plan creation can take several
     * seconds without wisdom; doing it here ensures the detector is fully
     * initialized before any samples arrive, preventing startup queue saturation. */
    burst_config_t det_config = {
        .center_frequency = center_freq,
        .sample_rate = (int)samp_rate,
        .fft_size = 0,
        .burst_pre_len = 0,
        .burst_post_len = 0,
        .burst_width = IR_DEFAULT_BURST_WIDTH,
        .max_bursts = 0,
        .max_burst_len = 0,
        .threshold = (float)threshold_db,
        .history_size = IR_DEFAULT_HISTORY_SIZE,
        .use_gpu = use_gpu,
    };
    burst_detector_t *det = burst_detector_create(&det_config);
    global_detector = det;

    /* Auto-detect worker count from CPU cores if not set via --workers */
    if (num_downmix_workers <= 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu >= 8)
            num_downmix_workers = 4;
        else if (ncpu >= 4)
            num_downmix_workers = 2;
        else
            num_downmix_workers = 1;
    }
    if (num_downmix_workers > MAX_DOWNMIX_WORKERS)
        num_downmix_workers = MAX_DOWNMIX_WORKERS;
    fprintf(stderr, "iridium-sniffer: %d downmix workers (%ld CPU cores)\n",
            num_downmix_workers, sysconf(_SC_NPROCESSORS_ONLN));

    burst_downmix_t *dm[num_downmix_workers];
    for (int i = 0; i < num_downmix_workers; i++) {
        downmix_config_t dm_config = { 0 };
        dm[i] = burst_downmix_create(&dm_config);
    }

    /* Launch burst detector thread */
    pthread_create(&detector, NULL, burst_detector_thread, det);
#ifdef __linux__
    pthread_setname_np(detector, "detector");
#endif

    /* Launch downmix worker pool */
    pthread_t downmix_workers[num_downmix_workers];
    for (int i = 0; i < num_downmix_workers; i++) {
        pthread_create(&downmix_workers[i], NULL, burst_downmix_thread, dm[i]);
#ifdef __linux__
        char name[16];
        snprintf(name, sizeof(name), "downmix-%d", i);
        pthread_setname_np(downmix_workers[i], name);
#endif
    }

    /* Launch frame consumer (QPSK demod + stdout) */
    pthread_t frame_consumer;
    pthread_create(&frame_consumer, NULL, frame_consumer_thread, NULL);
#ifdef __linux__
    pthread_setname_np(frame_consumer, "demod");
#endif

    /* Launch output thread (web map, ACARS, GSMTAP -- decoupled from demod) */
    pthread_t output_worker;
    pthread_create(&output_worker, NULL, output_thread_fn, NULL);
#ifdef __linux__
    pthread_setname_np(output_worker, "output");
#endif

    /* Launch stats thread */
    pthread_create(&stats, NULL, stats_thread_fn, NULL);
#ifdef __linux__
    pthread_setname_np(stats, "stats");
#endif

    if (live) {
        int sdr_started = 0;
#ifdef HAVE_BLADERF
        if (!sdr_started && bladerf_num >= 0) {
            bladerf_dev = bladerf_setup(bladerf_num);
            pthread_create(&bladerf_thread, NULL, bladerf_stream_thread, bladerf_dev);
            sdr_started = 1;
        }
#endif
#ifdef HAVE_UHD
        if (!sdr_started && usrp_serial != NULL) {
            usrp = usrp_setup(usrp_serial);
            pthread_create(&usrp_thread, NULL, usrp_stream_thread, (void *)usrp);
            sdr_started = 1;
        }
#endif
#ifdef HAVE_SOAPYSDR
        if (!sdr_started && (soapy_num >= 0 || soapy_args)) {
            soapy = soapy_setup(soapy_num, soapy_args);
            pthread_create(&soapy_thread, NULL, soapy_stream_thread, (void *)soapy);
            sdr_started = 1;
        }
#endif
#ifdef HAVE_SDRPLAY
        if (!sdr_started && sdrplay_serial) {
            sdrplay_ctx = sdrplay_setup(sdrplay_serial);
            pthread_create(&sdrplay_thread, NULL, sdrplay_stream_thread, sdrplay_ctx);
            sdr_started = 1;
        }
#endif
#ifdef HAVE_SIDEKIQ
        if (!sdr_started && sidekiq_dev) {
            sidekiq_ctx = sidekiq_setup(sidekiq_dev);
            pthread_create(&sidekiq_thread, NULL, sidekiq_stream_thread, sidekiq_ctx);
            sdr_started = 1;
        }
#endif
#ifdef HAVE_HACKRF
        if (!sdr_started && serial != NULL) {
            hackrf = hackrf_setup();
            hackrf_start_rx(hackrf, hackrf_rx_cb, NULL);
            sdr_started = 1;
        }
#endif
        if (!sdr_started)
            errx(1, "No SDR selected. Use -i to specify a device "
                 "(run --list to see available devices)");
    } else if (in_file != NULL) {
        pthread_create(&spewer, NULL, spewer_thread, in_file);
#ifdef __linux__
        pthread_setname_np(spewer, "spewer");
#endif
    }
#ifdef HAVE_ZMQ
    else if (zmq_sub_enabled) {
        pthread_create(&spewer, NULL, zmq_sub_thread, NULL);
#ifdef __linux__
        pthread_setname_np(spewer, "zmq-sub");
#endif
    }
#endif
    else if (vita49_enabled) {
        /* Already started above for context auto-detection */
    }

    /* Wait for signal */
    while (running) {
#ifdef HAVE_HACKRF
        if (live && hackrf != NULL && !hackrf_is_streaming(hackrf))
            break;
#endif
        pause();
    }
    running = 0;

    /* Shutdown SDR */
    if (live) {
#ifdef HAVE_HACKRF
        if (hackrf != NULL) {
            hackrf_stop_rx(hackrf);
            hackrf_close(hackrf);
            hackrf_exit();
        }
#endif
#ifdef HAVE_BLADERF
        if (bladerf_dev != NULL) {
            bladerf_enable_module(bladerf_dev, BLADERF_MODULE_RX, false);
            pthread_join(bladerf_thread, NULL);
            bladerf_close(bladerf_dev);
        }
#endif
#ifdef HAVE_UHD
        if (usrp != NULL) {
            pthread_join(usrp_thread, NULL);
            usrp_close(usrp);
        }
#endif
#ifdef HAVE_SOAPYSDR
        if (soapy != NULL) {
            pthread_join(soapy_thread, NULL);
            soapy_close(soapy);
        }
#endif
#ifdef HAVE_SDRPLAY
        if (sdrplay_ctx != NULL) {
            pthread_join(sdrplay_thread, NULL);
            sdrplay_close(sdrplay_ctx);
        }
#endif
#ifdef HAVE_SIDEKIQ
        if (sidekiq_ctx != NULL) {
            pthread_join(sidekiq_thread, NULL);
            sidekiq_close(sidekiq_ctx);
        }
#endif
    }

    /* Drain queues and join threads in pipeline order */
    blocking_queue_close(&samples_queue);
    if (!live && in_file != NULL)
        pthread_join(spewer, NULL);
#ifdef HAVE_ZMQ
    if (zmq_sub_enabled)
        pthread_join(spewer, NULL);
#endif
    if (vita49_enabled)
        pthread_join(spewer, NULL);
    pthread_join(detector, NULL);

    /* Wait for burst_queue to drain before closing */
    while (burst_queue.queue_size > 0)
        usleep(10000);
    blocking_queue_close(&burst_queue);
    for (int i = 0; i < num_downmix_workers; i++)
        pthread_join(downmix_workers[i], NULL);

    /* Wait for frame_queue to drain before closing */
    while (frame_queue.queue_size > 0)
        usleep(10000);
    blocking_queue_close(&frame_queue);
    pthread_join(frame_consumer, NULL);

    /* Wait for output_queue to drain before closing */
    while (output_queue.queue_size > 0)
        usleep(10000);
    blocking_queue_close(&output_queue);
    pthread_join(output_worker, NULL);
    pthread_join(stats, NULL);

    if (voice_enabled)
        voice_decode_shutdown();

    if (web_enabled)
        web_map_shutdown();

    if (basestation_enabled) {
        basestation_destroy();
        aircraft_db_destroy();
    }

    waypoint_db_destroy();

    if (gsmtap_enabled) {
        fprintf(stderr, "iridium-sniffer: sent %lu GSMTAP packets\n",
                atomic_load(&gsmtap_sent_count));
        gsmtap_shutdown();
    }

    if (acars_enabled) {
        acars_print_stats();
        acars_shutdown();
    }

#ifdef HAVE_ZMQ
    if (zmq_enabled)
        frame_output_zmq_shutdown();
#endif

    if (in_file != NULL)
        fclose(in_file);

    fftw_save_wisdom();
    free(file_info);
    fprintf(stderr, "iridium-sniffer: shutdown complete\n");
    return 0;
}
