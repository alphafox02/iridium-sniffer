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

#include "sdr.h"
#include "iridium.h"
#include "burst_detect.h"
#include "burst_downmix.h"
#include "qpsk_demod.h"
#include "frame_output.h"
#include "frame_decode.h"
#include "web_map.h"
#include "ida_decode.h"
#include "gsmtap.h"
#include "fftw_lock.h"

/* FFTW planner mutex (defined here, declared in fftw_lock.h) */
pthread_mutex_t fftw_planner_mutex;

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
#endif

/* Per-SDR gain settings (defaults from gr-iridium example configs) */
int hackrf_lna_gain = 40;
int hackrf_vga_gain = 20;
int hackrf_amp_enable = 0;
int bladerf_gain_val = 40;
int usrp_gain_val = 40;
double soapy_gain_val = 40.0;
int bias_tee = 0;
int web_enabled = 0;
int web_port = 8888;
int gsmtap_enabled = 0;
char *gsmtap_host = NULL;
int gsmtap_port = GSMTAP_DEFAULT_PORT;

/* GPU acceleration: enabled by default when compiled with GPU support */
#ifdef USE_GPU
int use_gpu = 1;
#else
int use_gpu = 0;
#endif

/* Threading state */
volatile sig_atomic_t running = 1;
pid_t self_pid;

/* Queues */
#define SAMPLES_QUEUE_SIZE 4096
#define BURST_QUEUE_SIZE   2048
#define FRAME_QUEUE_SIZE   512
#define NUM_DOWNMIX_WORKERS 4
Blocking_Queue samples_queue;
Blocking_Queue burst_queue;
Blocking_Queue frame_queue;

/* Atomic stats counters (for gr-iridium compatible status line) */
atomic_ulong stat_n_detected = 0;
atomic_ulong stat_n_handled = 0;
atomic_ulong stat_n_ok_bursts = 0;
atomic_ulong stat_n_ok_sub = 0;
atomic_ulong stat_n_dropped = 0;
atomic_ulong stat_sample_count = 0;

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

/* ---- IDA/GSMTAP state ---- */

static ida_context_t ida_ctx;

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

/* ---- Frame consumer: QPSK demod + output ---- */

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
            frame_output_print(demod);

            if (web_enabled) {
                decoded_frame_t decoded;
                if (frame_decode(demod, &decoded)) {
                    if (decoded.type == FRAME_IRA)
                        web_map_add_ra(&decoded.ira, decoded.timestamp,
                                        decoded.frequency);
                    else if (decoded.type == FRAME_IBC)
                        web_map_add_sat(&decoded.ibc, decoded.timestamp);
                }
            }

            if (gsmtap_enabled) {
                ida_burst_t burst;
                if (ida_decode(demod, &burst))
                    ida_reassemble(&ida_ctx, &burst, gsmtap_ida_cb, NULL);
                ida_reassemble_flush(&ida_ctx, demod->timestamp);
            }

            free(demod->bits);
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
        fprintf(stderr, "\n");

        /* Suppress unused variable warning */
        (void)dsamp;

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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    self_pid = getpid();

    parse_options(argc, argv);

    fprintf(stderr, "iridium-sniffer: center_freq=%.0f Hz, sample_rate=%.0f Hz, threshold=%.1f dB\n",
            center_freq, samp_rate, threshold_db);

    fftw_lock_init();
    frame_output_init(file_info);

    if (web_enabled || gsmtap_enabled)
        frame_decode_init();

    if (web_enabled) {
        if (web_map_init(web_port) != 0)
            errx(1, "Failed to start web map server on port %d", web_port);
    }

    if (gsmtap_enabled) {
        ida_decode_init();
        if (gsmtap_init(gsmtap_host, gsmtap_port) != 0)
            errx(1, "Failed to initialize GSMTAP socket");
    }

    blocking_queue_init(&samples_queue, SAMPLES_QUEUE_SIZE);
    blocking_queue_init(&burst_queue, BURST_QUEUE_SIZE);
    blocking_queue_init(&frame_queue, FRAME_QUEUE_SIZE);

    /* Launch burst detector thread */
    pthread_create(&detector, NULL, burst_detector_thread, NULL);
#ifdef __linux__
    pthread_setname_np(detector, "detector");
#endif

    /* Launch downmix worker pool */
    pthread_t downmix_workers[NUM_DOWNMIX_WORKERS];
    for (int i = 0; i < NUM_DOWNMIX_WORKERS; i++) {
        pthread_create(&downmix_workers[i], NULL, burst_downmix_thread, NULL);
#ifdef __linux__
        char name[16];
        snprintf(name, sizeof(name), "downmix-%d", i);
        pthread_setname_np(downmix_workers[i], name);
#endif
    }

    /* Launch frame consumer (QPSK demod + output) */
    pthread_t frame_consumer;
    pthread_create(&frame_consumer, NULL, frame_consumer_thread, NULL);
#ifdef __linux__
    pthread_setname_np(frame_consumer, "demod");
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
        if (!sdr_started && soapy_num >= 0) {
            soapy = soapy_setup(soapy_num);
            pthread_create(&soapy_thread, NULL, soapy_stream_thread, (void *)soapy);
            sdr_started = 1;
        }
#endif
#ifdef HAVE_HACKRF
        if (!sdr_started) {
            hackrf = hackrf_setup();
            hackrf_start_rx(hackrf, hackrf_rx_cb, NULL);
            sdr_started = 1;
        }
#endif
        if (!sdr_started)
            errx(1, "No SDR backend available (none compiled in or none selected)");
    } else if (in_file != NULL) {
        pthread_create(&spewer, NULL, spewer_thread, in_file);
#ifdef __linux__
        pthread_setname_np(spewer, "spewer");
#endif
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
    }

    /* Drain queues and join threads in pipeline order */
    blocking_queue_close(&samples_queue);
    if (!live && in_file != NULL)
        pthread_join(spewer, NULL);
    pthread_join(detector, NULL);

    /* Wait for burst_queue to drain before closing */
    while (burst_queue.queue_size > 0)
        usleep(10000);
    blocking_queue_close(&burst_queue);
    for (int i = 0; i < NUM_DOWNMIX_WORKERS; i++)
        pthread_join(downmix_workers[i], NULL);

    /* Wait for frame_queue to drain before closing */
    while (frame_queue.queue_size > 0)
        usleep(10000);
    blocking_queue_close(&frame_queue);
    pthread_join(frame_consumer, NULL);
    pthread_join(stats, NULL);

    if (web_enabled)
        web_map_shutdown();

    if (gsmtap_enabled) {
        fprintf(stderr, "iridium-sniffer: sent %lu GSMTAP packets\n",
                atomic_load(&gsmtap_sent_count));
        gsmtap_shutdown();
    }

    if (in_file != NULL)
        fclose(in_file);

    free(file_info);
    fprintf(stderr, "iridium-sniffer: shutdown complete\n");
    return 0;
}
