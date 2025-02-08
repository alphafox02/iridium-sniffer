/*
 * BladeRF SDR backend for iridium-sniffer
 * Based on ice9-bluetooth-sniffer (Copyright 2022 ICE9 Consulting LLC)
 */

#include <complex.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libbladeRF.h>

#include "sdr.h"

const unsigned num_transfers = 7;

extern sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern int bladerf_gain_val;
extern int bias_tee;

unsigned timeouts = 0;
int num_samples_workaround = 0;

void bladerf_list(void) {
    struct bladerf_devinfo *devices;
    int i, num;

    num = bladerf_get_device_list(&devices);
    if (num == 0 || num == BLADERF_ERR_NODEV) {
        num = 0;
        goto out;
    }
    if (num < 0)
        errx(1, "Unable to get bladeRF device list: %s", bladerf_strerror(num));

    for (i = 0; i < num; ++i)
        printf("interface {value=bladerf%i}{display=Iridium Sniffer (BladeRF)}\n", devices[i].instance);

out:
    if (num != 0)
        bladerf_free_device_list(devices);
}

struct bladerf *bladerf_setup(int id) {
    struct bladerf_version version;
    int status;
    char identifier[32];
    struct bladerf *bladerf = NULL;
    snprintf(identifier, sizeof(identifier), "*:instance=%d", id);

    bladerf_version(&version);
    if (version.major == 2 && version.minor == 5 && version.patch == 0)
        num_samples_workaround = 1;

    bladerf_set_usb_reset_on_open(true);
    if ((status = bladerf_open(&bladerf, identifier)) != 0)
        errx(1, "Unable to open bladeRF: %s", bladerf_strerror(status));

    if ((status = bladerf_set_bandwidth(bladerf, BLADERF_CHANNEL_RX(0), (unsigned)(samp_rate * 0.9), NULL)) != 0)
        errx(1, "Unable to set bladeRF bandwidth: %s", bladerf_strerror(status));
    if ((status = bladerf_set_frequency(bladerf, BLADERF_CHANNEL_RX(0), (uint64_t)center_freq)) != 0)
        errx(1, "Unable to set bladeRF center frequency: %s", bladerf_strerror(status));
    if ((status = bladerf_set_gain_mode(bladerf, BLADERF_CHANNEL_RX(0), BLADERF_GAIN_MGC)) != 0)
        errx(1, "Unable to set bladeRF manual gain control: %s", bladerf_strerror(status));
    if ((status = bladerf_set_gain(bladerf, BLADERF_CHANNEL_RX(0), bladerf_gain_val)) != 0)
        errx(1, "Unable to set bladeRF gain: %s", bladerf_strerror(status));

    if (bias_tee) {
        if ((status = bladerf_set_bias_tee(bladerf, BLADERF_CHANNEL_RX(0), true)) != 0)
            errx(1, "Unable to enable bladeRF bias tee: %s", bladerf_strerror(status));
    }

    return bladerf;
}

void *bladerf_rx_cb(struct bladerf *bladerf, struct bladerf_stream *stream, struct bladerf_metadata *meta, void *samples, size_t num_samples, void *user_data) {
    unsigned i;
    int16_t *d = (int16_t *)samples;

    timeouts = 0;
    if (num_samples_workaround)
        num_samples *= 2;

    sample_buf_t *s = malloc(sizeof(*s) + num_samples * sizeof(int8_t) * 2);
    s->format = SAMPLE_FMT_INT8;
    s->num = num_samples;
    for (i = 0; i < num_samples * 2; ++i)
        s->samples[i] = (int8_t)(d[i] >> 4);

    if (running)
        push_samples(s);
    else
        free(s);

    return samples;
}

void *bladerf_stream_thread(void *arg) {
    struct bladerf *bladerf = (struct bladerf *)arg;
    struct bladerf_stream *stream;
    struct bladerf_rational_rate rate = { .integer = (uint64_t)samp_rate, .num = 0, .den = 1 };
    void **buffers = NULL;
    unsigned timeout;
    int status;
    unsigned buf_samples = 16384;

    if ((status = bladerf_init_stream(&stream, bladerf, bladerf_rx_cb, &buffers, num_transfers, BLADERF_FORMAT_SC16_Q11, buf_samples, num_transfers, NULL)) != 0)
        errx(1, "Unable to initialize bladeRF stream: %s", bladerf_strerror(status));

    if ((status = bladerf_set_rational_sample_rate(bladerf, BLADERF_CHANNEL_RX(0), &rate, NULL)) != 0)
        errx(1, "Unable to set bladeRF sample rate: %s", bladerf_strerror(status));

    timeout = (unsigned)(1000.0 * buf_samples / samp_rate);
    if (bladerf_set_stream_timeout(bladerf, BLADERF_MODULE_RX, timeout * (num_transfers + 2)) != 0)
        errx(1, "Unable to set bladeRF timeout");

    if (bladerf_enable_module(bladerf, BLADERF_MODULE_RX, true) != 0)
        errx(1, "Unable to enable bladeRF RX module");

    timeouts = 0;
    while (running) {
        if ((status = bladerf_stream(stream, BLADERF_MODULE_RX)) < 0) {
            if (status != BLADERF_ERR_TIMEOUT)
                break;
            if (++timeouts < 5)
                continue;
            warnx("bladeRF timed out too many times, giving up");
            running = 0;
        }
    }

    running = 0;
    bladerf_enable_module(bladerf, BLADERF_MODULE_RX, false);

    kill(self_pid, SIGINT);

    return NULL;
}
