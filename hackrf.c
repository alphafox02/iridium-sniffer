/*
 * HackRF SDR backend for iridium-sniffer
 * Based on ice9-bluetooth-sniffer (Copyright 2022 ICE9 Consulting LLC)
 */

#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <libhackrf/hackrf.h>

#include "sdr.h"

extern double samp_rate;
extern double center_freq;
extern char *serial;
extern sig_atomic_t running;

extern int hackrf_lna_gain;
extern int hackrf_vga_gain;
extern int hackrf_amp_enable;
extern int bias_tee;

void hackrf_list(void) {
    int i;
    char *s;
    hackrf_init();
    hackrf_device_list_t *hackrf_devices = hackrf_device_list();
    for (i = 0; i < hackrf_devices->devicecount; ++i) {
        for (s = hackrf_devices->serial_numbers[i]; *s == '0'; ++s)
            ;
        printf("interface {value=hackrf-%s}{display=Iridium Sniffer (HackRF)}\n", s);
    }
    hackrf_device_list_free(hackrf_devices);
}

hackrf_device *hackrf_setup(void) {
    int r;
    hackrf_device *hackrf;

    hackrf_init();

    if (serial == NULL) {
        if ((r = hackrf_open(&hackrf)) != HACKRF_SUCCESS)
            errx(1, "Unable to open HackRF: %s", hackrf_error_name(r));
    } else {
        if ((r = hackrf_open_by_serial(serial, &hackrf)) != HACKRF_SUCCESS)
            errx(1, "Unable to open HackRF: %s", hackrf_error_name(r));
    }
    if ((r = hackrf_set_sample_rate(hackrf, samp_rate)) != HACKRF_SUCCESS)
        errx(1, "Unable to set HackRF sample rate: %s", hackrf_error_name(r));
    if ((r = hackrf_set_freq(hackrf, (uint64_t)center_freq)) != HACKRF_SUCCESS)
        errx(1, "Unable to set HackRF center frequency: %s", hackrf_error_name(r));
    if ((r = hackrf_set_vga_gain(hackrf, hackrf_vga_gain)) != HACKRF_SUCCESS)
        errx(1, "Unable to set HackRF VGA gain: %s", hackrf_error_name(r));
    if ((r = hackrf_set_lna_gain(hackrf, hackrf_lna_gain)) != HACKRF_SUCCESS)
        errx(1, "Unable to set HackRF LNA gain: %s", hackrf_error_name(r));
    if (hackrf_amp_enable) {
        if ((r = hackrf_set_amp_enable(hackrf, 1)) != HACKRF_SUCCESS)
            errx(1, "Unable to enable HackRF amp: %s", hackrf_error_name(r));
    }
    if (bias_tee) {
        if ((r = hackrf_set_antenna_enable(hackrf, 1)) != HACKRF_SUCCESS)
            errx(1, "Unable to enable HackRF bias tee: %s", hackrf_error_name(r));
    }

    return hackrf;
}

int hackrf_rx_cb(hackrf_transfer *t) {
    unsigned i;
    sample_buf_t *s = malloc(sizeof(*s) + t->valid_length * 4);
    s->format = SAMPLE_FMT_INT8;
    s->num = t->valid_length / 2;
    for (i = 0; i < s->num * 2; ++i)
        s->samples[i] = ((int8_t *)t->buffer)[i];
    if (running)
        push_samples(s);
    else
        free(s);
    return 0;
}
