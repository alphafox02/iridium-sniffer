/*
 * SoapySDR backend for iridium-sniffer
 * Based on ice9-bluetooth-sniffer (Copyright 2024 ICE9 Consulting LLC)
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <SoapySDR/Device.h>
#include <SoapySDR/Formats.h>
#include <SoapySDR/Version.h>

#include "sdr.h"

extern sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern double soapy_gain_val;
extern int bias_tee;
extern int verbose;

static int sample_mode = 0;  /* 0=CS8, 1=CF32, 2=CS16 (fallback) */

void soapy_list(void) {
    size_t length;
    SoapySDRKwargs *results = SoapySDRDevice_enumerate(NULL, &length);

    for (size_t i = 0; i < length; ++i) {
        char *driver = NULL;
        char *label = NULL;

        for (size_t j = 0; j < results[i].size; ++j) {
            if (strcmp(results[i].keys[j], "driver") == 0)
                driver = results[i].vals[j];
            if (strcmp(results[i].keys[j], "label") == 0)
                label = results[i].vals[j];
        }

        printf("interface {value=soapy-%zu}{display=Iridium Sniffer (%s%s%s)}\n",
               i,
               driver ? driver : "SoapySDR",
               label ? " - " : "",
               label ? label : "");
    }

    SoapySDRKwargsList_clear(results, length);
}

SoapySDRDevice *soapy_setup(int id) {
    SoapySDRDevice *device;
    size_t length;
    char **formats;
    size_t num_formats;

    SoapySDRKwargs *results = SoapySDRDevice_enumerate(NULL, &length);

    if (id < 0 || (size_t)id >= length) {
        SoapySDRKwargsList_clear(results, length);
        errx(1, "Invalid SoapySDR device index: %d (found %zu devices)", id, length);
    }

    device = SoapySDRDevice_make(&results[id]);
    SoapySDRKwargsList_clear(results, length);

    if (device == NULL)
        errx(1, "Unable to open SoapySDR device: %s", SoapySDRDevice_lastError());

    /* Check supported formats: prefer CS8, then CF32, then CS16 */
    formats = SoapySDRDevice_getStreamFormats(device, SOAPY_SDR_RX, 0, &num_formats);
    sample_mode = 2;  /* CS16 fallback */
    for (size_t i = 0; i < num_formats; ++i) {
        if (strcmp(formats[i], SOAPY_SDR_CS8) == 0) {
            sample_mode = 0;
            break;
        }
        if (strcmp(formats[i], SOAPY_SDR_CF32) == 0)
            sample_mode = 1;
    }
    SoapySDRStrings_clear(&formats, num_formats);

    if (verbose) {
        const char *fmt_name[] = { "CS8", "CF32", "CS16" };
        fprintf(stderr, "SoapySDR: using %s format\n", fmt_name[sample_mode]);
    }

    if (SoapySDRDevice_setSampleRate(device, SOAPY_SDR_RX, 0, samp_rate) != 0)
        errx(1, "Unable to set SoapySDR sample rate: %s", SoapySDRDevice_lastError());

    if (SoapySDRDevice_setFrequency(device, SOAPY_SDR_RX, 0, center_freq, NULL) != 0)
        errx(1, "Unable to set SoapySDR frequency: %s", SoapySDRDevice_lastError());

    if (SoapySDRDevice_setGain(device, SOAPY_SDR_RX, 0, soapy_gain_val) != 0) {
        if (verbose)
            warnx("Unable to set SoapySDR gain (continuing anyway)");
    }

    if (SoapySDRDevice_setBandwidth(device, SOAPY_SDR_RX, 0, samp_rate) != 0) {
        if (verbose)
            warnx("Unable to set SoapySDR bandwidth (continuing anyway)");
    }

    if (bias_tee) {
        if (SoapySDRDevice_writeSetting(device, "biastee", "true") != 0) {
            if (verbose)
                warnx("Unable to enable SoapySDR bias tee (continuing anyway)");
        }
    }

    return device;
}

static void soapy_cs16_to_float(int16_t *in, float *out, size_t num_samples) {
    for (size_t i = 0; i < num_samples * 2; ++i)
        out[i] = in[i] * (1.0f / 32768.0f);
}

void *soapy_stream_thread(void *arg) {
    SoapySDRDevice *device = (SoapySDRDevice *)arg;
    SoapySDRStream *stream;
    size_t channel = 0;
    int flags;
    long long time_ns;
    const char *format;
    size_t mtu;

    if (sample_mode == 0) {
        format = SOAPY_SDR_CS8;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL) {
            if (verbose)
                warnx("CS8 stream failed, trying CF32");
            sample_mode = 1;
        }
    } else {
        stream = NULL;
    }

    if (stream == NULL && sample_mode == 1) {
        format = SOAPY_SDR_CF32;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL) {
            if (verbose)
                warnx("CF32 stream failed, falling back to CS16");
            sample_mode = 2;
        }
    }

    if (stream == NULL) {
        format = SOAPY_SDR_CS16;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL)
            errx(1, "Unable to setup SoapySDR stream: %s", SoapySDRDevice_lastError());
    }

    if (verbose)
        fprintf(stderr, "SoapySDR: streaming with %s format\n", format);

    mtu = SoapySDRDevice_getStreamMTU(device, stream);
    if (mtu == 0)
        mtu = 65536;

    if (SoapySDRDevice_activateStream(device, stream, 0, 0, 0) != 0)
        errx(1, "Unable to activate SoapySDR stream: %s", SoapySDRDevice_lastError());

    int16_t *cs16_buf = NULL;
    if (sample_mode == 2) {
        cs16_buf = malloc(mtu * 2 * sizeof(int16_t));
        if (cs16_buf == NULL)
            errx(1, "Unable to allocate CS16 buffer");
    }

    /* Sample size per IQ pair depends on format */
    size_t sample_size = (sample_mode == 0) ? 2 * sizeof(int8_t)
                                            : 2 * sizeof(float);

    while (running) {
        sample_buf_t *s = malloc(sizeof(*s) + mtu * sample_size);
        if (s == NULL) {
            warnx("Unable to allocate sample buffer");
            break;
        }

        void *buffs[1];
        int ret;

        if (sample_mode == 2) {
            /* CS16 -> float conversion */
            buffs[0] = cs16_buf;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
            if (ret > 0)
                soapy_cs16_to_float(cs16_buf, (float *)s->samples, ret);
        } else if (sample_mode == 1) {
            /* CF32 direct */
            buffs[0] = s->samples;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
        } else {
            /* CS8 direct */
            buffs[0] = s->samples;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
        }

        if (ret < 0) {
            if (ret == SOAPY_SDR_TIMEOUT) {
                free(s);
                continue;
            }
            if (ret == SOAPY_SDR_OVERFLOW) {
                if (verbose)
                    warnx("SoapySDR overflow");
                free(s);
                continue;
            }
            warnx("SoapySDR read error: %d", ret);
            free(s);
            break;
        }

        s->format = (sample_mode == 0) ? SAMPLE_FMT_INT8 : SAMPLE_FMT_FLOAT;
        s->num = ret;
        if (running)
            push_samples(s);
        else
            free(s);
    }

    free(cs16_buf);

    SoapySDRDevice_deactivateStream(device, stream, 0, 0);
    SoapySDRDevice_closeStream(device, stream);

    running = 0;
    kill(self_pid, SIGINT);

    return NULL;
}

void soapy_close(SoapySDRDevice *device) {
    SoapySDRDevice_unmake(device);
}
