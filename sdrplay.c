/*
 * SDRplay native API v3 backend for iridium-sniffer
 *
 * Bypasses SoapySDR to talk directly to the SDRplay API, fixing
 * device-specific issues (RSP1A bias tee segfault, etc.) and giving
 * full control over per-model settings.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <err.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <sdrplay_api.h>

#include "sdr.h"

extern volatile sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern int sdrplay_gain_val;
extern int bias_tee;
extern int verbose;

/* Driver context passed between setup/stream/close */
typedef struct {
    sdrplay_api_DeviceT device;
    sdrplay_api_DeviceParamsT *params;
    int opened;       /* API opened */
    int locked;       /* device API locked */
    int selected;     /* device selected */
    int initialized;  /* streaming init'd */
} sdrplay_ctx_t;

/* Released at exit too: a device left selected or the API left locked
 * wedges the SDRplay service and the next sdrplay_api_Open() blocks. */
static sdrplay_ctx_t *active_ctx;

static void teardown(sdrplay_ctx_t *ctx)
{
    if (ctx->initialized) {
        ctx->initialized = 0;
        sdrplay_api_Uninit(ctx->device.dev);
    }
    if (ctx->locked) {
        ctx->locked = 0;
        sdrplay_api_UnlockDeviceApi();
    }
    if (ctx->selected) {
        ctx->selected = 0;
        sdrplay_api_ReleaseDevice(&ctx->device);
    }
    if (ctx->opened) {
        ctx->opened = 0;
        sdrplay_api_Close();
    }
}

static void teardown_at_exit(void)
{
    if (active_ctx)
        teardown(active_ctx);
}

/* Select the best bandwidth enum for a given sample rate */
static sdrplay_api_Bw_MHzT pick_bandwidth(double sr)
{
    if (sr <= 300000)  return sdrplay_api_BW_0_300;
    if (sr <= 600000)  return sdrplay_api_BW_0_600;
    if (sr <= 1536000) return sdrplay_api_BW_1_536;
    if (sr <= 5000000) return sdrplay_api_BW_5_000;
    if (sr <= 6000000) return sdrplay_api_BW_6_000;
    if (sr <= 7000000) return sdrplay_api_BW_7_000;
    return sdrplay_api_BW_8_000;
}

/* ---- Stream callback ---- */
static void stream_callback(short *xi, short *xq,
                             sdrplay_api_StreamCbParamsT *params,
                             unsigned int numSamples,
                             unsigned int reset, void *cbContext)
{
    (void)params;
    (void)reset;
    (void)cbContext;

    if (!running || numSamples == 0)
        return;

    /* Allocate float IQ buffer: 2 floats per sample */
    sample_buf_t *s = malloc(sizeof(*s) + numSamples * sizeof(float) * 2);
    if (!s) return;

    s->format = SAMPLE_FMT_FLOAT;
    s->hw_timestamp_ns = 0;
    s->num = numSamples;

    float *out = (float *)s->samples;

    /* Interleave separate I/Q int16 arrays and normalize.
     * SDRplay int16 range is roughly +/- 32767 but actual dynamic
     * range is ~14 bits. Use 1/32768 for clean normalization. */
    for (unsigned int i = 0; i < numSamples; i++) {
        out[i * 2]     = xi[i] * (1.0f / 32768.0f);
        out[i * 2 + 1] = xq[i] * (1.0f / 32768.0f);
    }

    push_samples(s);
}

/* ---- Event callback ---- */
static void event_callback(sdrplay_api_EventT eventId,
                            sdrplay_api_TunerSelectT tuner,
                            sdrplay_api_EventParamsT *params,
                            void *cbContext)
{
    (void)tuner;
    (void)cbContext;

    switch (eventId) {
    case sdrplay_api_GainChange:
        if (verbose)
            fprintf(stderr, "sdrplay: gain change: gRdB=%u lnaGRdB=%u "
                    "currGain=%.1f\n",
                    params->gainParams.gRdB,
                    params->gainParams.lnaGRdB,
                    params->gainParams.currGain);
        break;

    case sdrplay_api_PowerOverloadChange:
        /* Acknowledge the overload so the API can adjust */
        if (cbContext) {
            sdrplay_ctx_t *ctx = (sdrplay_ctx_t *)cbContext;
            sdrplay_api_Update(ctx->device.dev, tuner,
                               sdrplay_api_Update_Ctrl_OverloadMsgAck,
                               sdrplay_api_Update_Ext1_None);
        }
        if (verbose) {
            const char *msg =
                (params->powerOverloadParams.powerOverloadChangeType ==
                 sdrplay_api_Overload_Detected) ? "detected" : "corrected";
            fprintf(stderr, "sdrplay: power overload %s\n", msg);
        }
        break;

    case sdrplay_api_DeviceRemoved:
        warnx("sdrplay: device removed");
        running = 0;
        kill(self_pid, SIGINT);
        break;

#ifdef sdrplay_api_DeviceFailure
    case sdrplay_api_DeviceFailure:
        warnx("sdrplay: device failure");
        running = 0;
        kill(self_pid, SIGINT);
        break;
#endif

    default:
        break;
    }
}

/* ---- Device enumeration ---- */
void sdrplay_list(void)
{
    sdrplay_api_ErrT err;
    float ver = 0.0f;

    err = sdrplay_api_Open();
    if (err != sdrplay_api_Success) {
        warnx("sdrplay: cannot open API: %s",
              sdrplay_api_GetErrorString(err));
        return;
    }

    err = sdrplay_api_ApiVersion(&ver);
    if (err != sdrplay_api_Success) {
        sdrplay_api_Close();
        return;
    }

    sdrplay_api_DeviceT devices[SDRPLAY_MAX_DEVICES];
    unsigned int ndevs = 0;

    err = sdrplay_api_LockDeviceApi();
    if (err != sdrplay_api_Success) {
        sdrplay_api_Close();
        return;
    }

    err = sdrplay_api_GetDevices(devices, &ndevs, SDRPLAY_MAX_DEVICES);
    if (err != sdrplay_api_Success || ndevs == 0) {
        sdrplay_api_UnlockDeviceApi();
        sdrplay_api_Close();
        return;
    }

    for (unsigned int i = 0; i < ndevs; i++) {
        const char *model;
        switch (devices[i].hwVer) {
        case SDRPLAY_RSP1_ID:    model = "RSP1";    break;
        case SDRPLAY_RSP1A_ID:   model = "RSP1A";   break;
#ifdef SDRPLAY_RSP1B_ID
        case SDRPLAY_RSP1B_ID:   model = "RSP1B";   break;
#endif
        case SDRPLAY_RSP2_ID:    model = "RSP2";     break;
        case SDRPLAY_RSPduo_ID:  model = "RSPduo";   break;
        case SDRPLAY_RSPdx_ID:   model = "RSPdx";    break;
#ifdef SDRPLAY_RSPdxR2_ID
        case SDRPLAY_RSPdxR2_ID: model = "RSPdxR2";  break;
#endif
        default:                 model = "Unknown";  break;
        }
        {
            char val[64];
            snprintf(val, sizeof(val), "sdrplay-%s", devices[i].SerNo);
            printf("  %-24s SDRplay %s\n", val, model);
        }
    }

    sdrplay_api_UnlockDeviceApi();
    sdrplay_api_Close();
}

/* ---- Device setup ---- */
void *sdrplay_setup(const char *serial)
{
    sdrplay_api_ErrT err;
    float ver = 0.0f;

    sdrplay_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) errx(1, "sdrplay: out of memory");
    active_ctx = ctx;
    atexit(teardown_at_exit);

    /* Open API */
    err = sdrplay_api_Open();
    if (err != sdrplay_api_Success)
        errx(1, "sdrplay: cannot open API: %s",
             sdrplay_api_GetErrorString(err));
    ctx->opened = 1;

    /* Version check */
    err = sdrplay_api_ApiVersion(&ver);
    if (err != sdrplay_api_Success)
        errx(1, "sdrplay: cannot get API version: %s",
             sdrplay_api_GetErrorString(err));
    fprintf(stderr, "sdrplay: API version %.2f\n", ver);
    if (ver < 3.07f)
        warnx("sdrplay: API version %.2f is too old (minimum 3.07)", ver);
    else if (ver < 3.14f)
        warnx("sdrplay: API version %.2f -- consider upgrading to 3.14+ "
              "for RSP1B/RSPdxR2 support", ver);

    /* Enumerate devices */
    sdrplay_api_DeviceT devices[SDRPLAY_MAX_DEVICES];
    unsigned int ndevs = 0;

    err = sdrplay_api_LockDeviceApi();
    if (err != sdrplay_api_Success)
        errx(1, "sdrplay: cannot lock API: %s",
             sdrplay_api_GetErrorString(err));
    ctx->locked = 1;

    err = sdrplay_api_GetDevices(devices, &ndevs, SDRPLAY_MAX_DEVICES);
    if (err != sdrplay_api_Success || ndevs == 0)
        errx(1, "sdrplay: no devices found");

    /* Find device by serial (or use first) */
    int found = -1;
    if (serial && serial[0]) {
        for (unsigned int i = 0; i < ndevs; i++) {
            if (strcmp(devices[i].SerNo, serial) == 0) {
                found = (int)i;
                break;
            }
        }
        if (found < 0)
            errx(1, "sdrplay: device with serial '%s' not found", serial);
    } else {
        found = 0;
    }

    ctx->device = devices[found];

    /* RSPduo: force single tuner mode */
    if (ctx->device.hwVer == SDRPLAY_RSPduo_ID) {
        ctx->device.tuner = sdrplay_api_Tuner_A;
        ctx->device.rspDuoMode = sdrplay_api_RspDuoMode_Single_Tuner;
    }

    err = sdrplay_api_SelectDevice(&ctx->device);
    if (err != sdrplay_api_Success)
        errx(1, "sdrplay: cannot select device: %s",
             sdrplay_api_GetErrorString(err));
    ctx->selected = 1;

    sdrplay_api_UnlockDeviceApi();
    ctx->locked = 0;

    /* Enable debug output for troubleshooting */
    sdrplay_api_DebugEnable(ctx->device.dev, sdrplay_api_DbgLvl_Verbose);

    /* Get device parameters (populated with defaults) */
    err = sdrplay_api_GetDeviceParams(ctx->device.dev, &ctx->params);
    if (err != sdrplay_api_Success)
        errx(1, "sdrplay: cannot get device params: %s",
             sdrplay_api_GetErrorString(err));

    /* Configure all parameters on the struct before Init.
     * Init applies everything atomically -- no post-Init Update needed
     * for initial configuration. Only bias tee uses Update (post-stream). */
    sdrplay_api_DevParamsT *devp = ctx->params->devParams;
    sdrplay_api_RxChannelParamsT *chp = ctx->params->rxChannelA;

    /* Frequency */
    chp->tunerParams.rfFreq.rfHz = center_freq;

    /* Sample rate and bandwidth */
    devp->fsFreq.fsHz = samp_rate;
    chp->tunerParams.bwType = pick_bandwidth(samp_rate);
    chp->tunerParams.ifType = sdrplay_api_IF_Zero;

    /* DC and IQ correction */
    chp->ctrlParams.dcOffset.DCenable = 1;
    chp->ctrlParams.dcOffset.IQenable = 1;

    /* Gain / AGC configuration.
     * If --sdrplay-gain was specified, disable AGC and use manual gRdB.
     * Otherwise, enable AGC and let the hardware manage levels. */
    if (sdrplay_gain_val >= 0) {
        int grdb = sdrplay_gain_val;
        if (grdb < 20) grdb = 20;
        if (grdb > 59) grdb = 59;
        chp->tunerParams.gain.gRdB = grdb;
        chp->tunerParams.gain.LNAstate = 0;
        chp->ctrlParams.agc.enable = sdrplay_api_AGC_DISABLE;
        fprintf(stderr, "sdrplay: AGC disabled, manual gRdB=%d LNA=0\n", grdb);
    } else {
        chp->ctrlParams.agc.enable = sdrplay_api_AGC_5HZ;
        chp->ctrlParams.agc.setPoint_dBfs = -30;
        fprintf(stderr, "sdrplay: AGC enabled (5 Hz)\n");
    }

    /* Bias tee (set on struct before Init, like dumpvdl2) */
    if (bias_tee) {
        switch (ctx->device.hwVer) {
        case SDRPLAY_RSP1A_ID:
#ifdef SDRPLAY_RSP1B_ID
        case SDRPLAY_RSP1B_ID:
#endif
            chp->rsp1aTunerParams.biasTEnable = 1;
            break;
        case SDRPLAY_RSP2_ID:
            chp->rsp2TunerParams.antennaSel = sdrplay_api_Rsp2_ANTENNA_B;
            chp->rsp2TunerParams.biasTEnable = 1;
            break;
        case SDRPLAY_RSPduo_ID:
            chp->rspDuoTunerParams.biasTEnable = 1;
            break;
        case SDRPLAY_RSPdx_ID:
#ifdef SDRPLAY_RSPdxR2_ID
        case SDRPLAY_RSPdxR2_ID:
#endif
            devp->rspDxParams.antennaSel = sdrplay_api_RspDx_ANTENNA_B;
            devp->rspDxParams.biasTEnable = 1;
            break;
        default:
            warnx("sdrplay: bias tee not supported on this model");
            break;
        }
        fprintf(stderr, "sdrplay: bias tee enabled\n");
    }

    /* Init applies all params and starts streaming */
    sdrplay_api_CallbackFnsT cbFns;
    cbFns.StreamACbFn = stream_callback;
    cbFns.StreamBCbFn = stream_callback;  /* unused for single tuner */
    cbFns.EventCbFn = event_callback;

    err = sdrplay_api_Init(ctx->device.dev, &cbFns, ctx);
    if (err != sdrplay_api_Success) {
        sdrplay_api_ErrorInfoT *errInfo =
            sdrplay_api_GetLastError(NULL);
        if (errInfo)
            warnx("sdrplay: Init error detail: %s (file=%s func=%s line=%d)",
                  errInfo->message, errInfo->file,
                  errInfo->function, errInfo->line);
        errx(1, "sdrplay: cannot init device: %s",
             sdrplay_api_GetErrorString(err));
    }
    ctx->initialized = 1;

    /* Turn off debug now that setup is complete */
    sdrplay_api_DebugEnable(ctx->device.dev, sdrplay_api_DbgLvl_Disable);

    const char *model;
    switch (ctx->device.hwVer) {
    case SDRPLAY_RSP1_ID:    model = "RSP1";    break;
    case SDRPLAY_RSP1A_ID:   model = "RSP1A";   break;
#ifdef SDRPLAY_RSP1B_ID
    case SDRPLAY_RSP1B_ID:   model = "RSP1B";   break;
#endif
    case SDRPLAY_RSP2_ID:    model = "RSP2";     break;
    case SDRPLAY_RSPduo_ID:  model = "RSPduo";   break;
    case SDRPLAY_RSPdx_ID:   model = "RSPdx";    break;
#ifdef SDRPLAY_RSPdxR2_ID
    case SDRPLAY_RSPdxR2_ID: model = "RSPdxR2";  break;
#endif
    default:                 model = "Unknown";  break;
    }
    fprintf(stderr, "sdrplay: %s serial=%s sr=%.0f freq=%.0f bw=%d %s\n",
            model, ctx->device.SerNo, samp_rate, center_freq,
            (int)chp->tunerParams.bwType,
            sdrplay_gain_val >= 0 ? "gain=manual" : "gain=AGC");

    return ctx;
}

/* ---- Streaming thread ---- */
void *sdrplay_stream_thread(void *arg)
{
    (void)arg;

    /* Streaming is already active from Init in setup.
     * Callbacks deliver samples directly via push_samples().
     * This thread just blocks until shutdown. */
    while (running)
        usleep(100000);

    running = 0;
    kill(self_pid, SIGINT);

    return NULL;
}

/* ---- Cleanup ---- */
void sdrplay_close(void *arg)
{
    sdrplay_ctx_t *ctx = (sdrplay_ctx_t *)arg;
    if (!ctx) return;

    teardown(ctx);
    if (active_ctx == ctx)
        active_ctx = NULL;
    free(ctx);
}
