/*
 * Command-line option parsing
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Command-line option parsing for iridium-sniffer
 */

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

typedef enum {
    FMT_CI8 = 0,
    FMT_CI16,
    FMT_CF32,
} iq_format_t;

extern double samp_rate;
extern double center_freq;
extern int verbose;
extern int live;
extern char *file_info;
extern double threshold_db;
extern iq_format_t iq_format;
extern FILE *in_file;

extern char *serial;
#ifdef HAVE_BLADERF
extern int bladerf_num;
#endif
#ifdef HAVE_UHD
extern char *usrp_serial;
#endif
#ifdef HAVE_SOAPYSDR
extern int soapy_num;
#endif

extern int hackrf_lna_gain;
extern int hackrf_vga_gain;
extern int hackrf_amp_enable;
extern int bladerf_gain_val;
extern int usrp_gain_val;
extern double soapy_gain_val;
extern int bias_tee;
extern int use_gpu;
extern int no_simd;
extern char *save_bursts_dir;
extern int web_enabled;
extern int web_port;
extern int gsmtap_enabled;
extern char *gsmtap_host;
extern int gsmtap_port;
extern int diagnostic_mode;
extern int use_gardner;
extern int parsed_mode;

static void usage(int exitcode) {
    fprintf(stderr,
"Usage: iridium-sniffer <-f FILE | -l> [options]\n"
"Standalone Iridium satellite burst detector and demodulator.\n"
"Outputs iridium-toolkit compatible RAW format to stdout.\n"
"\n"
"Input (one required):\n"
"    -f, --file=FILE         read IQ samples from file\n"
"    -l, --live              capture live from SDR\n"
"    --format=FMT            IQ file format: ci8 (default), ci16, cf32\n"
"\n"
"SDR options:\n"
"    -i, --interface=IFACE   SDR to use (hackrf-SERIAL, bladerf0, usrp-PROD-SERIAL, soapy-N)\n"
"    -c, --center-freq=HZ    center frequency in Hz (default: 1622000000)\n"
"    -r, --sample-rate=HZ    sample rate in Hz (default: 10000000)\n"
"    -B, --bias-tee           enable bias tee power\n"
"\n"
"Gain options:\n"
"    --hackrf-lna=GAIN       HackRF LNA gain in dB (default: 40)\n"
"    --hackrf-vga=GAIN       HackRF VGA gain in dB (default: 20)\n"
"    --hackrf-amp            enable HackRF RF amplifier\n"
"    --bladerf-gain=GAIN     BladeRF gain in dB (default: 40)\n"
"    --usrp-gain=GAIN        USRP gain in dB (default: 40)\n"
"    --soapy-gain=GAIN       SoapySDR gain in dB (default: 30)\n"
"\n"
"Detection options:\n"
"    -d, --threshold=DB      burst detection threshold in dB (default: 16.0)\n"
#ifdef USE_GPU
"    --no-gpu                disable GPU acceleration (use CPU FFTW)\n"
#endif
"    --no-simd               disable SIMD acceleration (use scalar kernels)\n"
"\n"
"Web map:\n"
"    --web[=PORT]            enable live web map (default port: 8888)\n"
"\n"
"GSMTAP:\n"
"    --gsmtap[=HOST:PORT]    send IDA frames as GSMTAP/LAPDm via UDP\n"
"                             (default: 127.0.0.1:4729, for Wireshark)\n"
"\n"
"Output options:\n"
"    --file-info=STR         file info string for output (default: auto)\n"
"    --save-bursts=DIR       save IQ samples of decoded bursts to directory\n"
"    --diagnostic            setup verification mode (suppresses RAW output)\n"
"    --no-gardner           disable Gardner timing recovery (enabled by default)\n"
"    --parsed               output parsed IDA lines (pipe to reassembler.py)\n"
"    -v, --verbose           verbose output to stderr\n"
"    -h, --help              show this help\n"
"    --list                  list available SDR interfaces\n"
"\n"
"The output format is compatible with iridium-toolkit. Pipe to iridium-parser.py:\n"
"    iridium-sniffer -l | python3 iridium-toolkit/iridium-parser.py\n"
    );
    exit(exitcode);
}

static void list_interfaces(void) {
#ifdef HAVE_HACKRF
    hackrf_list();
#endif
#ifdef HAVE_BLADERF
    bladerf_list();
#endif
#ifdef HAVE_UHD
    usrp_list();
#endif
#ifdef HAVE_SOAPYSDR
    soapy_list();
#endif
    exit(0);
}

void parse_options(int argc, char **argv) {
    int ch;
    int format_explicit = 0;
    const char *in_filename = NULL;

    enum {
        OPT_HACKRF_LNA = 0x100,
        OPT_HACKRF_VGA,
        OPT_HACKRF_AMP,
        OPT_BLADERF_GAIN,
        OPT_USRP_GAIN,
        OPT_SOAPY_GAIN,
        OPT_FILE_INFO,
        OPT_FORMAT,
        OPT_LIST,
        OPT_NO_GPU,
        OPT_NO_SIMD,
        OPT_WEB,
        OPT_GSMTAP,
        OPT_SAVE_BURSTS,
        OPT_DIAGNOSTIC,
        OPT_GARDNER,
        OPT_NO_GARDNER,
        OPT_PARSED,
    };

    static const struct option longopts[] = {
        { "file",           required_argument, NULL, 'f' },
        { "live",           no_argument,       NULL, 'l' },
        { "interface",      required_argument, NULL, 'i' },
        { "center-freq",    required_argument, NULL, 'c' },
        { "sample-rate",    required_argument, NULL, 'r' },
        { "bias-tee",       no_argument,       NULL, 'B' },
        { "threshold",      required_argument, NULL, 'd' },
        { "file-info",      required_argument, NULL, OPT_FILE_INFO },
        { "format",         required_argument, NULL, OPT_FORMAT },
        { "verbose",        no_argument,       NULL, 'v' },
        { "help",           no_argument,       NULL, 'h' },
        { "list",           no_argument,       NULL, OPT_LIST },
        { "hackrf-lna",     required_argument, NULL, OPT_HACKRF_LNA },
        { "hackrf-vga",     required_argument, NULL, OPT_HACKRF_VGA },
        { "hackrf-amp",     no_argument,       NULL, OPT_HACKRF_AMP },
        { "bladerf-gain",   required_argument, NULL, OPT_BLADERF_GAIN },
        { "usrp-gain",      required_argument, NULL, OPT_USRP_GAIN },
        { "soapy-gain",     required_argument, NULL, OPT_SOAPY_GAIN },
        { "no-gpu",         no_argument,       NULL, OPT_NO_GPU },
        { "no-simd",        no_argument,       NULL, OPT_NO_SIMD },
        { "web",            optional_argument, NULL, OPT_WEB },
        { "gsmtap",         optional_argument, NULL, OPT_GSMTAP },
        { "save-bursts",    required_argument, NULL, OPT_SAVE_BURSTS },
        { "diagnostic",     no_argument,       NULL, OPT_DIAGNOSTIC },
        { "gardner",        no_argument,       NULL, OPT_GARDNER },
        { "no-gardner",     no_argument,       NULL, OPT_NO_GARDNER },
        { "parsed",         no_argument,       NULL, OPT_PARSED },
        { NULL,             0,                 NULL, 0 }
    };

    while ((ch = getopt_long(argc, argv, "f:li:c:r:Bd:vh", longopts, NULL)) != -1) {
        switch (ch) {
            case 'f':
                in_file = fopen(optarg, "rb");
                if (in_file == NULL)
                    err(1, "Cannot open input file '%s'", optarg);
                in_filename = optarg;
                break;

            case 'l':
                live = 1;
                break;

            case 'i':
#ifdef HAVE_HACKRF
                if (strstr(optarg, "hackrf-") == optarg) {
                    serial = strdup(optarg + 7);
                    break;
                }
#endif
#ifdef HAVE_BLADERF
                if (strstr(optarg, "bladerf") == optarg) {
                    bladerf_num = atoi(optarg + 7);
                    break;
                }
#endif
#ifdef HAVE_UHD
                if (strstr(optarg, "usrp-") == optarg) {
                    usrp_serial = strdup(usrp_get_serial(optarg));
                    break;
                }
#endif
#ifdef HAVE_SOAPYSDR
                if (strstr(optarg, "soapy-") == optarg) {
                    soapy_num = atoi(optarg + 6);
                    break;
                }
#endif
                errx(1, "Unknown SDR interface: %s", optarg);
                break;

            case 'c':
                center_freq = atof(optarg);
                break;

            case 'r':
                samp_rate = atof(optarg);
                break;

            case 'B':
                bias_tee = 1;
                break;

            case 'd':
                threshold_db = atof(optarg);
                break;

            case 'v':
                verbose = 1;
                break;

            case OPT_FILE_INFO:
                file_info = strdup(optarg);
                break;

            case OPT_FORMAT:
                format_explicit = 1;
                if (strcmp(optarg, "ci8") == 0)
                    iq_format = FMT_CI8;
                else if (strcmp(optarg, "ci16") == 0)
                    iq_format = FMT_CI16;
                else if (strcmp(optarg, "cf32") == 0)
                    iq_format = FMT_CF32;
                else
                    errx(1, "Unknown format '%s'. Use ci8, ci16, or cf32.", optarg);
                break;

            case OPT_LIST:
                list_interfaces();
                break;

            case OPT_HACKRF_LNA:  hackrf_lna_gain  = atoi(optarg); break;
            case OPT_HACKRF_VGA:  hackrf_vga_gain  = atoi(optarg); break;
            case OPT_HACKRF_AMP:  hackrf_amp_enable = 1;           break;
            case OPT_BLADERF_GAIN: bladerf_gain_val = atoi(optarg); break;
            case OPT_USRP_GAIN:   usrp_gain_val    = atoi(optarg); break;
            case OPT_SOAPY_GAIN:  soapy_gain_val   = atof(optarg); break;
            case OPT_NO_GPU:      use_gpu = 0;                       break;
            case OPT_NO_SIMD:     no_simd = 1;                       break;
            case OPT_WEB:
                web_enabled = 1;
                if (optarg) web_port = atoi(optarg);
                break;

            case OPT_GSMTAP:
                gsmtap_enabled = 1;
                if (optarg) {
                    char *colon = strrchr(optarg, ':');
                    if (colon) {
                        *colon = '\0';
                        gsmtap_host = strdup(optarg);
                        gsmtap_port = atoi(colon + 1);
                    } else {
                        gsmtap_host = strdup(optarg);
                    }
                }
                break;

            case OPT_SAVE_BURSTS:
                save_bursts_dir = strdup(optarg);
                break;

            case OPT_DIAGNOSTIC:
                diagnostic_mode = 1;
                break;

            case OPT_GARDNER:
                use_gardner = 1;
                break;

            case OPT_NO_GARDNER:
                use_gardner = 0;
                break;

            case OPT_PARSED:
                parsed_mode = 1;
                break;

            case 'h':
                usage(0);
                break;

            case '?':
            default:
                usage(1);
                break;
        }
    }

    if (!live && in_file == NULL)
        usage(1);

    if (live && in_file != NULL)
        errx(1, "Cannot use both --live and --file");

    /* Auto-detect format from file extension if not explicitly specified */
    if (in_filename && !format_explicit) {
        const char *ext = strrchr(in_filename, '.');
        if (ext) {
            if (strcmp(ext, ".cf32") == 0 || strcmp(ext, ".fc32") == 0 ||
                strcmp(ext, ".cfile") == 0)
                iq_format = FMT_CF32;
            else if (strcmp(ext, ".ci16") == 0 || strcmp(ext, ".cs16") == 0 ||
                     strcmp(ext, ".sc16") == 0)
                iq_format = FMT_CI16;
            /* .ci8 and other extensions keep the ci8 default */
        }
    }

    if (samp_rate <= 0)
        errx(1, "Invalid sample rate: %.0f", samp_rate);

    if (center_freq <= 0)
        errx(1, "Invalid center frequency: %.0f", center_freq);
}
