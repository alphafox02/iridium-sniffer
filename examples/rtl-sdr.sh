#!/bin/sh
# RTL-SDR (via SoapySDR) -- 8-bit ADC, 2.4 MHz max
#
# Gain range: 0-50 dB (varies by tuner chip)
# Recommended: 40 dB
#
# Center frequency: 1625500000 Hz (1625.5 MHz) -- shifted up from the
# default 1622 MHz because at 2.4 MHz bandwidth you only see a small
# slice of the 10.5 MHz Iridium band. The upper portion has the most
# active ring alert and broadcast channels.
#
# Limited to 2.4 MHz bandwidth, covering only a fraction of the
# 10.5 MHz Iridium band. Expect significantly fewer bursts than
# wideband receivers. Still useful for basic monitoring.
#
# The R820T/R820T2 tuner covers up to ~1766 MHz. The RTL-SDR Blog V4
# (R828D) also works via its built-in upconverter. Other tuners
# (FC0012/FC0013) do not reach L-band.
#
# Use a lower sample rate since the default 10 MHz exceeds RTL-SDR limits:
#   ./iridium-sniffer -l -i soapy-0 -r 2400000 -c 1625500000 --soapy-gain=40

exec ./iridium-sniffer -l -i soapy-0 -r 2400000 -c 1625500000 --soapy-gain=40 --web "$@"
