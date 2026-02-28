/* Iridium AMBE vocoder - Tone frames */

/* (C) 2015 by Sylvain Munaut <tnt@246tNt.com>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*! \addtogroup codec_private
 *  @{
 */

/*! \file codec/tone.c
 *  \brief Iridium AMBE vocoder tone frames handling
 */

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "private.h"


/*! \brief Structure describing a dual-frequency tone */
struct tone_desc {
	char *name;	/*!< \brief Tone description */
	int f1;		/*!< \brief Frequency 1 (Hz) */
	int f2;		/*!< \brief Frequency 2 (Hz) */
};

/*! \brief DTMF tones descriptions */
static const struct tone_desc dtmf_tones[] = {
	{ "0", 1336, 941 },
	{ "1", 1209, 697 },
	{ "2", 1336, 697 },
	{ "3", 1477, 697 },
	{ "4", 1209, 770 },
	{ "5", 1336, 770 },
	{ "6", 1477, 770 },
	{ "7", 1209, 852 },
	{ "8", 1336, 852 },
	{ "9", 1477, 852 },
	{ "A", 1633, 697 },
	{ "B", 1633, 770 },
	{ "C", 1633, 852 },
	{ "D", 1633, 941 },
	{ "#", 1477, 941 },
	{ "*", 1209, 941 },
};

/*! \brief Call progress tones descriptions */
static const struct tone_desc call_progress_tones[] = {
	{ "Dial", 440, 350 },
	{ "Ring", 480, 440 },
	{ "Busy", 630, 480 },
	{ "????", 490, 350 },
};


/*! \brief Synthesize and add a tone to a given audio buffer
 *  \param[out] audio Audio buffer to mix the tone into
 *  \param[in] N number of audio samples to generate
 *  \param[in] ampl Tone amplitude
 *  \param[in] freq_hz Tone frequency in Hertz
 *  \param[inout] phase_p Pointer to phase variable to use
 */
static void
tone_gen(int16_t *audio, int N, int ampl, int freq_hz, float *phase_p)
{
	float phase, phase_step;
	int i;

	phase = *phase_p;
	phase_step = (2.0f * M_PIf * freq_hz) / AMBE_RATE;

	for (i=0; i<N; i++)
	{
		audio[i] += (int16_t)(ampl * cosf(phase));
		phase += phase_step;
	}

	*phase_p = phase;
}


/*! \brief Decodes an AMBE tone frame
 *  \param[in] dec AMBE decoder state
 *  \param[out] audio Output audio buffer
 *  \param[in] N number of audio samples to produce (152..168)
 *  \param[in] frame Frame data (as de-prioritized 103 ubits). Must be tone !
 *  \returns 0 for success. -EINVAL if frame was invalid.
 */
int
ir77_ambe_decode_tone(struct ir77_ambe_decoder *dec,
                      int16_t *audio, int N, const ubit_t *frame)
{
	int p_log_ampl, p_freq;
	int i, j, cnt;
	int amplitude;

	/* Decode parameters */
	p_log_ampl =
		(frame[10] << 7) |
		(frame[11] << 6) |
		(frame[12] << 5) |
		(frame[15] << 4) |
		(frame[16] << 3) |
		(frame[17] << 2) |
		(frame[18] << 1) |
		(frame[19] << 0);

	p_freq = 0;
	for (i=0; i<8; i++) {
		cnt = 0;
		for (j=0; j<10; j++)
			cnt += frame[20+(j<<3)+i];
		p_freq = (p_freq << 1) | (cnt >= 5);
	}

	/* Clear audio */
	memset(audio, 0x00, sizeof(int16_t) * N);

	/* Compute amplitude */
	amplitude = (int)(32767.0f * exp2f(((float)p_log_ampl-255.0f)/17.0f));

	/* Interpret frequency code */
	if (p_freq < 0x10)
	{
		/* DTMF tone */
		int di = p_freq & 0xf;

		tone_gen(audio, N, amplitude >> 1,
		         dtmf_tones[di].f1, &dec->tone_phase_f1);
		tone_gen(audio, N, amplitude >> 1,
		         dtmf_tones[di].f2, &dec->tone_phase_f2);
	}
	else if ((p_freq >= 0x15) && (p_freq <= 0x8a))
	{
		int freq_hz = ((p_freq - 0x10) * 125) >> 2; /* 31.25 Hz increments */

		tone_gen(audio, N, amplitude,
		         freq_hz, &dec->tone_phase_f1);
	}
	else if ((p_freq >= 0x90) && (p_freq <= 0x94))
	{
		/* Call progress tone */
		int cpi = p_freq & 0xf;

		tone_gen(audio, N, amplitude >> 1,
		         call_progress_tones[cpi].f1, &dec->tone_phase_f1);
		tone_gen(audio, N, amplitude >> 1,
		         call_progress_tones[cpi].f2, &dec->tone_phase_f2);
	}
	else
	{
		/* Invalid */
		return -EINVAL;
	}

	return 0;
}

/*! @} */
