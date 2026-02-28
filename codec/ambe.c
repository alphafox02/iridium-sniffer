/* Iridium AMBE vocoder - AMBE API */

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

/*! \addtogroup codec
 *  @{
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ambe.h"
#include "private.h"


/*! \brief Allocates and inits a decoder object
 *  \returns A newly allocated and initialized decoder
 */
struct ir77_ambe_decoder *
ir77_ambe_decode_alloc(void)
{
	struct ir77_ambe_decoder *dec;

	dec = calloc(1, sizeof(struct ir77_ambe_decoder));
	if (!dec)
		return NULL;

	ir77_ambe_synth_init(&dec->synth);

	dec->sf_prev.w0 = 0.09378;
	dec->sf_prev.f0 = dec->sf_prev.w0 / (2 * M_PIf);
	dec->sf_prev.L = 30;

	return dec;
}

/*! \brief Release a decoder object created by \ref ir77_ambe_decode_alloc
 *  \param[in] dec Decoder object
 */
void
ir77_ambe_decode_release(struct ir77_ambe_decoder *dec)
{
	free(dec);
}


/*! \brief Decodes an AMBE frame to audio
 *  \param[in] dec Decoder object
 *  \param[out] audio Output audio buffers
 *  \param[in] N number of audio samples to produce (== 360 for now)
 *  \param[in] frame Frame data (as de-prioritized 103 ubits), Must be speech !
 *  \returns 0 for success. Negative error code otherwise.
 */
static int
ir77_ambe_decode_speech(struct ir77_ambe_decoder *dec,
                        int16_t *audio, int N, const ubit_t *frame_lin)
{
	struct ir77_ambe_raw_params rp;
	struct ir77_ambe_subframe sf[2];

	/* Read out params */
	ir77_ambe_frame_unpack_raw(&rp, frame_lin);

	/* Decode params */
	ir77_ambe_frame_decode_params(sf, &dec->sf_prev, &rp);

	/* Expand them */
	ir77_ambe_subframe_expand(&sf[0]);
	ir77_ambe_subframe_expand(&sf[1]);

	/* Perform the actual audio synthesis */
	ir77_ambe_synth_enhance(&dec->synth, &sf[0]);
	ir77_ambe_synth_enhance(&dec->synth, &sf[1]);

	ir77_ambe_synth_audio(&dec->synth, audio      , &sf[0], &dec->sf_prev);
	ir77_ambe_synth_audio(&dec->synth, audio + 180, &sf[1], &sf[0]);

	/* Save previous subframe */
	memcpy(&dec->sf_prev, &sf[1], sizeof(struct ir77_ambe_subframe));

	return 0;
}

/*! \brief Decodes an AMBE superframe (=2 frames) to audio
 *  \param[in] dec Decoder object
 *  \param[out] audio Output audio buffers
 *  \param[in] N number of audio samples to produce (== 720 for now)
 *  \param[in] superframe SuperFrame data (39 bytes = 312 bits)
 *  \returns Number of successfully decoded frames. Negative error code otherwise.
 */
int
ir77_ambe_decode_superframe(struct ir77_ambe_decoder *dec,
                            int16_t *audio, int N,
                            const uint8_t *superframe)
{
	ubit_t superframe_bits[312];
	ubit_t frame_bits[156];
	int frames = 0, i;

	/* Unpack to ubits */
	osmo_pbit2ubit_ext(superframe_bits, 0, superframe, 0, 312, 1);

	/* Process each frame */
	for (i=0; i<2; i++)
	{
		ubit_t frame[103], frame_lin[103];
		enum ir77_ambe_frame_type type;
		int err[6];
		uint32_t seed;

		/* De-interleave */
		ir77_ambe_interleave(frame_bits, superframe_bits+i, 2, 156, 1);

		/* De-FEC */
		err[0] = ir77_ambe_golay24_decode(&frame[ 0], &frame_bits[ 0], &seed);

		ir77_ambe_scramble(&frame_bits[24], &frame_bits[24], 156-24-33, seed);

		err[1] = ir77_ambe_golay23_decode    (&frame[12], &frame_bits[ 24], NULL);
		err[2] = ir77_ambe_golay23_decode    (&frame[24], &frame_bits[ 47], NULL);
		err[3] = ir77_ambe_golay23_decode    (&frame[36], &frame_bits[ 70], NULL);
		err[4] = ir77_ambe_hamming1511_decode(&frame[48], &frame_bits[ 93]);
		err[5] = ir77_ambe_hamming1511_decode(&frame[59], &frame_bits[108]);

		memcpy(&frame[70], &frame_bits[123], 33);

		/* Skip bad frames */
		if ((err[1] + err[2] + err[3]) > 6) {
			memset(&audio[360*i], 0x0, sizeof(int16_t) * 360);
			continue;
		}

		frames++;

		/* De-prioritize */
		ir77_ambe_prioritize(frame_lin, frame, 1);

		/* Classify frame */
		type = ir77_ambe_frame_classify(frame_lin);

		/* Decode appropriately */
		switch (type)
		{
		case AMBE_SPEECH:
			ir77_ambe_decode_speech(dec, &audio[360*i], 360, frame_lin);
			break;

		case AMBE_TONE:
			ir77_ambe_decode_tone(dec, &audio[360*i], 360, frame_lin);
			break;

		case AMBE_SILENCE:
		case AMBE_INVALID:
			memset(&audio[360*i], 0x0, sizeof(int16_t) * 360);
			break;
		}
	}

	return frames;
}

/*! @} */
