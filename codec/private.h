/* Iridium AMBE vocoder - private header */

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

#ifndef __OSMO_IR77_AMBE_PRIVATE_H__
#define __OSMO_IR77_AMBE_PRIVATE_H__

/*! \defgroup codec_private Iridium AMBE vocoder - internal API
 *  \ingroup codec
 *  @{
 */

/*! \file codec/private.h
 *  \brief Iridium AMBE vocoder private header
 */

#ifdef HAVE_LIBOSMOCORE
#include <osmocom/core/bits.h>
#else
#include "compat_bits.h"
#endif


#define AMBE_RATE 8000		/*!< \brief AMBE sample rate (Hz) */

/*! \brief AMBE possible frame types */
enum ir77_ambe_frame_type
{
	AMBE_INVALID,		/*!< \brief Invalid frame */
	AMBE_SPEECH,		/*!< \brief Speech frame */
	AMBE_SILENCE,		/*!< \brief Silence indication frame */
	AMBE_TONE,		/*!< \brief Tone frame  */
};

/*! \brief AMBE encoded frame raw parameters */
struct ir77_ambe_raw_params
{
	uint8_t pitch_mean;	/*!< \brief Pitch mean value scalar quantized */
	uint8_t pitch_diff;	/*!< \brief Pitch diff VQ */
	uint8_t gain_mean;	/*!< \brief Gain mean value scalar quantized */
	uint8_t gain_diff;	/*!< \brief Gain diff VQ */
	uint8_t v_uv[2];	/*!< \brief V/UV VQ for each subframe */

	uint8_t prba_sum12;	/*!< \brief PRBA Sum 1-2 VQ */
	uint8_t prba_sum34;	/*!< \brief PRBA Sum 3-4 VQ */
	uint8_t prba_sum57;	/*!< \brief PRBA Sum 5-7 VQ */
	uint8_t prba_dif13;	/*!< \brief PRBA Diff 1-3 VQ */
	uint8_t prba_dif47;	/*!< \brief PRBA Diff 4-7 VQ */

	uint8_t hoc_sum[4];	/*!< \brief HOC Sum VQ for each block */
	uint8_t hoc_dif[4];	/*!< \brief HOC Diff VQ for each block */
};

/*! \brief AMBE subframe parameters */
struct ir77_ambe_subframe
{
	float f0;		/*!< \brief fundamental normalized frequency */
	float f0log;		/*!< \brief log2(f0) */
	float w0;		/*!< \brief fundamental frequency (rad/samp) */
	int L;			/*!< \brief Number of harmonics */
	int Lb[4];		/*!< \brief Harmonics per block */
	int v_uv[8];		/*!< \brief Voicing state */
	int Vl[56];		/*!< \brief Per-harmonic voicing state */
	float gain;		/*!< \brief Gain */
	float Mlog[56];		/*!< \brief log spectral magnitudes */
	float Ml[56];		/*!< \brief spectral magnitudes */
};

/*! \brief AMBE synthesizer state */
struct ir77_ambe_synth
{
	int16_t u_prev;		/*!< \brief Last 'u' of previous subframe */
	float uw_prev[231];	/*!< \brief Unvoiced data from previous subframe */
	float psi1;		/*!< \brief Current PSI angle for fundamental */
	float phi[56];		/*!< \brief Current phase for each harmonic */
	float SE;		/*!< \brief Current energy parameter */
};

/*! \brief AMBE decoder state */
struct ir77_ambe_decoder
{
	float tone_phase_f1;	/*!< \brief Phase frequency 1 for tone frames */
	float tone_phase_f2;	/*!< \brief Phase frequency 2 for tone frames */

	struct ir77_ambe_subframe sf_prev;	/*!< \brief Previous subframe */
	struct ir77_ambe_synth synth;		/*!< \brief Synthesizer state */
};



/* From ecc.c */
void ir77_ambe_golay23_encode(ubit_t *out, ubit_t *in);
int  ir77_ambe_golay23_decode(ubit_t *out, ubit_t *in, uint32_t *data_p);

void ir77_ambe_golay24_encode(ubit_t *out, ubit_t *in);
int  ir77_ambe_golay24_decode(ubit_t *out, ubit_t *in, uint32_t *data_p);

void ir77_ambe_hamming1511_encode(ubit_t *out, ubit_t *in);
int  ir77_ambe_hamming1511_decode(ubit_t *out, ubit_t *in);


/* From frame.c */
void ir77_ambe_interleave(ubit_t *lin_buf, ubit_t *il_buf,
                          int il_step, int N, int dir);
void ir77_ambe_scramble(ubit_t *out, ubit_t *in, int N, uint32_t seed);
void ir77_ambe_prioritize(ubit_t *lin_buf, ubit_t *prio_buf, int dir);

enum ir77_ambe_frame_type ir77_ambe_frame_classify(const ubit_t *frame);

void ir77_ambe_frame_unpack_raw(struct ir77_ambe_raw_params *rp,
                                const ubit_t *frame);
void ir77_ambe_frame_decode_params(struct ir77_ambe_subframe *sf,
                                   struct ir77_ambe_subframe *sf_prev,
                                   struct ir77_ambe_raw_params *rp);
void ir77_ambe_subframe_expand(struct ir77_ambe_subframe *sf);


/* From synth.c */
void ir77_ambe_synth_init(struct ir77_ambe_synth *synth);
void ir77_ambe_synth_enhance(struct ir77_ambe_synth *synth, struct ir77_ambe_subframe *sf);
void ir77_ambe_synth_audio(struct ir77_ambe_synth *synth, int16_t *audio,
                           struct ir77_ambe_subframe *sf,
                           struct ir77_ambe_subframe *sf_prev);


/* From math.c */
#define M_PIf (3.141592653589793f)      /*!< \brief Value of pi as a float */

float cosf_fast(float angle);
float sinf_fast(float angle);
void ir77_ambe_fdct(float *out, float *in, int N, int M);
void ir77_ambe_idct(float *out, float *in, int N, int M);
void ir77_ambe_fdft_fc(float *out_i, float *out_q, float *in, int N, int M);
void ir77_ambe_idft_cf(float *out, float *in_i, float *in_q, int N, int M);


/* From tables.c */
extern const struct { uint8_t pos; uint8_t len; } ir77_ambe_prio_tbl[];

extern const float   ir77_ambe_pitch_diff_vq[64][2];
extern const uint8_t ir77_ambe_hpg_tbl[48][4];
extern const float   ir77_ambe_gain_diff_vq[32][2];
extern const uint8_t ir77_ambe_v_uv_tbl[16];

extern const float ir77_ambe_prba_sum12_vq[256][2];
extern const float ir77_ambe_prba_sum34_vq[ 64][2];
extern const float ir77_ambe_prba_sum57_vq[128][3];
extern const float ir77_ambe_prba_dif13_vq[256][3];
extern const float ir77_ambe_prba_dif47_vq[ 64][4];

extern const float ir77_ambe_hoc0_sum_vq[128][4];
extern const float ir77_ambe_hoc0_dif_vq[128][4];
extern const float ir77_ambe_hoc1_sum_vq[128][4];
extern const float ir77_ambe_hoc1_dif_vq[128][4];
extern const float ir77_ambe_hoc2_sum_vq[128][4];
extern const float ir77_ambe_hoc2_dif_vq[128][4];
extern const float ir77_ambe_hoc3_sum_vq[128][4];
extern const float ir77_ambe_hoc3_dif_vq[128][4];

/* From tones.c */
int ir77_ambe_decode_tone(struct ir77_ambe_decoder *dec,
                          int16_t *audio, int N, const ubit_t *frame);


/*! @} */

#endif /* __OSMO_IR77_AMBE_PRIVATE_H__ */
