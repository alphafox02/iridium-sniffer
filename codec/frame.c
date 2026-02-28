/* Iridium AMBE vocoder - Speech parameters to/from frame */

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

/*! \file codec/frame.c
 *  \brief Iridium AMBE speech parameters to/from frame
 */

#include <stdint.h>
#include <stdio.h>		/* DEBUG */
#include <stdlib.h>
#include <string.h>

#include <math.h>

#include "private.h"


/*! \brief Apply/Remove interleaving
 *         Can be used to do both intra & inter using il_step
 *  \param[inout] lin_buf Linear bit buffer
 *  \param[inout] il_buf Interleaved bit buffer
 *  \param[in] il_step step to use when accesing il_buf
 *  \param[in] N Number of bits
 *  \param[in] dir Directon (0=interleave 1=de-interleave)
 */
void
ir77_ambe_interleave(ubit_t *lin_buf, ubit_t *il_buf,
                     int il_step, int N, int dir)
{
	int div, mod;
	int lin_idx, il_idx;
	int i, j;

	div = N / 24;
	mod = N % 24;

	il_idx  = 0;
	i = j = 0;

	for (lin_idx=0; lin_idx<N; lin_idx++)
	{
		/* Data move */
		if (dir)
			lin_buf[lin_idx] = il_buf[il_idx];
		else
			il_buf[il_idx] = lin_buf[lin_idx];

		/* Next index */
		i++;

		if (i == 24) {
			i = 0;
			il_idx  = il_step * ++j;
		} else
			il_idx += il_step * (div + ((i > mod) ? 0 : 1));
	}
}

/*! \brief Apply/Remove the scramnling
 *  \param[out] out Output unpacked bit buffer (can be == in)
 *  \param[in] in Input unpacked bit buffer
 *  \param[in] N Number of bits
 *  \param[in] seed Seed value of the PRNG
 */
void
ir77_ambe_scramble(ubit_t *out, ubit_t *in, int N, uint32_t seed)
{
	uint32_t v;
	int i;

	v = seed << 3;

	for (i=0; i<N; i++)
	{
		v = ((v * 173) + 13849) & 0xffff;
		out[i] = in[i] ^ (v >> 15);
	}
}

/*! \brief Apply or remove prioritization of bits
 *  \param[inout] lin_buf Buffer containing linearized bits
 *  \param[inout] prio_buf Buffer containing prioritized bits
 *  \param[in] dir Directon (0=prioritize 1=de-prioritize)
 */
void
ir77_ambe_prioritize(ubit_t *lin_buf, ubit_t *prio_buf, int dir)
{
	int lin_idx, prio_idx, i, j;

	prio_idx = 0;

	for (i=0; ir77_ambe_prio_tbl[i].len; i++)
	{
		lin_idx = ir77_ambe_prio_tbl[i].pos;

		for (j=0; j<ir77_ambe_prio_tbl[i].len; j++)
		{
			if (dir)
				lin_buf[lin_idx] = prio_buf[prio_idx];
			else
				prio_buf[lin_idx] = lin_buf[prio_idx];

			prio_idx++;
			lin_idx++;
		}
	}
}

/*! \brief Grabs the requests bits from a frame (MSB first)
 *  \param[in] p Pointer to the first bit to read (MSB)
 *  \param[in] len Number of bits to grab (max 8)
 *  \returns The selected bits as a uint8_t
 */
static inline uint8_t
_get_bits(const ubit_t **p, int len)
{
	uint8_t v = 0;

	while (len--)
		v = (v << 1) | *(*p)++;

	return v;
}

/*! \brief Classify a frame into the different frame types
 *  \param[in] frame Frame data (as de-prioritized 103 ubits)
 *  \returns The frame type
 */
enum ir77_ambe_frame_type
ir77_ambe_frame_classify(const ubit_t *frame)
{
	const ubit_t *p = frame;
	uint8_t t;

	t = _get_bits(&p, 4);

	if (t == 0xf) {
		/* Special */
		t = _get_bits(&p, 2);

		switch (t) {
		case 0:
			return AMBE_SILENCE;
		case 1:
			return AMBE_TONE;
		default:
			return AMBE_INVALID;
		}
	} else {
		return AMBE_SPEECH;
	}
}

/*! \brief Unpacks a frame into its raw encoded parameters
 *  \param[out] rp Encoded frame raw parameters to unpack into
 *  \param[in] frame Frame data (as de-prioritized 103 ubits)
 */
void
ir77_ambe_frame_unpack_raw(struct ir77_ambe_raw_params *rp, const ubit_t *frame)
{
	const ubit_t *p = frame;
	int i;

	rp->pitch_mean = _get_bits(&p, 4);
	rp->pitch_diff = _get_bits(&p, 6);
	rp->gain_mean  = _get_bits(&p, 5);
	rp->gain_diff  = _get_bits(&p, 5);
	rp->v_uv[0]    = _get_bits(&p, 4);
	rp->v_uv[1]    = _get_bits(&p, 4);

	rp->prba_sum12 = _get_bits(&p, 8);
	rp->prba_sum34 = _get_bits(&p, 6);
	rp->prba_sum57 = _get_bits(&p, 7);
	rp->prba_dif13 = _get_bits(&p, 8);
	rp->prba_dif47 = _get_bits(&p, 6);

	for (i=0; i<4; i++)
	{
		rp->hoc_sum[i] = _get_bits(&p, 7);
		rp->hoc_dif[i] = _get_bits(&p, 3);
	}

#ifdef DEBUG
	printf("--- RAW frame:\n");
	for (i=0; i<103; i++)
		printf("%d", frame[i]);
	printf("\n");

	printf("--- RAW params:\n");
	printf("  .pitch_mean : %3d\n", rp->pitch_mean);
	printf("  .pitch_diff : %3d\n", rp->pitch_diff);
	printf("  .gain_mean  : %3d\n", rp->gain_mean);
	printf("  .gain_diff  : %3d\n", rp->gain_diff);
	printf("  .v_uv[0]    : %3d\n", rp->v_uv[0]);
	printf("  .v_uv[1]    : %3d\n", rp->v_uv[1]);
	printf("  .prba_sum12 : %3d\n", rp->prba_sum12);
	printf("  .prba_sum34 : %3d\n", rp->prba_sum34);
	printf("  .prba_sum57 : %3d\n", rp->prba_sum57);
	printf("  .prba_dif13 : %3d\n", rp->prba_dif13);
	printf("  .prba_dif47 : %3d\n", rp->prba_dif47);

	for (i=0; i<4; i++)
	{
		printf("  .hoc_sum[%d] : %3d\n", i, rp->hoc_sum[i]);
		printf("  .hoc_dif[%d] : %3d\n", i, rp->hoc_dif[i]);
	}
#endif
}

/*! \brief Computes and fill-in f0, L and Lb vaues for a given subframe
 *         (from f0log_mean and f0log_diff)
 *  \param[out] sf Subframe
 *  \param[in] f0log_mean f0 mean value for this subframe pair
 *  \param[in] f0log_diff f0 diff value for this subframe
 */
static void
ir77_ambe_subframe_compute_f0_L_Lb(struct ir77_ambe_subframe *sf,
                                   float f0log_mean, float f0log_diff)
{
	float f0;

	sf->f0log = f0log_mean + f0log_diff;

	f0 = powf(2.0f, sf->f0log);
	f0 = fmaxf(fminf(f0, 0.05222f), 0.00810f);
	sf->f0 = f0;

	sf->L = (int)floorf(0.4627f / sf->f0);
	sf->L = (sf->L < 9) ? 9 : ((sf->L > 56) ? 56 : sf->L);

	sf->Lb[0] = ir77_ambe_hpg_tbl[sf->L - 9][0];
	sf->Lb[1] = ir77_ambe_hpg_tbl[sf->L - 9][1];
	sf->Lb[2] = ir77_ambe_hpg_tbl[sf->L - 9][2];
	sf->Lb[3] = ir77_ambe_hpg_tbl[sf->L - 9][3];

#ifdef DEBUG
	printf("---- Decoded f0/L/Lb\n");
	printf("  .f0log_mean : %f\n", f0log_mean);
	printf("  .f0log_diff : %f\n", f0log_diff);
	printf("  .f0         : %f [%04x]\n", f0, (int)(roundf(f0 * (1<<19))));
	printf("  .L   : %d\n", sf->L);
	printf("  .Lb0 : %d\n", sf->Lb[0]);
	printf("  .Lb1 : %d\n", sf->Lb[1]);
	printf("  .Lb2 : %d\n", sf->Lb[2]);
	printf("  .Lb3 : %d\n", sf->Lb[3]);
#endif
}

/*! \brief Resample and "ac-couple" (remove mean) a magnitude array to a new L
 *  \param[in] mag_dst Destination magnitude array (L_dst elements)
 *  \param[in] L_dst Target number of magnitudes
 *  \param[in] mag_src Source magnitude array (L_src elements)
 *  \param[in] L_src Source number of magnitudes
 */
static void
ir77_ambe_resample_mag(float *mag_dst, int L_dst, float *mag_src, int L_src)
{
	float avg, step, pos;
	int i;

	avg  = 0.0f;
	step = (float)L_src / (float)L_dst;
	pos  = step;

	for (i=0; i<L_dst; i++)
	{
		int posi = (int)floorf(pos);

		if (posi == 0) {
			mag_dst[i] = mag_src[0];
		} else if (posi >= L_src) {
			mag_dst[i] = mag_src[L_src-1];
		} else {
			float alpha = pos - posi;
			mag_dst[i] = mag_src[posi-1] * (1.0f - alpha)
			           + mag_src[posi]   * alpha;
		}

		avg += mag_dst[i];
		pos += step;
	}

	avg /= L_dst;

	for (i=0; i<L_dst; i++)
		mag_dst[i] -= avg;
}

/*! \brief Decodes the speech parameters for both subframes from raw params
 *  \param[out] sf Array of 2 subframes data to fill-in
 *  \param[in] sf_prev Previous subframe 1 data
 *  \param[in] rp Encoded frame raw parameters
 */
void
ir77_ambe_frame_decode_params(struct ir77_ambe_subframe *sf,
                              struct ir77_ambe_subframe *sf_prev,
                              struct ir77_ambe_raw_params *rp)
{
	float f0log, gain;
	int i, j;

	/* f0 / L / Lb for each subframe */
	f0log = -4.4f - 1.777e-1f * rp->pitch_mean;

	for (i=0; i<2; i++)
		ir77_ambe_subframe_compute_f0_L_Lb(&sf[i],
			f0log, ir77_ambe_pitch_diff_vq[rp->pitch_diff][i]);

	/* Gain */
	gain = 0.34375f * (rp->gain_mean + 0.5f);

	for (i=0; i<2; i++)
		sf[i].gain = gain + ir77_ambe_gain_diff_vq[rp->gain_diff][i] - (0.5f * log2f(sf[i].L));

#ifdef DEBUG
	printf("---- Decoded Gain\n");
	printf(" .mean   : %f\n", gain);
	printf(" .diff0  : %f\n", ir77_ambe_gain_diff_vq[rp->gain_diff][0]);
	printf(" .diff1  : %f\n", ir77_ambe_gain_diff_vq[rp->gain_diff][1]);
	printf(" .final0 : %f [%04x]\n", sf[0].gain, (int)(roundf(2048.0f * sf[0].gain)));
	printf(" .final1 : %f [%04x]\n", sf[1].gain, (int)(roundf(2048.0f * sf[1].gain)));
#endif

	/* V/UV */
	for (i=0; i<2; i++)
	{
		uint8_t v_uv = ir77_ambe_v_uv_tbl[rp->v_uv[i]];

		for (j=0; j<8; j++)
			sf[i].v_uv[j] = (v_uv >> (7-j)) & 1;
	}

#ifdef DEBUG
	printf("---- Decode V/UV\n");
	printf(" .v_uv[0] : ");
	for (i=0; i<8; i++)
		printf("%d", sf[0].v_uv[i]);
	printf("\n");
	printf(" .v_uv[1] : ");
	for (i=0; i<8; i++)
		printf("%d", sf[1].v_uv[i]);
	printf("\n");
#endif

	/* Spectral magnitudes */
	for (i=0; i<2; i++)
	{
		int j, k, l;

		/* Prediction */
		ir77_ambe_resample_mag(sf[i].Mlog, sf[i].L, sf_prev->Mlog, sf_prev->L);

		for (j=0; j<sf[i].L; j++)
			sf[i].Mlog[j] *= 0.8f;

		/* PRBA */
		float d = (i == 0) ? -1.0f : 1.0f;
		float prba[8];
		float Ri[8];

		prba[0] = 0.0f;
		prba[1] = ir77_ambe_prba_sum12_vq[rp->prba_sum12][0] +
		      d * ir77_ambe_prba_dif13_vq[rp->prba_dif13][0];
		prba[2] = ir77_ambe_prba_sum12_vq[rp->prba_sum12][1] +
		      d * ir77_ambe_prba_dif13_vq[rp->prba_dif13][1];
		prba[3] = ir77_ambe_prba_sum34_vq[rp->prba_sum34][0] +
		      d * ir77_ambe_prba_dif13_vq[rp->prba_dif13][2];
		prba[4] = ir77_ambe_prba_sum34_vq[rp->prba_sum34][1] +
		      d * ir77_ambe_prba_dif47_vq[rp->prba_dif47][0];
		prba[5] = ir77_ambe_prba_sum57_vq[rp->prba_sum57][0] +
		      d * ir77_ambe_prba_dif47_vq[rp->prba_dif47][1];
		prba[6] = ir77_ambe_prba_sum57_vq[rp->prba_sum57][1] +
		      d * ir77_ambe_prba_dif47_vq[rp->prba_dif47][2];
		prba[7] = ir77_ambe_prba_sum57_vq[rp->prba_sum57][2] +
		      d * ir77_ambe_prba_dif47_vq[rp->prba_dif47][3];

		ir77_ambe_idct(Ri, prba, 8, 8);

		/* Process each block */
		float rconst = (1.0f / (2.0f * (float)M_SQRT2));
		float sum = 0.0f;

		k = 0;

		for (j=0; j<4; j++) {
			const float *hoc_sum_tbl[] = {
				ir77_ambe_hoc0_sum_vq[rp->hoc_sum[0]],
				ir77_ambe_hoc1_sum_vq[rp->hoc_sum[1]],
				ir77_ambe_hoc2_sum_vq[rp->hoc_sum[2]],
				ir77_ambe_hoc3_sum_vq[rp->hoc_sum[3]],
			};
			const float *hoc_dif_tbl[] = {
				ir77_ambe_hoc0_dif_vq[rp->hoc_dif[0]],
				ir77_ambe_hoc1_dif_vq[rp->hoc_dif[1]],
				ir77_ambe_hoc2_dif_vq[rp->hoc_dif[2]],
				ir77_ambe_hoc3_dif_vq[rp->hoc_dif[3]],
			};
			float C[6], c[17];

			/* From PRBA through 2x2 xform */
			C[0] = (Ri[j<<1] + Ri[(j<<1)+1]) * 0.5f;
			C[1] = (Ri[j<<1] - Ri[(j<<1)+1]) * rconst;

			/* HOC */
				/* Default to use all available */
			C[2] = hoc_sum_tbl[j][0] + d * hoc_dif_tbl[j][0];
			C[3] = hoc_sum_tbl[j][1] + d * hoc_dif_tbl[j][1];
			C[4] = hoc_sum_tbl[j][2] + d * hoc_dif_tbl[j][2];
			C[5] = hoc_sum_tbl[j][3] + d * hoc_dif_tbl[j][3];

				/* Zero unused value and if len differ for
				 * sf0/1, then diff vector is not used */
			for (l=2; l<6; l++)
			{
				if (l >= sf[i].Lb[j])
					C[l] = 0.0f;
				else if (l >= sf[i^1].Lb[j])
					C[l] = hoc_sum_tbl[j][l-2];
			}

			/* De-DCT */
			ir77_ambe_idct(c, C, sf[i].Lb[j], (sf[i].Lb[j] < 6) ? sf[i].Lb[j] : 6);

			/* Set magnitudes */
			for (l=0; l<sf[i].Lb[j]; l++)
				sf[i].Mlog[k++] += c[l];

			sum += C[0] * sf[i].Lb[j];
		}

		/* Adjust to final gain value */
		float ofs = sf[i].gain - (sum / sf[i].L);

		for (j=0; j<sf[i].L; j++)
			sf[i].Mlog[j] += ofs;
	}
}

/*! \brief Expands the decoded subframe params to prepare for synthesis
 *  \param[in] sf The subframe to expand
 */
void
ir77_ambe_subframe_expand(struct ir77_ambe_subframe *sf)
{
	float unvc;
	int i;

	sf->w0 = sf->f0 * (2.0f * M_PIf);

	unvc = 0.2046f / sqrtf(sf->w0); /* ??? */

	for (i=0; i<sf->L; i++) {
		int j = (int)(i * 16.0f * sf->f0);
		sf->Vl[i] = sf->v_uv[j];
		sf->Ml[i] = powf(2.0, sf->Mlog[i]) / 8.0f;
		if (!sf->Vl[i])
			sf->Ml[i] *= unvc;
	}
}

/*! @} */
