/* Iridium AMBE vocoder - Speech synthesis */

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

/*! \file codec/synth.c
 *  \brief Iridium AMBE vocoder speech synthesis
 */

#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

#include "private.h"

/*! \brief Synthesis window (49 samples overlap) */
static const float ws[] = {
	0.00f, 0.02f,
	0.04f, 0.06f, 0.08f, 0.10f, 0.12f, 0.14f, 0.16f, 0.18f,
	0.20f, 0.22f, 0.24f, 0.26f, 0.28f, 0.30f, 0.32f, 0.34f,
	0.36f, 0.38f, 0.40f, 0.42f, 0.44f, 0.46f, 0.48f, 0.50f,
	0.52f, 0.54f, 0.56f, 0.58f, 0.60f, 0.62f, 0.64f, 0.66f,
	0.68f, 0.70f, 0.72f, 0.74f, 0.76f, 0.78f, 0.80f, 0.82f,
	0.84f, 0.86f, 0.88f, 0.90f, 0.92f, 0.94f, 0.96f, 0.98f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f, 1.00f,
	0.98f, 0.96f, 0.94f, 0.92f, 0.90f, 0.88f, 0.86f, 0.84f,
	0.82f, 0.80f, 0.78f, 0.76f, 0.74f, 0.72f, 0.70f, 0.68f,
	0.66f, 0.64f, 0.62f, 0.60f, 0.58f, 0.56f, 0.54f, 0.52f,
	0.50f, 0.48f, 0.46f, 0.44f, 0.42f, 0.40f, 0.38f, 0.36f,
	0.34f, 0.32f, 0.30f, 0.28f, 0.26f, 0.24f, 0.22f, 0.20f,
	0.18f, 0.16f, 0.14f, 0.12f, 0.10f, 0.08f, 0.06f, 0.04f,
	0.02f, 0.00f,
};

/*! \brief Random phase increment (precomputed) */
static const float rho[] = {
	 3.002978f, -0.385743f, -1.804058f,  0.708389f,  3.080091f,  0.234237f,
	-2.601564f,  2.564900f,  0.101063f, -0.241570f, -2.283176f,  0.460491f,
	-1.611275f,  2.258339f, -2.055267f,  1.733923f,  2.517236f, -1.766211f,
	 0.897032f, -2.360999f, -0.280836f, -2.714514f,  2.100092f,  2.300326f,
	-1.158767f, -2.044268f, -2.668387f, -2.578737f,  0.185036f,  1.551429f,
	 2.726814f,  2.655614f,  3.046857f,  0.834348f, -0.513595f,  1.466037f,
	 0.691121f,  0.127319f, -2.034924f, -1.070655f,  0.456588f, -2.278682f,
	 1.229021f, -2.139595f, -0.119750f, -0.301534f,  0.029391f,  0.068775f,
	 0.520336f,  2.339119f, -0.808328f,  1.332154f,  2.929768f, -0.338316f,
	 0.022767f, -1.063795f,
};


/*! \brief Generates random sequence of uint16_t according to spec
 *  \param[out] u_seq Result buffer
 *  \param[in] u_prev Last 'u' value of where to resume from
 *  \param[in] n Number of items to generate
 */
static void
ir77_ambe_gen_random(uint16_t *u_seq, uint16_t u_prev, int n)
{
	uint32_t u = u_prev;
	int i;

	for (i=0; i<n; i++) {
		u = (u * 171 + 11213) % 53125;
		u_seq[i] = u;
	}
}

/*! \brief Perform unvoiced synthesis
 *  \param[in] synth Synthesizer state structure
 *  \param[out] suv Result buffer (180 samples)
 *  \param[in] sf Expanded subframe data
 */
static void
ir77_ambe_synth_unvoiced(struct ir77_ambe_synth *synth, float *suv,
                         struct ir77_ambe_subframe *sf)
{
	uint16_t u[231];
	float uw[231];
	float Uwi[129], Uwq[129];
	int i, al, bl, l;

	/* Generate the white noise sequence and window it with ws */
	ir77_ambe_gen_random(u, synth->u_prev, 231);
	synth->u_prev = u[179];

	for (i=0; i<231; i++)
		uw[i] = (float)u[i] * ws[i];

	/* Compute the DFT */
	ir77_ambe_fdft_fc(Uwi, Uwq, uw, 256, 231);

	/* Apply the spectral magnitude */
	bl = ceilf(256.0f / (2 * M_PIf) * (.5f) * sf->w0);

	for (i=0; i<bl; i++) {
		Uwi[i] = 0.0f;
		Uwq[i] = 0.0f;
	}

	for (l=0; l<sf->L; l++)
	{
		float ampl;

		/* Edges */
		al = bl;
		bl = ceilf(256.0f / (2 * M_PIf) * (l + 1.5f) * sf->w0);

		/* Compute factor */
		ampl = 0.0f;

		for (i=al; i<bl; i++) {
			ampl += Uwi[i] * Uwi[i] + Uwq[i] * Uwq[i];
		}

		ampl = 76.89f * sf->Ml[l] / sqrtf(ampl / (bl - al));

		/* Set magnitude */
		for (i=al; i<bl; i++) {
			if (sf->Vl[l]) {
				Uwi[i] = 0.0f;
				Uwq[i] = 0.0f;
			} else {
				Uwi[i] *= ampl;
				Uwq[i] *= ampl;
			}
		}
	}

	for (i=bl; i<=128; i++) {
		Uwi[i] = 0.0f;
		Uwq[i] = 0.0f;
	}

	/* Get time-domain samples via iDFT */
	ir77_ambe_idft_cf(uw, Uwi, Uwq, 256, 231);

	/* Weighted Overlap And Add */
	for (i=0; i<66; i++) {
		suv[i] = synth->uw_prev[i + 115];
	}

	for (i=66; i<115; i++) {
		suv[i] = (ws[i + 115] * synth->uw_prev[i + 115] + ws[i - 65] * uw[i - 65])
		       / (ws[i + 115] * ws[i + 115] + ws[i - 65] * ws[i - 65]);
	}

	for (i=115; i<180; i++) {
		suv[i] = uw[i - 65];
	}

	memcpy(synth->uw_prev, uw, sizeof(float) * 231);
}

/*! \brief Perform voiced synthesis
 *  \param[in] synth Synthesizer state structure
 *  \param[out] sv Result buffer (180 samples)
 *  \param[in] sf Expanded subframe data for current subframe
 *  \param[in] sf_prev Expanded subframe data for prevous subframe
 */
static void
ir77_ambe_synth_voiced(struct ir77_ambe_synth *synth, float *sv,
                       struct ir77_ambe_subframe *sf,
                       struct ir77_ambe_subframe *sf_prev)
{
	int i, l, L_max, L_uv;

	/* Pre-clear */
	memset(sv, 0x00, sizeof(float) * 180);

	/* How many subband to process */
	L_max = sf_prev->L > sf->L ? sf_prev->L : sf->L;

	/* psi update */
	L_uv = 0;
	for (l=0; l<L_max; l++)
		L_uv += sf->Vl[l] ? 0 : 1;

	synth->psi1 = remainderf(synth->psi1 + (sf->w0 + sf_prev->w0) * 90.0f, 2 * M_PIf);

	/* Scan each band */
	for (l=0; l<L_max; l++)
	{
		int   Vl_cur,  Vl_prev;
		float Ml_cur,  Ml_prev;
		float phi_cur, phi_prev;
		float w_cur,   w_prev;
		int fine;

		/* Handle out-of-bound for Vl and Ml */
		Vl_cur  = l >= sf->L      ? 0 : sf->Vl[l];
		Vl_prev = l >= sf_prev->L ? 0 : sf_prev->Vl[l];

		Ml_cur  = l >= sf->L      ? 0.0f : sf->Ml[l];
		Ml_prev = l >= sf_prev->L ? 0.0f : sf_prev->Ml[l];

		/* Phase and Angular speed */
		w_cur   = (l+1) * sf->w0;
		w_prev  = (l+1) * sf_prev->w0;

		phi_prev = synth->phi[l];
		phi_cur  = synth->psi1 * (l+1);

		if (l >= (sf->L / 4))
			phi_cur += ((float)L_uv / (float)sf->L) * rho[l];

		synth->phi[l] = phi_cur;

		/* Actual synthesis */
			/* Can we do a fine transistion ? */
		fine = Vl_cur && Vl_prev && (l < 7) && (fabsf(w_cur - w_prev) < (.1f * w_cur));

			/* Fine transition */
		if (fine)
		{
			float Ml_step = (Ml_cur - Ml_prev) / 180.0f;
			float Dpl = phi_cur - phi_prev - (w_cur + w_prev) * 90.0f;
			float Dwl = (Dpl - 2 * M_PIf * floorf((Dpl + M_PIf) / (2 * M_PIf))) / 180.0f;
			float THa = w_prev + Dwl;
			float THb = (w_cur - w_prev) / 360.0f;

			for (i=0; i<180; i++)
				sv[i] += (Ml_prev + i * Ml_step) * cosf_fast(
					phi_prev + (THa + THb * i) * i
				);
		}

			/* Coarse transition: Current frame (if voiced) */
		if (!fine && Vl_cur)
		{
			for (i=66; i<180; i++)
				sv[i] += ws[i-65] * Ml_cur * cosf_fast(phi_cur + w_cur * (i - 180));
		}

			/* Coarse transition: Previous frame (if voiced) */
		if (!fine && Vl_prev)
		{
			for (i=0; i<115; i++)
				sv[i] += ws[i+115] * Ml_prev * cosf_fast(phi_prev + w_prev * i);
		}
	}

	/* Still need to update phi for the rest of the bands */
	for (l=L_max; l<56; l++)
		synth->phi[l] = (synth->psi1 * (l+1)) + (((float)L_uv / (float)sf->L) * rho[l]);
}


/*! \brief Initialized Synthesizer state
 *  \param[out] synth The structure to reset
 */
void
ir77_ambe_synth_init(struct ir77_ambe_synth *synth)
{
	memset(synth, 0x00, sizeof(struct ir77_ambe_synth));
	synth->u_prev = 3147;
}

/*! \brief Apply the spectral magnitude enhancement on the subframe
 *  \param[in] synth Synthesizer state structure
 *  \param[in] sf Expanded subframe data for subframe to enhance
 */
void
ir77_ambe_synth_enhance(struct ir77_ambe_synth *synth,
                        struct ir77_ambe_subframe *sf)
{
	float rm0, rm1;
	float k1, k2, k3;
	float gamma;
	int l;

	/* Compute RM0 and RM1 */
	rm0 = 0.0f;
	rm1 = 0.0f;

	for (l=0; l<sf->L; l++)
	{
		float sq = sf->Ml[l] * sf->Ml[l];
		rm0 += sq;
		rm1 += sq * cosf_fast(sf->w0 * (l+1));
	}

	/* Pre compute some constants */
	k1 = 0.96f * M_PIf / (sf->w0 * rm0 * (rm0 * rm0 - rm1 * rm1));
	k2 = rm0 * rm0 + rm1 * rm1;
	k3 = 2.0f * rm0 * rm1;

	/* Apply to the amplitudes */
	gamma = 0.0f;

	for (l=0; l<sf->L; l++)
	{
		float w;

		if ( (l+1)*8 <= sf->L ) {
			w = 1.0f;
		} else {
			w = sqrtf(sf->Ml[l]) * powf(
				k1 * (k2 - k3 * cosf_fast(sf->w0 * (l+1))),
				0.25f
			);

			if (w > 1.2f)
				w = 1.2f;
			else if (w < 0.5f)
				w = 0.5f;
		}

		sf->Ml[l] *= w;

		gamma += sf->Ml[l] * sf->Ml[l];
	}

	/* Compute final gamma and apply it */
	gamma = sqrtf(rm0 / gamma);

	for (l=0; l<sf->L; l++)
	{
		sf->Ml[l] *= gamma;
	}

	/* Update SE */
	synth->SE = 0.95f * synth->SE + 0.05f * rm0;
	if (synth->SE < 1e4f)
		synth->SE = 1e4f;
}

/*! \brief Generate audio for a given subframe
 *  \param[in] synth Synthesizer state structure
 *  \param[out] audio Result buffer (180 samples)
 *  \param[in] sf Expanded subframe data for current subframe
 *  \param[in] sf_prev Expanded subframe data for prevous subframe
 */
void
ir77_ambe_synth_audio(struct ir77_ambe_synth *synth, int16_t *audio,
                      struct ir77_ambe_subframe *sf,
                      struct ir77_ambe_subframe *sf_prev)
{
	float suv[180], sv[180];
	int i;

	ir77_ambe_synth_unvoiced(synth, suv, sf);
	ir77_ambe_synth_voiced(synth, sv, sf, sf_prev);
	for (i=0; i<180; i++)
		audio[i] = (int16_t)((suv[i] + 2.0f * sv[i]) * 4.0f);
}

/*! @} */
