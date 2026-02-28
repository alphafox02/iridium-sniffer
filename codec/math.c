/* Iridium AMBE vocoder - Math functions */

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

/*! \file codec/math.c
 *  \brief Iridium AMBE vocoder math functions
 */

#include <math.h>

#include "private.h"


/*! \brief Table for \ref cosf_fast and \ref sinf_fast */
static float cos_tbl[1024];

/*! \brief Initializes \ref cos_tbl for \ref cosf_fast */
static void __attribute__ ((constructor))
cos_tbl_init(void)
{
	int i;

	for (i=0; i<1024; i++)
		cos_tbl[i] = cosf((M_PIf * i) / 512.0f);
}

/*! \brief Fast Cosinus approximation using a simple table
 *  \param[in] angle The angle value
 *  \returns The cosinus of the angle
 */
float
cosf_fast(float angle)
{
	const float f = 512.0f / M_PIf;
	return cos_tbl[(int)(angle*f) & 1023];
}

/*! \brief Fast Sinus approximation using a simple table
 *  \param[in] angle The angle value
 *  \returns The sinus of the angle
 */
float
sinf_fast(float angle)
{
	const float f = 512.0f / M_PIf;
	return cos_tbl[((int)(angle*f) + 768) & 1023];
}

/*! \brief Forward Discrete Cosine Transform (fDCT)
 *  \param[out] out fDCT result buffer (freq domain, M elements)
 *  \param[in] in fDCT input buffer (time domain, N elements)
 *  \param[in] N Number of points of the DCT
 *  \param[in] M Limit to the number of frequency components (M <= N)
 */
void
ir77_ambe_fdct(float *out, float *in, int N, int M)
{
	int i, j;

	for (i=0; i<M; i++)
	{
		float v = 0.0f;

		for (j=0; j<N; j++)
		{
			v += in[j] * cosf_fast( (M_PIf / N) * (j + .5f) * i );
		}

		out[i] = v / (float)N;
	}
}

/*! \brief Inverse Discrete Cosine Transform (iDCT)
 *  \param[out] out iDCT result buffer (time domain, N elements)
 *  \param[in] in iDCT input buffer (freq domain, M elements)
 *  \param[in] N Number of points of the DCT
 *  \param[in] M Limit to the number of frequency components (M <= N)
 */
void
ir77_ambe_idct(float *out, float *in, int N, int M)
{
	int i, j;

	for (i=0; i<N; i++)
	{
		float v = in[0];

		for (j=1; j<M; j++)
		{
			v += 2.0f * in[j] * cosf_fast( (M_PIf / N) * j * (i + .5f) );
		}

		out[i] = v;
	}
}

/*! \brief Forward Discrete Fourrier Transform (float->complex)
 *  \param[out] out_i Real component result buffer (freq domain, N/2+1 elements)
 *  \param[out] out_q Imag component result buffer (freq domain, N/2+1 elements)
 *  \param[in] in Input buffer (time domain, M elements)
 *  \param[in] N Number of points of the DFT
 *  \param[in] M Limit to to the number of available time domain elements
 *
 *  Since the input is float, the result is symmetric and so only one side
 *  is computed. The output index 0 is DC.
 */
void
ir77_ambe_fdft_fc(float *out_i, float *out_q, float *in, int N, int M)
{
	int fb, ts;

	for (fb=0; fb<=(N/2); fb++)
	{
		float i=0.0f, q=0.0f;

		for (ts=0; ts<M; ts++)
		{
			float angle = (- 2.0f * M_PIf / N) * fb * ts;
			i += in[ts] * cosf_fast(angle);
			q += in[ts] * sinf_fast(angle);
		}

		out_i[fb] = i;
		out_q[fb] = q;
	}
}

/*! \brief Inverse Discret Fourrier Transform (complex->float)
 *  \param[out] out Result buffer (time domain, M
 *  \param[in] in_i Real component input buffer (freq domain, N/2+1 elements)
 *  \param[in] in_q Imag component input buffer (freq domain, N/2+1 elements)
 *  \param[in] N Number of points of the DFT
 *  \param[in] M Limit to the number of time domain elements to generate
 *
 *  The input is assumed to be symmetric and so only N/2+1 inputs are
 *  needed. DC component must be input index 0.
 */
void
ir77_ambe_idft_cf(float *out, float *in_i, float *in_q, int N, int M)
{
	int fb, ts;

	for (ts=0; ts<M; ts++)
	{
		float r=0.0f;

		for (fb=0; fb<=(N/2); fb++)
		{
			float angle = (- 2.0f * M_PIf / N) * fb * ts;
			float m = (fb == 0 || fb == (N/2)) ? 1.0f : 2.0f;
			r += m * (in_i[fb] * cosf_fast(angle) + in_q[fb] * sinf_fast(angle));
		}

		out[ts] = r / N;
	}
}

/*! @} */
