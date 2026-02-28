/* Iridium AMBE vocoder - ECC routines */

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

/*! \file codec/ecc.c
 *  \brief Iridium AMBE vocoder ECC routines
 */

#ifdef HAVE_LIBOSMOCORE
#include <osmocom/core/bits.h>
#else
#include "compat_bits.h"
#endif

#include "ecc_tables.h"


/* Local helpers ---------------------------------------------------------- */

/*! \brief Writes a given word as ubits (MSBs first)
 *  \param[out] bits Pointer where to write the ubits
 *  \param[in] word Word to write
 *  \param[in] N Number of bits
 */
static void
_ubit_write(ubit_t *bits, uint32_t word, int N)
{
	int i, s;

	s = N - 1;
	for (i=0; i<N; i++)
		bits[i] = (word >> s--) & 1;
}

/*! \brief Reads a word from ubits (MSBs first)
 *  \param[in] bits Pointer where to read the ubits from
 *  \param[in] N Number of bits
 *  \returns The reconstructed value (unsigned)
 */
static uint32_t
_ubit_read(ubit_t *bits, int N)
{
	uint32_t rv = 0;
	int i;

	for (i=0; i<N; i++)
		rv = (rv << 1) | bits[i];

	return rv;
}

/*! \brief Computed the hamming weight of a given word (number of 1 bits)
 *  \param[in] v Value
 *  \returns Hamming weight of 'v'
 */
static int
_weight(uint32_t v)
{
	const int hw[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
	int i, t;

	t = 0;
	for (i=0; i<32; i+=4)
		t += hw[(v >> i) & 0xf];

	return t;
}


/* Golay 23/12 & 24/12 ---------------------------------------------------- */

/*! \brief Computes Golay Syndrome of given word
 *  \param[in] data Data word
 *  \param[in] tbl Mask table to use
 *  \returns Syndrome of 'data' using 'tbl'
 */
static uint32_t
_golay_syndrome(uint32_t data, const uint32_t *tbl)
{
	uint32_t syndrome, mask;
	int i;

	syndrome = 0;
	mask = 1<<11;

	for (i=0; i<12; i++) {
		if (data & mask)
			syndrome ^= tbl[i];
		mask >>= 1;
	}

	return syndrome;
}

/*! \brief Encode one word using Golay 23/12
 *  \param[out] out 23 ubits output buffer
 *  \param[in] in 12 ubits input buffer
 */
void
ir77_ambe_golay23_encode(ubit_t *out, ubit_t *in)
{
	uint32_t cw;

	cw = _ubit_read(in, 12);
	cw = (cw << 11) | _golay_syndrome(cw, _golay23_syn_tbl);

	_ubit_write(out, cw, 23);
}

/*! \brief Decode one word using Golay 23/12 code
 *  \param[out] out 12 ubits output buffer
 *  \param[in] in 23 ubits input buffer
 *  \param[out] data_p Optional return pointer for the decoded word
 *  \returns Number of bits errors
 */
int
ir77_ambe_golay23_decode(ubit_t *out, ubit_t *in, uint32_t *data_p)
{
	uint32_t cw, data, ecc_rx, ecc_ex, syn;
	int w = 0;

	cw = _ubit_read(in, 23);

	data   = cw >> 11;
	ecc_rx = cw & 0x7ff;
	ecc_ex = _golay_syndrome(data, _golay23_syn_tbl);

	syn = ecc_ex ^ ecc_rx;

	if (syn) {
		uint32_t errors = _golay23_dec_tbl[syn];
		data ^= errors >> 11;
		w = _weight(errors);
	}

	_ubit_write(out, data, 12);

	if (data_p)
		*data_p = data;

	return w;
}

/*! \brief Encode one word using Golay 24/12
 *  \param[out] out 24 ubits output buffer
 *  \param[in] in 12 ubits input buffer
 */
void
ir77_ambe_golay24_encode(ubit_t *out, ubit_t *in)
{
	uint32_t cw;

	cw = _ubit_read(in, 12);
	cw = (cw << 12) | _golay_syndrome(cw, _golay24_syn_tbl);

	_ubit_write(out, cw, 24);
}

/*! \brief Decode one word using Golay 24/12 code
 *  \param[out] out 12 ubits output buffer
 *  \param[in] in 24 ubits input buffer
 *  \param[out] data_p Optional return pointer for the decoded word
 *  \returns Number of bits errors
 */
int
ir77_ambe_golay24_decode(ubit_t *out, ubit_t *in, uint32_t *data_p)
{
	uint32_t cw, data, ecc_rx, ecc_ex, syn;
	int w = 0;

	cw = _ubit_read(in, 24);

	data   = cw >> 12;
	ecc_rx = cw & 0xfff;
	ecc_ex = _golay_syndrome(data, _golay24_syn_tbl);

	syn = ecc_ex ^ ecc_rx;

	if (syn) {
		uint32_t errors = _golay23_dec_tbl[syn >> 1];
		data ^= errors >> 11;
		w = _weight(errors);

		//w += (syn & 1) ^ (w & 1);	/* FIXME */
	}

	_ubit_write(out, data, 12);

	if (data_p)
		*data_p = data;

	return w;
}


/* Hamming 15/11 codes ---------------------------------------------------- */

/*! \brief Computes Hamming 15/11 syndrome of a given value
 *  \param[in] v Value
 *  \returns Hamming 15/11 syndrome of 'v'
 */
static uint32_t
_hamming1511_syndrome(uint32_t v)
{
	uint32_t s = 0;
	int i;

	for (i=0; i<4; i++) {
		s <<= 1;
		s |= _weight(v & _ham1511_mask_tbl[i]) & 1;
	}

	return s;
}

/*! \brief Encode one word using Hamming 15/11
 *  \param[out] out 15 ubits output buffer
 *  \param[in] in 11 ubits input buffer
 */
void
ir77_ambe_hamming1511_encode(ubit_t *out, ubit_t *in)
{
	uint32_t cw;

	cw  = _ubit_read(in, 11) << 4;
	cw |= _hamming1511_syndrome(cw);

	_ubit_write(out, cw, 15);
}

/*! \brief Decode one word using Hamming 15/11
 *  \param[out] out 11 ubits output buffer
 *  \param[in] in 15 ubits input buffer
 *  \returns 0 if no errors, 1 if errors
 */
int
ir77_ambe_hamming1511_decode(ubit_t *out, ubit_t *in)
{
	uint32_t cw = _ubit_read(in, 15);
	uint32_t syndrome;
	int w = 0;

	syndrome = _hamming1511_syndrome(cw);

	if (syndrome) {
		cw ^= 1 << _ham1511_fix_tbl[syndrome];
		w = 1;
	}

	_ubit_write(out, cw >> 4, 11);

	return w;
}

/*! @} */
