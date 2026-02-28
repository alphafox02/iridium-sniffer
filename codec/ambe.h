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

#ifndef __OSMO_IR77_AMBE_AMBE_H__
#define __OSMO_IR77_AMBE_AMBE_H__

/*! \defgroup codec AMBE vocoder
 *  \ingroup codec
 *  @{
 */

/*! \file codec/ambe.h
 *  \brief Iridium AMBE vocoder header
 */

#include <stdint.h>

struct ir77_ambe_decoder;

struct ir77_ambe_decoder *ir77_ambe_decode_alloc(void);
void ir77_ambe_decode_release(struct ir77_ambe_decoder *dec);
int  ir77_ambe_decode_superframe(struct ir77_ambe_decoder *dec,
                                 int16_t *audio, int N,
                                 const uint8_t *superframe);

/*! @} */

#endif /* __OSMO_IR77_AMBE_AMBE_H__ */
