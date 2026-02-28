#ifndef __OSMO_IR77_AMBE_COMPAT_BITS_H__
#define __OSMO_IR77_AMBE_COMPAT_BITS_H__

#include <stdint.h>

typedef uint8_t ubit_t;
typedef uint8_t pbit_t;

static inline int
osmo_pbit2ubit_ext(
	ubit_t *out, unsigned int out_ofs,
	const pbit_t *in, unsigned int in_ofs,
	unsigned int num_bits, int lsb_mode)
{
	int i, ip, bn;
	for (i=0; i<num_bits; i++) {
		ip = in_ofs + i;
		bn = lsb_mode ? (ip&7) : (7-(ip&7));
		out[out_ofs+i] = !!(in[ip>>3] & (1<<bn));
	}
	return out_ofs + num_bits;
}

#endif /* __OSMO_IR77_AMBE_COMPAT_BITS_H__ */
