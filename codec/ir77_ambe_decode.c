/* Iridium AMBE vocoder - Decoder tool */

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

#include <stdio.h>
#include <string.h>

#include "ambe.h"


static const uint8_t wav_hdr[] = {
	/* WAV header */
	'R', 'I', 'F', 'F',		/* ChunkID   */
	0x00, 0x00, 0x00, 0x00,		/* ChunkSize */
	'W', 'A', 'V', 'E',		/* Format    */

	/* Sub chunk: format */
	'f', 'm', 't', ' ',		/* Subchunk1ID         */
	0x10, 0x00, 0x00, 0x00,		/* Subchunk1Size       */
	0x01, 0x00,			/* AudioFormat: PCM    */
	0x01, 0x00,			/* NumChannels: Mono   */
	0x40, 0x1f, 0x00, 0x00,		/* SampleRate: 8000 Hz */
	0x80, 0x3e, 0x00, 0x00,		/* ByteRate: 16k/s     */
	0x02, 0x00,			/* BlockAlign: 2 bytes */
	0x10, 0x00,			/* BitsPerSample: 16   */

	/* Sub chunk: data */
	'd', 'a', 't', 'a',		/* Subchunk2ID   */
	0x00, 0x00, 0x00, 0x00,		/* Subchunk2Size */
};

static uint32_t
le32(uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return v;
#else
	return ((v & 0x000000ff) << 24) |
	       ((v & 0x0000ff00) <<  8) |
	       ((v & 0x00ff0000) >>  8) |
	       ((v & 0xff000000) >> 24);
#endif
}

static uint16_t
le16(uint16_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return v;
#else
	return ((v & 0x00ff) << 8) |
	       ((v & 0xff00) >> 8);
#endif
}

int main(int argc, char *argv[])
{
	struct ir77_ambe_decoder *dec = NULL;
	FILE *fin, *fout;
	int is_wave = 0, l, rv;
	int frames_ok = 0, frames_total = 0;
	float error_ratio = 1.0f;

        /* Arguments */
	if (argc > 3) {
		fprintf(stderr, "Usage: %s [in_file [out_file]]\n", argv[0]);
		return -1;
	}

	if ((argc < 2) || !strcmp(argv[1], "-"))
		fin = stdin;
	else {
		fin = fopen(argv[1], "rb");
		if (!fin) {
			fprintf(stderr, "[!] Unable to open input file\n");
			return -1;
		}
	}

	if ((argc < 3) || !strcmp(argv[2], "-"))
		fout = stdout;
	else {
		fout = fopen(argv[2], "wb");
		if (!fout) {
			fprintf(stderr, "[!] Unable to open output file\n");
			return -1;
		}

		l = strlen(argv[2]);

		if ((l > 4) && (!strcmp(".wav", &argv[2][l-4])))
			is_wave = 1;
	}

	/* Write inital wave header */
	if (is_wave) {
		rv = fwrite(wav_hdr, sizeof(wav_hdr), 1, fout);
		if (rv != 1) {
			fprintf(stderr, "[!] Failed to write WAV header\n");
			goto exit;
		}
	}

	/* Init decoder */
	dec = ir77_ambe_decode_alloc();
	if (!dec)
		goto exit;

        /* Process all frames */
	l = 0;

	while (!feof(fin))
	{
		uint8_t superframe[39];
		int16_t audio[2*360];
		int rv, i;

		/* Read input frame */
		rv = fread(superframe, 1, 39, fin);
		if (rv != 39)
			break;

		/* Skip dummy frames */
		if ((superframe[0] == 0xff) && (superframe[38] == 0xff))
			continue;

		/* Decompress */
		rv = ir77_ambe_decode_superframe(dec, audio, 2*360, superframe);
		if (rv < 0) {
			fprintf(stderr, "[!] codec error\n");
			break;
		}

		frames_ok += rv;
		frames_total += 2;

		/* Write audio output */
		for (i=0; i<2*360; i++)
			audio[i] = le16(audio[i]);

		rv = fwrite(audio, 2, 2*360, fout);
		if (rv != 2*360) {
			fprintf(stderr, "[!] short write\n");
			break;
		}

		/* Keep track of number of samples */
		l += 2*360;
	}

	/* Report the frame error ratio */
	error_ratio = 1.0f - (1.0f * frames_ok) / frames_total;
	fprintf(stderr, "Error ratio: %.2f\n", error_ratio);

	/* Release decoder */
	ir77_ambe_decode_release(dec);

	/* Fix wave header */
	if (is_wave)
	{
		uint32_t v;

		/* Fixup Subchunk2Size */
		v = le32(l * 2);

		rv = fseek(fout, 40, SEEK_SET);
		if (rv < 0)
			goto exit;

		rv = fwrite(&v, 4, 1, fout);
		if (rv < 0)
			goto exit;

		/* Fixup ChunkSize */
		v = le32(l * 2 + 36);

		rv = fseek(fout, 4, SEEK_SET);
		if (rv < 0)
			goto exit;

		rv = fwrite(&v, 4, 1, fout);
		if (rv < 0)
			goto exit;
	}

exit:
	/* Close in/out */
	fclose(fout);
	fclose(fin);

	/* All done ! */
	return error_ratio < 0.5f ? 0 : 1;
}
