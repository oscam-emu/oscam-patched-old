#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "module-emulator-osemu.h"

// Cryptoworks EMU

static int8_t get_key(uint8_t *buf,uint32_t ident, uint8_t keyIndex, uint32_t keyLength, uint8_t isCriticalKey)
{
	char keyName[EMU_MAX_CHAR_KEYNAME];
	uint32_t tmp;

	if ((ident >> 4) == 0xD02A)
	{
		keyIndex &= 0xFE; // map to even number key indexes
	}

	if ((ident >> 4) == 0xD00C)
	{
		ident = 0x0D00C0; // map provider C? to C0
	}
	else if (keyIndex == 6 && ((ident >> 8) == 0x0D05))
	{
		ident = 0x0D0504; // always use provider 04 system key
	}

	tmp = keyIndex;
	snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "%.2X", tmp);

	if (emu_find_key('W', ident, 0, keyName, buf, keyLength, isCriticalKey, 0, 0, NULL))
	{
		return 1;
	}

	return 0;
}

static const uint8_t cw_sbox1[64] =
{
	0xD8, 0xD7, 0x83, 0x3D, 0x1C, 0x8A, 0xF0, 0xCF, 0x72, 0x4C, 0x4D, 0xF2, 0xED, 0x33, 0x16, 0xE0,
	0x8F, 0x28, 0x7C, 0x82, 0x62, 0x37, 0xAF, 0x59, 0xB7, 0xE0, 0x00, 0x3F, 0x09, 0x4D, 0xF3, 0x94,
	0x16, 0xA5, 0x58, 0x83, 0xF2, 0x4F, 0x67, 0x30, 0x49, 0x72, 0xBF, 0xCD, 0xBE, 0x98, 0x81, 0x7F,
	0xA5, 0xDA, 0xA7, 0x7F, 0x89, 0xC8, 0x78, 0xA7, 0x8C, 0x05, 0x72, 0x84, 0x52, 0x72, 0x4D, 0x38
};

static const uint8_t cw_sbox2[64] =
{
	0xD8, 0x35, 0x06, 0xAB, 0xEC, 0x40, 0x79, 0x34, 0x17, 0xFE, 0xEA, 0x47, 0xA3, 0x8F, 0xD5, 0x48,
	0x0A, 0xBC, 0xD5, 0x40, 0x23, 0xD7, 0x9F, 0xBB, 0x7C, 0x81, 0xA1, 0x7A, 0x14, 0x69, 0x6A, 0x96,
	0x47, 0xDA, 0x7B, 0xE8, 0xA1, 0xBF, 0x98, 0x46, 0xB8, 0x41, 0x45, 0x9E, 0x5E, 0x20, 0xB2, 0x35,
	0xE4, 0x2F, 0x9A, 0xB5, 0xDE, 0x01, 0x65, 0xF8, 0x0F, 0xB2, 0xD2, 0x45, 0x21, 0x4E, 0x2D, 0xDB
};

static const uint8_t cw_sbox3[64] =
{
	0xDB, 0x59, 0xF4, 0xEA, 0x95, 0x8E, 0x25, 0xD5, 0x26, 0xF2, 0xDA, 0x1A, 0x4B, 0xA8, 0x08, 0x25,
	0x46, 0x16, 0x6B, 0xBF, 0xAB, 0xE0, 0xD4, 0x1B, 0x89, 0x05, 0x34, 0xE5, 0x74, 0x7B, 0xBB, 0x44,
	0xA9, 0xC6, 0x18, 0xBD, 0xE6, 0x01, 0x69, 0x5A, 0x99, 0xE0, 0x87, 0x61, 0x56, 0x35, 0x76, 0x8E,
	0xF7, 0xE8, 0x84, 0x13, 0x04, 0x7B, 0x9B, 0xA6, 0x7A, 0x1F, 0x6B, 0x5C, 0xA9, 0x86, 0x54, 0xF9
};

static const uint8_t cw_sbox4[64] =
{
	0xBC, 0xC1, 0x41, 0xFE, 0x42, 0xFB, 0x3F, 0x10, 0xB5, 0x1C, 0xA6, 0xC9, 0xCF, 0x26, 0xD1, 0x3F,
	0x02, 0x3D, 0x19, 0x20, 0xC1, 0xA8, 0xBC, 0xCF, 0x7E, 0x92, 0x4B, 0x67, 0xBC, 0x47, 0x62, 0xD0,
	0x60, 0x9A, 0x9E, 0x45, 0x79, 0x21, 0x89, 0xA9, 0xC3, 0x64, 0x74, 0x9A, 0xBC, 0xDB, 0x43, 0x66,
	0xDF, 0xE3, 0x21, 0xBE, 0x1E, 0x16, 0x73, 0x5D, 0xA2, 0xCD, 0x8C, 0x30, 0x67, 0x34, 0x9C, 0xCB
};

static const uint8_t AND_bit1[8] = { 0x00, 0x40, 0x04, 0x80, 0x21, 0x10, 0x02, 0x08 };
static const uint8_t AND_bit2[8] = { 0x80, 0x08, 0x01, 0x40, 0x04, 0x20, 0x10, 0x02 };
static const uint8_t AND_bit3[8] = { 0x82, 0x40, 0x01, 0x10, 0x00, 0x20, 0x04, 0x08 };
static const uint8_t AND_bit4[8] = { 0x02, 0x10, 0x04, 0x40, 0x80, 0x08, 0x01, 0x20 };

static void swap_key(uint8_t *key)
{
	uint8_t k[8];
	memcpy(k, key, 8);
	memcpy(key, key + 8, 8);
	memcpy(key + 8, k, 8);
}

static void swap_data(uint8_t *k)
{
	uint8_t d[4];
	memcpy(d, k + 4, 4);
	memcpy(k + 4, k, 4);
	memcpy(k, d, 4);
}

static void des_round(uint8_t *d, uint8_t *k)
{
	uint8_t aa[44] =
	{
		1, 0, 3, 1, 2, 2, 3, 2, 1, 3, 1, 1, 3, 0, 1, 2, 3, 1, 3, 2, 2, 0,
		7, 6, 5, 4, 7, 6, 5, 7, 6, 5, 6, 7, 5, 7, 5, 7, 6, 6, 7, 5, 4, 4
	};

	uint8_t bb[44] =
	{
		0x80, 0x08, 0x10, 0x02, 0x08, 0x40, 0x01, 0x20, 0x40, 0x80, 0x04,
		0x10, 0x04, 0x01, 0x01, 0x02, 0x20, 0x20, 0x02, 0x01, 0x80, 0x04,
		0x02, 0x02, 0x08, 0x02, 0x10, 0x80, 0x01, 0x20, 0x08, 0x80, 0x01,
		0x08, 0x40, 0x01, 0x02, 0x80, 0x10, 0x40, 0x40, 0x10, 0x08, 0x01
	};

	uint8_t ff[4] = { 0x02, 0x10, 0x04, 0x04};
	uint8_t l[24] = { 0, 2, 4, 6, 7, 5, 3, 1, 4, 5, 6, 7, 7, 6, 5, 4, 7, 4, 5, 6, 4, 7, 6, 5 };

	uint8_t des_td[8], i, o, n, c = 1, m = 0, r = 0;
	uint8_t *a = aa, *b = bb, *f = ff, *p1 = l, *p2 = l + 8, *p3 = l + 16;

	for (m = 0; m < 2; m++)
	{
		for (i = 0; i < 4; i++)
		{
			des_td[*p1++] = (m) ? ((d[*p2++] * 2) & 0x3F) | ((d[*p3++] & 0x80) ? 0x01 : 0x00) :
									(d[*p2++] / 2) | ((d[*p3++] & 0x01) ? 0x80 : 0x00);
		}
	}

	for (i = 0; i < 8; i++)
	{
		c = (c) ? 0 : 1;
		r = (c) ? 6 : 7;
		n = (i) ? i - 1 : 1;
		o = (c) ? ((k[n] & *f++) ? 1 : 0) : des_td[n];

		for (m = 1; m < r; m++)
		{
			o = (c) ? (o * 2) | ((k[*a++] & *b++) ? 0x01 : 0x00) : (o / 2) | ((k[*a++] & *b++) ? 0x80 : 0x00);
		}

		n = (i) ? n + 1 : 0;
		des_td[n] = (c) ? des_td[n] ^ o : (o ^ des_td[n]) / 4;
	}

	for (i = 0; i < 8; i++)
	{
		d[0] ^= (AND_bit1[i] & cw_sbox1[des_td[i]]);
		d[1] ^= (AND_bit2[i] & cw_sbox2[des_td[i]]);
		d[2] ^= (AND_bit3[i] & cw_sbox3[des_td[i]]);
		d[3] ^= (AND_bit4[i] & cw_sbox4[des_td[i]]);
	}

	swap_data(d);
}

static void cw_48_key(uint8_t *inkey, uint8_t *outkey, uint8_t algotype)
{
	uint8_t round_counter, i = 8;
	uint8_t *key128 = inkey;
	uint8_t *key48 = inkey + 0x10;

	round_counter = 7 - (algotype & 7);

	memset(outkey, 0, 16);
	memcpy(outkey, key48, 6);

	for ( ; i > round_counter; i--)
	{
		if (i > 1)
		{
			outkey[i - 2] = key128[i];
		}
	}
}

static void ls_des_key(uint8_t *key, uint8_t rotate_counter)
{
	uint8_t i, n;
	uint8_t rnd[] = { 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, 1 };
	uint16_t k[8];

	n = rnd[rotate_counter];

	for (i = 0; i < 8; i++)
	{
		k[i] = key[i];
	}

	for (i = 1; i < n + 1; i++)
	{
		k[7] = (k[7] * 2) | ((k[4] & 0x008) ? 1 : 0);
		k[6] = (k[6] * 2) | ((k[7] & 0xF00) ? 1 : 0);
		k[7] &= 0xFF;

		k[5] = (k[5] * 2) | ((k[6] & 0xF00) ? 1 : 0);
		k[6] &= 0xFF;

		k[4] = ((k[4] * 2) | ((k[5] & 0xF00) ? 1 : 0)) & 0xFF;
		k[5] &= 0xFF;

		k[3] = (k[3] * 2) | ((k[0] & 0x008) ? 1 : 0);
		k[2] = (k[2] * 2) | ((k[3] & 0xF00) ? 1 : 0);
		k[3] &= 0xFF;

		k[1] = (k[1] * 2) | ((k[2] & 0xF00) ? 1 : 0);
		k[2] &= 0xFF;

		k[0] = ((k[0] * 2) | ((k[1] & 0xF00) ? 1 : 0)) & 0xFF;
		k[1] &= 0xFF;
	}

	for (i = 0; i < 8; i++)
	{
		key[i] = (uint8_t) k[i];
	}
}

static void rs_des_key(uint8_t *k, uint8_t rotate_counter)
{
	uint8_t i, c;

	for (i = 1; i < rotate_counter + 1; i++)
	{
		c = (k[3] & 0x10) ? 0x80 : 0;
		k[3] /= 2;

		if (k[2] & 1)
		{
			k[3] |= 0x80;
		}

		k[2] /= 2;

		if (k[1] & 1)
		{
			k[2] |= 0x80;
		}

		k[1] /= 2;

		if (k[0] & 1)
		{
			k[1] |= 0x80;
		}

		k[0] /= 2;
		k[0] |= c ;
		c = (k[7] & 0x10) ? 0x80 : 0;
		k[7] /= 2;

		if (k[6] & 1)
		{
			k[7] |= 0x80;
		}

		k[6] /= 2;

		if (k[5] & 1)
		{
			k[6] |= 0x80;
		}

		k[5] /= 2;

		if (k[4] & 1)
		{
			k[5] |= 0x80;
		}

		k[4] /= 2;
		k[4] |= c;
	}
}

static void rs_des_subkey(uint8_t *k, uint8_t rotate_counter)
{
	uint8_t rnd[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

	rs_des_key(k, rnd[rotate_counter]);
}

static void prep_key(uint8_t *key)
{
	int32_t round_counter = 6, i, a;
	uint8_t DES_key[8], j;

	key[7] = 6;
	memset(DES_key, 0, 8);

	do
	{
		a = 7;
		i = key[7];
		j = key[round_counter];

		do
		{
			DES_key[i] = ( (DES_key[i] * 2) | ((j & 1) ? 1 : 0) ) & 0xFF;

			j /= 2;
			i--;

			if (i < 0)
			{
				i = 6;
			}
			a--;
		}
		while (a >= 0);

		key[7] = i;
		round_counter--;
	}
	while (round_counter >= 0);

	a = DES_key[4];
	DES_key[4] = DES_key[6];
	DES_key[6] = a;
	DES_key[7] = (DES_key[3] * 16) & 0xFF;

	memcpy(key, DES_key, 8);
	rs_des_key(key, 4);
}

static void l2_des(uint8_t *data, uint8_t *key, uint8_t algo)
{
	uint8_t i, k0[22], k1[22];

	memcpy(k0, key, 22);
	memcpy(k1, key, 22);

	cw_48_key(k0, k1, algo);
	prep_key(k1);

	for (i = 0; i < 2; i++)
	{
		ls_des_key(k1, 15);
		des_round(data, k1);
	}
}

static void r2_des(uint8_t *data, uint8_t *key, uint8_t algo)
{
	uint8_t i, k0[22], k1[22];

	memcpy(k0, key, 22);
	memcpy(k1, key, 22);

	cw_48_key(k0, k1, algo);
	prep_key(k1);

	for (i = 0; i < 2; i++)
	{
		ls_des_key(k1, 15);
	}

	for (i = 0; i < 2; i++)
	{
		des_round(data, k1);
		rs_des_subkey(k1, 1);
	}

	swap_data(data);
}

static void cw_des(uint8_t *data, uint8_t *inkey, uint8_t m)
{
	uint8_t key[22], i;

	memcpy(key, inkey + 9, 8);
	prep_key(key);

	for (i = 16; i > 0; i--)
	{
		if (m == 1)
		{
			ls_des_key(key, (uint8_t) (i - 1));
		}

		des_round( data ,key);

		if (m == 0)
		{
			rs_des_subkey(key, (uint8_t) (i - 1));
		}
	}
}

static void cw_dec_enc(uint8_t *d, uint8_t *k, uint8_t a, uint8_t m)
{
	uint8_t n = m & 1;

	l2_des(d, k, a);
	cw_des(d, k, n);
	r2_des(d, k, a);

	if (m & 2)
	{
		swap_key(k);
	}
}

static uint8_t process_nano80(uint8_t *data, uint32_t caid, int32_t provider, uint8_t *opKey,
								uint8_t nanoLength, uint8_t nano80Algo)
{
	int32_t i, j;
	uint8_t key[16], desKey[16], t[8], dat1[8], dat2[8], k0D00C000[16];

	if (nanoLength < 11)
	{
		return 0;
	}

	if (caid == 0x0D00 && provider != 0xA0 && !get_key(k0D00C000, 0x0D00C0, 0, 16, 1))
	{
		return 0;
	}

	if (nano80Algo > 1)
	{
		return 0;
	}

	memset(t, 0, 8);
	memcpy(dat1, data, 8);

	if(caid == 0x0D00 && provider != 0xA0)
	{
		memcpy(key, k0D00C000, 16);
	}
	else
	{
		memcpy(key, opKey, 16);
	}

	des_ecb3_decrypt(data, key);
	memcpy(desKey, data, 8);
	memcpy(data, dat1, 8);

	if (caid == 0x0D00 && provider != 0xA0)
	{
		memcpy(key, &k0D00C000[8], 8);
		memcpy(&key[8], k0D00C000, 8);
	}
	else
	{
		memcpy(key, &opKey[8], 8);
		memcpy(&key[8], opKey, 8);
	}

	des_ecb3_decrypt(data, key);
	memcpy(&desKey[8], data, 8);

	for (i = 8; i + 7 < nanoLength; i += 8)
	{
		memcpy(dat1, &data[i], 8);
		memcpy(dat2, dat1, 8);
		memcpy(key, desKey, 16);
		des_ecb3_decrypt(dat1, key);

		for (j = 0; j < 8; j++)
		{
			dat1[j] ^= t[j];
		}

		memcpy(&data[i], dat1, 8);
		memcpy(t, dat2, 8);
	}

	return data[10] + 5;
}

static void cryptoworks_signature(const uint8_t *data, uint32_t length, uint8_t *key, uint8_t *signature)
{
	uint32_t i, sigPos;
	int8_t algo, first;

	algo = data[0] & 7;
	if (algo == 7)
	{
		algo = 6;
	}

	memset(signature, 0, 8);
	first = 1;
	sigPos = 0;

	for (i = 0; i < length; i++)
	{
		signature[sigPos] ^= data[i];
		sigPos++;

		if (sigPos > 7)
		{
			if (first)
			{
				l2_des(signature, key, algo);
			}

			cw_des(signature, key, 1);

			sigPos = 0;
			first = 0;
		}
	}

	if (sigPos > 0)
	{
		cw_des(signature, key, 1);
	}

	r2_des(signature, key, algo);
}

static void decrypt_des(uint8_t *data, uint8_t algo, uint8_t *key)
{
	int32_t i;
	uint8_t k[22], t[8];

	algo &= 7;

	if (algo < 7)
	{
		cw_dec_enc(data, key, algo, 0);
	}
	else
	{
		memcpy(k, key, 22);

		for (i = 0; i < 3; i++)
		{
			cw_dec_enc(data, k, algo, i & 1);

			memcpy(t, k, 8);
			memcpy(k, k + 8, 8);
			memcpy(k + 8, t, 8);
		}
	}
}

int8_t cryptoworks_ecm(uint32_t caid, uint8_t *ecm, uint8_t *cw)
{
	int32_t provider = -1;
	uint8_t keyIndex = 0, nanoLength, newEcmLength, key[22], signature[8], nano80Algo = 1;
	uint16_t i, j, ecmLen = get_ecm_len(ecm);
	uint32_t ident;

	if (ecmLen < 8)
	{
		return 1;
	}

	if (ecm[7] != ecmLen - 8)
	{
		return 1;
	}

	memset(key, 0, 22);

	for (i = 8; i + 1 < ecmLen; i += ecm[i + 1] + 2)
	{
		if (ecm[i] == 0x83 && i + 2 < ecmLen)
		{
			provider = ecm[i + 2] & 0xFC;
			keyIndex = ecm[i + 2] & 3;
			keyIndex = keyIndex ? 1 : 0;
		}
		else if (ecm[i] == 0x84 && i + 3 < ecmLen)
		{
			//nano80Provider = ecm[i + 2] & 0xFC;
			//nano80KeyIndex = ecm[i + 2] & 3;
			//nano80KeyIndex = nano80KeyIndex ? 1 : 0;
			nano80Algo = ecm[i + 3];
		}
	}

	if (provider < 0)
	{
		switch (caid)
		{
			case 0x0D00:
				provider = 0xC0;
				break;

			case 0x0D02:
				provider = 0xA0;
				break;

			case 0x0D03:
				provider = 0x04;
				break;

			case 0x0D05:
				provider = 0x04;
				break;

			default:
				return 1;
		}
	}

	ident = (caid << 8) | provider;

	if (!get_key(key, ident, keyIndex, 16, 1))
	{
		return 2;
	}

	if (!get_key(&key[16], ident, 6, 6, 1))
	{
		return 2;
	}

	for (i = 8; i + 1 < ecmLen; i += ecm[i + 1] + 2)
	{
		if (ecm[i] == 0x80 && i + 2 + 7 < ecmLen && i + 2 + ecm[i + 1] <= ecmLen &&
			(provider == 0xA0 || provider == 0xC0 || provider == 0xC4 || provider == 0xC8))
		{
			nanoLength = ecm[i + 1];
			newEcmLength = process_nano80(ecm + i + 2, caid, provider, key, nanoLength, nano80Algo);

			if (newEcmLength == 0 || newEcmLength > ecmLen - (i + 2 + 3))
			{
				return 1;
			}

			ecm[i + 2 + 3] = 0x81;
			ecm[i + 2 + 4] = 0x70;
			ecm[i + 2 + 5] = newEcmLength;
			ecm[i + 2 + 6] = 0x81;
			ecm[i + 2 + 7] = 0xFF;

			return cryptoworks_ecm(caid, ecm + i + 2 + 3, cw);
		}
	}

	if (ecmLen - 15 < 1)
	{
		return 1;
	}

	cryptoworks_signature(ecm + 5, ecmLen - 15, key, signature);

	for (i = 8; i + 1 < ecmLen; i += ecm[i + 1] + 2)
	{
		switch (ecm[i])
		{
			case 0xDA:
			case 0xDB:
			case 0xDC:
				if (i + 2 + ecm[i + 1] > ecmLen)
				{
					break;
				}
				for (j = 0; j + 7 < ecm[i + 1]; j += 8)
				{
					decrypt_des(&ecm[i + 2 + j], ecm[5], key);
				}
				break;

			case 0xDF:
				if (i + 2 + 8 > ecmLen)
				{
					break;
				}
				if (memcmp(&ecm[i + 2], signature, 8))
				{
					return 6;
				}
				break;
		}
	}

	for (i = 8; i + 1 < ecmLen; i += ecm[i + 1] + 2)
	{
		switch (ecm[i])
		{
			case 0xDB:
				if (i + 2 + ecm[i + 1] <= ecmLen && ecm[i + 1] == 16)
				{
					memcpy(cw, &ecm[i + 2], 16);
					return 0;
				}
				break;
		}
	}

	return 5;
}

#endif // WITH_EMU
