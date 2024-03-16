#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "module-emulator-osemu.h"
#include "oscam-string.h"

static inline void xxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2)
{
	uint32_t i;

	switch (len)
	{
		case 16:
			for (i = 0; i < 16; ++i)
			{
				data[i] = v1[i] ^ v2[i];
			}
			break;

		case 8:
			for (i = 0; i < 8; ++i)
			{
				data[i] = v1[i] ^ v2[i];
			}
			break;

		case 4:
			for (i = 0; i < 4; ++i)
			{
				data[i] = v1[i] ^ v2[i];
			}
			break;

		default:
			while (len--)
			{
				*data++ = *v1++ ^ *v2++;
			}
			break;
	}
}

// Irdeto EMU
static int8_t get_key(uint8_t *buf, uint32_t ident, char keyName, uint32_t keyIndex,
						uint8_t isCriticalKey, uint32_t *keyRef)
{
	char keyStr[EMU_MAX_CHAR_KEYNAME];

	if (*keyRef > 0xFF)
	{
		return 0;
	}

	snprintf(keyStr, EMU_MAX_CHAR_KEYNAME, "%c%X", keyName, keyIndex);

	if (emu_find_key('I', ident, 0, keyStr, buf, 16, *keyRef > 0 ? 0 : isCriticalKey, *keyRef, 0, NULL))
	{
		(*keyRef)++;
		return 1;
	}

	return 0;
}

static void irdeto2_encrypt(uint8_t *data, const uint8_t *seed, const uint8_t *key, int32_t len)
{
	int32_t i;
	const uint8_t *tmp = seed;
	uint32_t ks1[32], ks2[32];

	des_set_key(key, ks1);
	des_set_key(key + 8, ks2);

	len &= ~7;

	for (i = 0; i + 7 < len; i += 8)
	{
		xxor(&data[i], 8, &data[i], tmp);
		tmp = &data[i];
		des(&data[i], ks1, 1);
		des(&data[i], ks2, 0);
		des(&data[i], ks1, 1);
	}
}

static void irdeto2_decrypt(uint8_t *data, const uint8_t *seed, const uint8_t *key, int32_t len)
{
	int32_t i, n = 0;
	uint8_t buf[2][8];
	uint32_t ks1[32], ks2[32];

	des_set_key(key, ks1);
	des_set_key(key + 8, ks2);

	len &= ~7;

	memcpy(buf[n], seed, 8);

	for (i = 0; i + 7 < len; i += 8, data += 8, n ^= 1)
	{
		memcpy(buf[1 - n], data, 8);
		des(data, ks1, 0);
		des(data, ks2, 1);
		des(data, ks1, 0);
		xxor(data, 8, data, buf[n]);
	}
}

static int8_t calculate_hash(const uint8_t *key, const uint8_t *iv, const uint8_t *data, int32_t len)
{
	int32_t l, y;
	uint8_t cbuff[32];
	uint32_t ks1[32], ks2[32];

	des_set_key(key, ks1);
	des_set_key(key + 8, ks2);

	memset(cbuff, 0, sizeof(cbuff));

	len -= 8;

	for (y = 0; y < len; y += 8)
	{
		if (y < len - 8)
		{
			xxor(cbuff, 8, cbuff, &data[y]);
		}
		else
		{
			l = len - y;
			xxor(cbuff, l, cbuff, &data[y]);
			xxor(cbuff + l, 8 - l, cbuff + l, iv + 8);
		}

		des(cbuff, ks1, 1);
		des(cbuff, ks2, 0);
		des(cbuff, ks1, 1);
	}

	return memcmp(cbuff, &data[len], 8) == 0;
}

int8_t irdeto2_ecm(uint16_t caid, uint8_t *oecm, uint8_t *dw)
{
	uint8_t keyNr = 0, length, end, key[16], okeySeed[16], keySeed[16], keyIV[16], tmp[16];
	uint8_t ecmCopy[EMU_MAX_ECM_LEN], *ecm = oecm;
	uint16_t ecmLen = SCT_LEN(ecm);
	uint32_t key0Ref, keySeedRef, keyIVRef, ident, i, j, l;

	if (ecmLen < 12)
	{
		return EMU_NOT_SUPPORTED;
	}

	length = ecm[11];
	keyNr = ecm[9];
	ident = ecm[8] | caid << 8;

	if (ecmLen < length + 12)
	{
		return EMU_NOT_SUPPORTED;
	}

	key0Ref = 0;

	while (get_key(key, ident, '0', keyNr, 1, &key0Ref))
	{
		keySeedRef = 0;

		while (get_key(okeySeed, ident, 'M', 1, 1, &keySeedRef))
		{
			keyIVRef = 0;

			while (get_key(keyIV, ident, 'M', 2, 1, &keyIVRef))
			{
				memcpy(keySeed, okeySeed, 16);
				memcpy(ecmCopy, oecm, ecmLen);

				ecm = ecmCopy;
				memset(tmp, 0, 16);
				irdeto2_encrypt(keySeed, tmp, key, 16);

				ecm += 12;
				irdeto2_decrypt(ecm, keyIV, keySeed, length);

				i = (ecm[0] & 7) + 1;
				end = length - 8 < 0 ? 0 : length - 8;

				while (i < end)
				{
					l = ecm[i + 1] ? (ecm[i + 1] & 0x3F) + 2 : 1;

					switch (ecm[i])
					{
						case 0x10:
						case 0x50:
							if (l == 0x13 && i <= length - 8 - l)
							{
								irdeto2_decrypt(&ecm[i + 3], keyIV, key, 16);
							}
							break;

						case 0x78:
							if (l == 0x14 && i <= length - 8 - l)
							{
								irdeto2_decrypt(&ecm[i + 4], keyIV, key, 16);
							}
							break;
					}
					i += l;
				}

				i = (ecm[0] & 7) + 1;

				if (calculate_hash(keySeed, keyIV, ecm - 6, length + 6))
				{
					while (i < end)
					{
						l = ecm[i + 1] ? (ecm[i + 1] & 0x3F) + 2 : 1;

						switch (ecm[i])
						{
							case 0x78:
							{
								if (l == 0x14 && i <= length - 8 - l)
								{
									memcpy(dw, &ecm[i + 4], 16);

									for (j = 0; j < 16; j += 4) // fix dw checksum bytes
									{
										dw[j + 3] = (dw[j] + dw[j + 1] + dw[j + 2]) & 0xFF;
									}
									return EMU_OK;
								}
							}
						}
						i += l;
					}
				}
			}

			if (keyIVRef == 0)
			{
				return EMU_KEY_NOT_FOUND;
			}
		}

		if (keySeedRef == 0)
		{
			return EMU_KEY_NOT_FOUND;
		}
	}

	if (key0Ref == 0)
	{
		return EMU_KEY_NOT_FOUND;
	}

	return EMU_NOT_SUPPORTED;
}

// Irdeto2 EMM EMU
static int8_t do_emm_type_op(uint32_t ident, uint8_t *emm, uint8_t *keySeed, uint8_t *keyIV, uint8_t *keyPMK,
								uint16_t emmLen, uint8_t startOffset, uint8_t length, uint32_t *keysAdded)
{
	uint8_t tmp[16];
	uint32_t end, i, l;
	char keyName[EMU_MAX_CHAR_KEYNAME], keyValue[36];

	memset(tmp, 0, 16);
	irdeto2_encrypt(keySeed, tmp, keyPMK, 16);
	irdeto2_decrypt(&emm[startOffset], keyIV, keySeed, length);

	i = 16;
	end = startOffset + (length - 8 < 0 ? 0 : length - 8);

	while (i < end)
	{
		l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

		switch (emm[i])
		{
			case 0x10:
			case 0x50:
				if (l == 0x13 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 3], keyIV, keyPMK, 16);
				}
				break;

			case 0x78:
				if (l == 0x14 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 4], keyIV, keyPMK, 16);
				}
				break;
		}
		i += l;
	}

	memmove(emm + 6, emm + 7, emmLen - 7);

	i = 15;
	end = startOffset + (length - 9 < 0 ? 0 : length - 9);

	if (calculate_hash(keySeed, keyIV, emm + 3, emmLen - 4))
	{
		while (i < end)
		{
			l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

			switch (emm[i])
			{
				case 0x10:
				case 0x50:
				{
					if (l == 0x13 && i <= startOffset + length - 9 - l)
					{
						snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "%02X", emm[i + 2] >> 2);
						SAFE_MUTEX_LOCK(&emu_key_data_mutex);
						emu_set_key('I', ident, keyName, &emm[i + 3], 16, 1, NULL, NULL);
						SAFE_MUTEX_UNLOCK(&emu_key_data_mutex);

						(*keysAdded)++;
						cs_hexdump(0, &emm[i + 3], 16, keyValue, sizeof(keyValue));
						cs_log("Key found in EMM: I %06X %s %s", ident, keyName, keyValue);
					}
				}
			}
			i += l;
		}

		if (*keysAdded > 0)
		{
			return 0;
		}
	}

	return 1;
}

static int8_t do_emm_type_pmk(uint32_t ident, uint8_t *emm, uint8_t *keySeed, uint8_t *keyIV, uint8_t *keyPMK,
								uint16_t emmLen, uint8_t startOffset, uint8_t length, uint32_t *keysAdded)
{
	uint32_t end, i, j, l;
	char keyName[EMU_MAX_CHAR_KEYNAME], keyValue[36];

	irdeto2_decrypt(&emm[startOffset], keyIV, keySeed, length);

	i = 13;
	end = startOffset + (length - 8 < 0 ? 0 : length - 8);

	while (i < end)
	{
		l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

		switch (emm[i])
		{
			case 0x10:
			case 0x50:
				if (l == 0x13 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 3], keyIV, keyPMK, 16);
				}
				break;

			case 0x78:
				if (l == 0x14 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 4], keyIV, keyPMK, 16);
				}
				break;

			case 0x68:
				if (l == 0x26 && i <= startOffset + length - 8 - l)
				{
					irdeto2_decrypt(&emm[i + 3], keyIV, keyPMK, 16 * 2);
				}
				break;
		}
		i += l;
	}

	memmove(emm + 7, emm + 9, emmLen - 9);

	i = 11;
	end = startOffset + (length - 10 < 0 ? 0 : length - 10);

	if (calculate_hash(keySeed, keyIV, emm + 3, emmLen - 5))
	{
		while (i < end)
		{
			l = emm[i + 1] ? (emm[i + 1] & 0x3F) + 2 : 1;

			switch (emm[i])
			{
				case 0x68:
				{
					if (l == 0x26 && i <= startOffset + length - 10 - l)
					{
						for (j = 0; j < 2; j++)
						{
							snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "M%01X", 3 + j);
							SAFE_MUTEX_LOCK(&emu_key_data_mutex);
							emu_set_key('I', ident, keyName, &emm[i + 3 + j * 16], 16, 1, NULL, NULL);
							SAFE_MUTEX_UNLOCK(&emu_key_data_mutex);

							(*keysAdded)++;
							cs_hexdump(0, &emm[i + 3 + j * 16], 16, keyValue, sizeof(keyValue));
							cs_log("Key found in EMM: I %06X %s %s", ident, keyName, keyValue);
						}
					}
				}
			}
			i += l;
		}

		if (*keysAdded > 0)
		{
			return 0;
		}
	}

	return 1;
}

static const uint8_t fausto_xor[16] =
{
	0x22, 0x58, 0xBD, 0x85, 0x2E, 0x8E, 0x52, 0x80,
	0xA3, 0x79, 0x98, 0x69, 0x68, 0xE2, 0xD8, 0x4D
};

int8_t irdeto2_emm(uint16_t caid, uint8_t *oemm, uint32_t *keysAdded)
{
	uint8_t length, okeySeed[16], keySeed[16], keyIV[16], keyPMK[16], startOffset, emmType;
	uint8_t emmCopy[EMU_MAX_EMM_LEN], *emm = oemm;
	uint16_t emmLen = SCT_LEN(emm);
	uint32_t ident, keySeedRef, keyIVRef, keyPMK0Ref, keyPMK1Ref, keyPMK0ERef, keyPMK1ERef;

	if (emmLen < 11)
	{
		return EMU_NOT_SUPPORTED;
	}

	if (emm[3] == 0xC3 || emm[3] == 0xCB)
	{
		emmType = 2;
		startOffset = 11;
	}
	else
	{
		emmType = 1;
		startOffset = 10;
	}

	ident = emm[startOffset - 2] | caid << 8;
	length = emm[startOffset - 1];

	if (emmLen < length + startOffset)
	{
		return EMU_NOT_SUPPORTED;
	}

	keySeedRef = 0;

	while (get_key(okeySeed, ident, 'M', emmType == 1 ? 0 : 0xA, 1, &keySeedRef))
	{
		keyIVRef = 0;

		while (get_key(keyIV, ident, 'M', 2, 1, &keyIVRef))
		{
			keyPMK0Ref = 0;
			keyPMK1Ref = 0;
			keyPMK0ERef = 0;
			keyPMK1ERef = 0;

			while (get_key(keyPMK, ident, 'M', emmType == 1 ? 3 : 0xB, 1, &keyPMK0Ref))
			{
				memcpy(keySeed, okeySeed, 16);
				memcpy(emmCopy, oemm, emmLen);
				emm = emmCopy;

				if (emmType == 1)
				{
					if (do_emm_type_op(ident, emm, keySeed, keyIV, keyPMK, emmLen, startOffset, length, keysAdded) == 0)
					{
						return EMU_OK;
					}
				}
				else
				{
					if (do_emm_type_pmk(ident, emm, keySeed, keyIV, keyPMK, emmLen, startOffset, length, keysAdded) == 0)
					{
						return EMU_OK;
					}
				}
			}

			if (emmType == 1)
			{
				while (get_key(keyPMK, ident, 'M', 4, 1, &keyPMK1Ref))
				{
					memcpy(keySeed, okeySeed, 16);
					memcpy(emmCopy, oemm, emmLen);
					emm = emmCopy;

					if (do_emm_type_op(ident, emm, keySeed, keyIV, keyPMK, emmLen, startOffset, length, keysAdded) == 0)
					{
						return EMU_OK;
					}
				}

				while (get_key(keyPMK, ident, 'M', 5, 1, &keyPMK0ERef))
				{
					xxor(keyPMK, 16, keyPMK, fausto_xor);
					memcpy(keySeed, okeySeed, 16);
					memcpy(emmCopy, oemm, emmLen);
					emm = emmCopy;

					if (do_emm_type_op(ident, emm, keySeed, keyIV, keyPMK, emmLen, startOffset, length, keysAdded) == 0)
					{
						return EMU_OK;
					}
				}

				while (get_key(keyPMK, ident, 'M', 6, 1, &keyPMK1ERef))
				{
					xxor(keyPMK, 16, keyPMK, fausto_xor);
					memcpy(keySeed, okeySeed, 16);
					memcpy(emmCopy, oemm, emmLen);
					emm = emmCopy;

					if (do_emm_type_op(ident, emm, keySeed, keyIV, keyPMK, emmLen, startOffset, length, keysAdded) == 0)
					{
						return EMU_OK;
					}
				}
			}

			if (keyPMK0Ref == 0 && keyPMK1Ref == 0 && keyPMK0ERef == 0 && keyPMK1ERef == 0)
			{
				return EMU_KEY_NOT_FOUND;
			}
		}

		if (keyIVRef == 0)
		{
			return EMU_KEY_NOT_FOUND;
		}
	}

	if (keySeedRef == 0)
	{
		return 2;
	}

	return EMU_NOT_SUPPORTED;
}

int8_t irdeto2_get_hexserial(uint16_t caid, uint8_t *hexserial)
{
	uint32_t i, len;
	KeyDataContainer *KeyDB;
	KeyData *tmpKeyData;

	KeyDB = emu_get_key_container('I');

	if (KeyDB == NULL)
	{
		return 0;
	}

	for (i = 0; i < KeyDB->keyCount; i++)
	{
		if (KeyDB->EmuKeys[i].provider >> 8 != caid)
		{
			continue;
		}

		if (strcmp(KeyDB->EmuKeys[i].keyName, "MC"))
		{
			continue;
		}

		tmpKeyData = &KeyDB->EmuKeys[i];
		len = tmpKeyData->keyLength;

		if (len > 3)
			{ len = 3; }

		memcpy(hexserial + (3 - len), tmpKeyData->key, len);
		return 1;
	}

	return 0;
}

#endif // WITH_EMU
