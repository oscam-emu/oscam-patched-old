#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "module-emulator-osemu.h"
#include "oscam-string.h"
#include "reader-dre-common.h"

// Drecrypt EMU
static void overcrypt(const uint8_t *ECMdata, uint8_t *dw)
{
	uint8_t key[8];
	uint32_t key_schedule[32];

	if (ECMdata[2] >= (43 + 4) && ECMdata[40] == 0x3A && ECMdata[41] == 0x4B)
	{
		if (!emu_find_key('D', ECMdata[42] & 0x0F, 0, "OVER", key, 8, 1, 0, 0, NULL))
		{
			return;
		}

		des_set_key(key, key_schedule);

		des(dw, key_schedule, 0); // even dw post-process
		des(dw + 8, key_schedule, 0); // odd dw post-process
	}
}

static uint32_t gost_dec(uint32_t inData)
{
	static uint8_t Sbox[128] =
	{
		0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
		0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07,
		0x0F, 0x01, 0x08, 0x0E, 0x06, 0x0B, 0x03, 0x04,
		0x09, 0x07, 0x02, 0x0D, 0x0C, 0x00, 0x05, 0x0A,
		0x0A, 0x00, 0x09, 0x0E, 0x06, 0x03, 0x0F, 0x05,
		0x01, 0x0D, 0x0C, 0x07, 0x0B, 0x04, 0x02, 0x08,
		0x07, 0x0D, 0x0E, 0x03, 0x00, 0x06, 0x09, 0x0A,
		0x01, 0x02, 0x08, 0x05, 0x0B, 0x0C, 0x04, 0x0F,
		0x02, 0x0C, 0x04, 0x01, 0x07, 0x0A, 0x0B, 0x06,
		0x08, 0x05, 0x03, 0x0F, 0x0D, 0x00, 0x0E, 0x09,
		0x0C, 0x01, 0x0A, 0x0F, 0x09, 0x02, 0x06, 0x08,
		0x00, 0x0D, 0x03, 0x04, 0x0E, 0x07, 0x05, 0x0B,
		0x04, 0x0B, 0x02, 0x0E, 0x0F, 0x00, 0x08, 0x0D,
		0x03, 0x0C, 0x09, 0x07, 0x05, 0x0A, 0x06, 0x01,
		0x0D, 0x02, 0x08, 0x04, 0x06, 0x0F, 0x0B, 0x01,
		0x0A, 0x09, 0x03, 0x0E, 0x05, 0x00, 0x0C, 0x07
	};
	uint8_t i, j;

	for (i = 0; i < 8; i++)
	{
		j = (inData >> 28) & 0x0F;
		inData = (inData << 4) | (Sbox[i * 16 + j] & 0x0F);
	}

	inData = (inData << 11) | (inData >> 21);

	return (inData);
}

static void drecrypt_decrypt(uint8_t *Data, uint8_t *Key) // DRE GOST 28147-89 CORE
{
	int i, j;
	uint32_t L_part = 0, R_part = 0, temp = 0;

	for (i = 0; i < 4; i++)
	{
		L_part = (L_part << 8) | (Data[i] & 0xFF);
		R_part = (R_part << 8) | (Data[i + 4] & 0xFF);
	}

	for (i = 0; i < 4; i++)
	{
		temp = ((Key[i * 8 + 0] & 0xFF) << 24) | ((Key[i * 8 + 1] & 0xFF) << 16) |
				((Key[i * 8 + 2] & 0xFF) << 8) | (Key[i * 8 + 3] & 0xFF);

		R_part ^= gost_dec(temp + L_part);

		temp = ((Key[i * 8 + 4] & 0xFF) << 24) | ((Key[i * 8 + 5] & 0xFF) << 16) |
				((Key[i * 8 + 6] & 0xFF) << 8) | (Key[i * 8 + 7] & 0xFF);

		L_part ^= gost_dec(temp + R_part);
	}

	for (j = 0; j < 3; j++)
	{
		for (i = 3; i >= 0; i--)
		{
			temp = ((Key[i * 8 + 4] & 0xFF) << 24) | ((Key[i * 8 + 5] & 0xFF) << 16) |
					((Key[i * 8 + 6] & 0xFF) << 8) | (Key[i * 8 + 7] & 0xFF);

			R_part ^= gost_dec(temp + L_part);

			temp = ((Key[i * 8 + 0] & 0xFF) << 24) | ((Key[i * 8 + 1] & 0xFF) << 16) |
					((Key[i * 8 + 2] & 0xFF) << 8) | (Key[i * 8 + 3] & 0xFF);

			L_part ^= gost_dec(temp + R_part);
		}
	}

	for (i = 0; i < 4; i++)
	{
		Data[i] = (R_part >> i * 8) & 0xFF;
		Data[i + 4] = (L_part >> i * 8) & 0xFF;
	}
}

static void post_cw(uint8_t *ccw)
{
	uint32_t i, j;
	uint8_t tmp[4];

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			tmp[j] = ccw[3 - j];
		}

		for (j = 0; j < 4; j++)
		{
			ccw[j] = tmp[j];
		}

		ccw += 4;
	}
}

static void swap(uint8_t *ccw)
{
	uint32_t tmp1, tmp2;

	memcpy(&tmp1, ccw, 4);
	memcpy(&tmp2, ccw + 4, 4);

	memcpy(ccw, ccw + 8, 8);

	memcpy(ccw + 8 , &tmp1, 4);
	memcpy(ccw + 8 + 4, &tmp2, 4);
}

int8_t drecrypt2_ecm(uint32_t provId, uint8_t *ecm, uint8_t *dw)
{
	uint8_t ecmDataLen, ccw[16], key[32];
	uint16_t ecmLen, overcryptId;
	char keyName[EMU_MAX_CHAR_KEYNAME];

	ecmLen = get_ecm_len(ecm);

	if (ecmLen < 3)
	{
		return 1; // Not supported
	}

	ecmDataLen = ecm[2];

	if (ecmLen < ecmDataLen + 3)
	{
		return 4; // Corrupt data
	}

	switch (provId & 0xFF)
	{
		case 0x11:
		{
			if (ecm[3] == 0x56)
			{
				snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "%02X%02X", ecm[6], ecm[5]);

				if (!emu_find_key('D', 0x4AE111, 0, keyName, key, 32, 1, 0, 0, NULL))
				{
					return 2;
				}
			}
			else
			{
				snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "%02X%02X", ecm[6], ecm[3]);

				if (!emu_find_key('D', 0x4AE111, 0, keyName, key, 32, 1, 0, 0, NULL))
				{
					return 2;
				}
			}

			break;
		}

		case 0x14:
		{
			snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "%02X%02X", ecm[6], ecm[5]);

			if (!emu_find_key('D', 0x4AE114, 0, keyName, key, 32, 1, 0, 0, NULL))
			{
				return 2;
			}

			break;
		}

		default:
			return 1;
	}

	memcpy(ccw, ecm + 13, 16);

	post_cw(key);
	post_cw(key + 16);

	drecrypt_decrypt(ccw, key);
	drecrypt_decrypt(ccw + 8, key);

	if (ecm[2] >= 46 && ecm[43] == 1 && provId == 0x11)
	{
		swap(ccw);
		overcryptId = b2i(2, &ecm[44]);

		Drecrypt2OverCW(overcryptId, ccw);

		if (is_valid_dcw(ccw) && is_valid_dcw(ccw + 8))
		{
			memcpy(dw, ccw, 16);
			return 0;
		}

		return 8; // ICG error
	}

	overcrypt(ecm, ccw);

	if (is_valid_dcw(ccw) && is_valid_dcw(ccw + 8))
	{
		swap(ccw);
		memcpy(dw, ccw, 16);
		return 0;
	}

	return 1;
}

// Drecrypt EMM EMU
static int8_t get_emm_key(uint8_t *buf, uint32_t keyIdent, uint16_t keyName, uint8_t isCriticalKey)
{
	char keyStr[EMU_MAX_CHAR_KEYNAME];
	snprintf(keyStr, EMU_MAX_CHAR_KEYNAME, "MK%04X", keyName);
	return emu_find_key('D', keyIdent, 0, keyStr, buf, 32, isCriticalKey, 0, 0, NULL);
}

static void write_eebin(const char *path, const char *name)
{
	char tmp[256];
	FILE *file = NULL;
	uint8_t i, buffer[64][32];
	uint32_t prvid;

	// Set path
	if (path != NULL)
	{
		snprintf(tmp, 256, "%s%s", path, name);
	}
	else // No path set, use SoftCam.Keys's path
	{
		snprintf(tmp, 256, "%s%s", emu_keyfile_path, name);
	}

	if ((file = fopen(tmp, "wb")) != NULL)
	{
		cs_log("Writing key file: %s", tmp);
	}
	else
	{
		cs_log("Error writing key file: %s", tmp);
		return;
	}

	// Load keys from db to buffer
	prvid = (strncmp(name, "ee36.bin", 9) == 0) ? 0x4AE111 : 0x4AE114;

	for (i = 0; i < 32; i++) // Load "3B" type keys
	{
		snprintf(tmp, 5, "3B%02X", i);
		if (!emu_find_key('D', prvid, 0, tmp, buffer[i], 32, 0, 0, 0, NULL))
		{
			memset(buffer[i], 0xFF, 32);
		}
	}

	for (i = 0; i < 32; i++) // Load "56" type keys
	{
		snprintf(tmp, 5, "56%02X", i);
		if (!emu_find_key('D', prvid, 0, tmp, buffer[32 + i], 32, 0, 0, 0, NULL))
		{
			memset(buffer[32 + i], 0xFF, 32);
		}
	}

	// Write buffer to ee.bin file
	fwrite(buffer, 1, sizeof(buffer), file);
	fclose(file);
}

static int8_t drecrypt_process_emm(struct s_reader *rdr, uint32_t provId, uint8_t *emm, uint32_t *keysAdded)
{
	uint32_t i, keyIdent;
	uint16_t keyName, emmLen, emmDataLen;
	uint8_t emmKey[32], curECMkey3B[32], curECMkey56[32];
	uint8_t keynum = 0, keyidx = 0, keyclass = 0, key1offset, key2offset;
	char newKeyName[EMU_MAX_CHAR_KEYNAME], curKeyName[EMU_MAX_CHAR_KEYNAME], keyValue[100];

	emmDataLen = get_ecm_len(emm);
	emmLen = ((emm[1] & 0xF) << 8) | emm[2];

	if (emmDataLen < emmLen + 3)
	{
		return 4; // Corrupt data
	}

	if (emm[0] == 0x91)
	{
		Drecrypt2OverEMM(emm);
		return 0;
	}
	else if (emm[0] == 0x82)
	{
		ReasmEMM82(emm);
		return 0;
	}
	else if (emm[0] != 0x86)
	{
		return 1; // Not supported
	}

	// Emm type 0x86 only
	switch (emm[4])
	{
		case 0x02:
			keynum = 0x2C;
			keyidx = 0x30;
			keyclass = 0x26;
			key1offset = 0x35;
			key2offset = 0x6D;
			break;

		case 0x4D:
			keynum = 0x61;
			keyidx = 0x60;
			keyclass = 0x05;
			key1offset = 0x62;
			key2offset = 0x8B;
			break;

		default:
			return 1; // Not supported
	}

	switch (provId & 0xFF)
	{
		case 0x11:
		{
			snprintf(curKeyName, EMU_MAX_CHAR_KEYNAME, "3B%02X", emm[keyclass]);
			emu_find_key('D', 0x4AE111, 0, curKeyName, curECMkey3B, 32, 0, 0, 0, NULL);

			snprintf(curKeyName, EMU_MAX_CHAR_KEYNAME, "56%02X", emm[keyclass]);
			emu_find_key('D', 0x4AE111, 0, curKeyName, curECMkey56, 32, 0, 0, 0, NULL);

			break;
		}

		case 0x14:
		{
			snprintf(curKeyName, EMU_MAX_CHAR_KEYNAME, "3B%02X", emm[keyclass]);
			emu_find_key('D', 0x4AE114, 0, curKeyName, curECMkey3B, 32, 0, 0, 0, NULL);

			snprintf(curKeyName, EMU_MAX_CHAR_KEYNAME, "56%02X", emm[keyclass]);
			emu_find_key('D', 0x4AE114, 0, curKeyName, curECMkey56, 32, 0, 0, 0, NULL);

			break;
		}

		default:
			return 9; // Wrong provider
	}

	keyIdent = (0x4AE1 << 8) | provId;
	keyName = (emm[3] << 8) | emm[keynum];

	if (!get_emm_key(emmKey, keyIdent, keyName, 1))
	{
		return 2;
	}

	// Key #1
	for (i = 0; i < 4; i++)
	{
		drecrypt_decrypt(&emm[key1offset + (i * 8)], emmKey);
	}

	// Key #2
	for (i = 0; i < 4; i++)
	{
		drecrypt_decrypt(&emm[key2offset + (i * 8)], emmKey);
	}

	// Key #1
	keyName = emm[keyidx] << 8 | emm[keyclass];
	snprintf(newKeyName, EMU_MAX_CHAR_KEYNAME, "%.4X", keyName);

	if (memcmp(&emm[key1offset], emm[keyidx] == 0x3B ? curECMkey3B : curECMkey56, 32) != 0)
	{
		memcpy(emm[keyidx] == 0x3B ? curECMkey3B : curECMkey56, &emm[key1offset], 32);
		SAFE_MUTEX_LOCK(&emu_key_data_mutex);
		emu_set_key('D', keyIdent, newKeyName, &emm[key1offset], 32, 0, NULL, NULL);
		SAFE_MUTEX_UNLOCK(&emu_key_data_mutex);
		(*keysAdded)++;

		cs_hexdump(0, &emm[key1offset], 32, keyValue, sizeof(keyValue));
		cs_log("Key found in EMM: D %.6X %s %s class %02X", keyIdent, newKeyName, keyValue, emm[keyclass]);
	}
	else
	{
		cs_log("Key %.6X %s already exists", keyIdent, newKeyName);
	}

	// Key #2
	keyName = (emm[keyidx] == 0x56 ? 0x3B00 : 0x5600) | emm[keyclass];
	snprintf(newKeyName, EMU_MAX_CHAR_KEYNAME, "%.4X", keyName);

	if (memcmp(&emm[key2offset], emm[keyidx] == 0x3B ? curECMkey56 : curECMkey3B, 32) != 0)
	{
		memcpy(emm[keyidx] == 0x3B ? curECMkey56 : curECMkey3B, &emm[key2offset], 32);
		SAFE_MUTEX_LOCK(&emu_key_data_mutex);
		emu_set_key('D', keyIdent, newKeyName, &emm[key2offset], 32, 0, NULL, NULL);
		SAFE_MUTEX_UNLOCK(&emu_key_data_mutex);
		(*keysAdded)++;

		cs_hexdump(0, &emm[key2offset], 32, keyValue, sizeof(keyValue));
		cs_log("Key found in EMM: D %.6X %s %s class %02X", keyIdent, newKeyName, keyValue, emm[keyclass]);
	}
	else
	{
		cs_log("Key %.6X %s already exists", keyIdent, newKeyName);
	}

	if (*keysAdded > 0) // Write new ecm keys to ee.bin file
	{
		switch (provId & 0xFF)
		{
			case 0x11:
				write_eebin(rdr->extee36, "ee36.bin");
				break;

			case 0x14:
				write_eebin(rdr->extee56, "ee56.bin");
				break;

			default:
				cs_log("Provider %02X doesn't have a matching ee.bin file", provId & 0xFF);
				break;
		}
	}

	return 0;
}

int8_t drecrypt2_emm(struct s_reader *rdr, uint32_t provId, uint8_t *emm, uint32_t *keysAdded)
{
	int8_t result = drecrypt_process_emm(rdr, provId, emm, keysAdded);

	if (result == 2)
	{
		uint8_t keynum = 0, emmkey;
		uint32_t i;
		KeyDataContainer *KeyDB = emu_get_key_container('D');

		if (KeyDB == NULL)
		{
			return result;
		}

		for (i = 0; i < KeyDB->keyCount; i++)
		{
			if (KeyDB->EmuKeys[i].provider != ((0x4AE1 << 8) | provId))
			{
				continue;
			}

			if (strlen(KeyDB->EmuKeys[i].keyName) < 6)
			{
				continue;
			}

			if (memcmp(KeyDB->EmuKeys[i].keyName, "MK", 2))
			{
				continue;
			}

			char_to_bin(&keynum, KeyDB->EmuKeys[i].keyName + 4, 2);
			emmkey = (emm[4] == 0x4D) ? emm[0x61] : emm[0x2C];

			if (keynum == emmkey)
			{
				if (provId == 0x11)
				{
					char_to_bin(&rdr->dre36_force_group, KeyDB->EmuKeys[i].keyName + 2, 2);
				}
				else
				{
					char_to_bin(&rdr->dre56_force_group, KeyDB->EmuKeys[i].keyName + 2, 2);
				}

				break;
			}
		}
	}

	return result;
}

int8_t drecrypt_get_hexserials(uint16_t caid, uint32_t provid, uint8_t *hexserials, int32_t length, int32_t *count)
{
	uint32_t i;
	KeyDataContainer *KeyDB = emu_get_key_container('D');

	if (KeyDB == NULL)
	{
		return 0;
	}

	(*count) = 0;

	for (i = 0; i < KeyDB->keyCount && (*count) < length; i++)
	{
		if (KeyDB->EmuKeys[i].provider != ((caid << 8) | provid))
		{
			continue;
		}

		if (strlen(KeyDB->EmuKeys[i].keyName) < 6)
		{
			continue;
		}

		if (memcmp(KeyDB->EmuKeys[i].keyName, "MK", 2))
		{
			continue;
		}

		char_to_bin(&hexserials[(*count)], KeyDB->EmuKeys[i].keyName + 2, 2);

		(*count)++;
	}

	return 1;
}

#endif // WITH_EMU
