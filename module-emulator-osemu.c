#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "oscam-string.h"
#include "cscrypt/bn.h"
#include "module-emulator-osemu.h"
#include "module-emulator-streamserver.h"
#include "module-emulator-biss.h"
#include "module-emulator-cryptoworks.h"
#include "module-emulator-director.h"
#include "module-emulator-drecrypt.h"
#include "module-emulator-irdeto.h"
#include "module-emulator-nagravision.h"
#include "module-emulator-powervu.h"
#include "module-emulator-viaccess.h"
#include "module-emulator-videoguard.h"

// Shared functions

inline uint16_t GetEcmLen(const uint8_t *ecm)
{
	return (((ecm[1] & 0x0F) << 8) | ecm[2]) + 3;
}

int8_t isValidDCW(uint8_t *dw)
{
	uint8_t i;

	for (i = 0; i < 8; i+= 4)
	{
		if (((dw[i] + dw[i + 1] + dw[i + 2]) & 0xFF) != dw[i + 3])
		{
			return 0;
		}
	}

	return 1;
}

void Date2Str(char *dateStr, uint8_t len, int8_t offset, uint8_t format)
{
	// Creates a formatted date string for use in various functions.
	// A positive or negative time offset (in hours) can be set as well
	// as the format of the output string.

	time_t rawtime;
	struct tm timeinfo;

	time(&rawtime);
	rawtime += (time_t) offset * 60 * 60; // Add a positive or negative offset
	localtime_r(&rawtime, &timeinfo);

	switch (format)
	{
		case 1: // Used in WriteKeyToFile()
			strftime(dateStr, len, "%c", &timeinfo);
			break;

		case 2: // Used in BissAnnotate()
			strftime(dateStr, len, "%F @ %R", &timeinfo);
			break;

		case 3: // Used in SetKey(), BissAnnotate(), BissGetKey()
			strftime(dateStr, len, "%y%m%d%H", &timeinfo);
			break;
	}
}

/*
 * Key DB
 *
 * The Emu reader gets keys from the OSCcam-Emu binary and the "SoftCam.Key" file.
 *
 * The keys are stored in structures of type "KeyDataContainer", one per CAS. Each
 * container points to a dynamically allocated array of type "KeyData", which holds
 * the actual keys. The array initially holds up to 64 keys (64 * KeyData), and it
 * is expanded by 16 every time it's filled with keys. The "KeyDataContainer" also
 * includes info about the number of keys it contains ("KeyCount") and the maximum
 * number of keys it can store ("KeyMax").
 *
 * The "KeyData" structure, on the other hand, stores the actual key information,
 * including the "identifier", "provider", "keyName", "key" and "keyLength". There
 * is also a "nextKey" pointer to a similar "KeyData" structure which is only used
 * for Irdeto multiple keys, in a linked list style structure. For all other CAS,
 * the "nextKey" is a "NULL" pointer.
 *
 * For storing keys, the "SetKey" function is used. Duplicate keys are not allowed.
 * When storing a key that is already present in the database, its "key" value is
 * updated with the new one. For reading keys from the database, the "FindKey"
 * function is used. To delete all keys in a container, the "DeleteKeysInContainer"
 * function can be called.
*/

char *emu_keyfile_path = NULL;

void set_emu_keyfile_path(const char *path)
{
	if (emu_keyfile_path != NULL)
	{
		free(emu_keyfile_path);
	}

	emu_keyfile_path = (char *)malloc(strlen(path) + 1);
	if (emu_keyfile_path == NULL)
	{
		return;
	}
	memcpy(emu_keyfile_path, path, strlen(path));
	emu_keyfile_path[strlen(path)] = 0;
}

int8_t CharToBin(uint8_t *out, const char *in, uint32_t inLen)
{
	uint32_t i, tmp;

	for (i = 0; i < inLen / 2; i++)
	{
		if (sscanf(in + i * 2, "%02X", &tmp) != 1)
		{
			return 0;
		}
		out[i] = (uint8_t)tmp;
	}
	return 1;
}

KeyDataContainer CwKeys = { NULL, 0, 0 };
KeyDataContainer ViKeys = { NULL, 0, 0 };
KeyDataContainer NagraKeys = { NULL, 0, 0 };
KeyDataContainer IrdetoKeys = { NULL, 0, 0 };
KeyDataContainer NDSKeys = { NULL, 0, 0 };
KeyDataContainer BissKeys = { NULL, 0, 0 };
KeyDataContainer PowervuKeys = { NULL, 0, 0 };
KeyDataContainer DreKeys = { NULL, 0, 0 };
KeyDataContainer TandbergKeys = { NULL, 0, 0 };

KeyDataContainer *GetKeyContainer(char identifier)
{
	switch (identifier)
	{
		case 'W':
			return &CwKeys;
		case 'V':
			return &ViKeys;
		case 'N':
			return &NagraKeys;
		case 'I':
			return &IrdetoKeys;
		case 'S':
			return &NDSKeys;
		case 'F':
			return &BissKeys;
		case 'P':
			return &PowervuKeys;
		case 'D':
			return &DreKeys;
		case 'T':
			return &TandbergKeys;
		default:
			return NULL;
	}
}

static void WriteKeyToFile(char identifier, uint32_t provider, const char *keyName, uint8_t *key,
							uint32_t keyLength, char *comment)
{
	char line[1200], dateText[100], filename[EMU_KEY_FILENAME_MAX_LEN + 1];
	char *path, *filepath, *keyValue;
	uint32_t pathLength;
	uint8_t fileNameLen = strlen(EMU_KEY_FILENAME);
	struct dirent *pDirent;
	DIR *pDir;
	FILE *file = NULL;

	pathLength = strlen(emu_keyfile_path);
	path = (char *)malloc(pathLength + 1);
	if (path == NULL)
	{
		return;
	}
	strncpy(path, emu_keyfile_path, pathLength + 1);

	pathLength = strlen(path);
	if (pathLength >= fileNameLen && strcasecmp(path + pathLength - fileNameLen, EMU_KEY_FILENAME) == 0)
	{
		// cut file name
		path[pathLength-fileNameLen] = '\0';
	}

	pathLength = strlen(path);
	if (path[pathLength - 1] == '/' || path[pathLength - 1] == '\\')
	{
		// cut trailing /
		path[pathLength - 1] = '\0';
	}

	pDir = opendir(path);
	if (pDir == NULL)
	{
		cs_log("Cannot open key file path: %s", path);
		free(path);
		return;
	}

	while ((pDirent = readdir(pDir)) != NULL)
	{
		if (strcasecmp(pDirent->d_name, EMU_KEY_FILENAME) == 0)
		{
			strncpy(filename, pDirent->d_name, sizeof(filename));
			break;
		}
	}
	closedir(pDir);

	if (pDirent == NULL)
	{
		strncpy(filename, EMU_KEY_FILENAME, sizeof(filename));
	}

	pathLength = strlen(path) + 1 + strlen(filename) + 1;
	filepath = (char *)malloc(pathLength);
	if (filepath == NULL)
	{
		free(path);
		return;
	}
	snprintf(filepath, pathLength, "%s/%s", path, filename);
	free(path);

	cs_log("Writing key file: %s", filepath);

	file = fopen(filepath, "a");
	free(filepath);
	if (file == NULL)
	{
		return;
	}

	Date2Str(dateText, sizeof(dateText), 0, 1);

	keyValue = (char *)malloc((keyLength * 2) + 1);
	if (keyValue == NULL)
	{
		fclose(file);
		return;
	}
	cs_hexdump(0, key, keyLength, keyValue, (keyLength * 2) + 1);

	if (comment)
	{
		snprintf(line, sizeof(line), "\n%c %.4X %s %s ; added by Emu %s %s",
					identifier, provider, keyName, keyValue, dateText, comment);
	}
	else
	{
		snprintf(line, sizeof(line), "\n%c %.4X %s %s ; added by Emu %s",
					identifier, provider, keyName, keyValue, dateText);
	}

	cs_log("Key written: %c %.4X %s %s", identifier, provider, keyName, keyValue);

	free(keyValue);

	fwrite(line, strlen(line), 1, file);
	fclose(file);
}

int8_t SetKey(char identifier, uint32_t provider, char *keyName, uint8_t *orgKey, uint32_t keyLength,
				uint8_t writeKey, char *comment, struct s_reader *rdr)
{
	uint32_t i, j;
	uint8_t *tmpKey = NULL;
	KeyDataContainer *KeyDB;
	KeyData *tmpKeyData, *newKeyData;

	identifier = (char)toupper((int)identifier);

	KeyDB = GetKeyContainer(identifier);
	if (KeyDB == NULL)
	{
		return 0;
	}

	keyName = strtoupper(keyName);

	if (identifier == 'F') // Prepare BISS keys before saving to the db
	{
		// Convert legacy BISS "00" & "01" keynames
		if (0 == strcmp(keyName, "00") || 0 == strcmp(keyName, "01"))
		{
			keyName = "00000000";
		}

		// All keyNames should have a length of 8 after converting
		if (strlen(keyName) != 8)
		{
			cs_log("WARNING: Wrong key format in %s: F %08X %s", EMU_KEY_FILENAME, provider, keyName);
			return 0;
		}

		// Verify date-coded keyName (if enabled), ignoring old (expired) keys
		if (rdr->emu_datecodedenabled)
		{
			char timeStr[9];
			Date2Str(timeStr, sizeof(timeStr), 0, 3);

			// Reject old date-coded keys, but allow our "00000000" evergreen label
			if (strcmp("00000000", keyName) != 0 && strcmp(timeStr, keyName) >= 0)
			{
				return 0;
			}
		}
	}

	// fix checksum for BISS keys with a length of 6
	if (identifier == 'F' && keyLength == 6)
	{
		tmpKey = (uint8_t *)malloc(8 * sizeof(uint8_t));
		if(tmpKey == NULL)
		{
			return 0;
		}

		tmpKey[0] = orgKey[0];
		tmpKey[1] = orgKey[1];
		tmpKey[2] = orgKey[2];
		tmpKey[3] = ((orgKey[0] + orgKey[1] + orgKey[2]) & 0xff);
		tmpKey[4] = orgKey[3];
		tmpKey[5] = orgKey[4];
		tmpKey[6] = orgKey[5];
		tmpKey[7] = ((orgKey[3] + orgKey[4] + orgKey[5]) & 0xff);

		keyLength = 8;
	}
	else // All keys with a length of 8, including BISS
	{
		tmpKey = (uint8_t *)malloc(keyLength * sizeof(uint8_t));
		if (tmpKey == NULL)
		{
			return 0;
		}

		memcpy(tmpKey, orgKey, keyLength);
	}

	// fix patched mgcamd format for Irdeto
	if (identifier == 'I' && provider < 0xFFFF)
	{
		provider = provider << 8;
	}

	// key already exists on db, update its value
	for (i = 0; i < KeyDB->keyCount; i++)
	{
		if (KeyDB->EmuKeys[i].provider != provider)
		{
			continue;
		}

		// Don't match keyName (i.e. expiration date) for BISS
		if (identifier != 'F' && strcmp(KeyDB->EmuKeys[i].keyName, keyName))
		{
			continue;
		}

		// allow multiple keys for Irdeto
		if (identifier == 'I')
		{
			// reject duplicates
			tmpKeyData = &KeyDB->EmuKeys[i];
			do
			{
				if (memcmp(tmpKeyData->key, tmpKey, tmpKeyData->keyLength < keyLength ? tmpKeyData->keyLength : keyLength) == 0)
				{
					free(tmpKey);
					return 0;
				}
				tmpKeyData = tmpKeyData->nextKey;
			}
			while(tmpKeyData != NULL);

			// add new key
			newKeyData = (KeyData *)malloc(sizeof(KeyData));
			if (newKeyData == NULL)
			{
				free(tmpKey);
				return 0;
			}
			newKeyData->identifier = identifier;
			newKeyData->provider = provider;
			if (strlen(keyName) < EMU_MAX_CHAR_KEYNAME)
			{
				strncpy(newKeyData->keyName, keyName, EMU_MAX_CHAR_KEYNAME);
			}
			else
			{
				memcpy(newKeyData->keyName, keyName, EMU_MAX_CHAR_KEYNAME);
			}
			newKeyData->keyName[EMU_MAX_CHAR_KEYNAME - 1] = 0;
			newKeyData->key = tmpKey;
			newKeyData->keyLength = keyLength;
			newKeyData->nextKey = NULL;

			tmpKeyData = &KeyDB->EmuKeys[i];
			j = 0;
			while (tmpKeyData->nextKey != NULL)
			{
				if (j == 0xFE)
				{
					break;
				}
				tmpKeyData = tmpKeyData->nextKey;
				j++;
			}
			if (tmpKeyData->nextKey)
			{
				NULLFREE(tmpKeyData->nextKey->key);
				NULLFREE(tmpKeyData->nextKey);
			}
			tmpKeyData->nextKey = newKeyData;

			if (writeKey)
			{
				WriteKeyToFile(identifier, provider, keyName, tmpKey, keyLength, comment);
			}
		}
		else // identifier != 'I'
		{
			free(KeyDB->EmuKeys[i].key);
			KeyDB->EmuKeys[i].key = tmpKey;
			KeyDB->EmuKeys[i].keyLength = keyLength;

			if (identifier == 'F') // Update keyName (i.e. expiration date) for BISS
			{
				strncpy(KeyDB->EmuKeys[i].keyName, keyName, EMU_MAX_CHAR_KEYNAME);
			}

			if (writeKey)
			{
				WriteKeyToFile(identifier, provider, keyName, tmpKey, keyLength, comment);
			}
		}
		return 1;
	}

	// key does not exist on db
	if (KeyDB->keyCount + 1 > KeyDB->keyMax)
	{
		if (KeyDB->EmuKeys == NULL) // db is empty
		{
			KeyDB->EmuKeys = (KeyData *)malloc(sizeof(KeyData) * (KeyDB->keyMax + 64));
			if (KeyDB->EmuKeys == NULL)
			{
				free(tmpKey);
				return 0;
			}
			KeyDB->keyMax += 64;
		}
		else // db is full, expand it
		{
			tmpKeyData = (KeyData *)realloc(KeyDB->EmuKeys, sizeof(KeyData) * (KeyDB->keyMax + 16));
			if (tmpKeyData == NULL)
			{
				free(tmpKey);
				return 0;
			}
			KeyDB->EmuKeys = tmpKeyData;
			KeyDB->keyMax += 16;
		}
	}

	KeyDB->EmuKeys[KeyDB->keyCount].identifier = identifier;
	KeyDB->EmuKeys[KeyDB->keyCount].provider = provider;
	if (strlen(keyName) < EMU_MAX_CHAR_KEYNAME)
	{
		strncpy(KeyDB->EmuKeys[KeyDB->keyCount].keyName, keyName, EMU_MAX_CHAR_KEYNAME);
	}
	else
	{
		memcpy(KeyDB->EmuKeys[KeyDB->keyCount].keyName, keyName, EMU_MAX_CHAR_KEYNAME);
	}
	KeyDB->EmuKeys[KeyDB->keyCount].keyName[EMU_MAX_CHAR_KEYNAME - 1] = 0;
	KeyDB->EmuKeys[KeyDB->keyCount].key = tmpKey;
	KeyDB->EmuKeys[KeyDB->keyCount].keyLength = keyLength;
	KeyDB->EmuKeys[KeyDB->keyCount].nextKey = NULL;
	KeyDB->keyCount++;

	if (writeKey)
	{
		WriteKeyToFile(identifier, provider, keyName, tmpKey, keyLength, comment);
	}
	return 1;
}

int8_t FindKey(char identifier, uint32_t provider, uint32_t providerIgnoreMask, char *keyName,
				uint8_t *key, uint32_t maxKeyLength, uint8_t isCriticalKey, uint32_t keyRef,
				uint8_t matchLength, uint32_t *getProvider)
{
	uint32_t i;
	uint16_t j;
	uint8_t provider_matching_key_count = 0;
	KeyDataContainer *KeyDB;
	KeyData *tmpKeyData;

	KeyDB = GetKeyContainer(identifier);
	if (KeyDB == NULL)
	{
		return 0;
	}

	for (i = 0; i < KeyDB->keyCount; i++)
	{

		if ((KeyDB->EmuKeys[i].provider & ~providerIgnoreMask) != provider)
		{
			continue;
		}

		// Don't match keyName (i.e. expiration date) for BISS
		if (identifier != 'F' && strcmp(KeyDB->EmuKeys[i].keyName, keyName))
		{
			continue;
		}

		//matchLength cannot be used when multiple keys are allowed
		//for a single provider/keyName combination.
		//Currently this is only the case for Irdeto keys.
		if (matchLength && KeyDB->EmuKeys[i].keyLength != maxKeyLength)
		{
			continue;
		}

		if (providerIgnoreMask)
		{
			if (provider_matching_key_count < keyRef)
			{
				provider_matching_key_count++;
				continue;
			}
			else
			{
				keyRef = 0;
			}
		}

		tmpKeyData = &KeyDB->EmuKeys[i];

		j = 0;
		while (j < keyRef && tmpKeyData->nextKey != NULL)
		{
			j++;
			tmpKeyData = tmpKeyData->nextKey;
		}

		if (j == keyRef)
		{
			memcpy(key, tmpKeyData->key, tmpKeyData->keyLength > maxKeyLength ? maxKeyLength : tmpKeyData->keyLength);
			if (tmpKeyData->keyLength < maxKeyLength)
			{
				memset(key+tmpKeyData->keyLength, 0, maxKeyLength - tmpKeyData->keyLength);
			}

			if (identifier == 'F') // Report the keyName of found key back to BissGetKey()
			{
				strncpy(keyName, tmpKeyData->keyName, EMU_MAX_CHAR_KEYNAME);
			}

			if (getProvider != NULL)
			{
				(*getProvider) = tmpKeyData->provider;
			}
			return 1;
		}
		else
		{
			break;
		}
	}

	if (isCriticalKey)
	{
		cs_log("Key not found: %c %X %s", identifier, provider, keyName);
	}

	return 0;
}

int8_t UpdateKey(char identifier, uint32_t provider, char *keyName, uint8_t *key, uint32_t keyLength,
					uint8_t writeKey, char *comment)
{
	uint32_t keyRef = 0;
	uint8_t *tmpKey = (uint8_t *)malloc(sizeof(uint8_t) * keyLength);

	if (tmpKey == NULL)
	{
		return 0;
	}

	while (FindKey(identifier, provider, 0, keyName, tmpKey, keyLength, 0, keyRef, 0, NULL))
	{
		if (memcmp(tmpKey, key, keyLength) == 0)
		{
			free(tmpKey);
			return 0;
		}

		keyRef++;
	}

	free(tmpKey);
	return SetKey(identifier, provider, keyName, key, keyLength, writeKey, comment, NULL);
}

int32_t DeleteKeysInContainer(char identifier)
{
	// Deletes all keys stored in memory for the specified identifier,
	// but keeps the container itself, re-initialized at { NULL, 0, 0 }.
	// Returns the count of deleted keys.

	uint32_t oldKeyCount, i;
	KeyData *tmpKeyData;
	KeyDataContainer *KeyDB = GetKeyContainer(identifier);

	if (KeyDB == NULL || KeyDB->EmuKeys == NULL || KeyDB->keyCount == 0)
	{
		return 0;
	}

	for (i = 0; i < KeyDB->keyCount; i++)
	{
		// For Irdeto multiple keys only (linked list structure)
		while (KeyDB->EmuKeys[i].nextKey != NULL)
		{
			tmpKeyData = KeyDB->EmuKeys[i].nextKey;
			KeyDB->EmuKeys[i].nextKey = KeyDB->EmuKeys[i].nextKey->nextKey;
			free(tmpKeyData->key); // Free key
			free(tmpKeyData); // Free KeyData
		}

		// For single keys (all identifiers, including Irdeto)
		free(KeyDB->EmuKeys[i].key); // Free key
	}

	// Free the KeyData array
	NULLFREE(KeyDB->EmuKeys);
	oldKeyCount = KeyDB->keyCount;
	KeyDB->keyCount = 0;
	KeyDB->keyMax = 0;

	return oldKeyCount;
}

void clear_emu_keydata(void)
{
	uint32_t total = 0;

	total  = CwKeys.keyCount;
	total += ViKeys.keyCount;
	total += NagraKeys.keyCount;
	total += IrdetoKeys.keyCount;
	total += NDSKeys.keyCount;
	total += BissKeys.keyCount;
	total += PowervuKeys.keyCount;
	total += DreKeys.keyCount;
	total += TandbergKeys.keyCount;

	if (total != 0)
	{
		cs_log("Freeing keys in memory: W:%d V:%d N:%d I:%d S:%d F:%d P:%d D:%d T:%d", \
						CwKeys.keyCount, ViKeys.keyCount, NagraKeys.keyCount, \
						IrdetoKeys.keyCount, NDSKeys.keyCount, BissKeys.keyCount, \
						PowervuKeys.keyCount, DreKeys.keyCount, TandbergKeys.keyCount);

		DeleteKeysInContainer('W');
		DeleteKeysInContainer('V');
		DeleteKeysInContainer('N');
		DeleteKeysInContainer('I');
		DeleteKeysInContainer('S');
		DeleteKeysInContainer('F');
		DeleteKeysInContainer('P');
		DeleteKeysInContainer('D');
		DeleteKeysInContainer('T');
	}
}

uint8_t read_emu_keyfile(struct s_reader *rdr, const char *opath)
{
	char line[1200], keyName[EMU_MAX_CHAR_KEYNAME], keyString[1026], identifier;
	char *path, *filepath, filename[EMU_KEY_FILENAME_MAX_LEN + 1];
	uint32_t pathLength, provider, keyLength;
	uint8_t fileNameLen = strlen(EMU_KEY_FILENAME);
	uint8_t *key;
	struct dirent *pDirent;
	DIR *pDir;
	FILE *file = NULL;

	pathLength = strlen(opath);
	path = (char *)malloc(pathLength + 1);
	if (path == NULL)
	{
		return 0;
	}
	strncpy(path, opath, pathLength + 1);

	pathLength = strlen(path);
	if (pathLength >= fileNameLen && strcasecmp(path + pathLength - fileNameLen, EMU_KEY_FILENAME) == 0)
	{
		// cut file name
		path[pathLength-fileNameLen] = '\0';
	}

	pathLength = strlen(path);
	if (path[pathLength - 1] == '/' || path[pathLength - 1] == '\\')
	{
		// cut trailing /
		path[pathLength - 1] = '\0';
	}

	pDir = opendir(path);
	if (pDir == NULL)
	{
		cs_log("Cannot open key file path: %s", path);
		free(path);
		return 0;
	}

	while ((pDirent = readdir(pDir)) != NULL)
	{
		if (strcasecmp(pDirent->d_name, EMU_KEY_FILENAME) == 0)
		{
			strncpy(filename, pDirent->d_name, sizeof(filename));
			break;
		}
	}
	closedir(pDir);

	if (pDirent == NULL)
	{
		cs_log("Key file not found in: %s", path);
		free(path);
		return 0;
	}

	pathLength = strlen(path) + 1 + strlen(filename) + 1;
	filepath = (char *)malloc(pathLength);
	if (filepath == NULL)
	{
		free(path);
		return 0;
	}
	snprintf(filepath, pathLength, "%s/%s", path, filename);
	free(path);

	cs_log("Reading key file: %s", filepath);

	file = fopen(filepath, "r");
	free(filepath);
	if (file == NULL)
	{
		return 0;
	}

	set_emu_keyfile_path(opath);

	while (fgets(line, 1200, file))
	{
		if (sscanf(line, "%c %8x %11s %1024s", &identifier, &provider, keyName, keyString) != 4)
		{
			continue;
		}

		keyLength = strlen(keyString) / 2;
		key = (uint8_t *)malloc(keyLength);
		if (key == NULL)
		{
			fclose(file);
			return 0;
		}

		if (CharToBin(key, keyString, strlen(keyString))) // Conversion OK
		{
			SetKey(identifier, provider, keyName, key, keyLength, 0, NULL, rdr);
		}
		else // Non-hex characters in keyString
		{
			if ((identifier != ';' && identifier != '#' && // Skip warning for comments, etc.
				 identifier != '=' && identifier != '-' &&
				 identifier != ' ') &&
				!(identifier == 'F' && 0 == strncmp(keyString, "XXXXXXXXXXXX", 12))) // Skip warning for BISS 'Example key' lines
			{
				// Alert user regarding faulty line
				cs_log("WARNING: non-hex value in %s at %c %04X %s %s",
						EMU_KEY_FILENAME, identifier, provider, keyName, keyString);
			}
		}
		free(key);
	}
	fclose(file);

	return 1;
}

#if !defined(__APPLE__) && !defined(__ANDROID__)
extern uint8_t SoftCamKey_Data[]    __asm__("_binary_SoftCam_Key_start");
extern uint8_t SoftCamKey_DataEnd[] __asm__("_binary_SoftCam_Key_end");

void read_emu_keymemory(struct s_reader *rdr)
{
	char *keyData, *line, *saveptr, keyName[EMU_MAX_CHAR_KEYNAME], keyString[1026], identifier;
	uint32_t provider, keyLength;
	uint8_t *key;

	keyData = (char *)malloc(SoftCamKey_DataEnd - SoftCamKey_Data + 1);
	if (keyData == NULL)
	{
		return;
	}
	memcpy(keyData, SoftCamKey_Data, SoftCamKey_DataEnd - SoftCamKey_Data);
	keyData[SoftCamKey_DataEnd-SoftCamKey_Data] = 0x00;

	line = strtok_r(keyData, "\n", &saveptr);
	while (line != NULL)
	{
		if (sscanf(line, "%c %8x %11s %1024s", &identifier, &provider, keyName, keyString) != 4)
		{
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}
		keyLength = strlen(keyString) / 2;
		key = (uint8_t *)malloc(keyLength);
		if (key == NULL)
		{
			free(keyData);
			return;
		}

		if (CharToBin(key, keyString, strlen(keyString))) // Conversion OK
		{
			SetKey(identifier, provider, keyName, key, keyLength, 0, NULL, rdr);
		}
		else // Non-hex characters in keyString
		{
			if ((identifier != ';' && identifier != '#' && // Skip warning for comments, etc.
				 identifier != '=' && identifier != '-' &&
				 identifier != ' ') &&
				!(identifier == 'F' && 0 == strncmp(keyString, "XXXXXXXXXXXX", 12))) // Skip warning for BISS 'Example key' lines
			{
				// Alert user regarding faulty line
				cs_log("WARNING: non-hex value in internal keyfile at %c %04X %s %s",
						identifier, provider, keyName, keyString);
			}
		}
		free(key);
		line = strtok_r(NULL, "\n", &saveptr);
	}
	free(keyData);
}
#endif

void read_emu_eebin(const char *path, const char *name)
{
	char tmp[256];
	FILE *file = NULL;
	uint8_t i, buffer[64][32], dummy[2][32];
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

	// Read file to buffer
	if ((file = fopen(tmp, "rb")) != NULL)
	{
		cs_log("Reading key file: %s", tmp);

		if (fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer))
		{
			cs_log("Corrupt key file: %s", tmp);
			fclose(file);
			return;
		}

		fclose(file);
	}
	else
	{
		if (path != NULL)
		{
			cs_log("Cannot open key file: %s", tmp);
		}

		return;
	}

	// Save keys to db
	memset(dummy[0], 0x00, 32);
	memset(dummy[1], 0xFF, 32);
	prvid = (strncmp(name, "ee36.bin", 9) == 0) ? 0x4AE111 : 0x4AE114;

	for (i = 0; i < 32; i++) // Set "3B" type keys
	{
		// Write keys if they have "real" values
		if ((memcmp(buffer[i], dummy[0], 32) !=0) && (memcmp(buffer[i], dummy[1], 32) != 0))
		{
			snprintf(tmp, 5, "3B%02X", i);
			SetKey('D', prvid, tmp, buffer[i], 32, 0, NULL, NULL);
		}
	}

	for (i = 0; i < 32; i++) // Set "56" type keys
	{
		// Write keys if they have "real" values
		if ((memcmp(buffer[32 + i], dummy[0], 32) !=0) && (memcmp(buffer[32 + i], dummy[1], 32) != 0))
		{
			snprintf(tmp, 5, "56%02X", i);
			SetKey('D', prvid, tmp, buffer[32 + i], 32, 0, NULL, NULL);
		}
	}
}

void read_emu_deskey(uint8_t *dreOverKey, uint8_t len)
{
	uint8_t i;

	if (len == 128)
	{
		cs_log("Reading DreCrypt overcrypt (ADEC) key");

		for (i = 0; i < 16; i++)
		{
			SetKey('D', i, "OVER", dreOverKey + (i * 8), 8, 0, NULL, NULL);
		}
	}
	else if ((len != 0 && len < 128) || len > 128)
	{
		cs_log("DreCrypt overcrypt (ADEC) key has wrong length");
	}
}

static const char *GetProcessECMErrorReason(int8_t result)
{
	switch (result)
	{
		case 0:
			return "No error";
		case 1:
			return "ECM not supported";
		case 2:
			return "Key not found";
		case 3:
			return "Nano80 problem";
		case 4:
			return "Corrupt data";
		case 5:
			return "CW not found";
		case 6:
			return "CW checksum error";
		case 7:
			return "Out of memory";
		case 8:
			return "ECM checksum error";
		case 9:
			return "ICG error";
		default:
			return "Unknown";
	}
}

/* Error codes
0  OK
1  ECM not supported
2  Key not found
3  Nano80 problem
4  Corrupt data
5  CW not found
6  CW checksum error
7  Out of memory
8  ECM checksum error
9  ICG error
*/

int8_t ProcessECM(struct s_reader *rdr, int16_t ecmDataLen, uint16_t caid, uint32_t provider,
				const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid, EXTENDED_CW* cw_ex)
{
	if (ecmDataLen < 3)
	{
		cs_log_dbg(D_TRACE, "Received ecm data of zero length!");
		return 4;
	}

	uint16_t ecmLen = GetEcmLen(ecm);
	uint8_t ecmCopy[ecmLen];
	int8_t result = 1;

	if (ecmLen != ecmDataLen)
	{
		cs_log_dbg(D_TRACE, "Actual ecm data length 0x%03X but ecm section length is 0x%03X",
							ecmDataLen, ecmLen);
		return 4;
	}

	if (ecmLen > EMU_MAX_ECM_LEN)
	{
		cs_log_dbg(D_TRACE, "Actual ecm data length 0x%03X but maximum supported ecm length is 0x%03X",
							ecmDataLen, EMU_MAX_ECM_LEN);
		return 1;
	}

	memcpy(ecmCopy, ecm, ecmLen);

	     if (caid_is_viaccess(caid))    result = ViaccessECM(ecmCopy, dw);
	else if (caid_is_irdeto(caid))      result = Irdeto2ECM(caid, ecmCopy, dw);
	else if (caid_is_videoguard(caid))  result = SoftNDSECM(caid, ecmCopy, dw);
	else if (caid_is_cryptoworks(caid)) result = CryptoworksECM(caid, ecmCopy, dw);
	else if (caid_is_powervu(caid))     result = PowervuECM(ecmCopy, dw, srvid, NULL, cw_ex);
	else if (caid_is_director(caid))    result = DirectorEcm(ecmCopy, dw);
	else if (caid_is_nagra(caid))       result = Nagra2ECM(ecmCopy, dw);
	else if (caid_is_biss(caid))        result = BissEcm(rdr, caid, ecm, dw, srvid, ecmpid);
	else if (caid_is_dre(caid))         result = Drecrypt2ECM(provider, ecmCopy, dw);

	if (result != 0)
	{
		cs_log("ECM failed: %s", GetProcessECMErrorReason(result));
	}

	return result;
}

static const char *GetProcessEMMErrorReason(int8_t result)
{
	switch (result)
	{
		case 0:
			return "No error";
		case 1:
			return "EMM not supported";
		case 2:
			return "Key not found";
		case 3:
			return "Nano80 problem";
		case 4:
			return "Corrupt data";
		case 5:
			return "Unknown";
		case 6:
			return "Checksum error";
		case 7:
			return "Out of memory";
		case 8:
			return "EMM checksum error";
		case 9:
			return "Wrong provider";
		default:
			return "Unknown";
	}
}

int8_t ProcessEMM(struct s_reader *rdr, uint16_t caid, uint32_t provider, const uint8_t *emm, uint32_t *keysAdded)
{
	uint16_t emmLen = GetEcmLen(emm);
	uint8_t emmCopy[emmLen];
	int8_t result = 1;

	if (emmLen > EMU_MAX_EMM_LEN)
	{
		return 1;
	}
	memcpy(emmCopy, emm, emmLen);
	*keysAdded = 0;

	     if (caid_is_viaccess(caid)) result = ViaccessEMM(emmCopy, keysAdded);
	else if (caid_is_irdeto(caid))   result = Irdeto2EMM(caid, emmCopy, keysAdded);
	else if (caid_is_powervu(caid))  result = PowervuEMM(emmCopy, keysAdded);
	else if (caid_is_director(caid)) result = DirectorEmm(emmCopy, keysAdded);
	else if (caid_is_dre(caid))      result = Drecrypt2EMM(rdr, provider, emmCopy, keysAdded);

	if (result != 0)
	{
		cs_log_dbg(D_EMM,"EMM failed: %s", GetProcessEMMErrorReason(result));
	}

	return result;
}

#endif // WITH_EMU
