#define MODULE_LOG_PREFIX "emu"

#include "globals.h"
#include "oscam-aes.h"
#include "oscam-string.h"
#include "cscrypt/des.h"
#include "module-emulator-osemu.h"

// Tandberg EMU
static uint16_t TandbergChecksum(uint8_t *data, uint8_t length)
{
	// ECM and EMM checksum calculation
	// 1. Combine data in 2 byte groups
	// 2. Add them together
	// 3. Multiply result by itself (power of 7)
	// 4. XOR with fixed value 0x17E3
	
	uint8_t i;
	uint16_t checksum = 0;
	
	for(i = 0; i < length; i += 2)
	{
		checksum += (data[i] << 8) | data[i + 1];
	}
	
	checksum =  checksum * checksum * checksum * checksum * checksum * checksum * checksum;
	checksum ^= 0x17E3;
	
	return checksum;
}

static int8_t GetTandbergKey(uint32_t keyIndex, char *keyName, uint8_t *key, uint32_t keyLength)
{
	// keyIndex: ecm keys --> entitlementId
	//			 emm keys --> aeskeyIndex
	//			 aes keys --> keyIndex

	// keyName: ecm keys --> "01"
	//			emm keys --> "MK" or "MK01"
	//			aes keys --> "AES"

	return FindKey('T', keyIndex, 0, keyName, key, keyLength, 1, 0, 0, NULL);
}

int8_t TandbergECM(uint8_t *ecm, uint8_t *dw)
{
	uint8_t nanoType, nanoLength;
	uint8_t* nanoData;
	uint32_t pos = 3;
	uint32_t entitlementId;
	uint32_t ks[32];
	uint8_t ecmKey[8];
	uint16_t ecmLen = GetEcmLen(ecm);
	
	if(ecmLen < 5)
	{
		return 1;
	}
	
	do
	{
		nanoType = ecm[pos];
		nanoLength = ecm[pos+1];
		
		if(pos + 2 + nanoLength > ecmLen)
		{
			break;
		}
		
		nanoData = ecm + pos + 2;
		
		// ECM validation
		uint16_t payloadChecksum = (nanoData[nanoLength - 2] << 8) | nanoData[nanoLength - 1];
		uint16_t calculatedChecksum = TandbergChecksum(nanoData, nanoLength - 2);
		
		if(calculatedChecksum != payloadChecksum)
		{
			cs_log("ECM checksum error (%.4X instead of %.4X)", calculatedChecksum, payloadChecksum);
			return 8;
		}
		// End of ECM validation
		
		switch(nanoType)
		{
			case 0xEC: // Director v6 (September 2017)
			{
				if(nanoLength != 0x28)
				{
					cs_log("WARNING: nanoType EC length (%d) != %d", nanoLength, 0x28);
					break;
				}
				
				entitlementId = b2i(4, nanoData);
				
				if(!GetTandbergKey(entitlementId, "01", ecmKey, 8))
				{
					return 2;
				}
				
				cs_log("Active entitlement %.4X", entitlementId);
				
				// Step 1 - Decrypt DES CBC with ecmKey and iv = { 0 } (equal to nanoED)
				uint8_t encryptedData[32] = { 0 };
				memcpy(encryptedData, nanoData + 6, 32);
				
				uint8_t iv[8] = { 0 };
				des_cbc_decrypt(encryptedData, iv, ecmKey, 32);
				
				uint8_t nanoMode = nanoData[5];

				if ((nanoMode & 0x20) == 0) // Old algo
				{
					// Step 2 - Create CW (equal to nano ED)
					dw[0] = encryptedData[0x05];
					dw[1] = encryptedData[0x19];
					dw[2] = encryptedData[0x1D];

					dw[4] = encryptedData[0x0B];
					dw[5] = encryptedData[0x12];
					dw[6] = encryptedData[0x1A];

					dw[8] = encryptedData[0x16];
					dw[9] = encryptedData[0x03];
					dw[10] = encryptedData[0x11];

					dw[12] = encryptedData[0x18];
					dw[13] = encryptedData[0x10];
					dw[14] = encryptedData[0x0E];

					return 0;
				}
				else // New algo (overencryption with AES)
				{
					// Step 2 - Prepare data for AES (it is like the creation of CW in nanoED but swapped each 8 bytes)
					uint8_t dataEC[16] = { 0 };

					dataEC[0] = encryptedData[0x02];
					dataEC[1] = encryptedData[0x0E];
					dataEC[2] = encryptedData[0x10];
					dataEC[3] = encryptedData[0x18];
					dataEC[4] = encryptedData[0x09];
					dataEC[5] = encryptedData[0x11];
					dataEC[6] = encryptedData[0x03];
					dataEC[7] = encryptedData[0x16];

					dataEC[8] = encryptedData[0x13];
					dataEC[9] = encryptedData[0x1A];
					dataEC[10] = encryptedData[0x12];
					dataEC[11] = encryptedData[0x0B];
					dataEC[12] = encryptedData[0x04];
					dataEC[13] = encryptedData[0x1D];
					dataEC[14] = encryptedData[0x19];
					dataEC[15] = encryptedData[0x05];

					// Step 3 - Decrypt AES CBC with new aesKey and iv 2EBD816A5E749A708AE45ADDD84333DE
					uint8_t aesKeyIndex = nanoMode & 0x1F; // 32 possible AES keys
					uint8_t aesKey[16] = { 0 };

					if(!GetTandbergKey(aesKeyIndex, "AES", aesKey, 16))
					{
						return 2;
					}

					struct aes_keys aes;
					aes_set_key(&aes, (char *)aesKey);

					uint8_t ivAes[16] = { 0x2E, 0xBD, 0x81, 0x6A, 0x5E, 0x74, 0x9A, 0x70, 0x8A, 0xE4, 0x5A, 0xDD, 0xD8, 0x43, 0x33, 0xDE };
					aes_cbc_decrypt(&aes, dataEC, 16, ivAes);

					// Step 4 - Create CW (a simple swap)
					uint8_t offset;
					for (offset = 0; offset < 16; offset++)
					{
						dw[offset] = dataEC[15 - offset];
					}

					return 0;
				}
			}

			case 0xED: // ECM_TAG_CW_DESCRIPTOR
			{
				if(nanoLength != 0x26)
				{
					cs_log("WARNING: nanoType ED length (%d) != %d", nanoLength, 0x26);
					break;
				}
				
				entitlementId = b2i(4, nanoData);
				
				if(!GetTandbergKey(entitlementId, "01", ecmKey, 8))
				{
					return 2;
				}
				
				cs_log("Active entitlement %.4X", entitlementId);
				
				uint8_t encryptedData[32] = { 0 };
				memcpy(encryptedData, nanoData + 4, 32);
				
				uint8_t iv[8] = { 0 };
				des_cbc_decrypt(encryptedData, iv, ecmKey, 32);
				
				dw[0] = encryptedData[0x05];
				dw[1] = encryptedData[0x19];
				dw[2] = encryptedData[0x1D];
				dw[4] = encryptedData[0x0B];
				dw[5] = encryptedData[0x12];
				dw[6] = encryptedData[0x1A];
				dw[8] = encryptedData[0x16];
				dw[9] = encryptedData[0x03];
				dw[10] = encryptedData[0x11];
				dw[12] = encryptedData[0x18];
				dw[13] = encryptedData[0x10];
				dw[14] = encryptedData[0x0E];
				
				return 0;
			}
			
			case 0xEE: // ECM_TAG_CW_DESCRIPTOR
			{
				if(nanoLength != 0x16)
				{
					cs_log("WARNING: nanoType EE length (%d) != %d", nanoLength, 0x16);
					break;
				}
				
				entitlementId = b2i(4, nanoData);
				
				if(!GetTandbergKey(entitlementId, "01", ecmKey, 8))
				{
					return 2;
				}
				
				cs_log("Active entitlement %.4X", entitlementId);
				
				memcpy(dw, nanoData + 4 + 8, 8); // even
				memcpy(dw + 8, nanoData + 4, 8); // odd
				
				des_set_key(ecmKey, ks);
				
				des(dw, ks, 0);
				des(dw + 8, ks, 0);
				
				return 0;
			}
			
			default:
				cs_log("WARNING: nanoType %.2X not supported", nanoType);
			break;
		}
		
		pos += 2 + nanoLength;
		
	} while (pos < ecmLen);
	
	return 1;
}

// Tandberg EMM EMU
static uint8_t MixTable[] =
{
	0x12,0x78,0x4B,0x19,0x13,0x80,0x2F,0x84,
	0x86,0x4C,0x09,0x53,0x15,0x79,0x6B,0x49,
	0x10,0x4D,0x33,0x43,0x18,0x37,0x83,0x38,
	0x82,0x1B,0x6E,0x24,0x2A,0x85,0x3C,0x3D,
	0x5A,0x58,0x55,0x5D,0x20,0x41,0x65,0x51,
	0x0C,0x45,0x63,0x7F,0x0F,0x46,0x21,0x7C,
	0x2C,0x61,0x7E,0x0A,0x42,0x57,0x35,0x16,
	0x87,0x3B,0x4F,0x40,0x34,0x22,0x26,0x74,
	0x32,0x69,0x44,0x7A,0x6A,0x6D,0x0D,0x56,
	0x23,0x2B,0x5C,0x72,0x76,0x36,0x28,0x25,
	0x2E,0x52,0x5B,0x6C,0x7D,0x30,0x0B,0x5E,
	0x47,0x1F,0x7B,0x31,0x3E,0x11,0x77,0x1E,
	0x60,0x75,0x54,0x27,0x50,0x17,0x70,0x59,
	0x1A,0x2D,0x4A,0x67,0x3A,0x5F,0x68,0x08,
	0x4E,0x3F,0x29,0x6F,0x81,0x71,0x39,0x64,
	0x48,0x66,0x73,0x14,0x0E,0x1D,0x62,0x1C
};

void TandbergRotateBytes(unsigned char *in, int n)
{
	if(n > 1)
	{
		unsigned char *e = in + n - 1;
		do
		{
			unsigned char temp = *in;
			*in++ = *e;
			*e-- = temp;
		}
		while (in < e);
	}
}

static void TandbergECMKeyDecrypt(uint8_t* emmKey, uint8_t* tagData, uint8_t* ecmKey)
{
	TandbergRotateBytes(emmKey, 8);
	uint8_t iv[8] = { 0 };
	uint8_t* payLoad = tagData + 4 + 5;
	des_cbc_decrypt(payLoad, iv, emmKey, 16);

	ecmKey[0] = payLoad[0x0F];
	ecmKey[1] = payLoad[0x01];
	ecmKey[2] = payLoad[0x0B];
	ecmKey[3] = payLoad[0x03];
	ecmKey[4] = payLoad[0x0E];
	ecmKey[5] = payLoad[0x04];
	ecmKey[6] = payLoad[0x0A];
	ecmKey[7] = payLoad[0x08];
}

static int8_t TandbergParseEMMNanoTags(uint8_t* data, uint32_t length, uint8_t keyIndex, uint32_t *keysAdded)
{
	uint8_t tagType, tagLength, blockIndex;
	uint32_t pos = 0, entitlementId;
	int32_t i, k;
	uint32_t ks[32];
	uint8_t* tagData;
	uint8_t emmKey[8];
	char keyValue[17];
	uint8_t tagDataDecrypted[0x10][8];
	
	if(length < 2)
	{
		return 1;
	}
	
	while(pos < length)
	{
		tagType = data[pos];
		tagLength = data[pos+1];
		
		if(pos + 2 + tagLength > length)
		{
			return 1;
		}
			
		tagData = data + pos + 2;
	
		switch(tagType)
		{
			case 0xE4: // EMM_TAG_SECURITY_TABLE_DESCRIPTOR (ram emm keys)
			{
				uint8_t tagMode = data[pos + 2];
				
				switch(tagMode)
				{
					case 0x01: // keySet 01 (MK01)
					{
						if(tagLength != 0x8A)
						{
							cs_log("WARNING: nanoTag E4 length (%d) != %d", tagLength, 0x8A);
							break;
						}
						
						if(!GetTandbergKey(keyIndex, "MK01", emmKey, 8))
						{
							break;
						}
						
						uint8_t iv[8] = { 0 };
						uint8_t* tagPayload = tagData + 2;
						des_cbc_decrypt(tagPayload, iv, emmKey, 136);
					
						for (k = 0; k < 0x10; k++) // loop 0x10 keys
						{
							for (i = 0; i < 8; i++) // loop 8 bytes of key
							{
								tagDataDecrypted[k][i] = tagPayload[MixTable[8*k + i]];
							}
						}
						
						blockIndex = tagData[1] & 0x03;
						
						for(i = 0; i < 0x10; i++)
						{
							SetKey('T', (blockIndex << 4) + i, "MK01", tagDataDecrypted[i], 8, 0, NULL, NULL);
						}
					}
					break;
					
					case 0xFF: // keySet FF (MK)
					{
						if(tagLength != 0x82)
						{
							cs_log("WARNING: nanoTag E4 length (%d) != %d", tagLength, 0x82);
							break;
						}
						
						blockIndex = tagData[1] & 0x03;
						
						if(!GetTandbergKey(keyIndex, "MK", emmKey, 8))
						{
							break;
						}
						
						des_set_key(emmKey, ks);
						
						for(i = 0; i < 0x10; i++)
						{
							des(tagData + 2 + (i*8), ks, 0);
						}
						
						for(i = 0; i < 0x10; i++)
						{
							SetKey('T', (blockIndex << 4) + i, "MK", tagData + 2 + (i*8), 8, 0, NULL, NULL);
						}
					}
					break;
					
					default:
						cs_log("WARNING: nanoTag E4 mode %.2X not supported", tagMode);
					break;
				}
				break;
			}
			
			case 0xE1: // EMM_TAG_EVENT_ENTITLEMENT_DESCRIPTOR (ecm keys)
			{
				uint8_t tagMode = data[pos + 2 + 4];
				
				switch(tagMode)
				{
					case 0x00: // ecm keys from mode FF
					{
						if(tagLength != 0x12)
						{
							cs_log("WARNING: nanoTag E1 length (%d) != %d", tagLength, 0x12);
							break;
						}
						
						entitlementId = b2i(4, tagData);
						
						if(!GetTandbergKey(keyIndex, "MK", emmKey, 8))
						{
							break;
						}
						
						des_set_key(emmKey, ks);
						des(tagData + 4 + 5, ks, 0);
						
						if((tagData + 4 + 5 + 7) != 0x00) // check if key looks valid (last byte 0x00)
						{
							break;
						}
						
						if(UpdateKey('T', entitlementId, "01", tagData + 4 + 5, 8, 1, NULL))
						{
							(*keysAdded)++;
							cs_hexdump(0, tagData + 4 + 5, 8, keyValue, sizeof(keyValue));
							cs_log("Key found in EMM: T %.8X 01 %s", entitlementId, keyValue);
						}
					}
					break;
					
					case 0x01: // ecm keys from mode 01
					{
						if(tagLength != 0x1A)
						{
							cs_log("WARNING: nanoTag E1 length (%d) != %d", tagLength, 0x1A);
							break;
						}
						
						entitlementId = b2i(4, tagData);
						
						if(!GetTandbergKey(keyIndex, "MK01", emmKey, 8))
						{
							break;
						}
						
						uint8_t ecmKey[8] = { 0 };
						TandbergECMKeyDecrypt(emmKey, tagData, ecmKey);
						
						if(ecmKey[7] != 0x00) // check if key looks valid (last byte 0x00)
						{
							break;
						}
						
						if(UpdateKey('T', entitlementId, "01", ecmKey, 8, 1, NULL))
						{
							(*keysAdded)++;
							cs_hexdump(0, ecmKey, 8, keyValue, sizeof(keyValue));
							cs_log("Key found in EMM: T %.8X 01 %s", entitlementId, keyValue);
						}
					}
					break;
					
					default:
						cs_log("WARNING: nanoTag E1 mode %.2X not supported", tagMode);
					break;
				}
				break;
			}
			
			default:
				cs_log("WARNING: nanoTag %.2X not supported", tagType);
			break;
		}
		
		pos += 2 + tagLength;
	}
	
	return 0;
}

static int8_t TandbergParseEMMNanoData(uint8_t* data, uint32_t* nanoLength, uint32_t maxLength, uint8_t keyIndex, uint32_t *keysAdded)
{
	uint32_t pos = 0;
	uint16_t sectionLength;
	int8_t ret = 0;
	
	if(maxLength < 2)
	{
		(*nanoLength) = 0;
		return 1;
	}
	
	sectionLength = ((data[pos]<<8) | data[pos+1]) & 0x0FFF;
	
	if(pos + 2 + sectionLength > maxLength)
	{
		(*nanoLength) = pos;
		return 1;
	}
		
	ret = TandbergParseEMMNanoTags(data + pos + 2, sectionLength, keyIndex, keysAdded);
		
	pos += 2 + sectionLength;	
	
	(*nanoLength) = pos;
	return ret;
}

int8_t TandbergEMM(uint8_t *emm, uint32_t *keysAdded)
{
	uint8_t keyIndex, ret = 0;
	uint16_t emmLen = GetEcmLen(emm);
	uint32_t pos = 3;
	uint32_t permissionDataType;
	uint32_t nanoLength = 0;
	
	while (pos < emmLen && !ret)
	{
		permissionDataType = emm[pos];
	
		switch(permissionDataType)
		{
			case 0x00:
			{
				break;
			}
			
			case 0x01:
			{
				pos += 0x0A;
				break;
			}
			
			case 0x02:
			{
				pos += 0x26;
				break;
			}
			
			default:
				cs_log("ERROR: unknown permissionDataType %.2X (pos: %d)", permissionDataType, pos);
				return 1;
		}
		
		if(pos+6 >= emmLen)
		{
			break;
		}
		
		keyIndex = emm[pos+1];
		
		// EMM validation
		// Copy payload checksum bytes and then set them to zero,
		// so they do not affect the calculated checksum.
		uint16_t payloadChecksum = (emm[pos + 2] << 8) | emm[pos + 3];
		memset(emm + pos + 2, 0, 2);
		uint16_t calculatedChecksum = TandbergChecksum(emm + 3, emmLen - 3);
		
		if(calculatedChecksum != payloadChecksum)
		{
			cs_log("EMM checksum error (%.4X instead of %.4X)", calculatedChecksum, payloadChecksum);
			return 8;
		}
		// End of EMM validation
		
		pos += 0x04;
		ret = TandbergParseEMMNanoData(emm + pos, &nanoLength, emmLen - pos, keyIndex, keysAdded);
		pos += nanoLength;
	}
	
	return ret;
}
