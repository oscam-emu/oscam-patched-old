#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "module-emulator-osemu.h"
#include "module-newcamd-des.h"
#include "oscam-aes.h"
#include "oscam-string.h"

// from reader-viaccess.c:
void hdSurEncPhase1_D2_0F_11(uint8_t *CWs);
void hdSurEncPhase2_D2_0F_11(uint8_t *CWs);
void hdSurEncPhase1_D2_13_15(uint8_t *cws);
void hdSurEncPhase2_D2_13_15(uint8_t *cws);

// Viaccess EMU
static int8_t GetViaKey(uint8_t *buf, uint32_t ident, char keyName, uint32_t keyIndex, uint32_t keyLength, uint8_t isCriticalKey)
{

	char keyStr[EMU_MAX_CHAR_KEYNAME];
	snprintf(keyStr, EMU_MAX_CHAR_KEYNAME, "%c%X", keyName, keyIndex);
	if(FindKey('V', ident, 0, keyStr, buf, keyLength, isCriticalKey, 0, 0, NULL)) {
		return 1;
	}

	if(ident == 0xD00040 && FindKey('V', 0x030B00, 0, keyStr, buf, keyLength, isCriticalKey, 0, 0, NULL)) {
		return 1;
	}

	return 0;
}

static void Via1Mod(const uint8_t* key2, uint8_t* data)
{
	int32_t kb, db;
	for (db=7; db>=0; db--) {
		for (kb=7; kb>3; kb--) {
			int32_t a0=kb^db;
			int32_t pos=7;
			if (a0&4) {
				a0^=7;
				pos^=7;
			}
			a0=(a0^(kb&3)) + (kb&3);
			if (!(a0&4)) {
				data[db]^=(key2[kb] ^ ((data[kb^pos]*key2[kb^4]) & 0xFF));
			}
		}
	}
	for (db=0; db<8; db++) {
		for (kb=0; kb<4; kb++) {
			int32_t a0=kb^db;
			int32_t pos=7;
			if (a0&4) {
				a0^=7;
				pos^=7;
			}
			a0=(a0^(kb&3)) + (kb&3);
			if (!(a0&4)) {
				data[db]^=(key2[kb] ^ ((data[kb^pos]*key2[kb^4]) & 0xFF));
			}
		}
	}
}

static void Via1Decode(uint8_t *data, uint8_t *key)
{
	Via1Mod(key+8, data);
	nc_des(key, DES_ECM_CRYPT, data);
	Via1Mod(key+8, data);
}

static void Via1Hash(uint8_t *data, uint8_t *key)
{
	Via1Mod(key+8, data);
	nc_des(key, DES_ECM_HASH, data);
	Via1Mod(key+8, data);
}

static inline void Via1DoHash(uint8_t *hashbuffer, uint8_t *pH, uint8_t data, uint8_t *hashkey)
{
	hashbuffer[*pH] ^= data;
	(*pH)++;

	if(*pH == 8) {
		Via1Hash(hashbuffer, hashkey);
		*pH = 0;
	}
}

static int8_t Via1Decrypt(uint8_t* ecm, uint8_t* dw, uint32_t ident, uint8_t desKeyIndex)
{
	uint8_t work_key[16];
	uint8_t *data, *des_data1, *des_data2;
	uint16_t ecmLen = GetEcmLen(ecm);
	int32_t msg_pos;
	int32_t encStart = 0, hash_start, i;
	uint8_t signature[8], hashbuffer[8], prepared_key[16], hashkey[16];
	uint8_t tmp, k, pH, foundData = 0;

	if (ident == 0) {
		return 4;
	}
	memset(work_key, 0, 16);
	if(!GetViaKey(work_key, ident, '0', desKeyIndex, 8, 1)) {
		return 2;
	}

	if(ecmLen < 11) {
		return 1;
	}
	data = ecm+9;
	des_data1 = dw;
	des_data2 = dw+8;

	msg_pos = 0;
	pH = 0;
	memset(hashbuffer, 0, sizeof(hashbuffer));
	memcpy(hashkey, work_key, sizeof(hashkey));
	memset(signature, 0, 8);

	while(9+msg_pos+2 < ecmLen) {
		switch (data[msg_pos]) {
		case 0xea:
			if(9+msg_pos+2+15 < ecmLen) {
				encStart = msg_pos + 2;
				memcpy(des_data1, &data[msg_pos+2], 8);
				memcpy(des_data2, &data[msg_pos+2+8], 8);
				foundData |= 1;
			}
			break;
		case 0xf0:
			if(9+msg_pos+2+7 < ecmLen) {
				memcpy(signature, &data[msg_pos+2], 8);
				foundData |= 2;
			}
			break;
		}
		msg_pos += data[msg_pos+1]+2;
	}

	if(foundData != 3) {
		return 1;
	}

	pH=i=0;

	if(data[0] == 0x9f && 10+data[1] <= ecmLen) {
		Via1DoHash(hashbuffer, &pH, data[i++], hashkey);
		Via1DoHash(hashbuffer, &pH, data[i++], hashkey);

		for (hash_start=0; hash_start < data[1]; hash_start++) {
			Via1DoHash(hashbuffer, &pH, data[i++], hashkey);
		}

		while (pH != 0) {
			Via1DoHash(hashbuffer, &pH, 0, hashkey);
		}
	}

	if (work_key[7] == 0) {
		for (; i < encStart + 16; i++) {
			Via1DoHash(hashbuffer, &pH, data[i], hashkey);
		}
		memcpy(prepared_key, work_key, 8);
	}
	else {
		prepared_key[0] = work_key[2];
		prepared_key[1] = work_key[3];
		prepared_key[2] = work_key[4];
		prepared_key[3] = work_key[5];
		prepared_key[4] = work_key[6];
		prepared_key[5] = work_key[0];
		prepared_key[6] = work_key[1];
		prepared_key[7] = work_key[7];
		memcpy(prepared_key+8, work_key+8, 8);

		if (work_key[7] & 1) {
			for (; i < encStart; i++) {
				Via1DoHash(hashbuffer, &pH, data[i], hashkey);
			}

			k = ((work_key[7] & 0xf0) == 0) ? 0x5a : 0xa5;

			for (i=0; i<8; i++) {
				tmp = des_data1[i];
				des_data1[i] = (k & hashbuffer[pH] ) ^ tmp;
				Via1DoHash(hashbuffer, &pH, tmp, hashkey);
			}

			for (i = 0; i < 8; i++) {
				tmp = des_data2[i];
				des_data2[i] = (k & hashbuffer[pH] ) ^ tmp;
				Via1DoHash(hashbuffer, &pH, tmp, hashkey);
			}
		}
		else {
			for (; i < encStart + 16; i++) {
				Via1DoHash(hashbuffer, &pH, data[i], hashkey);
			}
		}
	}
	Via1Decode(des_data1, prepared_key);
	Via1Decode(des_data2, prepared_key);
	Via1Hash(hashbuffer, hashkey);
	if(memcmp(signature, hashbuffer, 8)) {
		return 6;
	}
	return 0;
}

static int8_t Via26ProcessDw(uint8_t *indata, uint32_t ident, uint8_t desKeyIndex)
{
	uint8_t pv1,pv2, i;
	uint8_t Tmp[8], T1Key[300], P1Key[8], KeyDes1[16], KeyDes2[16], XorKey[8];
	uint32_t ks1[32], ks2[32];

	if(!GetViaKey(T1Key, ident, 'T', 1, 300, 1)) {
		return 2;
	}
	if(!GetViaKey(P1Key, ident, 'P', 1, 8, 1)) {
		return 2;
	}
	if(!GetViaKey(KeyDes1, ident, 'D', 1, 16, 1)) {
		return 2;
	}
	if(!GetViaKey(KeyDes2, ident, '0', desKeyIndex, 16, 1)) {
		return 2;
	}
	if(!GetViaKey(XorKey, ident, 'X', 1, 8, 1)) {
		return 2;
	}

	for (i=0; i<8; i++) {
		pv1 = indata[i];
		Tmp[i] = T1Key[pv1];
	}
	for (i=0; i<8; i++) {
		pv1 = P1Key[i];
		pv2 = Tmp[pv1];
		indata[i]=pv2;
	}
	
	des_set_key(KeyDes1, ks1);
	des(indata, ks1, 1);
	
	for (i=0; i<8; i++) {
		indata[i] ^= XorKey[i];
	}
	
	des_set_key(KeyDes2, ks1);
	des_set_key(KeyDes2+8, ks2);
	des(indata, ks1, 0);
	des(indata, ks2, 1);
	des(indata, ks1, 0);
	
	for (i=0; i<8; i++) {
		indata[i] ^= XorKey[i];
	}
	
	des_set_key(KeyDes1, ks1);
	des(indata, ks1, 0);

	for (i=0; i<8; i++) {
		pv1 = indata[i];
		pv2 = P1Key[i];
		Tmp[pv2] = pv1;
	}
	for (i=0; i<8; i++) {
		pv1 = Tmp[i];
		pv2 = T1Key[pv1];
		indata[i] = pv2;
	}
	return 0;
}

static int8_t Via26Decrypt(uint8_t* source, uint8_t* dw, uint32_t ident, uint8_t desKeyIndex)
{
	uint8_t tmpData[8], C1[8];
	uint8_t *pXorVector;
	int32_t i,j;

	if (ident == 0) {
		return 4;
	}
	if(!GetViaKey(C1, ident, 'C', 1, 8, 1)) {
		return 2;
	}

	for (i=0; i<2; i++) {
		memcpy(tmpData, source+ i*8, 8);
		Via26ProcessDw(tmpData, ident, desKeyIndex);
		if (i!=0) {
			pXorVector = source;
		}
		else {
			pXorVector = &C1[0];
		}
		for (j=0; j<8; j++) {
			dw[i*8+j] = tmpData[j]^pXorVector[j];
		}
	}
	return 0;
}

static void Via3Core(uint8_t *data, uint8_t Off, uint32_t ident, uint8_t* XorKey, uint8_t* T1Key)
{
	uint8_t i;
	uint32_t lR2, lR3, lR4, lR6, lR7;

	switch (ident) {
	case 0x032820: {
		for (i=0; i<4; i++) {
			data[i]^= XorKey[(Off+i) & 0x07];
		}
		lR2 = (data[0]^0xBD)+data[0];
		lR3 = (data[3]^0xEB)+data[3];
		lR2 = (lR2-lR3)^data[2];
		lR3 = ((0x39*data[1])<<2);
		data[4] = (lR2|lR3)+data[2];
		lR3 = ((((data[0]+6)^data[0]) | (data[2]<<1))^0x65)+data[0];
		lR2 = (data[1]^0xED)+data[1];
		lR7 = ((data[3]+0x29)^data[3])*lR2;
		data[5] = lR7+lR3;
		lR2 = ((data[2]^0x33)+data[2]) & 0x0A;
		lR3 = (data[0]+0xAD)^data[0];
		lR3 = lR3+lR2;
		lR2 = data[3]*data[3];
		lR7 = (lR2 | 1) + data[1];
		data[6] = (lR3|lR7)+data[1];
		lR3 = data[1] & 0x07;
		lR2 = (lR3-data[2]) & (data[0] | lR2 |0x01);
		data[7] = lR2+data[3];
		for (i=0; i<4; i++) {
			data[i+4] = T1Key[data[i+4]];
		}
	}
	break;
	case 0x030B00: {
		for (i=0; i<4; i++) {
			data[i]^= XorKey[(Off+i) & 0x07];
		}
		lR6 = (data[3] + 0x6E) ^ data[3];
		lR6 = (lR6*(data[2] << 1)) + 0x17;
		lR3 = (data[1] + 0x77) ^ data[1];
		lR4 = (data[0] + 0xD7) ^ data[0];
		data[4] = ((lR4 & lR3) | lR6) + data[0];
		lR4 = ((data[3] + 0x71) ^ data[3]) ^ 0x90;
		lR6 = (data[1] + 0x1B) ^ data[1];
		lR4 = (lR4*lR6) ^ data[0];
		data[5] = (lR4 ^ (data[2] << 1)) + data[1];
		lR3 = (data[3] * data[3])| 0x01;
		lR4 = (((data[2] ^ 0x35) + data[2]) | lR3) + data[2];
		lR6 = data[1] ^ (data[0] + 0x4A);
		data[6] = lR6 + lR4;
		lR3 = (data[0] * (data[2] << 1)) | data[1];
		lR4 = 0xFE - data[3];
		lR3 = lR4 ^ lR3;
		data[7] = lR3 + data[3];
		for (i=0; i<4; i++) {
			data[4+i] = T1Key[data[4+i]];
		}
	}
	break;
	default:
		break;
	}
}

static void Via3Fct1(uint8_t *data, uint32_t ident, uint8_t* XorKey, uint8_t* T1Key)
{
	uint8_t t;
	Via3Core(data, 0, ident, XorKey, T1Key);

	switch (ident) {
	case 0x032820: {
		t = data[4];
		data[4] = data[7];
		data[7] = t;
	}
	break;
	case 0x030B00: {
		t = data[5];
		data[5] = data[7];
		data[7] = t;
	}
	break;
	default:
		break;
	}
}

static void Via3Fct2(uint8_t *data, uint32_t ident, uint8_t* XorKey, uint8_t* T1Key)
{
	uint8_t t;
	Via3Core(data, 4, ident, XorKey, T1Key);

	switch (ident) {
	case 0x032820: {
		t = data[4];
		data[4] = data[7];
		data[7] = data[5];
		data[5] = data[6];
		data[6] = t;
	}
	break;
	case 0x030B00: {
		t = data[6];
		data[6] = data[7];
		data[7] = t;
	}
	break;
	default:
		break;
	}
}

static int8_t Via3ProcessDw(uint8_t *data, uint32_t ident, uint8_t desKeyIndex)
{
	uint8_t i;
	uint8_t tmp[8], T1Key[300], P1Key[8], KeyDes[16], XorKey[8];
	uint32_t ks1[32], ks2[32];

	if(!GetViaKey(T1Key, ident, 'T', 1, 300, 1)) {
		return 2;
	}
	if(!GetViaKey(P1Key, ident, 'P', 1, 8, 1)) {
		return 2;
	}
	if(!GetViaKey(KeyDes, ident, '0', desKeyIndex, 16, 1)) {
		return 2;
	}
	if(!GetViaKey(XorKey, ident, 'X', 1, 8, 1)) {
		return 2;
	}

	for (i=0; i<4; i++) {
		tmp[i] = data[i+4];
	}
	Via3Fct1(tmp, ident, XorKey, T1Key);
	for (i=0; i<4; i++) {
		tmp[i] = data[i]^tmp[i+4];
	}
	Via3Fct2(tmp, ident, XorKey, T1Key);
	for (i=0; i<4; i++) {
		tmp[i]^= XorKey[i+4];
	}
	for (i=0; i<4; i++) {
		data[i] = data[i+4]^tmp[i+4];
		data[i+4] = tmp[i];
	}
	
	des_set_key(KeyDes, ks1);
	des_set_key(KeyDes+8, ks2);
	
	des(data, ks1, 0);
	des(data, ks2, 1);
	des(data, ks1, 0);
	
	for (i=0; i<4; i++) {
		tmp[i] = data[i+4];
	}
	Via3Fct2(tmp, ident, XorKey, T1Key);
	for (i=0; i<4; i++) {
		tmp[i] = data[i]^tmp[i+4];
	}
	Via3Fct1(tmp, ident, XorKey, T1Key);
	for (i=0; i<4; i++) {
		tmp[i]^= XorKey[i];
	}
	for (i=0; i<4; i++) {
		data[i] = data[i+4]^tmp[i+4];
		data[i+4] = tmp[i];
	}
	return 0;
}

static void Via3FinalMix(uint8_t *dw)
{
	uint8_t tmp[4];

	memcpy(tmp, dw, 4);
	memcpy(dw, dw + 4, 4);
	memcpy(dw + 4, tmp, 4);

	memcpy(tmp, dw + 8, 4);
	memcpy(dw + 8, dw + 12, 4);
	memcpy(dw + 12, tmp, 4);
}

static int8_t Via3Decrypt(uint8_t* source, uint8_t* dw, uint32_t ident, uint8_t desKeyIndex, uint8_t aesKeyIndex, uint8_t aesMode, int8_t doFinalMix)
{
	int8_t aesAfterCore = 0;
	int8_t needsAES = (aesKeyIndex != 0xFF);
	uint8_t tmpData[8], C1[8];
	uint8_t *pXorVector;
	char aesKey[16];
	int32_t i, j;

	if(ident == 0) {
		return 4;
	}
	if(!GetViaKey(C1, ident, 'C', 1, 8, 1)) {
		return 2;
	}
	if(needsAES && !GetViaKey((uint8_t*)aesKey, ident, 'E', aesKeyIndex, 16, 1)) {
		return 2;
	}
	if(aesMode == 0x0D || aesMode == 0x11 || aesMode == 0x15) {
		aesAfterCore = 1;
	}

	if(needsAES && !aesAfterCore) {
		if(aesMode == 0x0F) {
			hdSurEncPhase1_D2_0F_11(source);
			hdSurEncPhase2_D2_0F_11(source);
		}
		else if(aesMode == 0x13) {
			hdSurEncPhase1_D2_13_15(source);
		}
		struct aes_keys aes;
		aes_set_key(&aes, aesKey);
		aes_decrypt(&aes, source, 16);
		if(aesMode == 0x0F) {
			hdSurEncPhase1_D2_0F_11(source);
		}
		else if(aesMode == 0x13) {
			hdSurEncPhase2_D2_13_15(source);
		}
	}

	for(i=0; i<2; i++) {
		memcpy(tmpData, source+i*8, 8);
		Via3ProcessDw(tmpData, ident, desKeyIndex);
		if (i!=0) {
			pXorVector = source;
		}
		else {
			pXorVector = &C1[0];
		}
		for (j=0; j<8; j++) {
			dw[i*8+j] = tmpData[j]^pXorVector[j];
		}
	}

	if(needsAES && aesAfterCore) {
		if(aesMode == 0x11) {
			hdSurEncPhase1_D2_0F_11(dw);
			hdSurEncPhase2_D2_0F_11(dw);
		}
		else if(aesMode == 0x15) {
			hdSurEncPhase1_D2_13_15(dw);
		}
		struct aes_keys aes;
		aes_set_key(&aes, aesKey);
		aes_decrypt(&aes, dw, 16);
		if(aesMode == 0x11) {
			hdSurEncPhase1_D2_0F_11(dw);
		}
		if(aesMode == 0x15) {
			hdSurEncPhase2_D2_13_15(dw);
		}
	}

	if(ident == 0x030B00) {
		if(doFinalMix) {
			Via3FinalMix(dw);
		}
		if (!isValidDCW(dw) || !isValidDCW(dw + 8))
		{
			return 6;
		}
	}
	return 0;
}

int8_t ViaccessECM(uint8_t *ecm, uint8_t *dw)
{
	uint32_t currentIdent = 0;
	uint8_t nanoCmd = 0, nanoLen = 0, version = 0, providerKeyLen = 0, desKeyIndex = 0, aesMode = 0, aesKeyIndex = 0xFF;
	int8_t doFinalMix = 0, result = 1;
	uint16_t i = 0, keySelectPos = 0, ecmLen = GetEcmLen(ecm);

	for (i=4; i+2<ecmLen; ) {
		nanoCmd = ecm[i++];
		nanoLen = ecm[i++];
		if(i+nanoLen > ecmLen) {
			return 1;
		}

		switch (nanoCmd) {
		case 0x40:
			if (nanoLen < 0x03) {
				break;
			}
			version = ecm[i];
			if (nanoLen == 3) {
				currentIdent = ((ecm[i]<<16)|(ecm[i+1]<<8))|(ecm[i+2]&0xF0);
				desKeyIndex  = ecm[i+2]&0x0F;
				keySelectPos = i+3;
			}
			else {
				currentIdent = (ecm[i]<<16)|(ecm[i+1]<<8)|((ecm[i+2]>>4)&0x0F);
				desKeyIndex  = ecm[i+3];
				keySelectPos = i+4;
			}
			providerKeyLen = nanoLen;
			break;
		case 0x90:
			if (nanoLen < 0x03) {
				break;
			}
			version = ecm[i];
			currentIdent = ((ecm[i]<<16)|(ecm[i+1]<<8))|(ecm[i+2]&0xF0);
			desKeyIndex  = ecm[i+2]&0x0F;
			keySelectPos = i+4;
			if((version == 3) && (nanoLen > 3)) {
				desKeyIndex = ecm[i+(nanoLen-4)]&0x0F;
			}
			providerKeyLen = nanoLen;
			break;
		case 0x80:
			nanoLen = 0;
			break;
		case 0xD2:
			if (nanoLen < 0x02) {
				break;
			}
			aesMode = ecm[i];
			aesKeyIndex = ecm[i+1];
			break;
		case 0xDD:
			nanoLen = 0;
			break;
		case 0xEA:
			if (nanoLen < 0x10) {
				break;
			}

			if (version < 2) {
				return Via1Decrypt(ecm, dw, currentIdent, desKeyIndex);
			}
			else if (version == 2) {
				return Via26Decrypt(ecm + i, dw, currentIdent, desKeyIndex);
			}
			else if (version == 3) {
				doFinalMix = 0;
				if (currentIdent == 0x030B00 && providerKeyLen>3) {
					if(keySelectPos+2 >= ecmLen) {
						break;
					}
					if (ecm[keySelectPos] == 0x05 && ecm[keySelectPos+1] == 0x67 && (ecm[keySelectPos+2] == 0x00 || ecm[keySelectPos+2] == 0x01)) {
						if(ecm[keySelectPos+2] == 0x01) {
							doFinalMix = 1;
						}
					}
					else {
						break;
					}
				}
				return Via3Decrypt(ecm + i, dw, currentIdent, desKeyIndex, aesKeyIndex, aesMode, doFinalMix);
			}
			break;
		default:
			break;
		}
		i += nanoLen;
	}
	return result;
}

// Viaccess EMM EMU
int8_t ViaccessEMM(uint8_t *emm, uint32_t *keysAdded)
{
	uint8_t nanoCmd = 0, subNanoCmd = 0, *tmp;
	uint16_t i = 0, j = 0, k = 0, emmLen = GetEcmLen(emm);
	uint8_t ecmKeys[6][16], keyD0[2], emmKey[16], emmXorKey[16], provName[17];
	uint8_t ecmKeyCount = 0, emmKeyIndex = 0, aesMode = 0x0D;
	uint8_t nanoLen = 0, subNanoLen = 0, haveEmmXorKey = 0, haveNewD0 = 0;
	uint32_t ui1, ui2, ui3, ecmKeyIndex[6], provider = 0, ecmProvider = 0;
	char keyName[EMU_MAX_CHAR_KEYNAME], keyValue[36];
	struct aes_keys aes;

	memset(keyD0, 0, 2);
	memset(ecmKeyIndex, 0, sizeof(uint32_t)*6);

	for(i=3; i+2<emmLen; ) {
		nanoCmd = emm[i++];
		nanoLen = emm[i++];
		if(i+nanoLen > emmLen) {
			return 1;
		}

		switch(nanoCmd) {
		case 0x90: {
			if(nanoLen < 3) {
				break;
			}
			ui1 = emm[i+2];
			ui2 = emm[i+1];
			ui3 = emm[i];
			provider = (ui1 | (ui2 << 8) | (ui3 << 16));
			if(provider == 0x00D00040) {
				ecmProvider = 0x030B00;
			}
			else {
				return 1;
			}
			break;
		}
		case 0xD2: {
			if(nanoLen < 2) {
				break;
			}
			emmKeyIndex = emm[i+1];
			break;
		}
		case 0x41: {
			if(nanoLen < 1) {
				break;
			}
			if(!GetViaKey(emmKey, provider, 'M', emmKeyIndex, 16, 1)) {
				return 2;
			}
			memset(provName, 0, 17);
			memset(emmXorKey, 0, 16);
			k = nanoLen < 16 ? nanoLen : 16;
			memcpy(provName, &emm[i], k);
			aes_set_key(&aes, (char*)emmKey);
			aes_decrypt(&aes, emmXorKey, 16);
			for(j=0; j<16; j++) {
				provName[j] ^= emmXorKey[j];
			}
			provName[k] = 0;

			if(strcmp((char*)provName, "TNTSAT") != 0 && strcmp((char*)provName, "TNTSATPRO") != 0
					&&strcmp((char*)provName, "CSAT V") != 0) {
				return 1;
			}
			break;
		}
		case 0xBA: {
			if(nanoLen < 2) {
				break;
			}
			GetViaKey(keyD0, ecmProvider, 'D', 0, 2, 0);
			ui1 = (emm[i] << 8) | emm[i+1];
			if( (uint32_t)((keyD0[0] << 8) | keyD0[1]) < ui1 || (keyD0[0] == 0x00 && keyD0[1] == 0x00)) {
				keyD0[0] = emm[i];
				keyD0[1] = emm[i+1];
				haveNewD0 = 1;
				break;
			}
			return 0;
		}
		case 0xBC: {
			break;
		}
		case 0x43: {
			if(nanoLen < 16) {
				break;
			}
			memcpy(emmXorKey, &emm[i], 16);
			haveEmmXorKey = 1;
			break;
		}
		case 0x44: {
			if(nanoLen < 3) {
				break;
			}
			if (!haveEmmXorKey) {
				memset(emmXorKey, 0, 16);
			}
			tmp = (uint8_t*)malloc(((nanoLen/16)+1)*16*sizeof(uint8_t));
			if(tmp == NULL) {
				return 7;
			}
			memcpy(tmp, &emm[i], nanoLen);
			aes_set_key(&aes, (char*)emmKey);
			for(j=0; j<nanoLen; j+=16) {
				aes_decrypt(&aes, emmXorKey, 16);
				for(k=0; k<16; k++) {
					tmp[j+k] ^= emmXorKey[k];
				}
			}
			memcpy(&emm[i-2], tmp, nanoLen);
			free(tmp);
			nanoLen = 0;
			i -= 2;
			break;
		}
		case 0x68: {
			if(ecmKeyCount > 5) {
				break;
			}
			for(j=i; j+2<i+nanoLen; ) {
				subNanoCmd = emm[j++];
				subNanoLen = emm[j++];
				if(j+subNanoLen > i+nanoLen) {
					break;
				}
				switch(subNanoCmd) {
				case 0xD2: {
					if(nanoLen < 2) {
						break;
					}
					aesMode = emm[j];
					emmKeyIndex = emm[j+1];
					break;
				}
				case 0x01: {
					if(nanoLen < 17) {
						break;
					}
					ecmKeyIndex[ecmKeyCount] = emm[j];
					memcpy(&ecmKeys[ecmKeyCount], &emm[j+1], 16);
					if(!GetViaKey(emmKey, provider, 'M', emmKeyIndex, 16, 1)) {
						break;
					}

					if(aesMode == 0x0F || aesMode == 0x11) {
						hdSurEncPhase1_D2_0F_11(ecmKeys[ecmKeyCount]);
						hdSurEncPhase2_D2_0F_11(ecmKeys[ecmKeyCount]);
					}
					else if(aesMode == 0x13 || aesMode == 0x15) {
						hdSurEncPhase1_D2_13_15(ecmKeys[ecmKeyCount]);
					}
					aes_set_key(&aes, (char*)emmKey);
					aes_decrypt(&aes, ecmKeys[ecmKeyCount], 16);
					if(aesMode == 0x0F || aesMode == 0x11) {
						hdSurEncPhase1_D2_0F_11(ecmKeys[ecmKeyCount]);
					}
					else if(aesMode == 0x13 || aesMode == 0x15) {
						hdSurEncPhase2_D2_13_15(ecmKeys[ecmKeyCount]);
					}

					ecmKeyCount++;
					break;
				}
				default:
					break;
				}
				j += subNanoLen;
			}
			break;
		}
		case 0xF0: {
			if(nanoLen != 4) {
				break;
			}
			ui1 = ((emm[i+2] << 8) | (emm[i+1] << 16) | (emm[i] << 24) | emm[i+3]);
			if(fletcher_crc32(emm + 3, emmLen - 11) != ui1) {
				return 4;
			}

			if(haveNewD0) {
				
				SAFE_MUTEX_LOCK(&emu_key_data_mutex);
				SetKey('V', ecmProvider, "D0", keyD0, 2, 1, NULL, NULL);
				
				for(j=0; j<ecmKeyCount; j++) {
					
					snprintf(keyName, EMU_MAX_CHAR_KEYNAME, "E%X", ecmKeyIndex[j]);
					SetKey('V', ecmProvider, keyName, ecmKeys[j], 16, 1, NULL, NULL);
					
					(*keysAdded)++;
					cs_hexdump(0, ecmKeys[j], 16, keyValue, sizeof(keyValue));
					cs_log("Key found in EMM: V %06X %s %s", ecmProvider, keyName, keyValue);
				}

				SAFE_MUTEX_UNLOCK(&emu_key_data_mutex);
			}
			break;
		}
		default:
			break;
		}
		i += nanoLen;
	}
	return 0;
}

#endif // WITH_EMU
