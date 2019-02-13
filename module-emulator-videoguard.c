#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/md5.h"
#include "module-emulator-osemu.h"

// VideoGuard (aka NDS) emulator

static const uint8_t nds_const[] =
{
	0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
	0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0
};

uint8_t viasat_const[] =
{
	0x15, 0x85, 0xC5, 0xE4, 0xB8, 0x52, 0xEC, 0xF7,
	0xC3, 0xD9, 0x08, 0xBA, 0x22, 0x4A, 0x66, 0xF2,
	0x82, 0x15, 0x4F, 0xB2, 0x18, 0x48, 0x63, 0x97,
	0xDC, 0x19, 0xD8, 0x51, 0x9A, 0x39, 0xFC, 0xCA,
	0x1C, 0x24, 0xD0, 0x65, 0xA9, 0x66, 0x2D, 0xD6,
	0x53, 0x3B, 0x86, 0xBA, 0x40, 0xEA, 0x4C, 0x6D,
	0xD9, 0x1E, 0x41, 0x14, 0xFE, 0x15, 0xAF, 0xC3,
	0x18, 0xC5, 0xF8, 0xA7, 0xA8, 0x01, 0x00, 0x01
};

int8_t videoguard_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw)
{
	int32_t i;
	uint8_t *tDW, irdEcmLen, offsetCw = 0, offsetP2 = 0;
	uint8_t digest[16], md5_const[64];
	uint16_t ecmLen = get_ecm_len(ecm);
	MD5_CTX mdContext;

	if (ecmLen < 7)
	{
		return 1;
	}

	if (ecm[3] != 0x00 || ecm[4] != 0x00 || ecm[5] != 0x01)
	{
		return 1;
	}

	irdEcmLen = ecm[6];

	if (irdEcmLen < (10 + 3 + 8 + 4) || irdEcmLen + 6 >= ecmLen)
	{
		return 1;
	}

	for (i = 0; 10 + i + 2 < irdEcmLen; i++)
	{
		if (ecm[17 + i] == 0x0F && ecm[17 + i + 1] == 0x40 && ecm[17 + i + 2] == 0x00)
		{
			offsetCw = 17 + i + 3;
			offsetP2 = offsetCw + 9;
		}
	}

	if (offsetCw == 0 || offsetP2 == 0)
	{
		return 1;
	}

	if (offsetP2 - 7 + 4 > irdEcmLen)
	{
		return 1;
	}

	if (caid == 0x090F || caid == 0x093E)
	{
		memcpy(md5_const, viasat_const, 64);
	}
	else if (!emu_find_key('S', caid, 0, "00", md5_const, 64, 1, 0, 0, NULL))
	{
		return 2;
	}

	memset(dw,0,16);
	tDW = &dw[ecm[0] == 0x81 ? 8 : 0];

	MD5_Init(&mdContext);
	MD5_Update(&mdContext, ecm + 7, 10);
	MD5_Update(&mdContext, ecm + offsetP2, 4);
	MD5_Update(&mdContext, md5_const, 64);
	MD5_Update(&mdContext, nds_const, 16);
	MD5_Final(digest, &mdContext);

	for (i = 0; i < 8; i++)
	{
		tDW[i] = digest[i + 8] ^ ecm[offsetCw + i];
	}

	if (!is_valid_dcw(tDW))
	{
		return 6;
	}

	return 0;
}

#endif // WITH_EMU
