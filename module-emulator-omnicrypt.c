#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "module-emulator-osemu.h"
#include "module-emulator-omnicrypt.h"
#include "oscam-aes.h"
#include "oscam-string.h"


static inline int8_t get_ecm_key(uint16_t provider, uint8_t parity, uint8_t *key)
{
	return emu_find_key('O', provider, 0, parity == 0 ? "00" : "01", key, 16, 1, 0, 0, NULL);
}

int8_t omnicrypt_ecm(uint8_t *ecm, uint8_t *dw)
{
	uint8_t section_syntax_indicator, session_key[16], session_key_parity, position;
	uint16_t private_section_length, session_key_id, payload_length;
	struct aes_keys aes;

	section_syntax_indicator = ecm[1] >> 7;
	if (section_syntax_indicator != 0) // The private_data_bytes immediately follow the private_section_length field
	{
		cs_log("ECM section syntax indicator %d not supported", section_syntax_indicator);
		return EMU_NOT_SUPPORTED;
	}

	private_section_length = b2i(2, ecm + 1) & 0x0FFF;
	if (private_section_length != 0x2D)
	{
		cs_log("ECM has an unsupported private section length of %d", private_section_length);
		return EMU_NOT_SUPPORTED;
	}

	session_key_parity = ecm[3] & 0x01;
	session_key_id = b2i(2, ecm + 4);

	if (!get_ecm_key(session_key_id, session_key_parity, session_key))
	{
		return EMU_KEY_NOT_FOUND;
	}
	aes_set_key(&aes, (char *)session_key);

	payload_length = b2i(2, ecm + 6) & 0x0FFF;
	if (payload_length != 0x28)
	{
		cs_log("ECM has an unsupported payload length of %d", payload_length);
		return EMU_NOT_SUPPORTED;
	}

	for (position = 8; position + 1 < payload_length; position += 4 + 16) // Run twice for odd, even CW
	{
		uint8_t parity = ecm[position + 1] & 0x01;
		uint8_t length = ecm[position + 3];

		if (length != 16)
		{
			cs_log("CW %d has an unsupported length of %d", parity, length);
			return EMU_NOT_SUPPORTED;
		}

		aes_decrypt(&aes, ecm + position + 4, 16);
		memcpy(dw + parity * 8, ecm + position + 4, 8); // Copy the first 8 bytes (rest are zeros)
	}

	return EMU_OK;
}

#endif // WITH_EMU
