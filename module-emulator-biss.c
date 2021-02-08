#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "module-emulator-osemu.h"
#include "module-emulator-biss.h"
#include "oscam-aes.h"
#include "oscam-string.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
//#include <openssl/rsa.h>
#include <openssl/x509.h>

// DVB-CISSA v1 IV as defined in ETSI TS 103 127
static const uint8_t dvb_cissa_iv[16] =
{
	0x44, 0x56, 0x42, 0x54, 0x4D, 0x43, 0x50, 0x54,
	0x41, 0x45, 0x53, 0x43, 0x49, 0x53, 0x53, 0x41
};

static void unify_orbitals(uint32_t *namespace)
{
	// Unify orbitals to produce same namespace among users
	// Set positions according to http://satellites-xml.org

	uint16_t pos = (*namespace & 0x0FFF0000) >> 16;

	switch (pos)
	{
		case 29: // Rascom QAF 1R
		case 31: // Eutelsat 3B
		{
			pos = 30;
			break;
		}

		case 49:
		case 50: // SES 5
		{
			pos = 48; // Astra 4A
			break;
		}

		case 215:
		{
			pos = 216; // Eutelsat 21B
			break;
		}

		case 285: // Astra 2E
		{
			pos = 282; // Astra 2F/2G
			break;
		}

		case 328: // Intelsat 28
		case 329:
		case 331: // Eutelsat 33C
		{
			pos = 330;
			break;
		}

		case 359: // Eutelsat 36B
		case 361: // Express AMU1
		{
			pos = 360;
			break;
		}

		case 451: // Intelsat 904
		{
			pos = 450; // Intelsat 12
			break;
		}

		case 550:
		case 551: // G-Sat 8/16
		{
			pos = 549; // Yamal 402
			break;
		}

		case 748:
		case 749: // ABS 2A
		{
			pos = 750;
			break;
		}

		case 848: // Horizons 2
		case 852: // Intelsat 15
		{
			pos = 850;
			break;
		}

		case 914: // Mesasat 3a
		{
			pos = 915; // Mesasat 3/3b
			break;
		}

		case 934: // G-Sat 17
		case 936: // Insat 4B
		{
			pos = 935; // G-Sat 15
			break;
		}

		case 3600 - 911: // Nimiq 6
		{
			pos = 3600 - 910; // Galaxy 17
			break;
		}

		case 3600 - 870: // SES 2
		case 3600 - 872: // TKSat 1
		{
			pos = 3600 - 871;
			break;
		}

		case 3600 - 432: // Sky Brasil 1
		case 3600 - 430: // Intelsat 11
		{
			pos = 3600 - 431;
			break;
		}

		case 3600 - 376: // Telstar 11N
		case 3600 - 374: // NSS 10
		{
			pos = 3600 - 375;
			break;
		}

		case 3600 - 359: // Hispasat 36W-1
		{
			pos = 3600 - 360; // Eutelsat 36 West A
			break;
		}

		case 3600 - 81: // Eutelsat 8 West B
		{
			pos = 3600 - 80;
			break;
		}

		case 3600 - 73: // Eutelsat 7 West A
		case 3600 - 72:
		case 3600 - 71:
		{
			pos = 3600 - 70; // Nilesat 201
			break;
		}

		case 3600 - 10: // Intelsat 10-02
		case 3600 - 9: // Thor 6
		case 3600 - 7: // Thor 7
		case 3600 - 6: // Thor 7
		{
			pos = 3600 - 8; // Thor 5
			break;
		}
	}

	*namespace = (*namespace & 0xF000FFFF) | (pos << 16);
}

static void annotate(char *buf, uint8_t len, const uint8_t *ecm, uint16_t ecmLen,
						uint32_t hash, int8_t isNamespaceHash, int8_t datecoded)
{
	// Extract useful information to append to the "Example key ..." message.
	//
	// For feeds, the orbital position & frequency are usually embedded in the namespace.
	// See https://github.com/OpenPLi/enigma2/blob/develop/lib/dvb/frontend.cpp#L476
	// hash = (sat.orbital_position << 16);
	// hash |= ((sat.frequency/1000)&0xFFFF)|((sat.polarisation&1) << 15);
	//
	// If the onid & tsid appear to be a unique DVB identifier, enigma2 strips the frequency
	// from our namespace. See https://github.com/OpenPLi/enigma2/blob/develop/lib/dvb/scan.cpp#L55
	// In that case, our annotation contains the onid:tsid:sid triplet in lieu of frequency.
	//
	// For the universal case, we print the number of elementary stream pids & pmtpid.
	// The sid and current time are included for all. Examples:
	//
	// F 1A2B3C4D 00000000 XXXXXXXXXXXXXXXX ; 110.5W 12345H sid:0001 added: 2017-10-17 @ 13:14:15 // namespace
	// F 1A2B3C4D 20180123 XXXXXXXXXXXXXXXX ;  33.5E  ABCD:9876:1234 added: 2017-10-17 @ 13:14:15 // stripped namespace
	// F 1A2B3C4D 20180123 XXXXXXXXXXXXXXXX ; av:5 pmt:0134 sid:0001 added: 2017-10-17 @ 13:14:15 // universal

	uint8_t pidcount;
	uint16_t frequency, degrees, pmtpid, srvid, tsid, onid;
	uint32_t ens;
	char compass, polarisation, timeStr1[9], timeStr2[19];

	if (datecoded)
	{
		date_to_str(timeStr1, sizeof(timeStr1), 4, 3);
	}
	else
	{
		snprintf(timeStr1, sizeof(timeStr1), "00000000");
	}

	date_to_str(timeStr2, sizeof(timeStr2), 0, 2);

	if (isNamespaceHash) // Namespace hash
	{
		ens = b2i(4, ecm + ecmLen - 4); // Namespace will be the last 4 bytes of the ecm
		degrees = (ens >> 16) & 0x0FFF; // Remove not-a-pid flag

		if (degrees > 1800)
		{
			degrees = 3600 - degrees;
			compass = 'W';
		}
		else
		{
			compass = 'E';
		}

		if (0 == (ens & 0xFFFF)) // Stripped namespace hash
		{
			srvid = b2i(2, ecm + 3);
			tsid = b2i(2, ecm + ecmLen - 8);
			onid = b2i(2, ecm + ecmLen - 6);
			// Printing degree sign "\u00B0" requires c99 standard
			snprintf(buf, len, "F %08X %s XXXXXXXXXXXXXXXX ; %5.1f%c  %04X:%04X:%04X added: %s",
								hash, timeStr1, degrees / 10.0, compass, onid, tsid, srvid, timeStr2);
		}
		else // Full namespace hash
		{
			srvid = b2i(2, ecm + 3);
			frequency = ens & 0x7FFF; // Remove polarity bit
			polarisation = ens & 0x8000 ? 'V' : 'H';
			// Printing degree sign "\u00B0" requires c99 standard
			snprintf(buf, len, "F %08X %s XXXXXXXXXXXXXXXX ; %5.1f%c %5d%c sid:%04X added: %s",
								hash, timeStr1, degrees / 10.0, compass, frequency, polarisation, srvid, timeStr2);
		}
	}
	else // Universal hash
	{
		srvid = b2i(2, ecm + 3);
		pmtpid = b2i(2, ecm + 5);
		pidcount = (ecmLen - 15) / 2; // video + audio pids count
		snprintf(buf, len, "F %08X %s XXXXXXXXXXXXXXXX ; av:%d pmt:%04X sid:%04X added: %s",
							hash, timeStr1, pidcount, pmtpid, srvid, timeStr2);
	}
}

static int8_t is_common_hash(uint32_t hash)
{
	// Check universal hash against a number of commnon universal
	// hashes in order to warn users about potential key clashes

	switch (hash)
	{
		case 0xBAFCD9FD: // 0001 0020 0200 1010 1020 (most common hash)
			return 1;
		case 0xA6A4FBD4: // 0001 0800 0200 1010 1020
			return 1;
		case 0xEFAB7A4D: // 0001 0800 1010 1020 0200
			return 1;
		case 0x83FA15D1: // 0001 0020 0134 0100 0101
			return 1;
		case 0x58934C38: // 0001 0800 1010 1020 1030 0200
			return 1;
		case 0x2C3CEC17: // 0001 0020 0134 0100
			return 1;
		case 0x73DF7F7E: // 0001 0020 0200 1010 1020 1030
			return 1;
		case 0xAFA85BC8: // 0001 0020 0021 0022 0023
			return 1;
		case 0x8C51F31D: // 0001 0800 0200 1010 1020 1030 1040
			return 1;
		case 0xE2F9BD29: // 0001 0800 0200 1010 1020 1030
			return 1;
		case 0xB9EBE0FF: // 0001 0100 0200 1010 1020 (less common hash)
			return 1;
		default:
			return 0;
	}
}

static int8_t is_valid_namespace(uint32_t namespace)
{
	// Note to developers:
	// If we ever have a satellite at 0.0E, edit to allow stripped namespace
	// '0xA0000000' with an additional test on tsid and onid being != 0

	uint16_t orbital, frequency;

	orbital = (namespace >> 16) & 0x0FFF;
	frequency = namespace & 0x7FFF;

	if ((namespace & 0xF0000000) != 0xA0000000) return 0;   // Value isn't flagged as namespace
	if ((namespace & 0x0FFFFFFF) == 0x00000000) return 0;   // Empty namespace
	if (orbital > 3599) return 0;                           // Allow only DVB-S
	if (frequency == 0) return 1;                           // Stripped namespace
	if (frequency >= 3400 && frequency <= 4200) return 1;   // Super extended C band
	if (frequency >= 10700 && frequency <= 12750) return 1; // Ku band Europe

	return 0;
}

static int8_t get_sw(uint32_t provider, uint8_t *sw, uint8_t sw_length, int8_t dateCoded, int8_t printMsg)
{
	// If date-coded keys are enabled in the webif, this function evaluates the expiration date
	// of the found keys. Expired keys are not sent to the calling function. If date-coded keys
	// are disabled, then every key is sent without any evaluation. It takes the "provider" as
	// input and outputs the "sw". Returns 0 (key not found, or expired) or 1 (key found).

	// printMsg: 0 => No message
	// printMsg: 1 => Print message only if key is found
	// printMsg: 2 => Always print message, regardless if key is found or not

	char keyExpDate[9] = "00000000";

	if (emu_find_key('F', provider, 0, keyExpDate, sw, sw_length, 0, 0, 0, NULL)) // Key found
	{
		if (dateCoded) // Date-coded keys are enabled, evaluate expiration date
		{
			char currentDate[9];
			date_to_str(currentDate, sizeof(currentDate), 0, 3);

			if (strncmp("00000000", keyExpDate, 9) == 0 || strncmp(currentDate, keyExpDate, 9) < 0) // Evergreen or not expired
			{
				if (printMsg == 1 || printMsg == 2) cs_log("Key found: F %08X %s", provider, keyExpDate);
				return 1;
			}
			else // Key expired
			{
				sw = NULL; // Make sure we don't send any expired key
				if (printMsg == 2) cs_log("Key expired: F %08X %s", provider, keyExpDate);
				return 0;
			}
		}
		else // Date-coded keys are disabled, don't evaluate expiration date
		{
			if (printMsg == 1 || printMsg == 2) cs_log("Key found: F %08X %s", provider, keyExpDate);
			return 1;
		}
	}
	else // Key not found
	{
		if (printMsg == 2) cs_log("Key not found: F %08X", provider);
		return 0;
	}
}

static int8_t biss_mode1_ecm(struct s_reader *rdr, const uint8_t *ecm, uint16_t caid, uint16_t ecm_pid, uint8_t *dw, EXTENDED_CW *cw_ex)
{
	// Oscam's fake ecm consists of [sid] [pmtpid] [pid1] [pid2] ... [pidx] [tsid] [onid] [ens]
	// On enigma boxes tsid, onid and namespace should be non zero, while on non-enigma
	// boxes they are usually all zero. The top 4 bits of the namespace are flagged with 0xA.

	// The emulator creates a unique channel hash using srvid and enigma namespace or
	// srvid, tsid, onid and namespace (in case of namespace without frequency) and
	// another weaker (not unique) hash based on every pid of the channel. This universal
	// hash should be available on all types of stbs (enigma and non-enigma).

	// Key searches are made from highest priority (tightest test first) to lowest priority
	// (loosest test last):
	// 1. Namespace hash (only on enigma boxes)
	// 2. Universal hash (all box types with emu r752+)
	// 3. Valid tsid, onid combination
	// 4. Reverse order pid (audio, video, pmt)
	// 5. Legacy srvid, ecm pid combination
	// 6. Default "All Feeds" key

	// If enabled in the webif, a date based key search is performed. If the expiration
	// date has passed, the key is not sent back from get_sw(). This option is used only
	// in the namespace hash, universal hash and the "All Feeds" search methods.

	uint32_t i, ens = 0, hash = 0;
	uint16_t srvid, tsid = 0, onid = 0, pid, ecm_len = SCT_LEN(ecm);
	uint8_t *sw, sw_length, ecm_copy[ecm_len];
	char tmp_buffer1[33], tmp_buffer2[90] = "0", tmp_buffer3[90] = "0";

	if (caid == 0x2602 && cw_ex != NULL) // BISS2
	{
		cw_ex->mode = CW_MODE_ONE_CW;
		cw_ex->algo = CW_ALGO_AES128;
		cw_ex->algo_mode = CW_ALGO_MODE_CBC;
		memcpy(cw_ex->data, dvb_cissa_iv, 16);

		sw = cw_ex->session_word;
		sw_length = 16;
	}
	else // BISS1
	{
		sw = dw;
		sw_length = 8;
	}

	srvid = b2i(2, ecm + 3);

	if (ecm_len >= 17) // Likely an r752+ extended ecm
	{
		tsid = b2i(2, ecm + ecm_len - 8);
		onid = b2i(2, ecm + ecm_len - 6);
		ens = b2i(4, ecm + ecm_len - 4);
	}

	// 1. Namespace hash (enigma only)
	if (is_valid_namespace(ens))
	{
		unify_orbitals(&ens);
		memcpy(ecm_copy, ecm, ecm_len);
		i2b_buf(4, ens, ecm_copy + ecm_len - 4);

		for (i = 0; i < 5; i++) // Find key matching hash made with frequency modified to: f+0, then f-1, f+1, f-2, lastly f+2
		{
			ecm_copy[ecm_len - 1] = (i & 1) ? ecm_copy[ecm_len - 1] - i : ecm_copy[ecm_len - 1] + i; // frequency +/- 1, 2 MHz

			if (0 != (ens & 0xFFFF)) // Full namespace - Calculate hash with srvid and namespace only
			{
				i2b_buf(2, srvid, ecm_copy + ecm_len - 6); // Put [srvid] right before [ens]
				hash = crc32(caid, ecm_copy + ecm_len - 6, 6);
			}
			else // Namespace without frequency - Calculate hash with srvid, tsid, onid and namespace
			{
				i2b_buf(2, srvid, ecm_copy + ecm_len - 10); // Put [srvid] right before [tsid] [onid] [ens] sequence
				hash = crc32(caid, ecm_copy + ecm_len - 10, 10);
			}

			if (get_sw(hash, sw, sw_length, rdr->emu_datecodedenabled, i == 0 ? 2 : 1)) // Do not print "key not found" for frequency off by 1, 2
			{
				memcpy(sw + sw_length, sw, sw_length);
				return EMU_OK;
			}

			if (i == 0) // No key found matching our hash: create example SoftCam.Key BISS line for the live log
			{
				annotate(tmp_buffer2, sizeof(tmp_buffer2), ecm_copy, ecm_len, hash, 1, rdr->emu_datecodedenabled);
			}

			if (0 == (ens & 0xFFFF)) // Namespace without frequency - Do not iterate
			{
				break;
			}
		}
	}

	// 2. Universal hash (in r752+ style ecms that contain pmt pid)
	if ((ens & 0xF0000000) == 0xA0000000)
	{
		hash = crc32(caid, ecm + 3, ecm_len - 3 - 8); // Do not include [tsid] [onid] [ens] in the hash

		if (get_sw(hash, sw, sw_length, rdr->emu_datecodedenabled, 2))
		{
			memcpy(sw + sw_length, sw, sw_length);
			return EMU_OK;
		}

		// No key found matching our hash: create example SoftCam.Key BISS line for the live log
		annotate(tmp_buffer3, sizeof(tmp_buffer3), ecm_copy, ecm_len, hash, 0, rdr->emu_datecodedenabled);
	}

	// 3. Valid [tsid] [onid] combination (per enigma2)
	if (onid != 0 && (onid != 1 || tsid >= 2) && onid < 0xFF00)
	{
		if (get_sw(tsid << 16 | onid, sw, sw_length, 0, 2))
		{
			memcpy(sw + sw_length, sw, sw_length);
			return EMU_OK;
		}
	}

	// 4. Reverse order pid search
	// (better identifies channels with variable counts of audio pids)
	// Strip [tsid] [onid] [ens] on r752+ ecms to be compatible with older versions)
	if ((ens & 0xF0000000) == 0xA0000000)
	{
		ecm_len -= 8;
	}

	for (i = ecm_len - 2; i >= 5; i -= 2)
	{
		pid = b2i(2, ecm + i);

		if (get_sw((srvid << 16) | pid, sw, sw_length, 0, 2))
		{
			memcpy(sw + sw_length, sw, sw_length);
			return EMU_OK;
		}
	}

	// 5. Legacy [srvid] [ecm pid] combination
	if (get_sw((srvid << 16) | ecm_pid, sw, sw_length, 0, 2))
	{
		memcpy(sw + sw_length, sw, sw_length);
		return EMU_OK;
	}

	// 6. Default BISS key for events with many feeds sharing the same session word
	// (limited to local ecms, network ecms with ecm pid equal to zero are blocked)
	if (ecm_pid != 0 && get_sw(0xA11FEED5, sw, sw_length, rdr->emu_datecodedenabled, 2))
	{
		memcpy(sw + sw_length, sw, sw_length);
		cs_hexdump(0, sw, sw_length, tmp_buffer1, sizeof(tmp_buffer1));
		cs_log("No specific match found. Using 'All Feeds' key: %s", tmp_buffer1);
		return EMU_OK;
	}

	// Print example key lines for available hash search methods, if no key is found
	if (strncmp(tmp_buffer2, "0", 2)) cs_log("Example key based on namespace hash: %s", tmp_buffer2);
	if (strncmp(tmp_buffer3, "0", 2)) cs_log("Example key based on universal hash: %s", tmp_buffer3);

	// Check if universal hash is common and warn user
	if (is_common_hash(hash)) cs_log("Feed has commonly used pids, universal hash clashes in SoftCam.Key are likely!");

	return EMU_KEY_NOT_FOUND;
}

static inline int8_t get_ecm_key(uint16_t onid, uint16_t esid, uint8_t parity, uint8_t *key)
{
	return emu_find_key('G', onid << 16 | esid, 0, parity == 0 ? "00" : "01", key, 16, 1, 0, 0, NULL);
}

static int8_t biss2_mode_ca_ecm(const uint8_t *ecm, EXTENDED_CW *cw_ex)
{
	uint8_t ecm_cipher_type, session_key_parity;
	uint8_t session_key[16], iv[16];
	uint16_t entitlement_session_id, original_network_id, descriptor_length;
	uint16_t position, ecm_length = SCT_LEN(ecm);
	uint32_t payload_checksum, calculated_checksum;
	char tmp_buffer[64];
	struct aes_keys aes;

	// Calculate crc32 checksum and compare against the checksum bytes of the ECM
	payload_checksum = b2i(4, ecm + ecm_length - 4);
	calculated_checksum = ccitt32_crc((uint8_t *)ecm, ecm_length - 4);

	if (payload_checksum != calculated_checksum)
	{
		cs_log_dbg(D_TRACE, "ECM checksum mismatch (payload: %08X vs calculated: %08X",
					payload_checksum, calculated_checksum);
		return EMU_CHECKSUM_ERROR;
	}

	// Unique identifiers of the session key
	entitlement_session_id = b2i(2, ecm + 3);
	original_network_id = b2i(2, ecm + 8);

	ecm_cipher_type = ecm[10] >> 5;
	if (ecm_cipher_type != 0) // Session words shall be encrypted with AES_128_CBC
	{
		cs_log("ECM cipher type %d not supported", ecm_cipher_type);
		return EMU_NOT_SUPPORTED;
	}

	descriptor_length = b2i(2, ecm + 10) & 0x0FFF;
	position = 12 + descriptor_length;

	session_key_parity = ecm[position] >> 7; // Parity can be "00" or "01"
	position++;

	if (!get_ecm_key(original_network_id, entitlement_session_id, session_key_parity, session_key))
	{
		return EMU_KEY_NOT_FOUND;
	}

	memcpy(iv, ecm + position, 16);                            // "AES_128_CBC_enc_session_word_iv"
	memcpy(cw_ex->session_word, ecm + position + 16, 16);      // "AES_128_CBC_enc_session_word_0"
	memcpy(cw_ex->session_word + 16, ecm + position + 32, 16); // "AES_128_CBC_enc_session_word_1"

	// Delete these cs_log calls when everything is confirmed to work correctly
	cs_hexdump(3, iv, 16, tmp_buffer, sizeof(tmp_buffer));
	cs_log_dbg(D_TRACE, "session_word_iv: %s", tmp_buffer);

	cs_hexdump(3, cw_ex->session_word, 16, tmp_buffer, sizeof(tmp_buffer));
	cs_log_dbg(D_TRACE, "encrypted session_word_0: %s", tmp_buffer);

	cs_hexdump(3, cw_ex->session_word + 16, 16, tmp_buffer, sizeof(tmp_buffer));
	cs_log_dbg(D_TRACE, "encrypted session_word_1: %s", tmp_buffer);

	// Decrypt session words
	aes_set_key(&aes, (char *)session_key);
	aes_cbc_decrypt(&aes, cw_ex->session_word, 16, iv);
	memcpy(iv, ecm + position, 16); // Set iv again to the correct one
	aes_cbc_decrypt(&aes, cw_ex->session_word + 16, 16, iv);

	// Delete these cs_log calls when everything is confirmed to work correctly
	cs_hexdump(3, cw_ex->session_word, 16, tmp_buffer, sizeof(tmp_buffer));
	cs_log_dbg(D_TRACE, "decrypted session_word_0: %s", tmp_buffer);

	cs_hexdump(3, cw_ex->session_word + 16, 16, tmp_buffer, sizeof(tmp_buffer));
	cs_log_dbg(D_TRACE, "decrypted session_word_1: %s", tmp_buffer);

	cw_ex->mode = CW_MODE_ONE_CW;
	cw_ex->algo = CW_ALGO_AES128;
	cw_ex->algo_mode = CW_ALGO_MODE_CBC;
	memcpy(cw_ex->data, dvb_cissa_iv, 16);

	return EMU_OK;
}

int8_t biss_ecm(struct s_reader *rdr, const uint8_t *ecm, uint16_t caid, uint16_t ecm_pid, uint8_t *dw, EXTENDED_CW *cw_ex)
{
	switch (caid)
	{
		case 0x2600:
			return biss_mode1_ecm(rdr, ecm, caid, ecm_pid, dw, NULL);

		case 0x2602:
			return biss_mode1_ecm(rdr, ecm, caid, ecm_pid, NULL, cw_ex);

		case 0x2610:
			return biss2_mode_ca_ecm(ecm, cw_ex);

		default:
			cs_log("Unknown Biss caid %04X - Please report!", caid);
			return EMU_NOT_SUPPORTED;
	}
}

static uint16_t parse_session_data_descriptor(const uint8_t *data, uint16_t esid, uint16_t onid, uint32_t *keysAdded)
{
	uint8_t descriptor_tag = data[0];
	uint8_t descriptor_length = data[1];

	switch (descriptor_tag)
	{
		case 0x81: // session_key_descriptor
		{
			uint8_t session_key_type = data[2] >> 1;
			if (session_key_type == 0) // AES-128
			{
				uint8_t session_key_parity = data[2] & 0x01;
				uint8_t session_key_data[16];
				memcpy(session_key_data, data + 3, 16); // This is the ECM key

				SAFE_MUTEX_LOCK(&emu_key_data_mutex);
				if (emu_update_key('G', onid << 16 | esid, session_key_parity ? "01" : "00", session_key_data, 16, 1, NULL))
				{
					(*keysAdded)++;
					char tmp[33];
					cs_hexdump(0, session_key_data, 16, tmp, sizeof(tmp));
					cs_log("Key found in EMM: G %08X %02d %s", onid << 16 | esid, session_key_parity, tmp);
				}
				SAFE_MUTEX_UNLOCK(&emu_key_data_mutex);
			}
			break;
		}

		case 0x82: // entitlement_flags_descriptor
			break;

		default:
			break;
	}

	return 2 + descriptor_length;
}

static int8_t parse_session_data(const uint8_t *data, RSA *key, uint16_t esid, uint16_t onid, uint32_t *keysAdded)
{
	// session_data is encrypted with RSA 2048 bit OAEP
	// Maximum size of decrypted session_data is less than (256-41) bytes
	uint8_t session_data[214];

	if (RSA_private_decrypt(256, data, session_data, key, RSA_PKCS1_OAEP_PADDING) > 0)
	{
		uint16_t pos = 0;
		uint16_t descriptor_length = b2i(2, session_data) & 0x0FFF;

		while (pos < descriptor_length)
		{
			pos += parse_session_data_descriptor(session_data + 2 + pos, esid, onid, keysAdded);
		}

		return EMU_OK;
	}

	return EMU_NOT_SUPPORTED; // Decryption failed for whatever reason
}

static int8_t get_rsa_key(struct s_reader *rdr, const uint8_t *ekid, RSA **key)
{
	LL_ITER itr;
	biss2_rsa_key_t *data;

	itr = ll_iter_create(rdr->ll_biss2_rsa_keys);
	while ((data = ll_iter_next(&itr)))
	{
		if (data->ekid == ekid)
		{
			*key = data->key;
			return 1;
		}
	}

	return 0;
}

int8_t biss_emm(struct s_reader *rdr, const uint8_t *emm, uint32_t *keysAdded)
{
	uint8_t emm_cipher_type, entitlement_priv_data_loop, entitlement_key_id[8];
	uint16_t entitlement_session_id, original_network_id, descriptor_length;
	uint16_t pos, emm_length = SCT_LEN(emm);
	uint32_t payload_checksum, calculated_checksum;
	int8_t result = EMU_NOT_SUPPORTED;
	char tmp[17];
	RSA *key;

	// Calculate crc32 checksum and compare against the checksum bytes of the EMM
	payload_checksum = b2i(4, emm + emm_length - 4);
	calculated_checksum = ccitt32_crc((uint8_t *)emm, emm_length - 4);

	if (payload_checksum != calculated_checksum)
	{
		cs_log_dbg(D_TRACE, "EMM checksum mismatch (payload: %08X vs calculated: %08X",
					payload_checksum, calculated_checksum);
		return EMU_CHECKSUM_ERROR;
	}

	// Identifiers of the session key carried in the EMM
	// We just pass them to the "parse_session_data()" function
	entitlement_session_id = b2i(2, emm + 3);
	original_network_id = b2i(2, emm + 8);
	cs_log_dbg(D_TRACE, "onid: %04X, esid: %04X", original_network_id, entitlement_session_id);

	emm_cipher_type = emm[11] >> 5; // top 3 bits;
	entitlement_priv_data_loop = (emm[11] >> 4) & 0x01; // 4th bit

	if (emm_cipher_type != 0) // EMM payload is not encrypted with RSA_2048_OAEP
	{
		cs_log_dbg(D_TRACE, "EMM cipher type %d not supported", emm_cipher_type);
		return EMU_NOT_SUPPORTED;
	}

	descriptor_length = b2i(2, emm + 12) & 0x0FFF;
	pos = 14 + descriptor_length;

	while (pos < emm_length - 4)
	{
		// Unique identifier of the public rsa key used for "session_data" encryption
		memcpy(entitlement_key_id, emm + pos, 8);
		pos += 8;

		if (get_rsa_key(rdr, entitlement_key_id, &key)) // Key found
		{
			cs_hexdump(0, entitlement_key_id, 8, tmp, sizeof(tmp));
			cs_log_dbg(D_TRACE, "RSA key found (ekid: %s)", tmp);

			// Parse "encrypted_session_data"
			result = parse_session_data(emm + pos, key, entitlement_session_id, original_network_id, keysAdded);
			if (result == EMU_OK)
			{
				break; // No need to decrypt again with another key
			}
		}
		else // Multiple ekid's can be present in the EMM - Do not exit just yet
		{
			cs_hexdump(0, entitlement_key_id, 8, tmp, sizeof(tmp));
			cs_log_dbg(D_TRACE, "RSA key not found (ekid: %s)", tmp);

			result = EMU_KEY_NOT_FOUND;
		}

		pos += 256; // 2048 bits

		if (entitlement_priv_data_loop) // Skip any remaining bytes
		{
			pos += 2 + (b2i(2, emm + pos) & 0x0FFF);
		}
	}

	return result;
}

static int8_t rsa_key_exists(struct s_reader *rdr, const biss2_rsa_key_t *item)
{
	LL_ITER itr;
	biss2_rsa_key_t *data;

	itr = ll_iter_create(rdr->ll_biss2_rsa_keys);
	while ((data = ll_iter_next(&itr)))
	{
		if (data->ekid == item->ekid)
		{
			return 1;
		}
	}

	return 0;
}

uint16_t biss_read_pem(struct s_reader *rdr, uint8_t max_keys)
{
	FILE *fp_pri = NULL;
	//FILE *fp_pub = NULL;

	char tmp[256];
	uint8_t hash[32], *der = NULL;
	uint16_t i, length, count = 0;;
	biss2_rsa_key_t *new_item;

	if (!rdr->ll_biss2_rsa_keys)
	{
		rdr->ll_biss2_rsa_keys = ll_create("ll_biss2_rsa_keys");
	}

	for (i = 0; i < max_keys; i++)
	{
		if (!cs_malloc(&new_item, sizeof(biss2_rsa_key_t)))
		{
			break; // No memory available (?) - Exit
		}

		snprintf(tmp, sizeof(tmp), "%sbiss2_private_%02d.pem", emu_keyfile_path, i);
		if ((fp_pri = fopen(tmp, "r")) == NULL)
		{
			continue; // File does not exist
		}

		cs_log("Reading RSA key from: biss2_private_%02d.pem", i);

		// Read RSA private key
		if ((new_item->key = PEM_read_RSAPrivateKey(fp_pri, NULL, NULL, NULL)) == NULL)
		{
			cs_log("Error reading RSA private key");
			continue;
		}

		fclose(fp_pri);

		// Write public key in PEM formatted file
		/*snprintf(tmp, sizeof(tmp), "%sbiss2_public_%02d.pem", emu_keyfile_path, i);
		if ((fp_pub = fopen(tmp, "w")) != NULL)
		{
			PEM_write_RSA_PUBKEY(fp_pub, item->key);
			fclose(fp_pub);
		}*/

		// Write public key in DER formatted file
		/*snprintf(tmp, sizeof(tmp), "%sbiss2_public_%02d.der", emu_keyfile_path, i);
		if ((fp_pub = fopen(tmp, "wb")) != NULL)
		{
			i2d_RSA_PUBKEY_fp(fp_pub, item->key);
			fclose(fp_pub);
		}*/

		// Encode RSA public key into DER format
		if ((length = i2d_RSA_PUBKEY(new_item->key, &der)) <= 0)
		{
			cs_log("Error encoding to DER format");
			NULLFREE(der);
			continue;
		}

		// Create SHA256 digest
		EVP_MD_CTX *mdctx;
		if ((mdctx = EVP_MD_CTX_create()) == NULL)
		{
			NULLFREE(der);
			continue;
		}

		EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(mdctx, der, length);
		EVP_DigestFinal_ex(mdctx, hash, NULL);
		EVP_MD_CTX_destroy(mdctx);

		NULLFREE(der);
		memcpy(new_item->ekid, hash, 8);

		// Add new RSA key, if not already present
		if (!rsa_key_exists(rdr, new_item))
		{
			ll_append(rdr->ll_biss2_rsa_keys, new_item);
			count++;
		}
	}

	return count;
}

#endif // WITH_EMU
