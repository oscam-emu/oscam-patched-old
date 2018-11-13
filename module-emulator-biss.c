#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "module-emulator-osemu.h"
#include "oscam-string.h"

static void BissUnifyOrbitals(uint32_t *namespace)
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

static void BissAnnotate(char *buf, uint8_t len, const uint8_t *ecm, uint16_t ecmLen, uint32_t hash, int8_t isNamespaceHash, int8_t datecoded)
{
	// Extract useful information to append to the "Example key ..." message.
	//
	// For feeds, the orbital position & frequency are usually embedded in the namespace.
	// See https://github.com/openatv/enigma2/blob/master/lib/dvb/frontend.cpp#L496
	// hash = (sat.orbital_position << 16);
	// hash |= ((sat.frequency/1000)&0xFFFF)|((sat.polarisation&1) << 15);
	//
	// If the onid & tsid appear to be a unique DVB identifier, enigma2 strips the frequency
	// from our namespace. See https://github.com/openatv/enigma2/blob/master/lib/dvb/scan.cpp#L59
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
		Date2Str(timeStr1, sizeof(timeStr1), 4, 3);
	}
	else
	{
		snprintf(timeStr1, sizeof(timeStr1), "00000000");
	}

	Date2Str(timeStr2, sizeof(timeStr2), 0, 2);

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

static int8_t BissIsCommonHash(uint32_t hash)
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

static int8_t BissIsValidNamespace(uint32_t namespace)
{
	// Note to developers:
	// If we ever have a satellite at 0.0E, edit to allow stripped namespace
	// '0xA0000000' with an additional test on tsid and onid being != 0

	uint16_t orbital, frequency;

	orbital = (namespace >> 16) & 0x0FFF;
	frequency = namespace & 0x7FFF;

	if ((namespace & 0xA0000000) != 0xA0000000) return 0;   // Value isn't flagged as namespace
	if (namespace == 0xA0000000) return 0;                  // Empty namespace
	if (orbital > 3599) return 0;                           // Allow only DVB-S
	if (frequency == 0) return 1;                           // Stripped namespace
	if (frequency >= 3400 && frequency <= 4200) return 1;   // Super extended C band
	if (frequency >= 10700 && frequency <= 12750) return 1; // Ku band Europe

	return 0;
}

static int8_t BissGetKey(uint32_t provider, uint8_t *key, int8_t dateCoded, int8_t printMsg)
{
	// If date-coded keys are enabled in the webif, this function evaluates the expiration date
	// of the keys found. Expired keys are not sent to the calling function. If date-coded keys
	// are disabled, then all keys found are sent without any evaluation. It takes the "provider"
	// as input and outputs the "key". Returns 0 (Key not found, or expired) or 1 (Key found).

	// printMsg: 0 => No message
	// printMsg: 1 => Print message only if key is found
	// printMsg: 2 => Always print message, regardless if key is found or not

	char keyExpDate[9] = "00000000";

	if (FindKey('F', provider, 0, keyExpDate, key, 8, 0, 0, 0, NULL)) // Key found
	{
		if (dateCoded) // Date-coded keys are enabled, evaluate expiration date
		{
			char currentDate[9];
			Date2Str(currentDate, sizeof(currentDate), 0, 3);

			if (strncmp("00000000", keyExpDate, 9) == 0 || strncmp(currentDate, keyExpDate, 9) < 0) // Evergreen or not expired
			{
				if (printMsg == 1 || printMsg == 2) cs_log("Key found: F %08X %s", provider, keyExpDate);
				return 1;
			}
			else // Key expired
			{
				key = NULL; // Make sure we don't send any expired key
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

int8_t Biss1Mode1Ecm(struct s_reader *rdr, uint16_t caid, const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid)
{
	// Oscam's fake ecm consists of [sid] [pmtpid] [pid1] [pid2] ... [pidx] [tsid] [onid] [namespace]
	//
	// On enigma boxes tsid, onid and namespace should be non zero, while on non-enigma
	// boxes they are usually all zero.
	// The emulator creates a unique channel hash using srvid and enigma namespace or
	// srvid, tsid, onid and namespace (in case of namespace without frequency) and
	// another weaker (not unique) hash based on every pid of the channel. This universal
	// hash should be available on all types of stbs (enigma and non-enigma).

	// Flags inside [namespace]
	//
	// emu r748- : no namespace, no flag
	// emu r749  : 0x80000000 (full namespase), 0xC0000000 (stripped namespace, injected with tsid^onid^ecmpid^0x1FFF)
	// emu r752+ : 0xA0000000 (pure namespace, either full, stripped, or null)

	// Key searches are made in order:
	// Highest priority / tightest test first
	// Lowest priority / loosest test last
	//
	// 1st: namespace hash (only on enigma boxes)
	// 2nd: universal hash (all box types with emu r752+)
	// 3rd: valid tsid, onid combination
	// 4th: faulty ecmpid (other than 0x1FFF)
	// 5th: reverse order pid (audio, video, pmt pids)
	// 6th: standard BISS ecmpid (0x1FFF)
	// 7th: default "All Feeds" key

	// If enabled in the webif, a date based key search can be performed. If the expiration
	// date has passed, the key is not sent from BissGetKey(). This search method is only
	// used in the namespace hash, universal hash and the default "All Feeds" key.

	uint32_t i, ens = 0, hash = 0;
	uint16_t pid = 0, ecmLen = GetEcmLen(ecm);
	uint8_t ecmCopy[ecmLen];
	char tmpBuffer1[17], tmpBuffer2[90] = "0", tmpBuffer3[90] = "0";

	// First try using the unique namespace hash (enigma only)
	if (ecmLen >= 13) // ecmLen >= 13, allow patching the ecmLen for r749 ecms
	{
		memcpy(ecmCopy, ecm, ecmLen);
		ens = b2i(4, ecm + ecmLen - 4); // Namespace will be the last 4 bytes

		if (BissIsValidNamespace(ens)) // An r752+ extended ecm with valid namespace
		{
			BissUnifyOrbitals(&ens);
			i2b_buf(4, ens, ecmCopy + ecmLen - 4);

			for (i = 0; i < 5; i++) // Find key matching hash made with frequency modified to: f+0, then f-1, f+1, f-2, lastly f+2
			{
				ecmCopy[ecmLen - 1] = (i & 1) ? ecmCopy[ecmLen - 1] - i : ecmCopy[ecmLen - 1] + i; // frequency +/- 1, 2 MHz

				if (0 != (ens & 0xFFFF)) // Full namespace - Calculate hash with srvid and namespace only
				{
					i2b_buf(2, srvid, ecmCopy + ecmLen - 6); // Put [srvid] right before [namespace]
					hash = crc32(caid, ecmCopy + ecmLen - 6, 6);
				}
				else // Namespace without frequency - Calculate hash with srvid, tsid, onid and namespace
				{
					i2b_buf(2, srvid, ecmCopy + ecmLen - 10); // Put [srvid] right before [tsid] [onid] [namespace] sequence
					hash = crc32(caid, ecmCopy + ecmLen - 10, 10);
				}

				if (BissGetKey(hash, dw, rdr->emu_datecodedenabled, i == 0 ? 2 : 1)) // Do not print "key not found" for frequency off by 1, 2
				{
					memcpy(dw + 8, dw, 8);
					return 0;
				}

				if (i == 0) // No key found matching our hash: create example SoftCam.Key BISS line for the live log
				{
					BissAnnotate(tmpBuffer2, sizeof(tmpBuffer2), ecmCopy, ecmLen, hash, 1, rdr->emu_datecodedenabled);
				}

				if (0 == (ens & 0xFFFF)) // Namespace without frequency - Do not iterate
				{
					break;
				}
			}
		}

		if ((ens & 0xA0000000) == 0x80000000) // r749 ecms only (exclude r752+ ecms)
		{
			cs_log("Hey! Network buddy, you need to upgrade your OSCam-Emu");
			ecmCopy[ecmLen] = 0xA0; // Patch ecm to look like r752+
			ecmLen += 4;
		}
	}

	// Try using the universal channel hash (namespace not available)
	if (ecmLen >= 17) // ecmLen >= 17, length of r749 ecms has been patched to match r752+ ecms
	{
		ens = b2i(4, ecmCopy + ecmLen - 4); // Namespace will be last 4 bytes

		if ((ens & 0xE0000000) == 0xA0000000) // We have an r752+ style ecm which contains pmtpid
		{
			memcpy(ecmCopy, ecm, ecmLen - 8); // Make a new ecmCopy from the original ecm as the old ecmCopy may be altered in namespace hash (skip [tsid] [onid] [namespace])
			hash = crc32(caid, ecmCopy + 3, ecmLen - 3 - 8); // ecmCopy doesn't have [tsid] [onid] [namespace] part

			if (BissGetKey(hash, dw, rdr->emu_datecodedenabled, 2)) // Key found
			{
				memcpy(dw + 8, dw, 8);
				return 0;
			}

			// No key found matching our hash: create example SoftCam.Key BISS line for the live log
			BissAnnotate(tmpBuffer3, sizeof(tmpBuffer3), ecmCopy, ecmLen, hash, 0, rdr->emu_datecodedenabled);
		}
	}

	// Try using only [tsid][onid] (useful when many channels on a transpoder use the same key)
	if (ecmLen >= 17) // ecmLen >= 17, length of r749 ecms has been patched to match r752+ ecms
	{
		ens = b2i(4, ecmCopy + ecmLen - 4); // Namespace will be last 4 bytes

		// We have an r752+ style ecm with stripped namespace, thus a valid [tsid][onid] combo to use as provider
		if ((ens & 0xE000FFFF) == 0xA0000000 && BissGetKey(b2i(4, ecm + ecmLen - 8), dw, 0, 2))
		{
			memcpy(dw + 8, dw, 8);
			return 0;
		}

		if ((ens & 0xE0000000) == 0xA0000000) // Strip [tsid] [onid] [namespace] on r752+ ecms
		{
			ecmLen -= 8;
		}
	}

	// Try using ecmpid if it seems to be faulty (should be 0x1FFF always for BISS)
	if (ecmpid != 0x1FFF && ecmpid != 0)
	{
		if (BissGetKey((srvid << 16) | ecmpid, dw, 0, 2))
		{
			memcpy(dw + 8, dw, 8);
			return 0;
		}
	}

	// Try to get the pid from oscam's fake ecm (only search [pid1] [pid2] ... [pidx] to be compatible with emu r748-)
	if (ecmLen >= 7) // Use >= 7 for radio channels with just one (audio) pid
	{
		// Reverse search order: last pid in list first
		// Better identifies channels where they share identical video pid but have variable counts of audio pids
		for (i = ecmLen - 2; i >= 5; i -= 2)
		{
			pid = b2i(2, ecm + i);

			if (BissGetKey((srvid << 16) | pid, dw, 0, 2))
			{
				memcpy(dw + 8, dw, 8);
				return 0;
			}
		}
	}

	// Try using the standard BISS ecm pid
	if (ecmpid == 0x1FFF || ecmpid == 0)
	{
		if (BissGetKey((srvid << 16) | 0x1FFF, dw, 0, 2))
		{
			memcpy(dw + 8, dw, 8);
			return 0;
		}
	}

	// Default BISS key for events with many feeds sharing same key
	if (ecmpid != 0 && BissGetKey(0xA11FEED5, dw, rdr->emu_datecodedenabled, 2)) // Limit to local ecms, block netwotk ecms
	{
		memcpy(dw + 8, dw, 8);
		cs_hexdump(0, dw, 8, tmpBuffer1, sizeof(tmpBuffer1));
		cs_log("No specific match found. Using 'All Feeds' key: %s", tmpBuffer1);
		return 0;
	}

	// Print example key lines for available hash search methods, if no key is found
	if (strncmp(tmpBuffer2, "0", 2)) cs_log("Example key based on namespace hash: %s", tmpBuffer2);
	if (strncmp(tmpBuffer3, "0", 2)) cs_log("Example key based on universal hash: %s", tmpBuffer3);

	// Check if universal hash is common and warn user
	if (BissIsCommonHash(hash)) cs_log("Feed has commonly used pids, universal hash clashes in SoftCam.Key are likely!");

	return 2;
}

int8_t BissEcm(struct s_reader *rdr, uint16_t caid, const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid)
{
	switch (caid)
	{
		case 0x2600:
			return Biss1Mode1Ecm(rdr, caid, ecm, dw, srvid, ecmpid);

		case 0x2602:
			cs_log("Unsupported Biss 2 Mode 1/E ecm (caid %04X) - Please report!", caid);
			return EMU_NOT_SUPPORTED;

		case 0x2610:
			cs_log("Unsupported Biss 2 Mode CA ecm (caid %04X) - Please report!", caid);
			return EMU_NOT_SUPPORTED;

		default:
			cs_log("Unknown Biss caid %04X - Please report!", caid);
			return EMU_NOT_SUPPORTED;
	}
}

#endif // WITH_EMU
