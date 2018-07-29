#define MODULE_LOG_PREFIX "emu"

#include "globals.h"
#include "oscam-string.h"
#include "oscam-config.h"
#include "oscam-conf-chk.h"
#include "oscam-time.h"
#include "oscam-reader.h"
#include "module-emulator-osemu.h"
#include "module-emulator-stream.h"

/*
 * Readers in OSCam consist of 2 basic parts.
 * The hardware or the device part. This is where physical smart cards are inserted
 * and made available to OSCam.
 * The software or the emulation part. This is where the actual card reading is done,
 * including ecm and emm processing (i.e emulation of the various cryptosystems).
 * In the Emu reader, the device part has no meaning, but we have to create it in
 * order to be compatible with OSCam's reader structure.
*/

/*
 * Create the Emu "emulation" part. This is of type s_cardsystem.
 * Similar structures are found in the main sources folder (files reader-xxxxxx.c)
 * for every cryptosystem supported by OSCam.
 * Here we read keys from our virtual card (aka the SoftCam.Key file) and we inform
 * OSCam about them. This is done with the emu_card_info() function. Keep in mind
 * that Emu holds all its keys to separate structures for faster access.
 * In addition, ECM and EMM requests are processed here, with the emu_do_ecm() and
 * emu_do_emm() functions.
*/

#define CS_OK     1
#define CS_ERROR  0

static uint8_t oneByte = 0x01;
extern char cs_confdir[128];

static void set_hexserial_to_version(struct s_reader *rdr)
{
	char cVersion[32];
	uint32_t version = GetOSemuVersion();
	uint8_t hversion[2];
	memset(hversion, 0, 2);
	snprintf(cVersion, sizeof(cVersion), "%04d", version);
	CharToBin(hversion, cVersion, 4);
	rdr->hexserial[3] = hversion[0];
	rdr->hexserial[4] = hversion[1];
}

static void set_prids(struct s_reader *rdr)
{
	int32_t i, j;

	rdr->nprov = 0;

	for (i = 0; (i < rdr->emu_auproviders.nfilts) && (rdr->nprov < CS_MAXPROV); i++)
	{
		for (j = 0; (j < rdr->emu_auproviders.filts[i].nprids) && (rdr->nprov < CS_MAXPROV); j++)
		{
			i2b_buf(4, rdr->emu_auproviders.filts[i].prids[j], rdr->prid[i]);
			rdr->nprov++;
		}
	}
}

static void emu_add_entitlement(struct s_reader *rdr, uint16_t caid, uint32_t provid, uint8_t *key, char *keyName, uint32_t keyLength, uint8_t isData)
{
	if (!rdr->ll_entitlements)
	{
		rdr->ll_entitlements = ll_create("ll_entitlements");
	}

	S_ENTITLEMENT *item;
	if (cs_malloc(&item, sizeof(S_ENTITLEMENT)))
	{
		// fill item
		item->caid = caid;
		item->provid = provid;
		item->id = 0;
		item->class = 0;
		item->start = 0;
		item->end = 2147472000;
		item->type = 0;
		item->isKey = 1;
		memcpy(item->name, keyName, 8);
		item->key = key;
		item->keyLength = keyLength;
		item->isData = isData;

		// add item
		ll_append(rdr->ll_entitlements, item);
	}
}

static void refresh_entitlements(struct s_reader *rdr)
{
	uint32_t i;
	KeyData *tmpKeyData;

	cs_clear_entitlement(rdr);

	for (i = 0; i < CwKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, CwKeys.EmuKeys[i].provider >> 8, CwKeys.EmuKeys[i].provider & 0xFF,
							CwKeys.EmuKeys[i].key, CwKeys.EmuKeys[i].keyName, CwKeys.EmuKeys[i].keyLength, 0);
	}

	for (i = 0; i < ViKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, 0x500, ViKeys.EmuKeys[i].provider, ViKeys.EmuKeys[i].key,
							ViKeys.EmuKeys[i].keyName, ViKeys.EmuKeys[i].keyLength, 0);
	}

	for (i = 0; i < NagraKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, 0x1801, NagraKeys.EmuKeys[i].provider, NagraKeys.EmuKeys[i].key,
							NagraKeys.EmuKeys[i].keyName, NagraKeys.EmuKeys[i].keyLength, 0);
	}

	for (i = 0; i < IrdetoKeys.keyCount; i++)
	{
		tmpKeyData = &IrdetoKeys.EmuKeys[i];
		do
		{
			emu_add_entitlement(rdr, tmpKeyData->provider >> 8, tmpKeyData->provider & 0xFF,
								tmpKeyData->key, tmpKeyData->keyName, tmpKeyData->keyLength, 0);

			tmpKeyData = tmpKeyData->nextKey;
		}
		while (tmpKeyData != NULL);
	}

	for (i = 0; i < NDSKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, NDSKeys.EmuKeys[i].provider, 0, NDSKeys.EmuKeys[i].key,
							NDSKeys.EmuKeys[i].keyName, NDSKeys.EmuKeys[i].keyLength, 0);
	}

	emu_add_entitlement(rdr, 0x090F, 0, viasat_const, "00", 64, 1);
	emu_add_entitlement(rdr, 0x093E, 0, viasat_const, "00", 64, 1);

	for (i = 0; i < BissKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, 0x2600, BissKeys.EmuKeys[i].provider, BissKeys.EmuKeys[i].key,
							BissKeys.EmuKeys[i].keyName, BissKeys.EmuKeys[i].keyLength, 0);
	}

	emu_add_entitlement(rdr, 0xFFFF, 0, &oneByte, "00", 1, 1);
	
	for (i = 0; i < PowervuKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, 0x0E00, PowervuKeys.EmuKeys[i].provider, PowervuKeys.EmuKeys[i].key,
							PowervuKeys.EmuKeys[i].keyName, PowervuKeys.EmuKeys[i].keyLength, 0);
	}

	for (i = 0; i < DreKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, 0x4AE1, DreKeys.EmuKeys[i].provider, DreKeys.EmuKeys[i].key,
							DreKeys.EmuKeys[i].keyName, DreKeys.EmuKeys[i].keyLength, 0);
	}

	for (i = 0; i < TandbergKeys.keyCount; i++)
	{
		emu_add_entitlement(rdr, 0x1010, TandbergKeys.EmuKeys[i].provider, TandbergKeys.EmuKeys[i].key,
							TandbergKeys.EmuKeys[i].keyName, TandbergKeys.EmuKeys[i].keyLength, 0);
	}
}

static int32_t emu_do_ecm(struct s_reader *rdr, const struct ecm_request_t *er, struct s_ecm_answer *ea)
{

	if (!ProcessECM(rdr, er->ecmlen, er->caid, er->prid, er->ecm, ea->cw, er->srvid, er->pid, &ea->cw_ex))
	{
		return CS_OK;
	}

	return CS_ERROR;
}

static int32_t emu_do_emm(struct s_reader *rdr, struct emm_packet_t *emm)
{
	uint32_t keysAdded = 0;

	if (emm->emmlen < 3)
	{
		return CS_ERROR;
	}

	if (SCT_LEN(emm->emm) > emm->emmlen)
	{
		return CS_ERROR;
	}

	if (!ProcessEMM(rdr, b2i(2, emm->caid), b2i(4, emm->provid), emm->emm, &keysAdded))
	{
		if (keysAdded > 0)
		{
			refresh_entitlements(rdr);
		}

		return CS_OK;
	}

	return CS_ERROR;
}

static int32_t emu_card_info(struct s_reader *rdr)
{
	// Delete keys from Emu's memory
	clear_emu_keydata();

	// Read keys built in the OSCam-Emu binary
#if !defined(__APPLE__) && !defined(__ANDROID__)
	read_emu_keymemory(rdr);
#endif

	// Read keys from SoftCam.Key file
	set_emu_keyfile_path(cs_confdir);

	if (!read_emu_keyfile(rdr, cs_confdir))
	{
		if (read_emu_keyfile(rdr, "/var/keys/"))
		{
			set_emu_keyfile_path("/var/keys/");
		}
	}

	// Load keys from external files (set via the webif or the reader config directly)
	read_emu_eebin(rdr->extee36, "ee36.bin");           // Read "ee36.bin"
	read_emu_eebin(rdr->extee56, "ee56.bin");           // Read "ee56.bin"
	read_emu_deskey(rdr->des_key, rdr->des_key_length); // Read overcrypt keys for DreCrypt ADEC

	cs_log("Total keys in memory: W:%d V:%d N:%d I:%d S:%d F:%d P:%d D:%d T:%d", \
					CwKeys.keyCount, ViKeys.keyCount, NagraKeys.keyCount, \
					IrdetoKeys.keyCount, NDSKeys.keyCount, BissKeys.keyCount, \
					PowervuKeys.keyCount, DreKeys.keyCount, TandbergKeys.keyCount);

	// Inform OSCam about all available keys.
	// This is used for listing the "entitlements" in the webif's reader page.
	refresh_entitlements(rdr);

	set_prids(rdr);

	set_hexserial_to_version(rdr);

	return CS_OK;
}

/*
static int32_t emu_card_init(struct s_reader *UNUSED(rdr), struct s_ATR *UNUSED(atr))
{
	return CS_ERROR;
}
*/

int32_t emu_get_via3_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	uint32_t provid = 0;

	if(ep->emm[3] == 0x90 && ep->emm[4] == 0x03)
	{
		provid = b2i(3, ep->emm+5);
		provid &=0xFFFFF0; 
		i2b_buf(4, provid, ep->provid);
	}

	switch(ep->emm[0])
	{
	case 0x88:
		ep->type = UNIQUE;
		memset(ep->hexserial, 0, 8);
		memcpy(ep->hexserial, ep->emm + 4, 4);
		rdr_log_dbg(rdr, D_EMM, "UNIQUE");
		return 1;

	case 0x8A:
	case 0x8B:
		ep->type = GLOBAL;
		rdr_log_dbg(rdr, D_EMM, "GLOBAL");
		return 1;

	case 0x8C:
	case 0x8D:
		ep->type = SHARED;
		rdr_log_dbg(rdr, D_EMM, "SHARED (part)");
		// We need those packets to pass otherwise we would never
		// be able to complete EMM reassembly
		return 1;

	case 0x8E:
		ep->type = SHARED;
		rdr_log_dbg(rdr, D_EMM, "SHARED");
		memset(ep->hexserial, 0, 8);
		memcpy(ep->hexserial, ep->emm + 3, 3);
		return 1;

	default:
		ep->type = UNKNOWN;
		rdr_log_dbg(rdr, D_EMM, "UNKNOWN");
		return 1;
	}
}

int32_t emu_get_ird2_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	int32_t l = (ep->emm[3] & 0x07);
	int32_t base = (ep->emm[3] >> 3);
	char dumprdrserial[l * 3], dumpemmserial[l * 3];

	switch(l)
	{

	case 0:
		// global emm, 0 bytes addressed
		ep->type = GLOBAL;
		rdr_log_dbg(rdr, D_EMM, "GLOBAL base = %02x", base);
		return 1;

	case 2:
		// shared emm, 2 bytes addressed
		ep->type = SHARED;
		memset(ep->hexserial, 0, 8);
		memcpy(ep->hexserial, ep->emm + 4, l);
		cs_hexdump(1, rdr->hexserial, l, dumprdrserial, sizeof(dumprdrserial));
		cs_hexdump(1, ep->hexserial, l, dumpemmserial, sizeof(dumpemmserial));
		rdr_log_dbg_sensitive(rdr, D_EMM, "SHARED l = %d ep = {%s} rdr = {%s} base = %02x", l,
								 dumpemmserial, dumprdrserial, base);
		return 1;

	case 3:
		// unique emm, 3 bytes addressed
		ep->type = UNIQUE;
		memset(ep->hexserial, 0, 8);
		memcpy(ep->hexserial, ep->emm + 4, l);
		cs_hexdump(1, rdr->hexserial, l, dumprdrserial, sizeof(dumprdrserial));
		cs_hexdump(1, ep->hexserial, l, dumpemmserial, sizeof(dumpemmserial));
		rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE l = %d ep = {%s} rdr = {%s} base = %02x", l,
								 dumpemmserial, dumprdrserial, base);
		return 1;

	default:
		ep->type = UNKNOWN;
		rdr_log_dbg(rdr, D_EMM, "UNKNOWN");
		return 1;
	}
}

int32_t emu_get_pvu_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	if(ep->emm[0] == 0x82)
	{
		ep->type = UNIQUE;
		memset(ep->hexserial, 0, 8);
		memcpy(ep->hexserial, ep->emm + 12, 4);
	}
	else
	{
		ep->type = UNKNOWN;
		rdr_log_dbg(rdr, D_EMM, "UNKNOWN");
	}
	return 1;	
}

int32_t emu_get_dre2_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(rdr))
{
	switch (ep->emm[0])
	{
		case 0x82:
			ep->type = GLOBAL;
			return 1;

		case 0x86:
			ep->type = SHARED;
			memset(ep->hexserial, 0, 8);
			ep->hexserial[0] = ep->emm[3];
			return 1;

		//case 0x87:
		//	ep->type = UNIQUE;
		//	return 1; //FIXME: no filling of ep->hexserial

		case 0x88:
			ep->type = UNIQUE;
			return 1; //FIXME: no filling of ep->hexserial

		case 0x91:
			ep->type = GLOBAL;
			return 1;

		default:
			ep->type = UNKNOWN;
			return 1;
	}
}

int32_t emu_get_tan_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	if(ep->emm[0] == 0x82 || ep->emm[0] == 0x83)
	{
		ep->type = GLOBAL;
	}
	else
	{
		ep->type = UNKNOWN;
		rdr_log_dbg(rdr, D_EMM, "UNKNOWN");
	}
	return 1;
}

static int32_t emu_get_emm_type(struct emm_packet_t *ep, struct s_reader *rdr)
{
	switch(b2i(2, ep->caid)>>8)
	{
		case 0x05:
			return emu_get_via3_emm_type(ep, rdr);
		
		case 0x06:
			return emu_get_ird2_emm_type(ep, rdr);
		
		case 0x0E:
			return emu_get_pvu_emm_type(ep, rdr);
		
		case 0x4A:
			return emu_get_dre2_emm_type(ep, rdr);
		
		case 0x10:
			return emu_get_tan_emm_type(ep, rdr);
		
		default:
			break;
	}
	
	return CS_ERROR;
}

FILTER* get_emu_prids_for_caid(struct s_reader *rdr, uint16_t caid)
{
	int32_t i;
	
	for(i = 0; i < rdr->emu_auproviders.nfilts; i++)
	{
		if(caid == rdr->emu_auproviders.filts[i].caid)
		{
			return &rdr->emu_auproviders.filts[i];
		}
	}
	
	return NULL;
}

static int32_t emu_get_via3_emm_filter(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count, uint16_t UNUSED(caid), uint32_t UNUSED(provid))
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 1;
		
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return CS_ERROR; }
		
		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;
		
		int32_t idx = 0;
		
		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x8A;
		filters[idx].mask[0]   = 0xFE;
		filters[idx].filter[3] = 0x80;
		filters[idx].mask[3]   = 0x80;
		idx++;
		
		*filter_count = idx;
	}
	
	return CS_OK;
}

static int32_t emu_get_ird2_emm_filter(struct s_reader* rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count, uint16_t caid, uint32_t UNUSED(provid))
{
	uint8_t hexserial[3], prid[4];
	FILTER* emu_provids;
	int8_t have_provid = 0, have_serial = 0;
	int32_t i;
	
	if(GetIrdeto2Hexserial(caid, hexserial))
		{ have_serial = 1; }

	emu_provids = get_emu_prids_for_caid(rdr, caid);
	if(emu_provids != NULL && emu_provids->nprids > 0)
		{ have_provid = 1; }

	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = have_serial + (2*(have_provid ? emu_provids->nprids : 0));
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return CS_ERROR; }

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		unsigned int idx = 0;

		if(have_serial)
		{
			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled   = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0]   = 0xFF;
			filters[idx].filter[1] = 0xFB;
			filters[idx].mask[1]   = 0x07;
			memcpy(&filters[idx].filter[2], hexserial, 3);
			memset(&filters[idx].mask[2], 0xFF, 3);
			idx++;
		}
		
		for(i=0; have_provid && i<emu_provids->nprids; i++)
		{
			i2b_buf(4, emu_provids->prids[i], prid);
			
			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled   = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0]   = 0xFF;
			filters[idx].filter[1] = 0xFB;
			filters[idx].mask[1]   = 0x07;
			memcpy(&filters[idx].filter[2], &prid[1], 3);
			memset(&filters[idx].mask[2], 0xFF, 3);
			idx++;
			
			filters[idx].type = EMM_SHARED;
			filters[idx].enabled   = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0]   = 0xFF;
			filters[idx].filter[1] = 0xFA;
			filters[idx].mask[1]   = 0x07;
			memcpy(&filters[idx].filter[2], &prid[1], 2);
			memset(&filters[idx].mask[2], 0xFF, 2);
			idx++;
		}
		
		*filter_count = idx;
	}
	
	return CS_OK;
}

static int32_t emu_get_pvu_emm_filter(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count, uint16_t UNUSED(caid), uint32_t UNUSED(provid), uint16_t srvid)
{
	uint8_t hexserials[16][4];
	int32_t i, count = 0;
	
	if(!GetPowervuHexserials(srvid, hexserials, 16, &count))
		{ return CS_ERROR; }
	
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = count;
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return CS_ERROR; }
		
		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;
		
		int32_t idx = 0;
		
		for(i=0; i<count; i++)
		{
			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled    = 1;
			filters[idx].filter[0]  = 0x82;
			filters[idx].filter[10] = hexserials[i][0];
			filters[idx].filter[11] = hexserials[i][1];
			filters[idx].filter[12] = hexserials[i][2];
			filters[idx].filter[13] = hexserials[i][3];
			filters[idx].mask[0]    = 0xFF;
			filters[idx].mask[10]   = 0xFF;
			filters[idx].mask[11]   = 0xFF;
			filters[idx].mask[12]   = 0xFF;
			filters[idx].mask[13]   = 0xFF;
			idx++;
		}
		
		*filter_count = idx;
	}

	return CS_OK;
}

static int32_t emu_get_dre2_emm_filter(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count, uint16_t caid, uint32_t provid)
{
	uint8_t hexserials[16];
	int32_t i, count = 0;
	
	if(!GetDrecryptHexserials(caid, provid, hexserials, 16, &count))
		{ count = 0; }
	
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 1 + count + 1;
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return CS_ERROR; }
		
		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;
		
		int32_t idx = 0;
		
		if(provid == 0xFE)
		{
			filters[idx].type = EMM_GLOBAL;
			filters[idx].enabled   = 1;
			filters[idx].filter[0] = 0x91;
			filters[idx].mask[0]   = 0xFF;
			idx++;
		}
		
		for(i=0; i<count; i++)
		{
			filters[idx].type = EMM_SHARED;
			filters[idx].enabled   = 1;
			filters[idx].filter[0] = 0x86;
			filters[idx].filter[1] = hexserials[i];
			filters[idx].mask[0]   = 0xFF;
			filters[idx].mask[1]   = 0xFF;
			idx++;
		}
		
		//filters[idx].type = EMM_UNIQUE;
		//filters[idx].enabled   = 1;
		//filters[idx].filter[0] = 0x87;
		//filters[idx].mask[0]   = 0xFF;
		//idx++;
		
		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x88;
		filters[idx].mask[0]   = 0xFF;
		idx++;
		
		*filter_count = idx;
	}
	
	return CS_OK;
}

static int32_t emu_get_tan_emm_filter(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count, uint16_t UNUSED(caid), uint32_t UNUSED(provid))
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 2;
		uint8_t buf[8];
		
		if(!FindKey('T', 0x40, 0, "MK", buf, 8, 0, 0, 0, NULL) && !FindKey('T', 0x40, 0, "MK01", buf, 8, 0, 0, 0, NULL))
			{ return CS_ERROR; }
		
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return CS_ERROR; }
		
		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;
		
		int32_t idx = 0;
		
		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0]   = 0xFF;
		idx++;
		
		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x83;
		filters[idx].mask[0]   = 0xFF;
		idx++;
		
		*filter_count = idx;
	}	
	
	return CS_OK;
}

static int32_t emu_get_emm_filter(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **UNUSED(emm_filters), unsigned int *UNUSED(filter_count))
{
	return CS_ERROR;
}

static int32_t emu_get_emm_filter_adv(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count, uint16_t caid, uint32_t provid, uint16_t srvid)
{
	switch(caid>>8)
	{
		case 0x05:
			return emu_get_via3_emm_filter(rdr, emm_filters, filter_count, caid, provid);
		
		case 0x06:
			return emu_get_ird2_emm_filter(rdr, emm_filters, filter_count, caid, provid);
		
		case 0x0E:
			return emu_get_pvu_emm_filter(rdr, emm_filters, filter_count, caid, provid, srvid);
		
		case 0x4A:
			return emu_get_dre2_emm_filter(rdr, emm_filters, filter_count, caid, provid);
		
		case 0x10:
			return emu_get_tan_emm_filter(rdr, emm_filters, filter_count, caid, provid);
		
		default:
			break;
	}
	
	return CS_ERROR;
}

const struct s_cardsystem reader_emu =
{
	.desc = "emu",
	.caids = (uint16_t[]){ 0x0D, 0x09, 0x0500, 0x18, 0x06, 0x26, 0xFFFF, 0x0E, 0x4A, 0x10, 0 },
	.do_ecm = emu_do_ecm,
	.do_emm = emu_do_emm,
	.card_info = emu_card_info,
	//.card_init = emu_card_init, // apparently this is not needed at all
	.get_emm_type = emu_get_emm_type,
	.get_emm_filter = emu_get_emm_filter, // needed to pass checks
	.get_emm_filter_adv = emu_get_emm_filter_adv,
};

/*
 * Create the Emu virtual "device" part. This is of type s_cardreader.
 * Similar structures are found in the csctapi (Card System Card Terminal API)
 * folder for every IFD (InterFace Device), aka smart card reader.
 * Since we have no hardware to initialize, we start our Stream Relay server
 * with the emu_reader_init() function.
 * At Emu shutdown, we remove keys from memory with the emu_close() function.
*/

#define CR_OK     0
#define CR_ERROR  1

static int32_t emu_reader_init(struct s_reader *UNUSED(reader))
{
	int32_t i;
	char authtmp[128];

	if (cfg.emu_stream_relay_enabled && (stream_server_thread_init == 0))
	{
		stream_server_thread_init = 1;
		SAFE_MUTEX_INIT(&emu_fixed_key_srvid_mutex, NULL);

		for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
		{
			SAFE_MUTEX_INIT(&emu_fixed_key_data_mutex[i], NULL);
			ll_emu_stream_delayed_keys[i] = ll_create("ll_emu_stream_delayed_keys");
			memset(&emu_fixed_key_data[i], 0, sizeof(emu_stream_client_key_data));
		}

		start_thread("stream_key_delayer", stream_key_delayer, NULL, NULL, 1, 1);
		cs_log("Stream key delayer initialized");

		cs_strncpy(emu_stream_source_host, cfg.emu_stream_source_host, sizeof(emu_stream_source_host));
		emu_stream_source_port = cfg.emu_stream_source_port;
		emu_stream_relay_port = cfg.emu_stream_relay_port;
		emu_stream_emm_enabled = cfg.emu_stream_emm_enabled;

		if (cfg.emu_stream_source_auth_user && cfg.emu_stream_source_auth_password)
		{
			snprintf(authtmp, sizeof(authtmp), "%s:%s", cfg.emu_stream_source_auth_user, cfg.emu_stream_source_auth_password);
			b64encode(authtmp, strlen(authtmp), &emu_stream_source_auth);
		}
		else
		{
			NULLFREE(emu_stream_source_auth);
		}

		start_thread("stream_server", stream_server, NULL, NULL, 1, 1);
		cs_log("Stream relay server initialized");
	}

	return CR_OK;
}

static int32_t emu_close(struct s_reader *UNUSED(reader))
{
	cs_log("Reader is shutting down");

	// Delete keys from Emu's memory
	clear_emu_keydata();

	return CR_OK;
}

static int32_t emu_get_status(struct s_reader *UNUSED(reader), int32_t *in) { *in = 1; return CR_OK; }
static int32_t emu_activate(struct s_reader *UNUSED(reader), struct s_ATR *UNUSED(atr)) { return CR_OK; }
static int32_t emu_transmit(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer), uint32_t UNUSED(size), uint32_t UNUSED(expectedlen), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t emu_receive(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer), uint32_t UNUSED(size), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t emu_write_settings(struct s_reader *UNUSED(reader), struct s_cardreader_settings *UNUSED(s)) { return CR_OK; }
static int32_t emu_card_write(struct s_reader *UNUSED(pcsc_reader),const uchar *UNUSED(buf) ,uint8_t *UNUSED(cta_res), uint16_t *UNUSED(cta_lr),int32_t UNUSED(l)) { return CR_OK; }
static int32_t emu_set_protocol(struct s_reader *UNUSED(rdr),uint8_t *UNUSED(params),uint32_t *UNUSED(length), uint32_t UNUSED(len_request)) { return CR_OK; }

const struct s_cardreader cardreader_emu =
{
	.desc                   = "emu",
	.typ                    = R_EMU,
	.skip_extra_atr_parsing = 1,
	.reader_init            = emu_reader_init,
	.get_status             = emu_get_status,
	.activate               = emu_activate,
	.transmit               = emu_transmit,
	.receive                = emu_receive,
	.close                  = emu_close,
	.write_settings         = emu_write_settings,
	.card_write             = emu_card_write,
	.set_protocol           = emu_set_protocol,
};

void add_emu_reader(void)
{
	// This function is called inside oscam.c and creates an emu [reader] with default
	// settings in oscam.server file. If an emu [reader] already exists, it uses that.

	LL_ITER itr;
	struct s_reader *rdr;
	int8_t haveEmuReader = 0;
	char *emuName = "emulator";
	char *ctab, *ftab, *emu_auproviders;

	// Check if emu [reader] entry already exists in oscam.server file and get it
	itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr)))
	{
		if (rdr->typ == R_EMU)
		{
			haveEmuReader = 1;
			break;
		}
	}

	rdr = NULL;

	// If there's no emu [reader] in oscam.server, create one with default settings
	if (!haveEmuReader)
	{
		if (!cs_malloc(&rdr, sizeof(struct s_reader)))
		{
			return;
		}

		reader_set_defaults(rdr);

		rdr->enable = 1;
		rdr->typ = R_EMU;
		strncpy(rdr->label, emuName, strlen(emuName));
		strncpy(rdr->device, emuName, strlen(emuName));

		// CAIDs
		ctab = strdup("090F,0500,1801,0604,2600,FFFF,0E00,4AE1,1010");
		chk_caidtab(ctab, &rdr->ctab);
		NULLFREE(ctab);

		// Idents
		ftab = strdup("090F:000000;"
					  "0500:000000,023800,021110,007400,007800;"
					  "1801:000000,007301,001101,002111;"
					  "0604:000000;"
					  "2600:000000;"
					  "FFFF:000000;"
					  "0E00:000000;"
					  "4AE1:000011,000014,0000FE;"
					  "1010:000000;"
					 );
		chk_ftab(ftab, &rdr->ftab);
		NULLFREE(ftab);

		// AU providers
		emu_auproviders = strdup("0604:010200;0E00:000000;4AE1:000011,000014,0000FE;1010:000000;");
		chk_ftab(emu_auproviders, &rdr->emu_auproviders);
		NULLFREE(emu_auproviders);

		// EMM cache
		rdr->cachemm = 2;
		rdr->rewritemm = 1;
		rdr->logemm = 2;
		rdr->deviceemm = 1;

		// User group
		rdr->grp = 0x1ULL;

		// Add the "device" part to our emu reader
		rdr->crdr = &cardreader_emu;

		reader_fixups_fn(rdr);
		ll_append(configured_readers, rdr);
	}

	// Set DVB Api delayer option
#ifdef HAVE_DVBAPI
	if (cfg.dvbapi_enabled && cfg.dvbapi_delayer < 60)
	{
		cfg.dvbapi_delayer = 60;
	}
#endif

	cs_log("OSCam-Emu version %d", GetOSemuVersion());
}
