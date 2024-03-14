#include "globals.h"
#ifdef READER_SECA
#include "reader-common.h"
#include "csctapi/icc_async.h"
#include "cscrypt/idea.h"

struct seca_data
{
	bool valid_provider[CS_MAXPROV];
	IDEA_KEY_SCHEDULE ks;
	IDEA_KEY_SCHEDULE ksSession;
};


static uint64_t get_pbm(struct s_reader *reader, uint8_t idx, bool fedc)
{
	def_resp;
	uint8_t ins34[] = { 0xc1, 0x34, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 }; // set request options
	uint8_t ins32[] = { 0xc1, 0x32, 0x00, 0x00, 0x0A }; // get PBM
	uint64_t pbm = 0;

	ins32[2] = idx;
	if (!idx) // change request options for first (=managment) provider only
	{
		ins32[4] = 0x0D;
		ins34[5] = 0x04;
	}

	if(!fedc)
	{
		write_cmd(ins34, ins34 + 5); // set request options
		write_cmd(ins32, NULL); // pbm request

		switch(cta_res[0])
		{
			case 0x04:
				rdr_log(reader, "no PBM for provider %u", idx + 1);
				break;

			case 0x83:
				pbm = b2ll(8, cta_res + 1);
				rdr_log(reader, "PBM for provider %u: %08llx", idx + 1, (unsigned long long) pbm);
				break;

			case 0xb2:
				pbm = b2ll(8, cta_res + 1);
				rdr_log(reader, "PBM for provider %u: %08llx", idx + 1, (unsigned long long) pbm);
				break;

			default:
				rdr_log(reader, "ERROR: PBM returns unknown byte %02x", cta_res[0]);
		}
	}
	return pbm;
}

static int32_t set_provider_info(struct s_reader *reader, int32_t i)
{
	def_resp;
	uint8_t ins12[] = { 0xc1, 0x12, 0x00, 0x00, 0x19 }; // get provider info
	int32_t year, month, day;
	struct tm lt;
	time_t t;
	bool valid = false;
	bool fedc = false;
	char l_name[16 + 8 + 1] = ", name: ";
	char tmp[9];

	uint32_t provid;

	ins12[2] = i; // select provider
	rdr_log(reader, "Request provider %i", i + 1);
	write_cmd(ins12, NULL); // show provider properties

	if((cta_res[25] != 0x90) || (cta_res[26] != 0x00))
	{
		return ERROR;
	}

	reader->prid[i][0] = 0;
	reader->prid[i][1] = 0; // blanken high byte provider code

	if (cta_res[0] == 0xFE)
	{
		fedc = true;
		rdr_log(reader, "FEDC provider %i", i + 1);
		cta_res[0] = 0x00;

		switch(i + 1)
		{
			case 0x01:
				cta_res[1] = 0x00;
				break;

			case 0x02:
				cta_res[1] = 0x68;
				break;

			case 0x03:
				cta_res[1] = 0x65;
				break;

			default:
				cta_res[1] = 0x68;
		}
	}
	memcpy(&reader->prid[i][2], cta_res, 2);

	provid = b2ll(4, reader->prid[i]);
	year = (cta_res[22] >> 1) + 1990;
	month = ((cta_res[22] & 0x1) << 3) | (cta_res[23] >> 5);
	day = (cta_res[23] & 0x1f);
	t = time(NULL);
	localtime_r(&t, &lt);

	if(lt.tm_year + 1900 != year)
	{
		valid = (lt.tm_year + 1900 < year);
	}
	else if(lt.tm_mon + 1 != month)
	{
		valid = (lt.tm_mon + 1 < month);
	}
	else if(lt.tm_mday != day)
	{
		valid = (lt.tm_mday < day);
	}

	memcpy(l_name + 8, cta_res + 2, 16);
	l_name[sizeof(l_name) - 1] = 0;
	trim(l_name + 8);
	l_name[0] = (l_name[8]) ? ',' : 0;

	if(l_name[8])
	{
		add_provider(0x0100, provid, l_name + 8, "", "");
	}

	struct seca_data *csystem_data = reader->csystem_data;
	csystem_data->valid_provider[i] = valid;
	rdr_log(reader, "provider %d: %04X, valid: %i%s, expiry date: %4d/%02d/%02d", i + 1, provid, valid, l_name, year, month, day);
	memcpy(&reader->sa[i][0], cta_res + 18, 4);

	if(valid) // if not expired
	{
		rdr_log_sensitive(reader, "SA: {%s}", cs_hexdump(0, cta_res + 18, 4, tmp, sizeof(tmp)));
	}

	// add entitlement to list
	memset(&lt, 0, sizeof(struct tm));
	lt.tm_year = year - 1900;
	lt.tm_mon = month - 1;
	lt.tm_mday = day;

	// Check if entitlement entry exists
	LL_ITER it = ll_iter_create(reader->ll_entitlements);
	S_ENTITLEMENT *entry = NULL;

	do
	{
		entry = ll_iter_next(&it);
		if((entry) && (entry->provid == provid))
		{
			break;
		}
	}
	while(entry);

	if(entry)
	{
		// update entitlement info if found
		entry->end = mktime(&lt);
		entry->id = get_pbm(reader, i, fedc);
		entry->type = (i) ? 6 : 7;
	}
	else // add entitlement info
	{
		cs_add_entitlement(reader, reader->caid, provid, get_pbm(reader, i, fedc), 0, 0, mktime(&lt), (i) ? 6 : 7, 1);
	}

	return OK;
}

static int32_t get_maturity(struct s_reader *reader)
{
	// Get maturity on card
	static const uint8_t ins16[] = { 0xC1, 0x16, 0x00, 0x00, 0x06 };

	def_resp;

	write_cmd(ins16, NULL);
	if((cta_res[cta_lr - 2] == 0x90) && cta_res[cta_lr - 1] == 0x00)
	{
		reader->maturity=cta_res[cta_lr - 4] & 0xF ;
		//rdr_log(reader, "Maturity rating on the card 0x%X!", reader->maturity);

		if (reader->maturity<0xF)
		{
			rdr_log(reader, "Maturity level [%X]= older than %i years", reader->maturity, reader->maturity);
		}
		else
		{
			rdr_log(reader, "Maturity level [%X]=no age limit", reader->maturity);
		}
	}

	rdr_log_dbg(reader, D_READER, "ins30_answer: %02x%02x", cta_res[0], cta_res[1]);
	return 0;
}

static int32_t unlock_parental(struct s_reader *reader)
{
	// Unlock parental control
	// c1 30 00 01 09
	// 00 00 00 00 00 00 00 00 ff
	static const uint8_t ins30[] = { 0xc1, 0x30, 0x00, 0x01, 0x09 };
	static uint8_t ins30data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };

	def_resp;

	if(strcmp(reader->pincode, "none"))
	{
		rdr_log(reader, "Using PIN %s", reader->pincode);
		// the pin need to be coded in bcd, so we need to convert from ascii to bcd, so '1234' -> 0x12 0x34
		ins30data[6] = ((reader->pincode[0] - 0x30) << 4) | ((reader->pincode[1] - 0x30) & 0x0f);
		ins30data[7] = ((reader->pincode[2] - 0x30) << 4) | ((reader->pincode[3] - 0x30) & 0x0f);
	}
	else
	{
		rdr_log(reader, "Using PIN 0000!");
	}

	write_cmd(ins30, ins30data);
	rdr_log_dbg(reader, D_READER, "ins30_answer: %02x%02x", cta_res[0], cta_res[1]);

	if(!(cta_res[cta_lr - 2] == 0x90 && cta_res[cta_lr - 1] == 0))
	{
		if(strcmp(reader->pincode, "none"))
		{
			rdr_log(reader, "Can't disable parental lock. Wrong PIN? OSCam used %s!", reader->pincode);
		}
		else
		{
			rdr_log(reader, "Can't disable parental lock. Wrong PIN? OSCam used 0000!");
		}
	}
	else
	{
		rdr_log(reader, "Parental lock disabled");
		get_maturity(reader);
	}

	return 0;
}

static int32_t seca_card_init(struct s_reader *reader, ATR *newatr)
{
	get_atr;
	def_resp;
	char *card;
	uint64_t serial ;
	static const uint8_t ins0e[] = { 0xc1, 0x0e, 0x00, 0x00, 0x08 }; // get serial number (UA)

	cs_clear_entitlement(reader);

	if((atr[10] != 0x0e) || (atr[11] != 0x6c) || (atr[12] != 0xb6) || (atr[13] != 0xd6))
	{
		return ERROR;
	}

	if(!cs_malloc(&reader->csystem_data, sizeof(struct seca_data)))
	{
		return ERROR;
	}

	switch(atr[7] << 8 | atr[8])
	{
		case 0x5084:
			card = "Generic";
			break;

		case 0x5384:
			card = "Philips";
			break;

		case 0x5130:
		case 0x5430:
		case 0x5760:
			card = "Thompson";
			break;

		case 0x5284:
		case 0x5842:
		case 0x6060:
			card = "Siemens";
			break;

		case 0x7070:
			card = "Mediaguard";
			break;

		default:
			card = "Unknown";
			break;
	}

	reader->caid = 0x0100;
	memset(reader->prid, 0xff, sizeof(reader->prid));
	write_cmd(ins0e, NULL); // read unique id
	memcpy(reader->hexserial, cta_res + 2, 6);
	serial = b2ll(5, cta_res + 3);

	rdr_log_sensitive(reader, "type: SECA, caid: %04X, serial: {%llu}, card: %s v%d.%d",
					reader->caid, (unsigned long long) serial, card, atr[9] & 0x0F, atr[9] >> 4);

	int seca_version = atr[9] & 0X0F; // Get seca cardversion from cardatr

	if(seca_version == 10) // check for nagra smartcard (seca3)
	{
		reader->secatype = 3;
		rdr_log_dbg(reader, D_IFD, "Detected seca/nagra (seca3) card");
	}

	if(seca_version == 7) // check for seca smartcard (seca2)
	{
		reader->secatype = 2;
		rdr_log(reader, "Detected seca2 card");
	}

	get_maturity(reader);

	// Unlock parental control
	if(cfg.ulparent != 0)
	{
		unlock_parental(reader);
		get_maturity(reader);
	}
	else
	{
		rdr_log_dbg(reader, D_IFD, "parental locked");
	}

	struct seca_data *csystem_data = reader->csystem_data;
	//init ideakeys
	uint8_t IdeaKey[16];
	memcpy(IdeaKey, reader->boxkey, 16);
	idea_set_encrypt_key(IdeaKey, &csystem_data->ks);
	idea_set_decrypt_key(&csystem_data->ks, &csystem_data->ksSession);

	return OK;
}

// returns provider id or -1 if not found
static int32_t get_prov_index(struct s_reader *rdr, const uint8_t *provid)
{
	int32_t prov;
	for(prov = 0; prov < rdr->nprov; prov++) // search for provider index
	{
		if(!memcmp(provid, &rdr->prid[prov][2], 2))
		{
			return (prov);
		}
	}
	return (-1);
}

// CDS seca2/3 solution
static int32_t seca_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	// provid006A=CDS NL uses seca2 and nagra/mediaguard3 crypt on same caid/provid only ecmpid is different
	if(er->ecm[3] == 0x00 && er->ecm[4] == 0x6a)
	{
		// default assume ecmtype same as cardtype in reader
		int32_t ecm_type = reader->secatype;

		if(er->ecm[8] == 0x00) // this is a mediaguard3 ecm request
		{
			ecm_type = 3; // flag it!
		}

		if((er->ecm[8] == 0x10) && (er->ecm[9] == 0x01)) // this is a seca2 ecm request
		{
			ecm_type = 2; // flag it!
		}

		if(ecm_type != reader->secatype) // only accept ecmrequest for right card!
		{
			return ERROR;
		}
	}

	def_resp;
	uint8_t ins3c[] = { 0xc1, 0x3c, 0x00, 0x00, 0x00 }; // coding cw
	uint8_t ins3a[] = { 0xc1, 0x3a, 0x00, 0x00, 0x10 }; // decoding cw
	int32_t i;

	if((i = get_prov_index(reader, er->ecm + 3)) == -1) // if provider not found
	{
		snprintf(ea->msglog, MSGLOGSIZE, "provider not found");
		return ERROR;
	}

	struct seca_data *csystem_data = reader->csystem_data;
	if((er->ecm[7] & 0x0F) != 0x0E && !csystem_data->valid_provider[i]) // if expired and not using OP Key 0E
	{
		snprintf(ea->msglog, MSGLOGSIZE, "provider expired");
		return ERROR;
	}

	ins3c[2] = i;
	ins3c[3] = er->ecm[7]; // key nr
	ins3c[4] = (((er->ecm[1] & 0x0f) << 8) | er->ecm[2]) - 0x05;
	int32_t try = 1;
	int32_t ret;

	do
	{
		if(try > 1)
		{
			snprintf(ea->msglog, MSGLOGSIZE, "ins3c try nr %i", try);
		}

		write_cmd(ins3c, er->ecm + 8); // ecm request
		uint8_t ins30[] = { 0xC1, 0x30, 0x00, 0x02, 0x09 };
		uint8_t ins30data[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };

		/* We need to use a token */
		if(cta_res[0] == 0x90 && cta_res[1] == 0x1a)
		{
			write_cmd(ins30, ins30data);
			write_cmd(ins3c, er->ecm + 8); // ecm request
		}

		ret = (((cta_res[0] != 0x90) && (cta_res[0] != 0x93) && (cta_res[0] != 0x96)) || ((cta_res[1] != 0x00) && (cta_res[1] != 0x02)));

		// Handle all not initial 90 00 ecm of with a get decoding cw
		// does avoid the need off card reset after a lot off them
		// the try ++ has been removed as it triggers the anti share mode
		// off seca cards due to not recorded extra ecm's by rate limiter

		if((cta_res[0] == 0x93) && (cta_res[1] == 0x02))
		{
			write_cmd(ins3a, NULL); // get cw
			if(er->ecm[2] > 0x61 && er->ecm[7] == 0x5C && er->ecm[100] == 0x0B)
			{
				rdr_log(reader, "reinit card in CAK7 mode");
			}
			else
			{
				snprintf(ea->msglog, MSGLOGSIZE, "unsubscribed 93 02");
			}
			return ERROR;
		} // exit if unsubscribed

		if((cta_res[0] == 0x96) && (cta_res[1] == 0x00))
		{
			write_cmd(ins3a, NULL); // get cw
			if(er->ecm[2] > 0x61 && er->ecm[7] == 0x5C && er->ecm[100] == 0x0B) {
				rdr_log(reader, "reinit card in CAK7 mode");
			} else {
				snprintf(ea->msglog, MSGLOGSIZE, "fake 96 00 ecm");
			}
			return E_CORRUPT;
		} // exit if fake 96 00 ecm

		if(ret)
		{
			snprintf(ea->msglog, MSGLOGSIZE, "%.16s ins3c card res: %02x %02x", reader->label, cta_res[0] , cta_res[1]);
			write_cmd(ins3a, NULL); // get cw
			return ERROR;
		} // exit on other's then 96 00 or 93 02
	}

	while((try < 2) && (ret));

	if(ret)
	{
		return ERROR;
	}

	write_cmd(ins3a, NULL); // get cw's
	if((cta_res[16] != 0x90) || (cta_res[17] != 0x00))
	{
		snprintf(ea->msglog, MSGLOGSIZE, "ins3a card response: %02x %02x", cta_res[16] , cta_res[17]);
		return ERROR;
	} // exit if response not 90 00

	// TODO: if response is 9027 ppv mode is possible!

	if(er->ecm[5] == 0x01 && ((reader->card_atr[9] & 0X0F) == 10)) // seca3: nano 01 in effect?
	{
		if(reader->boxkey_length == 16)
		{
			uint8_t v[8];
			memset(v, 0, sizeof(v));
			idea_cbc_encrypt(cta_res, ea->cw, 8, &csystem_data->ksSession, v, IDEA_DECRYPT);
			memset(v, 0, sizeof(v));
			idea_cbc_encrypt(cta_res + 8, ea->cw + 8, 8, &csystem_data->ksSession, v, IDEA_DECRYPT);
			uint8_t c;

			for(i = 0; i < 16; i += 4)
			{
				c = ((ea->cw[i] + ea->cw[i + 1] + ea->cw[i + 2]) & 0xff);

				if(ea->cw[i + 3] != c)
				{
					break;
				}
			}

			if(i == 16)
			{
				return OK;
			}
		}
		memset(ea->cw, 0, 16);
		snprintf(ea->msglog, MSGLOGSIZE, "need sessionkey");
		return ERROR;
	}
	memcpy(ea->cw, cta_res, 16);
	return OK;
}

// returns 1 if shared emm matches SA, unique emm matches serial, or global or unknown
static int32_t seca_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	rdr_log_dbg(rdr, D_EMM, "Entered seca_get_emm_type ep->emm[0]=%i", ep->emm[0]);
	int32_t i;
	char tmp_dbg[25];

	switch(ep->emm[0])
	{
		case 0x82:
			ep->type = UNIQUE;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 3, 6);

			rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE, ep->hexserial = {%s}",
								cs_hexdump(1, ep->hexserial, 6, tmp_dbg, sizeof(tmp_dbg)));

			rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE, rdr->hexserial = {%s}",
								cs_hexdump(1, rdr->hexserial, 6, tmp_dbg, sizeof(tmp_dbg)));

			return (!memcmp(rdr->hexserial, ep->hexserial, 6));
			break;

		case 0x84:
			ep->type = SHARED;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 5, 3); // don't include custom byte; this way the network also knows SA
			i = get_prov_index(rdr, ep->emm + 3);

			rdr_log_dbg_sensitive(rdr, D_EMM, "SHARED, ep->hexserial = {%s}",
								cs_hexdump(1, ep->hexserial, 3, tmp_dbg, sizeof(tmp_dbg)));

			if(i == -1) // provider not found on this card
				{ return 0; } //do not pass this EMM

			rdr_log_dbg_sensitive(rdr, D_EMM, "SHARED, rdr->sa[%i] = {%s}", i,
								cs_hexdump(1, rdr->sa[i], 3, tmp_dbg, sizeof(tmp_dbg)));

			return (!memcmp(rdr->sa[i], ep->hexserial, 3));
			break;

			// Unknown EMM types, but allready subbmited to dev's
			// FIXME: Drop EMM's until there are implemented
		case 0x83:
			ep->type = GLOBAL;
			rdr_log_dbg(rdr, D_EMM, "GLOBAL, PROVID: %04X", (ep->emm[3] << 8) | ep->emm[4]);
			return 1;
			/* EMM-G manadge ppv by provid
			83 00 74 33 41 04 70 00 BF 20 A1 15 48 1B 88 FF
			CF F5 50 CB 6F E1 26 A2 70 02 8F D0 07 6A 13 F9
			50 F9 61 88 FB E4 B8 03 EF 68 C9 54 EB C0 51 2E
			9D F9 E1 4A D9 A6 3F 5D 7A 1E B0 6E 3D 9B 93 E7
			5A E8 D4 AE 29 B9 37 07 5A 43 C8 F2 DE BD F8 BA
			69 DC A4 87 C2 FA 25 87 87 42 47 67 AE B7 1A 54
			CA F6 B7 EC 15 0A 67 1C 59 F8 B9 B8 6F 7D 58 94
			24 63 17 15 58 1E 59
			*/

		case 0x88:
		case 0x89:
			// EMM-G ?
			ep->type = UNKNOWN;
			return 0;

		default:
			ep->type = UNKNOWN;
			return 1;
	}
}

static int32_t seca_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 1 + (2 * rdr->nprov);
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
		{
			return ERROR;
		}

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		int32_t idx = 0;

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		memcpy(&filters[idx].filter[1], rdr->hexserial, 6);
		memset(&filters[idx].mask[1], 0xFF, 6);
		idx++;

		int32_t prov;
		for(prov = 0; prov < rdr->nprov; prov++)
		{
			// if sa == null skip update by shared & global (provid inactive)
			if(!memcmp(rdr->sa[prov], "\x00\x00\x00", 3))
			{
				continue;
			}

			filters[idx].type = EMM_GLOBAL; // global by provider
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x83;
			filters[idx].mask[0] = 0xFF;
			memcpy(&filters[idx].filter[1], &rdr->prid[prov][2], 2);
			memset(&filters[idx].mask[1], 0xFF, 2);
			idx++;

			filters[idx].type = EMM_SHARED;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x84;
			filters[idx].mask[0] = 0xFF;
			memcpy(&filters[idx].filter[1], &rdr->prid[prov][2], 2);
			memset(&filters[idx].mask[1], 0xFF, 2);
			memcpy(&filters[idx].filter[3], &rdr->sa[prov], 3);
			memset(&filters[idx].mask[3], 0xFF, 3);
			idx++;
		}

		*filter_count = idx;
	}

	return OK;
}

static int32_t seca_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	def_resp;
	uint8_t ins40[] = { 0xc1, 0x40, 0x00, 0x00, 0x00 };
	int32_t i, ins40data_offset;
	int32_t emm_length = ((ep->emm[1] & 0x0f) << 8) + ep->emm[2];
	uint8_t *prov_id_ptr;

	switch(ep->type)
	{
		case SHARED:
			ins40[3] = ep->emm[9];
			ins40[4] = emm_length - 0x07;
			ins40data_offset = 10;
			prov_id_ptr = ep->emm + 3;
			break;

		case UNIQUE:
			ins40[3] = ep->emm[12];
			ins40[4] = emm_length - 0x0A;
			ins40data_offset = 13;
			prov_id_ptr = ep->emm + 9;
			break;

		case GLOBAL:
			ins40[3] = ep->emm[6];
			ins40[4] = emm_length - 0x04;
			ins40data_offset = 7;
			prov_id_ptr = ep->emm + 3;
			break;

		default:
			rdr_log(reader, "EMM: Congratulations, you have discovered a new EMM on SECA.");
			rdr_log(reader, "This has not been decoded yet, so send this output to authors:");
			rdr_log_dump(reader, ep->emm, emm_length + 3, "EMM:");
			return ERROR;
	}

	i = get_prov_index(reader, prov_id_ptr);
	if(i == -1)
	{
		rdr_log(reader, "EMM: skipped since provider id doesnt match");
		return SKIPPED;
	}

	ins40[2] = (ep->emm[ins40data_offset - 2] & 0xF0) | (i & 0x0F);
	write_cmd(ins40, ep->emm + ins40data_offset); // emm request

	if(cta_res[0] == 0x97)
	{
		if(!(cta_res[1] & 4)) // date updated
		{
			set_provider_info(reader, i);
		}
		else
		{
			rdr_log(reader, "EMM: Update not necessary.");
		}
		return OK; // Update not necessary
	}

	if((cta_res[0] == 0x90) && ((cta_res[1] == 0x00) || (cta_res[1] == 0x19)))
	{
		if(ep->type == GLOBAL) // do not print new provider info after global emm
		{
			return OK;
		}

		if(set_provider_info(reader, i) == OK) // after successful EMM, print32_t new provider info
		{
			return OK;
		}
	}
	return ERROR;
}

static int32_t seca_card_info(struct s_reader *reader)
{
	def_resp;
	static const uint8_t ins16[] = { 0xc1, 0x16, 0x00, 0x00, 0x06 }; // get nr. of providers
	int32_t prov = 0;
	uint16_t pmap = 0; // provider-maptable

	int16_t tries = 0;
	int16_t i = 0;

	while(reader->nprov == 0 && tries < 254)
	{
		write_cmd(ins16, NULL); // read nr of providers
		pmap = cta_res[2] << 8 | cta_res[3];

		for(reader->nprov = 0, i = pmap; i; i >>= 1)
		{
			reader->nprov += i & 1;
		}

		if(reader->nprov == 0)
		{
			tries++;
			continue;
		}
	}

	for(prov = 0; prov < reader->nprov; prov++)
	{
		set_provider_info(reader, prov);
	}
	return OK;
}

const struct s_cardsystem reader_seca =
{
	.desc           = "seca",
	.caids          = (uint16_t[]){ 0x01, 0 },
	.do_emm         = seca_do_emm,
	.do_ecm         = seca_do_ecm,
	.card_info      = seca_card_info,
	.card_init      = seca_card_init,
	.get_emm_type   = seca_get_emm_type,
	.get_emm_filter = seca_get_emm_filter,
};

#endif
