#include "globals.h"
#ifdef READER_CONAX
#include "cscrypt/bn.h"
#include "reader-common.h"
#include "cscrypt/des.h"

static int32_t CWPK_CNX(struct s_reader *reader,uint8_t *msg)
{
int32_t ret = 0;

uint8_t CWp1[8];
uint8_t CWp2[8];
uint8_t CWs1[8];
uint8_t CWs2[8];

CWp1[0] = msg[7];
CWp1[1] = msg[8];
CWp1[2] = msg[9];
CWp1[3] = msg[10];
CWp1[4] = msg[11];
CWp1[5] = msg[12];
CWp1[6] = msg[13];
CWp1[7] = msg[14];

CWp2[0] = msg[22];
CWp2[1] = msg[23];
CWp2[2] = msg[24];
CWp2[3] = msg[25];
CWp2[4] = msg[26];
CWp2[5] = msg[27];
CWp2[6] = msg[28];
CWp2[7] = msg[29];

des_ecb3_decrypt(CWp1,reader->cwpk_mod);
des_ecb3_decrypt(CWp2,reader->cwpk_mod);
CWs1[0] = CWp1[4];
CWs1[1] = CWp1[5];
CWs1[2] = CWp1[6];
CWs1[3] = CWp1[7];
CWs1[4] = CWp1[0];
CWs1[5] = CWp1[1];
CWs1[6] = CWp1[2];
CWs1[7] = CWp1[3];

CWs2[0] = CWp2[4];
CWs2[1] = CWp2[5];
CWs2[2] = CWp2[6];
CWs2[3] = CWp2[7];
CWs2[4] = CWp2[0];
CWs2[5] = CWp2[1];
CWs2[6] = CWp2[2];
CWs2[7] = CWp2[3];

int chkok = 1;
if(((CWs1[0] + CWs1[1] + CWs1[2]) & 0xFF) != CWs1[3])
{
	chkok = 0;
	rdr_log(reader, "CW0 checksum error [0]");
}
if(((CWs1[4] + CWs1[5] + CWs1[6]) & 0xFF) != CWs1[7])
{
	chkok = 0;
	rdr_log(reader, "CW0 checksum error [1]");
}
if(((CWs2[0] + CWs2[1] + CWs2[2]) & 0xFF) != CWs2[3])
{
	chkok = 0;
	rdr_log(reader, "CW1 checksum error [0]");
}
if(((CWs2[4] + CWs2[5] + CWs2[6]) & 0xFF) != CWs2[7])
{
	chkok = 0;
	rdr_log(reader, "CW1 checksum error [1]");
}

if(chkok == 1)
{
	memcpy(&msg[7],CWs1,0x08);
	memcpy(&msg[22],CWs2,0x08);

	ret = 0;
}
if(chkok != 1)
{
	ret = -8;
}

return ret;
}

static int32_t RSA_CNX(struct s_reader *reader, uint8_t *msg, uint8_t *mod, uint8_t *exp, uint32_t cta_lr, uint32_t modbytes, uint32_t expbytes)
{
	int32_t ret = 0;
	uint32_t n = 0, pre_size = 0, size = 0;
	BN_CTX *ctx;
	BIGNUM *bn_mod, *bn_exp, *bn_data, *bn_res;
	uint8_t data[64];

	/*prefix size*/
	pre_size = 2 + 4 + msg[5];

	/*size of data to decryption*/
	if(msg[1] > (pre_size - 2))
		{ size = msg[1] - pre_size + 2; }

	if(cta_lr > (pre_size + size) && size >= modbytes && size < 128)
	{
		ctx = BN_CTX_new();

		if(ctx == NULL)
		{
			rdr_log_dbg(reader, D_READER, "RSA Error in RSA_CNX");
		}

		BN_CTX_start(ctx);
		bn_mod = BN_CTX_get(ctx);
		bn_exp = BN_CTX_get(ctx);
		bn_data = BN_CTX_get(ctx);
		bn_res = BN_CTX_get(ctx);

		/*RSA first round*/
		BN_bin2bn(mod, modbytes, bn_mod); // rsa modulus
		BN_bin2bn(exp, expbytes, bn_exp); // exponent
		BN_bin2bn(msg + pre_size, modbytes, bn_data);
		BN_mod_exp(bn_res, bn_data, bn_exp, bn_mod, ctx);

		n = BN_bn2bin(bn_res, data);

		size -= modbytes; // 3
		pre_size += modbytes;

		/*Check if second round is needed*/
		if(0 < size)
		{
			/*check if length of data from first RSA round will be enough to padding rest of data*/
			if((n + size) >= modbytes)
			{
				/*RSA second round*/
				/*move the remaining data at the beginning of the buffer*/
				memcpy(msg, msg + pre_size, size);
				/*padding buffer with data from first round*/
				memcpy(msg + size, data + (n - (modbytes - size)), modbytes - size);

				BN_bin2bn(msg, modbytes, bn_data);
				BN_mod_exp(bn_res, bn_data, bn_exp, bn_mod, ctx);
				n = BN_bn2bin(bn_res, data);
				if(0x25 != data[0])
					{ ret = -1; } /*RSA key is probably wrong*/
			}
			else
				{ ret = -3; } /*wrong size of data for second round*/
		}

		if(0 == ret)
			{ memcpy(msg, data, n); }

		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	else
		{ ret = -2; } /*wrong size of data*/

	return ret;
}

static time_t chid_date(const uint8_t *ptr, char *buf, int32_t l)
{
	time_t rc = 0;
	struct tm timeinfo;
	memset(&timeinfo, 0, sizeof(struct tm));

	if(buf)
	{
		timeinfo.tm_year = 90 + (ptr[1] >> 4) + (((ptr[0] >> 5) & 7) * 10);
		timeinfo.tm_mon = (ptr[1] & 0xf) - 1;
		timeinfo.tm_mday = ptr[0] & 0x1f;
		timeinfo.tm_isdst = -1;
		rc = mktime(&timeinfo);
		strftime(buf, l, "%Y/%m/%d", &timeinfo);
	}
	return (rc);
}

static int32_t read_record(struct s_reader *reader, const uint8_t *cmd, const uint8_t *data, uint8_t *cta_res)
{
	uint16_t cta_lr;
	uint8_t insCA[] = { 0xDD, 0xCA, 0x00, 0x00, 0x00 };

	write_cmd(cmd, data); // select record
	if(cta_res[0] != 0x98)
		{ return (-1); }

	insCA[4] = cta_res[1]; // get len
	write_cmd(insCA, NULL); // read record

	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1]))
		{ return (-1); }

	return (cta_lr - 2);
}

static int32_t check_pairing(struct s_reader *reader, const uint8_t *cmd, const uint8_t *data, uint8_t *cta_res)
{
	uint16_t cta_lr;

	if(reader->cwpk_mod_length)
	{
		write_cmd(cmd, data);
		rdr_log(reader, "CWPK Pairing is active");
	}
	else if(reader->rsa_mod_length)
	{
		rdr_log(reader, "RSA Pairing is active");
	}
	else
	{
		rdr_log(reader, "Pairing is not active");
	}
	return OK;
}

static uint8_t PairingECMRotation(struct s_reader *reader, const ECM_REQUEST *er, int32_t n)
{
	uint8_t cta_res[CTA_RES_LEN] = { 0x00 };
	uint8_t ins26[] = { 0xDD, 0x26, 0x00, 0x00, 0x03, 0x10, 0x01, 0x00 };
	uint8_t cnxcurrecm = 0;

	if(0x0 != reader->rsa_mod[0] && n > 3 &&
			0x54 == er->ecm[n - 3] &&
			0x02 == er->ecm[n - 2] &&
			0x00 == er->ecm[n - 1])
	{
		cnxcurrecm = 1;
	}

	if((0 == reader->cnxlastecm) != (0 == cnxcurrecm))
	{
		if(0 == cnxcurrecm) // not paired
			{ ins26[7] = 0x30; }
		else
			{ ins26[7] = 0x40; }

		if(read_record(reader, ins26, ins26 + 5, cta_res) <= 0)
			{ rdr_log(reader, "PairingECMRotation - ERROR"); }
	}
	reader->cnxlastecm = cnxcurrecm;
	return cnxcurrecm;
}

static int32_t conax_card_init(struct s_reader *reader, ATR *newatr)
{
	uint8_t cta_res[CTA_RES_LEN];
	int32_t i, j, n;
	static const uint8_t ins26[] = { 0xDD, 0x26, 0x00, 0x00, 0x03, 0x10, 0x01, 0x40 };
	static const uint8_t inscp[] = { 0xDD, 0x26, 0x00, 0x00, 0x04, 0x6C, 0x02, 0x10,0x00 };
	uint8_t ins82[] = { 0xDD, 0x82, 0x00, 0x00, 0x11, 0x11, 0x0f, 0x01, 0xb0, 0x0f, 0xff,
						0xff, 0xfb, 0x00, 0x00, 0x09, 0x04, 0x0b, 0x00, 0xe0, 0x30, 0x2b };

	uint8_t cardver = 0;

	get_hist;
	if((hist_size < 4) || (memcmp(hist, "0B00", 4)))
		{ return ERROR; }

	reader->caid = 0xB00;

	if((n = read_record(reader, ins26, ins26 + 5, cta_res)) <= 0) { return ERROR; } // read caid, card-version

	for(i = 0; i < n; i += cta_res[i + 1] + 2)
	{
		switch(cta_res[i])
		{
			case 0x20:
				cardver = cta_res[i + 2];
				break;

			case 0x28:
				reader->caid = (cta_res[i + 2] << 8) | cta_res[i + 3];
		}
	}

	// Ins82 command needs to use the correct CAID reported in nano 0x28
	ins82[17] = (reader->caid >> 8) & 0xFF;
	ins82[18] = (reader->caid) & 0xFF;

	if((n = read_record(reader, ins82, ins82 + 5, cta_res)) <= 0) { return ERROR; } // read serial

	reader->nprov = 0;

	for(j = 0, i = 2; i < n; i += cta_res[i + 1] + 2)
	{
		switch(cta_res[i])
		{
			case 0x23:
				if(cta_res[i + 5] != 0x00)
				{
					memcpy(reader->hexserial, &cta_res[i + 3], 6);
				}
				else
				{
					memcpy(reader->sa[j], &cta_res[i + 5], 4);
					j++;
					reader->nprov++;
				}
				break;
		}
	}

	memset(reader->prid, 0x00, sizeof(reader->prid));

	rdr_log_sensitive(reader, "type: Conax, caid: %04X, serial: {%llu}, hex serial: {%02x%02x%02x%02x}, card: v%d",
						reader->caid, (unsigned long long) b2ll(6, reader->hexserial), reader->hexserial[2],
						reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], cardver);

	rdr_log(reader, "Providers: %d", reader->nprov);

	for(j = 0; j < reader->nprov; j++)
	{
		rdr_log(reader, "Provider: %d Provider-Id: %06X", j + 1, b2i(4, reader->prid[j]));
		rdr_log_sensitive(reader, "Provider: %d SharedAddress: {%08X}", j + 1, b2i(4, reader->sa[j]));
	}
	check_pairing(reader, inscp, inscp + 5, cta_res);

	return OK;
}

static int32_t conax_send_pin(struct s_reader *reader)
{
	def_resp;
	uint8_t insPIN[] = { 0xDD, 0xC8, 0x00, 0x00, 0x07, 0x1D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 }; // Last four are the Pin-Code
	memcpy(insPIN + 8, reader->pincode, 4);

	write_cmd(insPIN, insPIN + 5);
	rdr_log_dbg(reader, D_READER, "Sent pincode to card.");

	return OK;
}

static int32_t conax_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp;
	int32_t i, j, n, num_dw = 0, rc = 0;
	uint8_t insA2[] = { 0xDD, 0xA2, 0x00, 0x00, 0x00 };
	uint8_t insCA[] = { 0xDD, 0xCA, 0x00, 0x00, 0x00 };

	uint8_t exp[] = { 0x01, 0x00, 0x01 };
	uint8_t buf[256];

	char ppp = 0x00;

	if((n = check_sct_len(er->ecm, 3)) < 0)
		{ return ERROR; }

	buf[0] = 0x14;
	buf[1] = n + 1;

	if(reader->cwpk_mod_length)
	{
		buf[2] = 4;
		ppp = 0x01;
	}
	else if(0x0 != reader->rsa_mod[0])
	{
		if(0x0 != PairingECMRotation(reader, er, n))
		{
			buf[2] = 2;
			ppp = 0x03;
		}
		else
		{
			buf[2] = 0;
			ppp = 0x02;
		}
	}
	else
	{
		buf[2] = 0;
		ppp = 0x02;
	}

	memcpy(buf + 3, er->ecm, n);
	insA2[4] = n + 3;

	write_cmd(insA2, buf); // write Header + ECM

	while((cta_res[cta_lr - 2] == 0x98) && // Antwort
		((insCA[4] = cta_res[cta_lr - 1]) > 0) && (insCA[4] != 0xFF))
	{
		write_cmd(insCA, NULL); // Codeword auslesen

		if((cta_res[cta_lr - 2] == 0x98) || ((cta_res[cta_lr - 2] == 0x90)))
		{
			/*checks if answer is encrypted with RSA algo and decrypts it if needed*/
			if(0x81 == cta_res[0] && 2 == cta_res[2] >> 5 && 0x03 == ppp) /*81 XX 5X*/
			{
				if(0x00 == cta_res[cta_lr - 1])
					{ rc = RSA_CNX(reader, cta_res, reader->rsa_mod, exp, cta_lr, 64u, 3u); }
				else
					{ rc = -4; } /*card has no right to decode this channel*/
			}
			else if(0x01 == ppp)
			{
				if(0x00 == cta_res[cta_lr - 1])
				{
					/*trying to decode using CWPK*/
					rc = CWPK_CNX(reader, cta_res);		/*enabled when no loging needed*/
				}
				else
				{
					rc = -4;
				}
			}

			if(0 == rc)
			{
				for(i = 0; i < cta_lr - 2 && num_dw < 2; i += cta_res[i + 1] + 2)
				{
					switch(cta_res[i])
					{
						case 0x25:
							if((cta_res[i + 1] >= 0xD) && !((n = cta_res[i + 4]) & 0xFE))
							{
								rc |= (1 << n);
								memcpy(ea->cw + (n << 3), cta_res + i + 7, 8);
								++num_dw;
							}
							break;

						case 0x31:
							if((cta_res[i + 1] == 0x02 && cta_res[i + 2] == 0x00 && cta_res[i + 3] == 0x00) || \
									(cta_res[i + 1] == 0x02 && cta_res[i + 2] == 0x40 && cta_res[i + 3] == 0x00))
								{ break; }
							else if(strcmp(reader->pincode, "none"))
							{
								conax_send_pin(reader);
								write_cmd(insA2, buf); // write Header + ECM

								while((cta_res[cta_lr - 2] == 0x98) && // Antwort
									((insCA[4] = cta_res[cta_lr - 1]) > 0) && (insCA[4] != 0xFF))
								{
									write_cmd(insCA, NULL); // Codeword auslesen

									if((cta_res[cta_lr - 2] == 0x98) ||
											((cta_res[cta_lr - 2] == 0x90) && (!cta_res[cta_lr - 1])))
									{
										for(j = 0; j < cta_lr - 2; j += cta_res[j + 1] + 2)
										{
											if((cta_res[j] == 0x25) && // access: is cw
													(cta_res[j + 1] >= 0xD) && // 0xD: 5 header + 8 cw
													!((n = cta_res[j + 4]) & 0xFE)) // cw idx must be 0 or 1
											{
												rc |= (1 << n);
												memcpy(ea->cw + (n << 3), cta_res + j + 7, 8);
												++num_dw;
											}
										}
									}
								}
							}
							break;
					}
				}
			}
		}
	}

	switch(rc)
	{
		case -1:
			rdr_log(reader, "conax decode ECM problem - RSA key is probably faulty");
			break;

		case -2:
			rdr_log(reader, "conax RSA pairing - wrong size of data");
			break;

		case -3:
			rdr_log(reader, "conax RSA pairing- wrong size of data for second round");
			/* fallthrough */

		case -4:
			rdr_log(reader, "card has no right to decode this channel");
			break;

		case -8:
			rdr_log(reader, "CWPK is faulty");
			break;
	}

	/* answer 9011 - conax smart card need reset */
	if(2 <= cta_lr && 0x90 == cta_res[cta_lr - 2] && 0x11 == cta_res[cta_lr - 1])
	{
		rdr_log(reader, "conax card hangs - reset is required");
		reader->card_status = UNKNOWN;
	}

	if(rc == 3)
		{ return OK; }
	else
		{ return ERROR; }
}

static int32_t conax_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	int32_t i, ok = 0;
	char tmp_dbg[17];

	rdr_log_dbg(rdr, D_EMM, "Entered conax_get_emm_type ep->emm[2]=%02x", ep->emm[2]);

	for(i = 0; i < rdr->nprov; i++)
	{
		ok = (!memcmp(&ep->emm[6], rdr->sa[i], 4));
		if(ok) { break; }
	}

	if(ok)
	{
		ep->type = SHARED;
		memset(ep->hexserial, 0, 8);
		memcpy(ep->hexserial, &ep->emm[6], 4);
		rdr_log_dbg_sensitive(rdr, D_EMM, "SHARED, ep->hexserial = {%s}",
						cs_hexdump(1, ep->hexserial, 8, tmp_dbg, sizeof(tmp_dbg)));
		return 1;
	}
	else
	{
		if(!memcmp(&ep->emm[6], rdr->hexserial + 2, 4))
		{
			ep->type = UNIQUE;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial + 2, &ep->emm[6], 4);
			rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE, ep->hexserial = {%s}",
							cs_hexdump(1, ep->hexserial, 8, tmp_dbg, sizeof(tmp_dbg)));
			return 1;
		}
		else
		{
			ep->type = GLOBAL;
			rdr_log_dbg(rdr, D_EMM, "GLOBAL");
			memset(ep->hexserial, 0, 8);
			return 1;
		}
	}
}

static int32_t conax_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 2 + rdr->nprov;
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return ERROR; }

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		int idx = 0, prov;

		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled = 0; // FIXME: dont see any conax global EMM yet
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		filters[idx].filter[8] = 0x70;
		filters[idx].mask[8] = 0xFF;
		idx++;

		for(prov = 0; prov < rdr->nprov; prov++)
		{
			filters[idx].type = EMM_SHARED;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			memcpy(&filters[idx].filter[4], rdr->sa[prov], 4);
			memset(&filters[idx].mask[4], 0xFF, 4);
			idx++;
		}

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		memcpy(&filters[idx].filter[4], rdr->hexserial + 2, 4);
		memset(&filters[idx].mask[4], 0xFF, 4);
		idx++;

		*filter_count = idx;
	}

	return OK;
}

static int32_t conax_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	def_resp;
	uint8_t insCA[] = { 0xDD, 0xCA, 0x00, 0x00, 0x00 };
	uint8_t insEMM[] = { 0xDD, 0x84, 0x00, 0x00, 0x00 };
	uint8_t buf[255];
	int32_t rc = 0;

	const int32_t l = ep->emm[2];

	insEMM[4] = l + 5;
	buf[0] = 0x12;
	buf[1] = l + 3;
	memcpy(buf + 2, ep->emm, buf[1]);
	write_cmd(insEMM, buf);

	if(cta_res[0] == 0x98)
	{
		insCA[4] = cta_res[1];
		write_cmd(insCA, NULL);
	}

	rc = ((cta_res[0] == 0x90) && (cta_res[1] == 0x00));

	if(rc)
		{ return OK; }
	else
		{ return ERROR; }
}

static int32_t conax_card_info(struct s_reader *reader)
{
	def_resp;
	int32_t type, i, j, k = 0, n = 0, l;
	uint16_t provid = 0;
	char provname[32], pdate[32], chid[32];
	static const uint8_t insC6[] = { 0xDD, 0xC6, 0x00, 0x00, 0x03, 0x1C, 0x01, 0x00 };
	static const uint8_t ins26[] = { 0xDD, 0x26, 0x00, 0x00, 0x03, 0x1C, 0x01, 0x01 };
	uint8_t insCA[] = { 0xDD, 0xCA, 0x00, 0x00, 0x00 };
	char *txt[] = { "Package", "PPV-Event" };
	static const uint8_t *cmd[] = { insC6, ins26 };
	time_t start_t = 0, end_t = 0;
	uint32_t cxclass = 0;

	cs_clear_entitlement(reader); // reset the entitlements

	for(type = 0; type < 2; type++)
	{
		n = 0;
		write_cmd(cmd[type], cmd[type] + 5);
		while(cta_res[cta_lr - 2] == 0x98)
		{
			insCA[4] = cta_res[cta_lr - 1]; // get len
			write_cmd(insCA, NULL); // read

			if((cta_res[cta_lr - 2] == 0x90) || (cta_res[cta_lr - 2] == 0x98))
			{
				for(j = 0; j < cta_lr - 2; j += cta_res[j + 1] + 2)
				{
					provid = (cta_res[j + 2 + type] << 8) | cta_res[j + 3 + type];
					chid[0] = '\0';

					for(k = 0, i = j + 4 + type; (i < j + cta_res[j + 1]); i += cta_res[i + 1] + 2)
					{
						switch(cta_res[i])
						{
							case 0x01:
								l = (cta_res[i + 1] < (sizeof(provname) - 1)) ? cta_res[i + 1] : sizeof(provname) - 1;
								memcpy(provname, cta_res + i + 2, l);
								provname[l] = '\0';
								break;

							case 0x30:
								if(k > 1)
								{
									rdr_log(reader, "%s: %d, id: %04X%s, date: %s - %s, name: %s",
											txt[type], ++n, provid, chid, pdate, pdate + 16, trim(provname));

									// add entitlements to list
									cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]),
											provid, cxclass, start_t, end_t, type + 1, 1);

									k = 0;
									chid[0] = '\0';
								}
								if(k == 0) { start_t = chid_date(cta_res + i + 2, pdate, 15); }
								else { end_t = chid_date(cta_res + i + 2, pdate + 16, 15) /* add 23:59:59 here: */ + 0x1517F; }
								++k;
								break;

							case 0x20: // Provider classes
							case 0x90: // (?) not sure what this is, saw it once in log
								snprintf(chid, sizeof(chid), ", classes: %02X%02X%02X%02X",
										cta_res[i + 2], cta_res[i + 3], cta_res[i + 4] , cta_res[i + 5]);
								cxclass = b2ll(4, &cta_res[i + 2]);
								break;
						}
					}
					rdr_log(reader, "%s: %d, id: %04X%s, date: %s - %s, name: %s",
							txt[type], ++n, provid, chid, pdate, pdate + 16, trim(provname));

					// add entitlements to list
					cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]),
							provid, cxclass, start_t, end_t, type + 1, 1);
				}
			}
		}
	}
	rdr_log(reader, "ready for requests");
	return OK;
}

const struct s_cardsystem reader_conax =
{
	.desc           = "conax",
	.caids          = (uint16_t[]){ 0x0B, 0 },
	.do_emm         = conax_do_emm,
	.do_ecm         = conax_do_ecm,
	.card_info      = conax_card_info,
	.card_init      = conax_card_init,
	.get_emm_type   = conax_get_emm_type,
	.get_emm_filter = conax_get_emm_filter,
};

#endif
