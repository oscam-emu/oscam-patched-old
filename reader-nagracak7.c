#include "globals.h"
#ifdef READER_NAGRA_MERLIN
#include "math.h"
#include "cscrypt/bn.h"
#include "cscrypt/idea.h"
#include "csctapi/icc_async.h"
#include "oscam-time.h"
#include "reader-common.h"
#include "reader-nagra-common.h"
#include "oscam-work.h"
#include "cscrypt/des.h"
#include "cscrypt/mdc2.h"
static const uint8_t public_exponent[] = { 0x01, 0x00, 0x01 };
static const uint8_t d00ff[] = { 0x00, 0xFF, 0xFF, 0xFF };
// Datatypes
#define IRDINFO 0x03
#define TIERS   0x0C
#define SYSID   0x05
static time_t tier_date(uint64_t date, char *buf, int32_t l)
{
	time_t ut = +694224000L + (date >> 1);
	if(buf)
	{
		struct tm t;
		cs_gmtime_r(&ut, &t);
		l = 27;
		snprintf(buf, l, "%04d/%02d/%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
	}
	return ut;
}
static void rsa_decrypt(uint8_t *edata50, int len, uint8_t *out, uint8_t *key, int keylen)
{
	BN_CTX *ctx0 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx0);
#endif
	BIGNUM *bnN0 = BN_CTX_get(ctx0);
	BIGNUM *bnE0 = BN_CTX_get(ctx0);
	BIGNUM *bnCT0 = BN_CTX_get(ctx0);
	BIGNUM *bnPT0 = BN_CTX_get(ctx0);
	BN_bin2bn(&key[0], keylen, bnN0);
	BN_bin2bn(public_exponent, 0x03, bnE0);
	BN_bin2bn(&edata50[0], len, bnCT0);
	BN_mod_exp(bnPT0, bnCT0, bnE0, bnN0, ctx0);
	memset(out,0x00,len);
	BN_bn2bin(bnPT0, out+ (len- BN_num_bytes(bnPT0)));
	BN_CTX_end(ctx0);
	BN_CTX_free(ctx0);
}
static void addProvider(struct s_reader *reader, uint8_t *cta_res)
{
	int i;
	bool toadd = true;
	for(i = 0; i < reader->nprov; i++)
	{
		if((cta_res[0] == reader->prid[i][2]) && (cta_res[1] == reader->prid[i][3]))
		{
			toadd = false;
		}
	}
	if(toadd)
	{
		reader->prid[reader->nprov][0] = 0;
		reader->prid[reader->nprov][1] = 0;
		reader->prid[reader->nprov][2] = cta_res[0];
		reader->prid[reader->nprov][3] = cta_res[1];
		reader->nprov += 1;
	}
}
static int32_t get_prov_index(struct s_reader *reader, const uint8_t *provid)
{
	int prov;
	for(prov = 0; prov < reader->nprov; prov++)
	{
		if(!memcmp(provid, &reader->prid[prov][2], 2))
		{
			return (prov);
		}
	}
	return (-1);
}
static void addSA(struct s_reader *reader, uint8_t *cta_res)
{
	if((cta_res[0] == 0x83 && cta_res[5] == 0x10) || cta_res[0] == 0x87)
	{
		int i;
		bool toadd = true;
		if(reader->evensa)
		{
			unsigned long sax = (cta_res[3] << 16) + (cta_res[2] << 8) + (cta_res[1]);
			if(sax % 2 != 0)
			{
				sax--;
				cta_res[3]=(sax>>16)&0xFF;
				cta_res[2]=(sax>>8)&0xFF;
				cta_res[1]=(sax)&0xFF;
			}
		}
		for(i = 0; i < reader->nsa; i++)
		{
			if((cta_res[1] == reader->sa[i][2]) && (cta_res[2] == reader->sa[i][1]) && (cta_res[3] == reader->sa[i][0]) && (cta_res[4] == reader->sa[i][3]))
			{
				toadd = false;
			}
		}
		if(toadd && (memcmp(cta_res + 1, "\x00\x00\x00", 3)))
		{
			reader->sa[reader->nsa][0] = cta_res[3];
			reader->sa[reader->nsa][1] = cta_res[2];
			reader->sa[reader->nsa][2] = cta_res[1];
			reader->sa[reader->nsa][3] = cta_res[4];
			reader->nsa += 1;
		}
	}
}
static void addSAseca(struct s_reader *reader, uint8_t *cta_res)
{
	if(cta_res[0] == 0x84)
	{
		addProvider(reader, cta_res + 1);
		if(memcmp(cta_res + 3, "\x00\x00\x00", 3))
		{
			int i;
			i = get_prov_index(reader, cta_res + 1);
			memcpy(reader->sa[i], cta_res + 3, 3);
		}
	}
}
static void addemmfilter(struct s_reader *reader, uint8_t *cta_res)
{
	if(cta_res[0] == 0x82)
	{
		reader->emm82 = 1;
	}
	else if(cta_res[0] == 0x84)
	{
		int i;
		bool toadd = true;
		for(i = 0; i < reader->nemm84; i++)
		{
			if(!memcmp(cta_res, reader->emm84[i], 3))
			{
				toadd = false;
			}
		}
		if(toadd && (memcmp(cta_res + 1, "\x00\x00", 2)))
		{
			reader->emm84[reader->nemm84][0] = cta_res[0];
			reader->emm84[reader->nemm84][1] = cta_res[1];
			reader->emm84[reader->nemm84][2] = cta_res[2];
			reader->nemm84 += 1;
		}
	}
	else if(cta_res[0] == 0x83 && cta_res[5] == 0x00)
	{
		int i;
		bool toadd = true;
		for(i = 0; i < reader->nemm83u; i++)
		{
			if(!memcmp(cta_res, reader->emm83u[i], 6))
			{
				toadd = false;
			}
		}
		if(toadd && (memcmp(cta_res + 1, "\x00\x00\x00\x00", 4)))
		{
			memcpy(reader->emm83u[reader->nemm83u], cta_res, 6);
			reader->nemm83u += 1;
		}
	}
	else if(cta_res[0] == 0x83 && cta_res[5] == 0x10)
	{
		int i;
		bool toadd = true;
		if(reader->evensa)
		{
			unsigned long sax = (cta_res[3] << 16) + (cta_res[2] << 8) + (cta_res[1]);
			if(sax % 2 != 0)
			{
				sax--;
				cta_res[3]=(sax>>16)&0xFF;
				cta_res[2]=(sax>>8)&0xFF;
				cta_res[1]=(sax)&0xFF;
			}
		}
		for(i = 0; i < reader->nemm83s; i++)
		{
			if(!memcmp(cta_res, reader->emm83s[i], 6))
			{
				toadd = false;
			}
		}
		if(toadd && (memcmp(cta_res + 1, "\x00\x00\x00", 3)))
		{
			memcpy(reader->emm83s[reader->nemm83s], cta_res, 6);
			reader->nemm83s += 1;
		}
	}
	else if(cta_res[0] == 0x87)
	{
		int i;
		bool toadd = true;
		if(reader->evensa)
		{
			unsigned long sax = (cta_res[3] << 16) + (cta_res[2] << 8) + (cta_res[1]);
			if(sax % 2 != 0)
			{
				sax--;
				cta_res[3]=(sax>>16)&0xFF;
				cta_res[2]=(sax>>8)&0xFF;
				cta_res[1]=(sax)&0xFF;
			}
		}
		for(i = 0; i < reader->nemm87; i++)
		{
			if(!memcmp(cta_res, reader->emm87[i], 6))
			{
				toadd = false;
			}
		}
		if(toadd && (memcmp(cta_res + 1, "\x00\x00\x00", 3)))
		{
			memcpy(reader->emm87[reader->nemm87], cta_res, 6);
			reader->nemm87 += 1;
		}
	}
}
static int32_t ParseDataType(struct s_reader *reader, uint8_t dt, uint8_t *cta_res, uint16_t cta_lr)
{
	char ds[27], de[27];
	switch(dt)
	{
		case 0x02:
		{
			reader->prid[0][0] = 0x00;
			reader->prid[0][1] = 0x00;
			reader->prid[0][2] = cta_res[19];
			reader->prid[0][3] = cta_res[20];
			reader->prid[1][0] = 0x00;
			reader->prid[1][1] = 0x00;
			reader->prid[1][2] = 0x00;
			reader->prid[1][3] = 0x00;
			reader->nprov += 1;
			reader->caid = (SYSTEM_NAGRA | cta_res[25]);
			rdr_log_dbg(reader, D_READER, "CAID : %04X", reader->caid);
			return OK;
		}
		case IRDINFO: // case 0x03
		{
			if(cta_res[21] == 0x9C)
			{
				uint32_t timestamp = b2i(0x04, cta_res + 22);
				uint8_t timestamp186D[4] = {0xA6, 0x9E, 0xFB, 0x7F};
				uint32_t timestamp186Db2i = b2i(0x04, timestamp186D);
				if(reader->caid == 0x186D)
				{
					reader->card_valid_to = tier_date(timestamp186Db2i, de, 11);
				}
				else
				{
					reader->card_valid_to = tier_date(timestamp, de, 11);
				}
				uint16_t chid = 0;
				uint32_t id = b2i(0x02, cta_res + 19);
				uint32_t start_date;
				uint32_t expire_date;
				start_date = 1;
				expire_date = b2i(0x04, cta_res + 22);
				cs_add_entitlement(reader,
				reader->caid,
				id,
				chid,
				0,
				tier_date(start_date, ds, 11),
				tier_date(expire_date, de, 11),
				4,
				1);
				rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
				addProvider(reader, cta_res + 19);
			}
			if((reader->caid == 0x1856) && (cta_res[21] == 0x01))
			{
				uint16_t chid = 0;
				uint32_t id = b2i(0x02, cta_res + 19);
				uint32_t start_date;
				uint32_t expire_date;
				start_date = 1;
				expire_date = b2i(0x04, cta_res + 22);
				cs_add_entitlement(reader,
				reader->caid,
				id,
				chid,
				0,
				tier_date(start_date, ds, 11),
				tier_date(expire_date, de, 11),
				4,
				1);
				rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
				addProvider(reader, cta_res + 19);
			}
			if(reader->protocol_type == ATR_PROTOCOL_TYPE_T0)
			{
				uint16_t chid = 0;
				uint32_t id = b2i(0x02, cta_res + 19);
				uint32_t start_date;
				uint32_t expire_date;
				start_date = 1;
				expire_date = b2i(0x04, cta_res + 22);
				cs_add_entitlement(reader,
				reader->caid,
				id,
				chid,
				0,
				tier_date(start_date, ds, 11),
				tier_date(expire_date, de, 11),
				4,
				1);
				rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
				addProvider(reader, cta_res + 19);
			}
			return OK;
		}
		case 0x04:
		{
			if(cta_res[18] != 0x80)
			{
				addProvider(reader, cta_res + 19);
				uint8_t check[] = {0x00, 0x01};
				uint8_t checkecmcaid[] = {0xFF, 0x07};
				if (reader->caid == 0x186D)
				{
					check[0] = (reader->caid - 0x03) & 0xFF;
				}
				else if (reader->caid == 0x1856)
				{
					check[0] = (reader->caid + 0x28) & 0xFF;
				}
				else
				{
					check[0] = reader->caid & 0xFF;
				}
				int p;
				for(p=23; p < (cta_lr - 6); p++)
				{
					if(!memcmp(cta_res + p, check, 2))
					{
						addProvider(reader, cta_res + p + 2);
						if(reader->cak7type == 3)
						{
							addSAseca(reader, cta_res + p + 5);
						}
						else
						{
							if ((reader->caid == 0x1884) && (((cta_res + p + 5)[0] == 0x83) || ((cta_res + p + 5)[0] == 0x87)) && ((cta_res + p + 5)[2] == reader->cardid[1]) && ((cta_res + p + 5)[3] == reader->cardid[0]) && ((cta_res + p + 5)[4] == 0x00))
							{
								(cta_res + p + 5)[1] -= 0x01;
							}
							if ((reader->caid == 0x1856) && ((cta_res + p + 5)[0] == 0x87) && ((cta_res + p + 5)[1] != reader->cardid[2]) && ((cta_res + p + 5)[2] != reader->cardid[1]) && ((cta_res + p + 5)[3] != reader->cardid[0]) && ((cta_res + p + 5)[4] != reader->cardid[3]))
							{
								(cta_res + p + 5)[4] = 0x00;
							}
							addSA(reader, cta_res + p + 5);
							addemmfilter(reader, cta_res + p + 5);
						}
					}
					if(!memcmp(cta_res + p, checkecmcaid, 2))
					{
						reader->caid = (SYSTEM_NAGRA | (cta_res + p + 2)[0]);
					}
				}
			}
			return OK;
		}
		case 0x09:
		{
			if((cta_res[19] == cta_res[23]) && (cta_res[20] == cta_res[24]))
			{
				addProvider(reader, cta_res + 19);
			}
			return OK;
		}
		case SYSID: // case 0x05
		{
			memcpy(reader->edata,cta_res + 26, 0x70);
			reader->dt5num = cta_res[20];
			char tmp[8];
			rdr_log(reader, "Card has DT05_%s", cs_hexdump(1, &reader->dt5num, 1, tmp, sizeof(tmp)));
			if(reader->dt5num == 0x00)
			{
				IDEA_KEY_SCHEDULE ks;
				rsa_decrypt(reader->edata, 0x70, reader->out, reader->mod1, reader->mod1_length);
				memcpy(reader->kdt05_00,&reader->out[18], 0x5C + 2);
				memcpy(&reader->kdt05_00[0x5C + 2], cta_res + 26 + 0x70, 6);
				memcpy(reader->ideakey1, reader->out, 16);
				rdr_log_dump_dbg(reader, D_READER, reader->ideakey1, 16, "IDEAKEY1: ");
				memcpy(reader->block3, cta_res + 26 + 0x70 + 6, 8);
				idea_set_encrypt_key(reader->ideakey1, &ks);
				memset(reader->v, 0, sizeof(reader->v));
				idea_cbc_encrypt(reader->block3, reader->iout, 8, &ks, reader->v, IDEA_DECRYPT);
				memcpy(&reader->kdt05_00[0x5C + 2 + 6],reader->iout, 8);
				uint8_t mdc_hash1[MDC2_DIGEST_LENGTH];
				memset(mdc_hash1,0x00,MDC2_DIGEST_LENGTH);
				uint8_t check1[0x7E];
				memset(check1, 0x00, 0x7E);
				memcpy(check1 + 18, reader->kdt05_00, 0x6C);
				MDC2_CTX c1;
				MDC2_Init(&c1);
				MDC2_Update(&c1, check1, 0x7E);
				MDC2_Final(&(mdc_hash1[0]), &c1);
				rdr_log_dump_dbg(reader, D_READER, mdc_hash1, 16, "MDC_HASH: ");
				if(memcmp(mdc_hash1 + 1, reader->ideakey1 + 1, 14) == 0)
				{
				rdr_log(reader, "DT05_00 is correct");
				}
				else
				{
				rdr_log(reader, "DT05_00 error - check MOD1");
				}
				rdr_log_dump_dbg(reader, D_READER, reader->kdt05_00, sizeof(reader->kdt05_00), "DT05_00: ");
			}
			if(reader->dt5num == 0x10)
			{
				IDEA_KEY_SCHEDULE ks;
				rsa_decrypt(reader->edata, 0x70, reader->out, reader->mod1, reader->mod1_length);
				memcpy(reader->kdt05_10, &reader->out[16], 6 * 16);
				memcpy(reader->ideakey1, reader->out, 16);
				memcpy(reader->block3, cta_res + 26 + 0x70, 8);
				idea_set_encrypt_key(reader->ideakey1, &ks);
				memset(reader->v, 0, sizeof(reader->v));
				idea_cbc_encrypt(reader->block3, reader->iout, 8, &ks, reader->v, IDEA_DECRYPT);
				memcpy(&reader->kdt05_10[6 * 16],reader->iout,8);
				rdr_log_dump_dbg(reader, D_READER, reader->kdt05_10, sizeof(reader->kdt05_10), "DT05_10: ");
			}
			if(reader->dt5num == 0x20)
			{
				rsa_decrypt(reader->edata, 0x70, reader->out, reader->mod2, reader->mod2_length);
				memcpy(reader->tmprsa, reader->out, 0x70);
				reader->hasunique = 1;
			}
			return OK;
		}
		case TIERS: // case 0x0C
		{
			uint16_t chid;
			if((cta_lr >= 0x30) && (chid = b2i(0x02, cta_res + 23)))
			{
				uint32_t id = b2i(0x02, cta_res + 19);
				uint32_t start_date;
				uint32_t expire_date1;
				uint32_t expire_date2;
				uint32_t expire_date;
				switch(reader->caid)
				{
					case 0x1830: // Max TV
					case 0x1843: // HD02
					case 0x1860: // HD03
					case 0x1861: // Polsat, Vodafone D08
						start_date = b2i(0x04, cta_res + 42);
						expire_date1 = b2i(0x04, cta_res + 28);
						expire_date2 = (reader->caid != 0x1861) ? b2i(0x04, cta_res + 46) : expire_date1;
						expire_date = expire_date1 <= expire_date2 ? expire_date1 : expire_date2;
						break;
					case 0x186A: // HD04, HD05
						start_date = b2i(0x04, cta_res + 53);
						expire_date1 = b2i(0x04, cta_res + 39);
						expire_date2 = b2i(0x04, cta_res + 57);
						expire_date = expire_date1 <= expire_date2 ? expire_date1 : expire_date2;
						break;
					default: // unknown card
						start_date = 1;
						expire_date = 0xA69EFB7F;
				}
				cs_add_entitlement(reader,
					reader->caid,
					id,
					chid,
					0,
					tier_date(start_date, ds, 11),
					tier_date(expire_date, de, 11),
					4,
					1);
				rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
				addProvider(reader, cta_res + 19);
			}
			return OK;
		}
		default:
			return OK;
	}
	return ERROR;
}
static int32_t CAK7do_cmd(struct s_reader *reader, uint8_t dt, uint8_t len, uint8_t *res, uint16_t *rlen, int32_t sub, uint8_t retlen)
{
	uint8_t dtdata[0x10];
	memset(dtdata, 0xCC, len);
	dtdata[7] = 0x04;
	dtdata[8] = 0x04;
	dtdata[9]  = (sub >> 16) & 0xFF;
	dtdata[10] = (sub >> 8) & 0xFF;
	dtdata[11] = (sub) & 0xFF;
	dtdata[12] = dt;
	do_cak7_cmd(reader, res, rlen, dtdata, sizeof(dtdata), retlen);
	return OK;
}
static int32_t CAK7GetDataType(struct s_reader *reader, uint8_t dt)
{
	def_resp;
	int32_t sub = 0x00;
	uint8_t retlen = 0x10;
	while(1)
	{
		CAK7do_cmd(reader, dt, 0x10, cta_res, &cta_lr, sub, retlen);
		rdr_log_dump_dbg(reader, D_READER, cta_res, cta_lr, "Decrypted Answer:");
		// hier eigentlich check auf 90 am ende usw... obs halt klarging ...
		if(cta_lr == 0)
		{
			break;
		}
		if(cta_res[cta_lr-2] == 0x6F && cta_res[cta_lr-1] == 0x01)
		{
			reader->card_status = CARD_NEED_INIT;
			add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
			break;
		}
		uint32_t newsub = (cta_res[9] << 16) + (cta_res[10] << 8) + (cta_res[11]);
		if(newsub == 0xFFFFFF)
		{
			break;
		}
		if(cta_res[12] == dt)
		{
			uint8_t oretlen = retlen;
			retlen = cta_res[13] + 0x10 + 0x2;
			while(retlen % 0x10 != 0x00)
			{
				retlen++;
			}
			if(retlen == oretlen)
			{
				sub = newsub + 1;
				retlen = 0x10;
				ParseDataType(reader, dt, cta_res, cta_lr);
			}
		}
		else
		{
			break;
		}
	}
	return OK;
}
static void sub_6AD78(uint32_t *dinit) // gbox function
{
	uint32_t v0 = (uint32_t) * dinit;
	double f0;
	f0 = v0;
	double f12 = 16807;
	double f15 = 2147483647;
	f12 = f0 * f12;
	double v12;
	v12 = fmod(f12, f15);
	*dinit = v12;
}
static void calc_cak7_exponent(uint32_t *dinit, uint8_t *out, uint8_t len)
{
	memset(out, 0x00, len);
	sub_6AD78(dinit);
	int nR4 = 0;
	int nR5 = 0;
	while(true)
	{
		uint32_t nR0 = (uint32_t)* dinit;
		int nR3 = nR4 + 3;
		nR5 += 4;
		if(nR3 > len)
		{
			break;
		}
		out[nR5 - 1] = ((nR0    ) & 0xFF);
		out[nR5 - 2] = ((nR0 >> 8) & 0xFF);
		out[nR5 - 3] = ((nR0 >> 16) & 0xFF);
		out[nR5 - 4] = ((nR0 >> 24) & 0xFF);
		nR4 += 4;
		sub_6AD78(dinit);
	}
	uint32_t nR0 = (uint32_t)* dinit;
	while(nR4 < len)
	{
		out[nR4] = nR0 & 0xFF;
		nR4++;
		nR0 >>= 8;
	}
	out[0] &= 0x03;
	out[0x10] |= 0x01;
}
static void IdeaDecrypt(unsigned char *data, int len, const unsigned char *key, unsigned char *iv)
{
	unsigned char v[8];
	if(!iv) { memset(v,0,sizeof(v)); iv=v; }
	IDEA_KEY_SCHEDULE ks;
	idea_set_encrypt_key(key,&ks);
	idea_cbc_encrypt(data,data,len&~7,&ks,iv,IDEA_DECRYPT);
}
static inline void xxxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2)
{
	int i;
	switch(len)
	{
	case 16:
	case 8:
	case 4:
		for(i = 0; i < len; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
		break;
	default:
		while(len--)
		{
			*data++ = *v1++ ^ *v2++;
		}
		break;
	}
}
static void CreateRSAPair60(struct s_reader *reader, const unsigned char *key)
{
unsigned char idata[96];
int i;
for(i=11; i>=0; i--) {
unsigned char *d=&idata[i*8];
memcpy(d,&key[13],8);
*d^=i;
IdeaDecrypt(d,8,key,0);
xxxor(d,8,d,&key[13]);
*d^=i;
}
BN_CTX *ctx5 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
BN_CTX_start(ctx5);
#endif
BIGNUM *p = BN_CTX_get(ctx5);
BIGNUM *q = BN_CTX_get(ctx5);
BIGNUM *m = BN_CTX_get(ctx5);
BIGNUM *e = BN_CTX_get(ctx5);
BIGNUM *a = BN_CTX_get(ctx5);
BIGNUM *r = BN_CTX_get(ctx5);
// Calculate P
idata[0] |= 0x80;
idata[47] |= 1;
BN_bin2bn(idata,48,p);
BN_add_word(p,(key[21] << 5 ) | ((key[22] & 0xf0) >> 3));
// Calculate Q
idata[48] |= 0x80;
idata[95] |= 1;
BN_bin2bn(idata+48,48,q);
BN_add_word(q,((key[22]&0xf)<<9) | (key[23]<<1));
// Calculate M=P*Q
BN_mul(m,p,q,ctx5);
memset(reader->key60,0x00,0x60);
BN_bn2bin(m, reader->key60 + (0x60 - BN_num_bytes(m)));
rdr_log_dump_dbg(reader, D_READER, reader->key60, sizeof(reader->key60), "key60: ");
// Calculate D
BN_sub_word(p,1);
BN_sub_word(q,1);
BN_mul(e,p,q,ctx5);
BN_bin2bn(public_exponent,3,a);
BN_mod_inverse(r, a, e, ctx5);
memset(reader->exp60,0x00,0x60);
BN_bn2bin(r, reader->exp60 + (0x60 - BN_num_bytes(r)));
rdr_log_dump_dbg(reader, D_READER, reader->exp60, sizeof(reader->exp60), "exp60: ");
BN_CTX_end(ctx5);
BN_CTX_free(ctx5);
}
static void CreateRSAPair68(struct s_reader *reader, const unsigned char *key)
{
unsigned char idata[104];
int i;
for(i=12; i>=0; i--) {
unsigned char *d=&idata[i*8];
memcpy(d,&key[13],8);
*d^=i;
IdeaDecrypt(d,8,key,0);
xxxor(d,8,d,&key[13]);
*d^=i;
}
BN_CTX *ctx6 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
BN_CTX_start(ctx6);
#endif
BIGNUM *p = BN_CTX_get(ctx6);
BIGNUM *q = BN_CTX_get(ctx6);
BIGNUM *m = BN_CTX_get(ctx6);
BIGNUM *e = BN_CTX_get(ctx6);
BIGNUM *a = BN_CTX_get(ctx6);
BIGNUM *r = BN_CTX_get(ctx6);
// Calculate P
idata[0] |= 0x80;
idata[51] |= 1;
BN_bin2bn(idata,52,p);
BN_add_word(p,(key[21] << 5 ) | ((key[22] & 0xf0) >> 3));
// Calculate Q
idata[52] |= 0x80;
idata[103] |= 1;
BN_bin2bn(idata+52,52,q);
BN_add_word(q,((key[22]&0xf)<<9) | (key[23]<<1));
// Calculate M=P*Q
BN_mul(m,p,q,ctx6);
memset(reader->key68,0x00,0x68);
BN_bn2bin(m, reader->key68 + (0x68 - BN_num_bytes(m)));
rdr_log_dump_dbg(reader, D_READER, reader->key68, sizeof(reader->key68), "key68: ");
// Calculate D
BN_sub_word(p,1);
BN_sub_word(q,1);
BN_mul(e,p,q,ctx6);
BN_bin2bn(public_exponent,3,a);
BN_mod_inverse(r, a, e, ctx6);
memset(reader->exp68,0x00,0x68);
BN_bn2bin(r, reader->exp68 + (0x68 - BN_num_bytes(r)));
rdr_log_dump_dbg(reader, D_READER, reader->exp68, sizeof(reader->exp68), "exp68: ");
BN_CTX_end(ctx6);
BN_CTX_free(ctx6);
}
static void dt05_20(struct s_reader *reader)
{
	uint8_t data_20_00[72];
	uint8_t sig_20_00[16];
	uint8_t data_20_id[72];
	uint8_t data_20_x[64];
	uint8_t data_20_fin[72];
	uint8_t data_20_flag58[16];
	rdr_log_dump_dbg(reader, D_READER, reader->tmprsa, sizeof(reader->tmprsa), "DT05_20 after RSA: ");
	// copy signature
	memcpy(sig_20_00, reader->tmprsa+24, 16);
	// copy data
	memcpy(data_20_00, reader->tmprsa+40, 72);
	// IDEA encrypt 0x48 data
	int i;
	int offs = 0;
	for(i=0; i<9; i++)
	{
		IDEA_KEY_SCHEDULE ks;
		idea_set_encrypt_key(reader->key3310, &ks);
		idea_ecb_encrypt(data_20_00+offs, data_20_id+offs, &ks);
		offs+=8;
	}
	// xor
	for (i=0; i<64; i++)
	{
		data_20_x[i] = data_20_00[i] ^ data_20_id[i+8];
	}
	rdr_log_dump_dbg(reader, D_READER, data_20_x, sizeof(data_20_x), "data_20_x: ");
	// create final data block
	memcpy(data_20_fin,data_20_id,8);
	memcpy(data_20_fin+8,data_20_x,64);
	rdr_log_dump_dbg(reader, D_READER, data_20_fin, sizeof(data_20_fin), "data_20_fin: ");
	uint8_t mdc_hash4[MDC2_DIGEST_LENGTH];
	memset(mdc_hash4,0x00,MDC2_DIGEST_LENGTH);
	uint8_t check4[112];
	memset(check4, 0x00, 112);
	memcpy(check4, reader->cardid, 4);
	memcpy(check4 + 4, reader->idird, 4);
	memcpy(check4 + 23, reader->tmprsa + 23, 1);
	memcpy(check4 + 40, data_20_fin, 72);
	MDC2_CTX c4;
	MDC2_Init(&c4);
	MDC2_Update(&c4, check4, 112);
	MDC2_Final(&(mdc_hash4[0]), &c4);
	if(memcmp(mdc_hash4, sig_20_00, 16) == 0)
	{
	rdr_log(reader, "DT05_20 is correct");
	}
	else
	{
	rdr_log(reader, "DT05_20 error - check MOD2");
	}
	// Store 3des software key Flag58 CW overencrypt
	memcpy(data_20_flag58, data_20_x+16, 16);
	memcpy(reader->key3des, data_20_flag58, 16);
	rdr_log_dump_dbg(reader, D_READER, reader->key3des, sizeof(reader->key3des), "Flag58 3DES Key: ");
	// create rsa pair from final data
	memcpy(reader->klucz68, data_20_fin, 0x18);
	rdr_log_dump_dbg(reader, D_READER, reader->klucz68, sizeof(reader->klucz68), "klucz68: ");
}
static int32_t CAK7_cmd03_global(struct s_reader *reader)
{
	def_resp;
	if(reader->cak7_seq <= 15)
	{
		unsigned char klucz[24];
		memset(klucz, 0x00, 24);
		memcpy(klucz, reader->key3588, 24);
		CreateRSAPair60(reader, klucz);
	}
	BN_CTX *ctx1 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx1);
#endif
	BIGNUM *bnN1 = BN_CTX_get(ctx1);
	BIGNUM *bnE1 = BN_CTX_get(ctx1);
	BIGNUM *bnCT1 = BN_CTX_get(ctx1);
	BIGNUM *bnPT1 = BN_CTX_get(ctx1);
	BN_bin2bn(&reader->key60[0], 0x60, bnN1);
	BN_bin2bn(&reader->exp60[0], 0x60, bnE1);
	BN_bin2bn(&reader->step1[0], 0x60, bnCT1);
	BN_mod_exp(bnPT1, bnCT1, bnE1, bnN1, ctx1);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT1, reader->data + (0x60 - BN_num_bytes(bnPT1)));
	BN_CTX_end(ctx1);
	BN_CTX_free(ctx1);
	memcpy(&reader->step2[0], d00ff, 4);
	memcpy(&reader->step2[4], reader->cardid, 4);
	memcpy(&reader->step2[8], reader->data, 0x60);
	rdr_log_dump_dbg(reader, D_READER, reader->step2, sizeof(reader->step2), "STEP 2:");
	BN_CTX *ctx2 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx2);
#endif
	BIGNUM *bnN2 = BN_CTX_get(ctx2);
	BIGNUM *bnE2 = BN_CTX_get(ctx2);
	BIGNUM *bnCT2 = BN_CTX_get(ctx2);
	BIGNUM *bnPT2 = BN_CTX_get(ctx2);
	BN_bin2bn(&reader->kdt05_10[0], 0x68, bnN2);
	BN_bin2bn(public_exponent, 3, bnE2);
	BN_bin2bn(&reader->step2[0], 0x68, bnCT2);
	BN_mod_exp(bnPT2, bnCT2, bnE2, bnN2, ctx2);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT2, reader->data + (0x68 - BN_num_bytes(bnPT2)));
	BN_CTX_end(ctx2);
	BN_CTX_free(ctx2);
	memcpy(&reader->step3[0], d00ff, 4);
	memcpy(&reader->step3[4], reader->data, 0x68);
	rdr_log_dump_dbg(reader, D_READER, reader->step3, sizeof(reader->step3), "STEP 3:");
	BN_CTX *ctx3 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx3);
#endif
	BIGNUM *bnN3 = BN_CTX_get(ctx3);
	BIGNUM *bnE3 = BN_CTX_get(ctx3);
	BIGNUM *bnCT3 = BN_CTX_get(ctx3);
	BIGNUM *bnPT3 = BN_CTX_get(ctx3);
	BN_bin2bn(&reader->kdt05_00[0], 0x6c, bnN3);
	BN_bin2bn(public_exponent, 3, bnE3);
	BN_bin2bn(&reader->step3[0], 0x6c, bnCT3);
	BN_mod_exp(bnPT3, bnCT3, bnE3, bnN3, ctx3);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT3, reader->data + (0x6c - BN_num_bytes(bnPT3)));
	BN_CTX_end(ctx3);
	BN_CTX_free(ctx3);
	uint8_t cmd03[] = {0xCC,0xCC,0xCC,0xCC,0x00,0x00,0x0A,0x03,0x6C,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC};
	memcpy(&cmd03[9],reader->data,0x6c);
	do_cak7_cmd(reader,cta_res,&cta_lr,cmd03,sizeof(cmd03),0x90);
	if(cta_lr == 0)
	{
		rdr_log(reader, "card is not responding to CMD03 - check your data");
		return ERROR;
	}
	rdr_log_dump_dbg(reader, D_READER, cta_res, 0x90, "CMD03 ANSWER:");
	memcpy(reader->encrypted,&cta_res[10],0x68);
	BN_CTX *ctx = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx);
#endif
	BIGNUM *bnN = BN_CTX_get(ctx);
	BIGNUM *bnE = BN_CTX_get(ctx);
	BIGNUM *bnCT = BN_CTX_get(ctx);
	BIGNUM *bnPT = BN_CTX_get(ctx);
	BN_bin2bn(&reader->kdt05_10[0], 104, bnN);
	BN_bin2bn(public_exponent, 3, bnE);
	BN_bin2bn(&reader->encrypted[0], 104, bnCT);
	BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
	memset(reader->result, 0, 104);
	BN_bn2bin(bnPT, reader->result + (104 - BN_num_bytes(bnPT)));
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	//uint8_t stillencrypted[0x50];
	memcpy(reader->stillencrypted,&reader->result[12],0x50);
	//uint8_t resultrsa[0x50];
	BN_CTX *ctxs = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctxs);
#endif
	BIGNUM *bnNs  = BN_CTX_get(ctxs);
	BIGNUM *bnEs  = BN_CTX_get(ctxs);
	BIGNUM *bnCTs = BN_CTX_get(ctxs);
	BIGNUM *bnPTs = BN_CTX_get(ctxs);
	BN_bin2bn(&reader->mod50[0], reader->mod50_length, bnNs);
	BN_bin2bn(&reader->cak7expo[0], 0x11, bnEs);
	BN_bin2bn(&reader->stillencrypted[0], 0x50, bnCTs);
	BN_mod_exp(bnPTs, bnCTs, bnEs, bnNs, ctxs);
	memset(reader->resultrsa, 0x00, 0x50);
	BN_bn2bin(bnPTs, reader->resultrsa + (0x50 - BN_num_bytes(bnPTs)));
	BN_CTX_end(ctxs);
	BN_CTX_free(ctxs);
	uint8_t mdc_hash3[MDC2_DIGEST_LENGTH];
	memset(mdc_hash3,0x00,MDC2_DIGEST_LENGTH);
	MDC2_CTX c3;
	MDC2_Init(&c3);
	MDC2_Update(&c3, reader->resultrsa, sizeof(reader->resultrsa));
	MDC2_Final(&(mdc_hash3[0]), &c3);
	memcpy(&reader->cak7_aes_key[16],mdc_hash3,16);
	memcpy(reader->cak7_aes_key,mdc_hash3,16);
	char tmp7[128];
	rdr_log(reader, "New AES: %s", cs_hexdump(1, reader->cak7_aes_key, 16, tmp7, sizeof(tmp7)));
	return OK;
}
static int32_t CAK7_cmd03_unique(struct s_reader *reader)
{
	def_resp;
	BN_CTX *ctx1 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx1);
#endif
	BIGNUM *bnN1 = BN_CTX_get(ctx1);
	BIGNUM *bnE1 = BN_CTX_get(ctx1);
	BIGNUM *bnCT1 = BN_CTX_get(ctx1);
	BIGNUM *bnPT1 = BN_CTX_get(ctx1);
	BN_bin2bn(&reader->key3460[0], 0x60, bnN1);
	BN_bin2bn(public_exponent, 3, bnE1);
	BN_bin2bn(&reader->step1[0], 0x60, bnCT1);
	BN_mod_exp(bnPT1, bnCT1, bnE1, bnN1, ctx1);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT1, reader->data + (0x60 - BN_num_bytes(bnPT1)));
	BN_CTX_end(ctx1);
	BN_CTX_free(ctx1);
	memcpy(&reader->step2[0], d00ff, 4);
	memcpy(&reader->step2[4], reader->cardid, 4);
	memcpy(&reader->step2[8], reader->data, 0x60);
	rdr_log_dump_dbg(reader, D_READER, reader->step2, sizeof(reader->step2), "STEP 2:");
	if(reader->cak7_seq <= 15)
	{
		dt05_20(reader);
		CreateRSAPair68(reader, reader->klucz68);
	}
	BN_CTX *ctx2 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx2);
#endif
	BIGNUM *bnN2 = BN_CTX_get(ctx2);
	BIGNUM *bnE2 = BN_CTX_get(ctx2);
	BIGNUM *bnCT2 = BN_CTX_get(ctx2);
	BIGNUM *bnPT2 = BN_CTX_get(ctx2);
	BN_bin2bn(&reader->key68[0], 0x68, bnN2);
	BN_bin2bn(&reader->exp68[0], 0x68, bnE2);
	BN_bin2bn(&reader->step2[0], 0x68, bnCT2);
	BN_mod_exp(bnPT2, bnCT2, bnE2, bnN2, ctx2);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT2, reader->data + (0x68 - BN_num_bytes(bnPT2)));
	BN_CTX_end(ctx2);
	BN_CTX_free(ctx2);
	memcpy(&reader->step3[0], d00ff, 4);
	memcpy(&reader->step3[4], reader->data, 0x68);
	rdr_log_dump_dbg(reader, D_READER, reader->step3, sizeof(reader->step3), "STEP 3:");
	BN_CTX *ctx3 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx3);
#endif
	BIGNUM *bnN3 = BN_CTX_get(ctx3);
	BIGNUM *bnE3 = BN_CTX_get(ctx3);
	BIGNUM *bnCT3 = BN_CTX_get(ctx3);
	BIGNUM *bnPT3 = BN_CTX_get(ctx3);
	BN_bin2bn(&reader->kdt05_00[0], 0x6c, bnN3);
	BN_bin2bn(public_exponent, 3, bnE3);
	BN_bin2bn(&reader->step3[0], 0x6c, bnCT3);
	BN_mod_exp(bnPT3, bnCT3, bnE3, bnN3, ctx3);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT3, reader->data + (0x6c - BN_num_bytes(bnPT3)));
	BN_CTX_end(ctx3);
	BN_CTX_free(ctx3);
	uint8_t cmd03[] = {0xCC,0xCC,0xCC,0xCC,0x00,0x00,0x0A,0x03,0x6C,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC};
	memcpy(&cmd03[9],reader->data,0x6c);
	do_cak7_cmd(reader,cta_res,&cta_lr,cmd03,sizeof(cmd03),0x90);
	if(cta_lr == 0)
	{
		rdr_log(reader, "card is not responding to CMD03 - check your data");
		return ERROR;
	}
	rdr_log_dump_dbg(reader, D_READER, cta_res, 0x90, "CMD03 ANSWER:");
	memcpy(reader->encrypted,&cta_res[18],0x60);
	BN_CTX *ctx = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx);
#endif
	BIGNUM *bnN = BN_CTX_get(ctx);
	BIGNUM *bnE = BN_CTX_get(ctx);
	BIGNUM *bnCT = BN_CTX_get(ctx);
	BIGNUM *bnPT = BN_CTX_get(ctx);
	BN_bin2bn(&reader->key3460[0], 96, bnN);
	BN_bin2bn(public_exponent, 3, bnE);
	BN_bin2bn(&reader->encrypted[0], 96, bnCT);
	BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
	memset(reader->result, 0, 96);
	BN_bn2bin(bnPT, reader->result + (96 - BN_num_bytes(bnPT)));
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	rdr_log_dump_dbg(reader, D_READER, reader->result, 96, "after RSA_3460: ");
	//uint8_t stillencrypted[0x50];
	memcpy(reader->stillencrypted,&reader->result[4],0x50);
	//uint8_t resultrsa[0x50];
	BN_CTX *ctxs = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctxs);
#endif
	BIGNUM *bnNs  = BN_CTX_get(ctxs);
	BIGNUM *bnEs  = BN_CTX_get(ctxs);
	BIGNUM *bnCTs = BN_CTX_get(ctxs);
	BIGNUM *bnPTs = BN_CTX_get(ctxs);
	BN_bin2bn(&reader->mod50[0], reader->mod50_length, bnNs);
	BN_bin2bn(&reader->cak7expo[0], 0x11, bnEs);
	BN_bin2bn(&reader->stillencrypted[0], 0x50, bnCTs);
	BN_mod_exp(bnPTs, bnCTs, bnEs, bnNs, ctxs);
	memset(reader->resultrsa, 0x00, 0x50);
	BN_bn2bin(bnPTs, reader->resultrsa + (0x50 - BN_num_bytes(bnPTs)));
	BN_CTX_end(ctxs);
	BN_CTX_free(ctxs);
	uint8_t mdc_hash5[MDC2_DIGEST_LENGTH];
	memset(mdc_hash5,0x00,MDC2_DIGEST_LENGTH);
	MDC2_CTX c5;
	MDC2_Init(&c5);
	MDC2_Update(&c5, reader->resultrsa, sizeof(reader->resultrsa));
	MDC2_Final(&(mdc_hash5[0]), &c5);
	memcpy(&reader->cak7_aes_key[16],mdc_hash5,16);
	memcpy(reader->cak7_aes_key,mdc_hash5,16);
	char tmp7[128];
	rdr_log(reader, "New AES: %s", cs_hexdump(1, reader->cak7_aes_key, 16, tmp7, sizeof(tmp7)));
	return OK;
}
static int32_t CAK7_GetCamKey(struct s_reader *reader)
{
	def_resp;
	uint8_t cmd0e[] = {0xCC,0xCC,0xCC,0xCC,0x00,0x00,0x00,0x0E,0x83,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC};
	if(!reader->nuid_length)
	{
		uint8_t cmd02[] = {0x02,0x7B};
		memcpy(cmd0e + 7, cmd02, 2);
		rdr_log(reader, "using CMD02");
	}
	else
	{
		int cwekeycount = 0, i;
		memcpy(cmd0e + 132, reader->nuid, reader->nuid_length); // inject NUID

		for (i = 0; i < 8; i++)
			cwekeycount += !!reader->cwekey_length[i];

		if(cwekeycount == 0)
		{
			rdr_log(reader, "only NUID defined - enter at least CWPK0");
			return ERROR;
		}
		else
		{
			if(reader->otpcsc_length)
			{
				memcpy(cmd0e + 136, reader->otpcsc, reader->otpcsc_length);
			}
			else
			{
				cmd0e[136] = 0x00;
				cmd0e[137] = !reader->cwpkota ? cwekeycount: 0x00;
			}
			if(reader->otacsc_length)
			{
				memcpy(cmd0e + 138, reader->otacsc, reader->otacsc_length);
			}
			else
			{
				cmd0e[138] = 0x00;
				cmd0e[139] = reader->cwpkota ? cwekeycount : 0x00;
			}
		}
		char tmp[16];
		rdr_log(reader, "OTP CSC No. of keys: %s", cs_hexdump(1, cmd0e + 136, 2, tmp, sizeof(tmp)));
		rdr_log(reader, "OTA CSC No. of keys: %s", cs_hexdump(1, cmd0e + 138, 2, tmp, sizeof(tmp)));
	}
	if(reader->forcepair_length)
	{
		rdr_log(reader, "Forcing Pairing Type");
		memcpy(cmd0e + 13, reader->forcepair, 1);
	}
	else
	{
		if(reader->hasunique == 1)
		{
			cmd0e[13] = 0x40;
		}
	}
	memcpy(cmd0e + 14, reader->idird, 4);
	memcpy(reader->irdId, reader->idird, 4);
	if(reader->cmd0eprov_length)
	{
		memcpy(cmd0e + 18, reader->cmd0eprov, 2);
	}
	else
	{
		memcpy(cmd0e + 18, reader->prid[0] + 2, 2);
	}
	memcpy(cmd0e + 20, reader->key3588 + 24, 0x70);
	if(reader->cak7_seq <= 15)
	{
		srand(time(NULL));
	}
	uint32_t data1r = rand() % 4294967294u;
	reader->timestmp1[0]=(data1r>>24)&0xFF;
	reader->timestmp1[1]=(data1r>>16)&0xFF;
	reader->timestmp1[2]=(data1r>>8)&0xFF;
	reader->timestmp1[3]=(data1r)&0xFF;
	memcpy(cmd0e + 9, reader->timestmp1, 0x04);
	rdr_log_dump_dbg(reader, D_READER, reader->timestmp1, 4, "DATA1  CMD0E:");
	rdr_log_dump_dbg(reader, D_READER, reader->prid[0], 4, "SysID:");
	do_cak7_cmd(reader,cta_res, &cta_lr, cmd0e, sizeof(cmd0e), 0x20);
	if(cta_lr == 0)
	{
		rdr_log(reader, "card is not responding to CMD02/E - check your data");
		return ERROR;
	}
	rdr_log_dump_dbg(reader, D_READER, cta_res, 0x20, "Decrypted answer to CMD02/0E:");
	reader->needrestart =  (cta_res[22] << 16);
	reader->needrestart += (cta_res[23] <<  8);
	reader->needrestart += (cta_res[24]      );
	reader->needrestart--;
	if(reader->cak7_seq <= 15)
	{
		rdr_log(reader, "card needs FASTreinit after %d CMDs", reader->needrestart);
	}
	else
	{
		uint32_t cmdleft = reader->needrestart - reader->cak7_seq;
		rdr_log(reader, "%d CMDs left to FASTreinit", cmdleft);
	}
	reader->dword_83DBC =  (cta_res[18] << 24);
	reader->dword_83DBC += (cta_res[19] << 16);
	reader->dword_83DBC += (cta_res[20] <<  8);
	reader->dword_83DBC += (cta_res[21]      );
	calc_cak7_exponent(&reader->dword_83DBC, reader->cak7expo, 0x11);
	rdr_log_dump_dbg(reader, D_READER, reader->cak7expo, 0x11, "CAK7 Exponent:");
	memcpy(reader->cardid,cta_res + 14, 4);
	rdr_log_dump_dbg(reader, D_READER, reader->cardid, 0x04, "CardSerial: ");
	memcpy(reader->hexserial + 2, reader->cardid, 4);
	unsigned long datal = (cta_res[9] << 24) + (cta_res[10] << 16) + (cta_res[11] << 8) + (cta_res[12]);
	datal++;
	reader->data2[0] = (datal >> 24) & 0xFF;
	reader->data2[1] = (datal >> 16) & 0xFF;
	reader->data2[2] = (datal >>  8) & 0xFF;
	reader->data2[3] = (datal      ) & 0xFF;
	data1r++;
	reader->timestmp2[0]=(data1r>>24)&0xFF;
	reader->timestmp2[1]=(data1r>>16)&0xFF;
	reader->timestmp2[2]=(data1r>>8)&0xFF;
	reader->timestmp2[3]=(data1r)&0xFF;
	memcpy(reader->ecmheader,cta_res + 18,4);
	if(reader->cak7_seq <= 15)
	{
		uint8_t mdc_hash2[MDC2_DIGEST_LENGTH];
		memset(mdc_hash2,0x00,MDC2_DIGEST_LENGTH);
		uint8_t check2[0x78];
		memset(check2, 0x00, 0x78);
		memcpy(check2, reader->cardid, 4);
		memcpy(check2 + 16, reader->kdt05_10, 0x68);
		MDC2_CTX c2;
		MDC2_Init(&c2);
		MDC2_Update(&c2, check2, 0x78);
		MDC2_Final(&(mdc_hash2[0]), &c2);
		rdr_log_dump_dbg(reader, D_READER, reader->ideakey1, 16, "IDEAKEY1: ");
		rdr_log_dump_dbg(reader, D_READER, mdc_hash2, 16, "MDC_HASH: ");
		if(memcmp(mdc_hash2 + 1, reader->ideakey1 + 1, 14) == 0)
		{
		rdr_log(reader, "DT05_10 is correct");
		}
		else
		{
		rdr_log(reader, "DT05_10 error - check MOD1");
		}
	}
	BN_CTX *ctx0 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx0);
#endif
	BIGNUM *bnN0 = BN_CTX_get(ctx0);
	BIGNUM *bnE0 = BN_CTX_get(ctx0);
	BIGNUM *bnCT0 = BN_CTX_get(ctx0);
	BIGNUM *bnPT0 = BN_CTX_get(ctx0);
	BN_bin2bn(&reader->mod50[0], 0x50, bnN0);
	BN_bin2bn(&reader->cak7expo[0], 0x11, bnE0);
	BN_bin2bn(&reader->data50[0], 0x50, bnCT0);
	BN_mod_exp(bnPT0, bnCT0, bnE0, bnN0, ctx0);
	memset(reader->data, 0x00, sizeof(reader->data));
	BN_bn2bin(bnPT0, reader->data + (0x50 - BN_num_bytes(bnPT0)));
	BN_CTX_end(ctx0);
	BN_CTX_free(ctx0);
	rdr_log_dump_dbg(reader, D_READER, reader->timestmp2, 4, "DATA1  CMD03:");
	memcpy(&reader->step1[0], d00ff, 4);
	memcpy(&reader->step1[4], reader->data, 0x50);
	memcpy(&reader->step1[4 + 0x50], reader->idird, 0x04);
	memcpy(&reader->step1[4 + 4 + 0x50], reader->timestmp2, 0x04);
	memcpy(&reader->step1[4 + 4 + 4 + 0x50], reader->data2, 0x04);
	rdr_log_dump_dbg(reader, D_READER, reader->step1, sizeof(reader->step1), "STEP 1:");
	reader->pairtype = cta_res[13];
	if((reader->pairtype > 0x00) && (reader->pairtype < 0xC0))
	{
		rdr_log(reader,"Card is starting in GLOBAL mode");
		if(!CAK7_cmd03_global(reader))
		{return ERROR;}
	}
	else if(reader->pairtype == 0xC0)
	{
		rdr_log(reader,"Card is starting in UNIQUE mode");
		if(!reader->mod2_length)
			{
					rdr_log(reader, "no mod2 defined");
					return ERROR;
			}
				if(!reader->key3460_length)
				{
						rdr_log(reader, "no key3460 defined");
						return ERROR;
				}
				if(!reader->key3310_length)
				{
						rdr_log(reader, "no key3310 defined");
						return ERROR;
				}
		if(!CAK7_cmd03_unique(reader))
		{return ERROR;}
	}
	else
	{
		rdr_log(reader,"Unknown Pairing Type");
		return ERROR;
	}
	return OK;
}
static int32_t nagra3_card_init(struct s_reader *reader, ATR *newatr)
{
	get_atr;
	memset(reader->hexserial, 0, 8);
	reader->cak7_seq = 0;
	reader->hasunique = 0;
	memset(reader->ecmheader, 0, 4);
	cs_clear_entitlement(reader);
	if(memcmp(atr + 8, "DNASP4", 6) == 0)
	{
		if((memcmp(atr + 8, "DNASP400", 8) == 0) && !reader->cak7_mode)
		{
			return ERROR;
		}
		else
		{
			memcpy(reader->rom, atr + 8, 15);
			rdr_log(reader,"Rom revision: %.15s", reader->rom);
		}
	}
	else if(memcmp(atr + 11, "DNASP4", 6) == 0)
	{
		memcpy(reader->rom, atr + 11, 15);
		rdr_log(reader,"Rom revision: %.15s", reader->rom);
	}
	else
	{
		return ERROR;
	}
	reader->nprov   = 1;
	/*reader->nsa     = 0;
	reader->nemm84  = 0;
	reader->nemm83u = 0;
	reader->nemm83s = 0;
	reader->nemm87  = 0;*/
	if(!reader->mod1_length)
	{
		rdr_log(reader, "no MOD1 defined");
		return ERROR;
	}
	if(!reader->key3588_length)
	{
				rdr_log(reader, "no key3588 defined");
				return ERROR;
		}
		if(!reader->data50_length)
		{
				rdr_log(reader, "no data50 defined");
				return ERROR;
		}
		if(!reader->mod50_length)
		{
				rdr_log(reader, "no mod50 defined");
				return ERROR;
		}
		if(!reader->idird_length)
		{
				rdr_log(reader, "no idird defined");
				return ERROR;
		}
	CAK7GetDataType(reader, 0x02);
	CAK7GetDataType(reader, 0x05);
	if(!CAK7_GetCamKey(reader))
	{return ERROR;}
	CAK7GetDataType(reader, 0x09);
	char tmp[4 * 3 + 1];
	reader->nsa     = 0;
	reader->nemm84  = 0;
	reader->nemm83u = 0;
	reader->nemm83s = 0;
	reader->nemm87  = 0;
	CAK7GetDataType(reader, 0x04);
	if(reader->forceemmg)
	{
		reader->emm82 = 1;
	}
	int i;
	for(i = 1; i < reader->nprov; i++)
	{
		rdr_log(reader, "Prv.ID: %s", cs_hexdump(1, reader->prid[i], 4, tmp, sizeof(tmp)));
	}
	if(reader->cak7type != 3)
	{
		rdr_log(reader, "-----------------------------------------");
		rdr_log(reader, "|       EMM Filters (PRIVATE!!)         |");
		rdr_log(reader, "+---------------------------------------+");
		if(reader->emm82 == 1)
		{
			rdr_log(reader, "|emm82                                  |");
		}
		char tmp7[48];
		for(i = 0; i < reader->nemm84; i++)
		{
			rdr_log(reader, "|emm84 : %s                      |", cs_hexdump(1, reader->emm84[i], 3, tmp7, sizeof(tmp7)));
		}
		for(i = 0; i < reader->nemm83u; i++)
		{
			rdr_log(reader, "|emm83U: %s             |", cs_hexdump(1, reader->emm83u[i], 6, tmp7, sizeof(tmp7)));
		}
		for(i = 0; i < reader->nemm83s; i++)
		{
			rdr_log(reader, "|emm83S: %s             |", cs_hexdump(1, reader->emm83s[i], 6, tmp7, sizeof(tmp7)));
		}
		for(i = 0; i < reader->nemm87; i++)
		{
			rdr_log(reader, "|emm87 : %s             |", cs_hexdump(1, reader->emm87[i], 6, tmp7, sizeof(tmp7)));
		}
		rdr_log(reader, "-----------------------------------------");
	}
	rdr_log(reader, "ready for requests");
	return OK;
}
static int32_t nagra3_card_info(struct s_reader *reader)
{
	char tmp[4 * 3 + 1];
	rdr_log(reader, "ROM:    %c %c %c %c %c %c %c %c", reader->rom[0], reader->rom[1], reader->rom[2], reader->rom[3], reader->rom[4], reader->rom[5], reader->rom[6], reader->rom[7]);
	rdr_log(reader, "REV:    %c %c %c %c %c %c", reader->rom[9], reader->rom[10], reader->rom[11], reader->rom[12], reader->rom[13], reader->rom[14]);
	rdr_log_sensitive(reader, "SER:    {%s}", cs_hexdump(1, reader->hexserial + 2, 4, tmp, sizeof(tmp)));
	rdr_log(reader, "CAID:   %04X", reader->caid);
	rdr_log(reader, "Prv.ID: %s(sysid)", cs_hexdump(1, reader->prid[0], 4, tmp, sizeof(tmp)));
	cs_clear_entitlement(reader); // reset the entitlements
	rdr_log(reader, "-----------------------------------------");
	rdr_log(reader, "|id  |tier    |valid from  |valid to    |");
	rdr_log(reader, "+----+--------+------------+------------+");
	CAK7GetDataType(reader, 0x03);
	CAK7GetDataType(reader, 0x0C);
	rdr_log(reader, "-----------------------------------------");
	return OK;
}
static int32_t fastreinit(struct s_reader *reader)
{
	ATR newatr[ATR_MAX_SIZE];
	memset(newatr, 0, 1);
	if(ICC_Async_Activate(reader, newatr, 0))
	{
		return ERROR;
	}
	reader->cak7_seq = 0;
	if(!CAK7_GetCamKey(reader))
	{
		return ERROR;
	}
	return OK;
}
static void nagra3_post_process(struct s_reader *reader)
{
	if(reader->cak7_seq >= reader->needrestart)
	{
		rdr_log(reader, "card needs FASTreinit to prevent crash");
		if(!fastreinit(reader))
		{
			rdr_log(reader, "FASTreinit failed - need to restart reader");
			reader->card_status = CARD_NEED_INIT;
			add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
		}
	}
	else if((reader->cak7_camstate & 64) == 64)
	{
		rdr_log(reader, "negotiating new Session Key");
		if(!CAK7_GetCamKey(reader))
		{
			rdr_log(reader, "negotiations failed - trying FASTreinit");
			if(!fastreinit(reader))
			{
				rdr_log(reader, "FASTreinit failed - need to restart reader");
				reader->card_status = CARD_NEED_INIT;
				add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
			}
		}
	}
}
static int32_t nagra3_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp;
	if(reader->cak7type == 3)
	{
		if(er->ecm[2] > 0x61 && er->ecm[7] == 0x5C && er->ecm[100] == 0x0B)
		{
			if(er->ecm[101] == 0x03 || er->ecm[101] == 0x04)
			{
				if(er->ecm[104] > reader->pairtype)
				{
					rdr_log(reader, "reinit card in Unique Pairing Mode");
					return ERROR;
				}
				if(er->ecm[104] == 0x80 && reader->pairtype == 0x80)
				{
					rdr_log(reader, "reinit card in Unique Pairing Mode");
					return ERROR;
				}
			}
			if(er->ecm[101] == 0x04 && !reader->nuid_length)
			{
				rdr_log(reader, "reinit card with NUID");
				return ERROR;
			}
		}
	}
	else
	{
		if(er->ecm[2] > 0x86 && er->ecm[4] == 0x84 && er->ecm[137] == 0x0B)
		{
			if(er->ecm[138] == 0x03 || er->ecm[138] == 0x04)
			{
				if(er->ecm[141] > reader->pairtype)
				{
					rdr_log(reader, "reinit card in Unique Pairing Mode");
					return ERROR;
				}
				if(er->ecm[141] == 0x80 && reader->pairtype == 0x80)
				{
					rdr_log(reader, "reinit card in Unique Pairing Mode");
					return ERROR;
				}
			}
			if(er->ecm[138] == 0x04 && !reader->nuid_length)
			{
				rdr_log(reader, "reinit card with NUID");
				return ERROR;
			}
		}
	}
	uint8_t ecmreq[0xC0];
	memset(ecmreq,0xCC,0xC0);
	ecmreq[ 7] = 0x05;
	if(reader->caid == 0x1830)
	{
		ecmreq[ 9] = 0x00;
		ecmreq[10] = 0x00;
		ecmreq[11] = 0x00;
		ecmreq[12] = 0x00;
		ecmreq[13] = 0x00;
	}
	else
	{
		ecmreq[ 9] = 0x04;
		ecmreq[10] = reader->ecmheader[0];
		ecmreq[11] = reader->ecmheader[1];
		ecmreq[12] = reader->ecmheader[2];
		ecmreq[13] = reader->ecmheader[3];
	}
	if(reader->cak7type == 3)
	{
		ecmreq[8] = er->ecm[7] + 6;
		memcpy(&ecmreq[14], er->ecm + 7, er->ecm[7] + 1);
	}
	else
	{
		ecmreq[8] = er->ecm[4] + 6;
		memcpy(&ecmreq[14], er->ecm + 4, er->ecm[4] + 1);
	}
	if((er->ecm[2] == 0xAC) && (er->ecm[3] == 0x05))
	{
		ecmreq[15] = 0x0A;
	}
	do_cak7_cmd(reader, cta_res, &cta_lr, ecmreq, sizeof(ecmreq), 0xB0);
	rdr_log_dump_dbg(reader, D_READER, cta_res, 0xB0, "Decrypted ECM Answer:");
	if((cta_res[cta_lr - 2] != 0x90 && cta_res[cta_lr - 1] != 0x00) || cta_lr == 0)
	{
		rdr_log(reader, "(ECM) Reader will be restart now cause: %02X %02X card answer!!!", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
		reader->card_status = CARD_NEED_INIT;
		add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
	}
	else if(cta_res[27] != 0x00 && cta_res[27] != 0xCC)
	{
		memcpy(reader->ecmheader, cta_res + 9, 4);
		reader->cak7_camstate = cta_res[4];
		uint8_t _cwe0[8];
		uint8_t _cwe1[8];
		if(cta_res[78] == 0x01 || reader->forcecwswap)
		{
			memcpy(_cwe0,&cta_res[52], 0x08);
			memcpy(_cwe1,&cta_res[28], 0x08);
		}
		else
		{
			memcpy(_cwe0,&cta_res[28], 0x08);
			memcpy(_cwe1,&cta_res[52], 0x08);
		}
		if(cta_res[27] == 0x5C)
		{
			uint8_t cta_res144 = cta_res[144];
			if(cta_res144 < 0x08)
			{
				if(!reader->cwekey_length[cta_res144])
				{
					rdr_log(reader, "ERROR: CWPK%d is not set, can not decrypt CW", cta_res[144]);
					return ERROR;
				}
				des_ecb3_decrypt(_cwe0, reader->cwekey[cta_res144]);
				des_ecb3_decrypt(_cwe1, reader->cwekey[cta_res144]);
			}
		}
		else if(cta_res[27] == 0x58)
		{
			des_ecb3_decrypt(_cwe0, reader->key3des);
			des_ecb3_decrypt(_cwe1, reader->key3des);
		}
		rdr_log_dbg(reader, D_READER, "CW Decrypt ok");
		memcpy(ea->cw, _cwe0, 0x08);
		memcpy(ea->cw + 8, _cwe1, 0x08);
		return OK;
	}
	else if(cta_res[23] == 0x00)
	{
		memcpy(reader->ecmheader, cta_res + 9, 4);
		reader->cak7_camstate = cta_res[4];
		if(reader->hasunique && reader->pairtype < 0xC0)
		{
			rdr_log(reader, "reinit card in Unique Pairing Mode");
		}
		else
		{
			rdr_log(reader, "card has no right to decode this channel");
		}
	}
	else if(cta_res[23] == 0x04)
	{
		if(!reader->nuid_length)
		{
			rdr_log(reader, "reinit card with NUID");
		}
		else
		{
			rdr_log(reader, "wrong OTP/OTA CSC values");
		}
	}
	else
	{
		rdr_log(reader, "card got wrong ECM");
	}
	return ERROR;
}
static int32_t nagra3_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	def_resp;
	if(ep->emm[0] == 0x90)
	{
		rdr_log(reader, "OSCam got your BoxEMM");
		char tmp[128];
		rdr_log(reader, "NUID: %s", cs_hexdump(1, reader->nuid, 4, tmp, sizeof(tmp)));
		rdr_log(reader, "Index: %s", cs_hexdump(1, ep->emm + 10, 1, tmp, sizeof(tmp)));
		rdr_log(reader, "eCWPK: %s", cs_hexdump(1, ep->emm + 11, 16, tmp, sizeof(tmp)));
	}
	else
	{
		uint8_t emmreq[0xC0];
		memset(emmreq, 0xCC, 0xC0);
		emmreq[ 7] = 0x05;
		if(reader->caid == 0x1830)
		{
			emmreq[ 9] = 0x00;
			emmreq[10] = 0x00;
			emmreq[11] = 0x00;
			emmreq[12] = 0x00;
			emmreq[13] = 0x00;
		}
		else
		{
			emmreq[ 9] = 0x04;
			emmreq[10] = reader->ecmheader[0];
			emmreq[11] = reader->ecmheader[1];
			emmreq[12] = reader->ecmheader[2];
			emmreq[13] = reader->ecmheader[3];
		}
		if(reader->cak7type == 3)
		{
			int32_t i;
			uint8_t *prov_id_ptr;
			switch(ep->type)
			{
				case SHARED:
					emmreq[8] = ep->emm[9] + 6;
					prov_id_ptr = ep->emm + 3;
					memcpy(&emmreq[14], ep->emm + 9, ep->emm[9] + 1);
					break;
				case UNIQUE:
					emmreq[8] = ep->emm[12] + 6;
					prov_id_ptr = ep->emm + 9;
					memcpy(&emmreq[14], ep->emm + 12, ep->emm[12] + 1);
					break;
				case GLOBAL:
					emmreq[8] = ep->emm[6] + 6;
					prov_id_ptr = ep->emm + 3;
					memcpy(&emmreq[14], ep->emm + 6, ep->emm[6] + 1);
					break;
				default:
					rdr_log(reader, "EMM: Congratulations, you have discovered a new EMM on Merlin.");
					rdr_log(reader, "This has not been decoded yet.");
					return ERROR;
			}
			i = get_prov_index(reader, prov_id_ptr);
			if(i == -1)
			{
				rdr_log(reader, "EMM: skipped since provider id doesnt match");
				return SKIPPED;
			}
		}
		else
		{
			emmreq[8] = ep->emm[9] + 6;
			memcpy(&emmreq[14], ep->emm + 9, ep->emm[9] + 1);
		}
		do_cak7_cmd(reader, cta_res, &cta_lr, emmreq, sizeof(emmreq), 0xB0);
		if((cta_res[cta_lr-2] != 0x90 && cta_res[cta_lr-1] != 0x00) || cta_lr == 0)
		{
			rdr_log(reader, "(EMM) Reader will be restart now cause: %02X %02X card answer!!!", cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
			reader->card_status = CARD_NEED_INIT;
			add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
		}
		else
		{
			memcpy(reader->ecmheader, cta_res + 9, 4);
			if(reader->cak7_seq >= reader->needrestart)
			{
				rdr_log(reader, "card needs FASTreinit to prevent crash");
				if(!fastreinit(reader))
				{
					rdr_log(reader, "FASTreinit failed - need to restart reader");
					reader->card_status = CARD_NEED_INIT;
					add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
				}
			}
			else if((cta_res[4] & 64) == 64)
			{
				rdr_log(reader, "negotiating new Session Key");
				if(!CAK7_GetCamKey(reader))
				{
					rdr_log(reader, "negotiations failed - trying FASTreinit");
					if(!fastreinit(reader))
					{
						rdr_log(reader, "FASTreinit failed - need to restart reader");
						reader->card_status = CARD_NEED_INIT;
						add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
					}
				}
			}
		}
	}
	return OK;
}
const struct s_cardsystem reader_nagracak7 =
{
	.desc           = "nagra merlin",
	.caids          = (uint16_t[]){ 0x18, 0 },
	.do_emm         = nagra3_do_emm,
	.do_ecm         = nagra3_do_ecm,
	.post_process   = nagra3_post_process,
	.card_info      = nagra3_card_info,
	.card_init      = nagra3_card_init,
	.get_emm_type   = nagra_get_emm_type,
	.get_emm_filter = nagra_get_emm_filter,
};
#endif
