#include "globals.h"
#include <math.h>
#ifdef READER_NAGRA_MERLIN
#include "cscrypt/bn.h"
#include "cscrypt/idea.h"
#include "cscrypt/sha256.h"
#include "cscrypt/aescbc.h"
#include "csctapi/icc_async.h"
#include "oscam-time.h"
#include "reader-common.h"
#include "oscam-work.h"
#include "cscrypt/des.h"
#include "cscrypt/mdc2.h"
#include "reader-nagracak7.h"

const unsigned char exponent[] = {0x01, 0x00, 0x01};
const unsigned char d00ff[]    = {0x00,0xff,0xff,0xFF};
const unsigned char irdid[]    = {0x64,0x65,0x6D,0x6F};
const unsigned char data1[]    = {0x00,0x00,0x00,0x01};

struct nagra_data
{
	IDEA_KEY_SCHEDULE ksSession;
	int8_t		is_pure_nagra;
	int8_t		is_tiger;
	int8_t		is_n3_na;
	int8_t		has_dt08;
	int8_t		swapCW;
	uint8_t		ExpiryDate[2];
	uint8_t		ActivationDate[2];
	uint8_t		plainDT08RSA[64];
	uint8_t		IdeaCamKey[16];
	uint8_t		sessi[16];
	uint8_t		signature[8];
	uint8_t		cam_state[3];
	uint32_t	Date_ird;
	uint32_t	Provider_ID_tiers;
	uint16_t	tiers;
	uint32_t	Expire_date_tiers_2;
	uint32_t	Begin_date_tiers_2;
	uint16_t	tiers_2;
	int32_t		num_records;
};

// Datatypes
#define IRDINFO		0x03
#define TIERS		0x0C
#define SYSID		0x05
#define allproviders	0x06

#define SYSTEM_NAGRA	0x1800
#define SYSTEM_MASK	0xFF00

static time_t tier_date(uint64_t date, char *buf, int32_t l)
{
	time_t ut = +694224000L + (date>>1);
	if(buf){
		struct tm t;
		cs_gmtime_r(&ut, &t);
		snprintf(buf, l, "%04d/%02d/%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
	}
	return ut;
}

void rsa_decrypt(unsigned char *edata50, int len,unsigned char *out, unsigned char *key, int keylen)
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
	BN_bin2bn(exponent, 0x03, bnE0);
	BN_bin2bn(&edata50[0], len, bnCT0);
	BN_mod_exp(bnPT0, bnCT0, bnE0, bnN0, ctx0);
	memset(out,0x00,len);
	BN_bn2bin(bnPT0, out+ (len- BN_num_bytes(bnPT0)));
	BN_CTX_end(ctx0);
	BN_CTX_free(ctx0);
}

static void addProvider(struct s_reader *reader, unsigned char *cta_res)
{
	int32_t i;
	int32_t toadd = 1;
	for(i = 0; i < reader->nprov; i++){
		if((cta_res[19] == reader->prid[i][2]) && (cta_res[20] == reader->prid[i][3])){
			toadd = 0;
		}
	}
	if(toadd){
		reader->prid[reader->nprov][0] = 0;
		reader->prid[reader->nprov][1] = 0;
		reader->prid[reader->nprov][2] = cta_res[19];
		reader->prid[reader->nprov][3] = cta_res[20];
		memcpy(reader->sa[reader->nprov], reader->sa[0], 4);
		reader->nprov += 1;
	}
}

typedef struct{
	uint32_t	Expire_date_tiers;
	uint32_t	Begin_date_tiers;
	uint16_t	tiers;
	int32_t		num_records;
	uint32_t	Provider_ID_tiers;
} tiers_rec;

static int32_t ParseDataType(struct s_reader *reader, unsigned char dt, unsigned char *cta_res, uint16_t cta_lr)
{
	struct nagra_data *csystem_data = reader->csystem_data;
	char ds[20], de[16], da[16];
	IDEA_KEY_SCHEDULE ks;
	//rdr_log_dump_dbg(reader, D_READER, cta_res, cta_lr, "cta_res:");
	switch(dt)
	{
	//case 0x0C:
	case TIERS:
		if((cta_res[13] >= 0x20) && (cta_lr != 0x10) && (reader->caid==0x1860 || reader->caid==0x186A))
		{
			csystem_data->tiers = b2i(2,cta_res +23);
			uint16_t chid = csystem_data->tiers;
			int32_t id = b2i(2,cta_res +19);
			rdr_log_dbg(reader, D_READER, "Provid : %04X", id);
			rdr_log_dbg(reader, D_READER, "ID : %04X", chid);
			
			if(reader->caid==0x1860)
			{
				cs_add_entitlement(
							reader,
							reader->caid,
							id,
							chid,
							0,
							tier_date(b2ll(4, cta_res + 42)-0x7f7, ds, 15), // noch nicht richtig
							tier_date(b2ll(4, cta_res + 28)-0x7f7, de, 15),
							4,
							1);

				rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
				addProvider(reader, cta_res);
			}
			if(reader->caid==0x186A)
			{
				cs_add_entitlement(
							reader,
							reader->caid,
							id,
							chid,
							0,
							tier_date(b2ll(4, cta_res + 0x35)-0x7f7, ds, 15),
							tier_date(b2ll(4, cta_res + 0x27)-0x7f7, de, 15),
							4,
							1);

				rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
				addProvider(reader, cta_res);
			}
		}
		break;

	//case 0x03:
	case IRDINFO:
		//if(cta_res[13] == 0x4D || cta_res[13] == 0x50 || cta_res[13] == 0x55)
		if(cta_lr == 0x72)	
		{
			rdr_log_dump_dbg(reader, D_READER, cta_res+19, 2, "Provider ID :");
			reader->card_valid_to=tier_date(b2ll(4, cta_res + 22)-0x7f7, da, 15);
			rdr_log(reader, "Card expire date: %s", da);
		}
		break;

	case 0x02:
		reader->prid[0][0]=cta_res[17];
		reader->prid[0][1]=cta_res[18];
		reader->prid[0][2]=cta_res[19];
		reader->prid[0][3]=cta_res[20];

		reader->prid[1][0] = 0x00;
		reader->prid[1][1] = 0x00;
		reader->prid[1][2] = 0x00;
		reader->prid[1][3] = 0x00;
		memcpy(reader->sa[1], reader->sa[0], 4);
		reader->nprov += 1;
		reader->caid = (SYSTEM_NAGRA | cta_res[25]);
		rdr_log_dbg(reader, D_READER, "CAID : %04X", reader->caid);
		break;

	//case 0x05:
	case SYSID:
		memcpy(reader->edata,cta_res+26,0x70);
		reader->dt5num=cta_res[20];
		rsa_decrypt(reader->edata,0x70,reader->out,mod1,sizeof(mod1));
		if(reader->dt5num==0x00)
		{
			memcpy(reader->kdt05_00,&reader->out[18],0x5C+2);
			memcpy(&reader->kdt05_00[0x5C+2],cta_res+26+0x70,6);
			memcpy(reader->ideakey1,reader->out,16);
			memcpy(reader->block3,cta_res+26+0x70+6,8);
			idea_set_encrypt_key(reader->ideakey1, &ks);
			memset(reader->v, 0, sizeof(reader->v));
			idea_cbc_encrypt(reader->block3, reader->iout, 8, &ks, reader->v, IDEA_DECRYPT);
			memcpy(&reader->kdt05_00[0x5C+2+6],reader->iout,8);
			rdr_log_dump_dbg(reader, D_READER, reader->kdt05_00, sizeof(reader->kdt05_00), "DT05_00: ");
		}
		if(reader->dt5num==0x10)
		{
			memcpy(reader->kdt05_10,&reader->out[16],6*16);
			memcpy(reader->ideakey1,reader->out,16);
			memcpy(reader->block3,cta_res+26+0x70,8);
			idea_set_encrypt_key(reader->ideakey1, &ks);
			memset(reader->v, 0, sizeof(reader->v));
			idea_cbc_encrypt(reader->block3, reader->iout, 8, &ks, reader->v, IDEA_DECRYPT);
			memcpy(&reader->kdt05_10[6*16],reader->iout,8);
			rdr_log_dump_dbg(reader, D_READER, reader->kdt05_10, sizeof(reader->kdt05_10), "DT05_10: ");
		}
		if(cta_res[8] != 0x07)
		{
			reader->prid[reader->nprov][0] = 0;
			reader->prid[reader->nprov][1] = 0;
			reader->prid[reader->nprov][2] = cta_res[19];
			reader->prid[reader->nprov][3] = cta_res[20];
		}
		break;

	default:
		return OK;
	}
	return ERROR;
}

static int32_t CAS7do_cmd(struct s_reader *reader, unsigned char dt,unsigned char len,unsigned char *res, uint16_t *rlen,int32_t sub,unsigned char retlen)
{
	//unsigned char dtdata[0x10];
	memset(reader->dtdata,0xCC,len);

	reader->dtdata[7]=0x04;
	reader->dtdata[8]=0x04;

	reader->dtdata[ 9]=(sub>>16)&0xFF;
	reader->dtdata[10]=(sub>>8)&0xFF;
	reader->dtdata[11]=(sub)&0xFF;

	reader->dtdata[12]=dt;

	do_cas7_cmd(reader,res,rlen,reader->dtdata,sizeof(reader->dtdata),retlen);

	return true;
}

static int32_t CAS7GetDataType(struct s_reader *reader, unsigned char dt)
{
	def_resp;

	int32_t sub=0x00;
	unsigned char retlen=0x10;
	while(true)
	{
		CAS7do_cmd(reader,dt,0x10,cta_res,&cta_lr,sub,retlen);
		// check auf 90 am ende ??

		uint32_t newsub=(cta_res[9]<<16)+(cta_res[10]<<8)+(cta_res[11]);
		if(newsub==0xFFFFFF)
		{
			break;
		}

		if(cta_res[12]==dt) // seqcounter check ??
		{
			unsigned char oretlen=retlen;
			retlen=cta_res[13]+0x10+0x2;
			while(retlen%0x10!=0x00)retlen++;

			if(retlen==oretlen)
			{
				sub=newsub+1;
				retlen=0x10;
				ParseDataType(reader,dt,cta_res,cta_lr);
			}
		}
		else
		{
			break;
		}
	}

	return true;
}

void sub_6AD78(uint32_t *dinit) // gbox function
{
	uint32_t v0=(uint32_t)*dinit;
	double f0;
	f0=v0;
	double f12=16807;
	double f15=2147483647;
	f12=f0*f12;
	double v12;
	v12=fmod(f12,f15);
	*dinit=v12;
}

void calc_cas7_exponent(uint32_t *dinit, unsigned char *out, uint8_t  len)
{
	memset(out,0x00,len);

	sub_6AD78(dinit);

	int R4=0;
	int R5=0;
	while(true)
	{
		uint32_t R0=(uint32_t)*dinit;
		int R3=R4+3;
		R5+=4;
		if(R3>len)break;

		out[R5-1]=((R0    )&0xFF);
		out[R5-2]=((R0>> 8)&0xFF);
		out[R5-3]=((R0>>16)&0xFF);
		out[R5-4]=((R0>>24)&0xFF);
		R4+=4;
		sub_6AD78(dinit);

	}

	uint32_t R0=(uint32_t)*dinit;
	while(R4<len)
	{
		out[R4]=R0&0xFF;
		R4++;
		R0>>=8;
	}

	out[0]&=0x03;
	out[0x10]|=0x01;

}

void CAS7_getCamKey(struct s_reader *reader)
{
	def_resp;
	uint8_t cmd0e[] = {0xCC,0xCC,0xCC,0xCC,0x00,0x00,0x09,0x0E,0x83,0x00,0x00,0x00,0x00,0x00,0x64,0x65,0x6D,0x6F,0x34,0x11,0x9D,
	0x7E,0xEE,0xCE,0x53,0x09,0x80,0xAE,0x6B,0x5A,0xEE,0x3A,0x41,0xCE,0x09,0x75,0xEF,0xA6,0xBF,0x1E,0x98,0x4F,
	0xA4,0x11,0x6F,0x43,0xCA,0xCD,0xD0,0x6E,0x69,0xFA,0x25,0xC1,0xF9,0x11,0x8E,0x7A,0xD0,0x19,0xC0,0xEB,0x00,
	0xC0,0x57,0x2A,0x40,0xB7,0xFF,0x8A,0xBB,0x25,0x21,0xD7,0x50,0xE7,0x35,0xA1,0x85,0xCD,0xA6,0xD3,0xDE,0xB3,
	0x3D,0x16,0xD4,0x94,0x76,0x8A,0x82,0x8C,0x70,0x25,0xD4,0x00,0xD0,0x64,0x8C,0x26,0xB9,0x5F,0x44,0xFF,0x73,
	0x70,0xAB,0x43,0xF5,0x68,0xA2,0xB1,0xB5,0x8A,0x8E,0x02,0x5F,0x96,0x06,0xA8,0xC3,0x4F,0x15,0xCD,0x99,0xC2,
	0x69,0xB8,0x35,0x68,0x11,0x4C,0x84,0x3E,0x94,0x1E,0x00,0x08,0x00,0x00,0xCC,0xCC,0xCC,0xCC};
	do_cas7_cmd(reader,cta_res,&cta_lr,cmd0e,sizeof(cmd0e),0x20);
	reader->dword_83DBC= (cta_res[18]<<24);
	reader->dword_83DBC+=(cta_res[19]<<16);
	reader->dword_83DBC+=(cta_res[20]<< 8);
	reader->dword_83DBC+=(cta_res[21]    );
	calc_cas7_exponent(&reader->dword_83DBC,reader->cas7expo,0x11);
	memcpy(reader->cardid,cta_res+14,4);
	rdr_log_dump_dbg(reader, D_READER, reader->cardid, 0x04, "CardSerial: ");
	memcpy(reader->hexserial + 2, reader->cardid,4);
	memcpy(reader->sa[0],reader->cardid,2);
	unsigned long datal=(cta_res[9]<<24)+(cta_res[10]<<16)+(cta_res[11]<<8)+(cta_res[12]);
	datal++;
	reader->data2[0]=(datal>>24)&0xFF;
	reader->data2[1]=(datal>>16)&0xFF;
	reader->data2[2]=(datal>> 8)&0xFF;
	reader->data2[3]=(datal    )&0xFF;

	BN_CTX *ctx0 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx0);
#endif
	BIGNUM *bnN0 = BN_CTX_get(ctx0);
	BIGNUM *bnE0 = BN_CTX_get(ctx0);
	BIGNUM *bnCT0 = BN_CTX_get(ctx0);
	BIGNUM *bnPT0 = BN_CTX_get(ctx0);
	BN_bin2bn(&mod50[0], 0x50, bnN0);
	BN_bin2bn(&reader->cas7expo[0], 0x11, bnE0);
	BN_bin2bn(&data50[0], 0x50, bnCT0);
	BN_mod_exp(bnPT0, bnCT0, bnE0, bnN0, ctx0);
	memset(reader->data,0x00,sizeof(reader->data));
	BN_bn2bin(bnPT0, reader->data+ (0x50- BN_num_bytes(bnPT0)));
	BN_CTX_end(ctx0);
	BN_CTX_free(ctx0);
	
	memcpy(&reader->step1[0],d00ff,4);
	memcpy(&reader->step1[4],reader->data,0x50);
	memcpy(&reader->step1[4+0x50],irdid,0x04);
	memcpy(&reader->step1[4+4+0x50],data1,0x04);
	memcpy(&reader->step1[4+4+4+0x50],reader->data2,0x04);

	BN_CTX *ctx1 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx1);
#endif
	BIGNUM *bnN1 = BN_CTX_get(ctx1);
	BIGNUM *bnE1 = BN_CTX_get(ctx1);
	BIGNUM *bnCT1 = BN_CTX_get(ctx1);
	BIGNUM *bnPT1 = BN_CTX_get(ctx1);
	BN_bin2bn(&key60[0], 0x60, bnN1);
	BN_bin2bn(&exp60[0], 0x60, bnE1);
	BN_bin2bn(&reader->step1[0], 0x60, bnCT1);
	BN_mod_exp(bnPT1, bnCT1, bnE1, bnN1, ctx1);
	BN_bn2bin(bnPT1, reader->data+ (0x60- BN_num_bytes(bnPT1)));
	BN_CTX_end(ctx1);
	BN_CTX_free(ctx1);

	memcpy(&reader->step2[0],d00ff,4);
	memcpy(&reader->step2[4],reader->cardid,4);
	memcpy(&reader->step2[8],reader->data,0x60);

	BN_CTX *ctx2 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx2);
#endif
	BIGNUM *bnN2 = BN_CTX_get(ctx2);
	BIGNUM *bnE2 = BN_CTX_get(ctx2);
	BIGNUM *bnCT2 = BN_CTX_get(ctx2);
	BIGNUM *bnPT2 = BN_CTX_get(ctx2);
	BN_bin2bn(&reader->kdt05_10[0], 0x68, bnN2);
	BN_bin2bn(&exponent[0], 3, bnE2);
	BN_bin2bn(&reader->step2[0], 0x68, bnCT2);
	BN_mod_exp(bnPT2, bnCT2, bnE2, bnN2, ctx2);
	BN_bn2bin(bnPT2, reader->data+ (0x68- BN_num_bytes(bnPT2)));
	BN_CTX_end(ctx2);
	BN_CTX_free(ctx2);

	memcpy(&reader->step3[0],d00ff,4);
	memcpy(&reader->step3[4],reader->data,0x68);

	BN_CTX *ctx3 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctx3);
#endif
	BIGNUM *bnN3 = BN_CTX_get(ctx3);
	BIGNUM *bnE3 = BN_CTX_get(ctx3);
	BIGNUM *bnCT3 = BN_CTX_get(ctx3);
	BIGNUM *bnPT3 = BN_CTX_get(ctx3);
	BN_bin2bn(&reader->kdt05_00[0], 0x6c, bnN3);
	BN_bin2bn(&exponent[0], 3, bnE3);
	BN_bin2bn(&reader->step3[0], 0x6c, bnCT3);
	BN_mod_exp(bnPT3, bnCT3, bnE3, bnN3, ctx3);
	BN_bn2bin(bnPT3, reader->data+ (0x6c- BN_num_bytes(bnPT3)));
	BN_CTX_end(ctx3);
	BN_CTX_free(ctx3);

	uint8_t cmd03[] = {0xCC,0xCC,0xCC,0xCC, 0x00,0x00,0x0A,0x03,0x6C,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };

	memcpy(&cmd03[9],reader->data,0x6c);
	do_cas7_cmd(reader,cta_res,&cta_lr,cmd03,sizeof(cmd03),0x90);
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
	BN_bin2bn(&exponent[0], 3, bnE);
	BN_bin2bn(&reader->encrypted[0], 104, bnCT);
	BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
	memset(reader->result, 0, 104);
	BN_bn2bin(bnPT, reader->result + (104 - BN_num_bytes(bnPT)));
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	//uchar stillencrypted[0x50];
	memcpy(reader->stillencrypted,&reader->result[12],0x50);

	//uchar resultrsa[0x50];
	BN_CTX *ctxs = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
	BN_CTX_start(ctxs);
#endif
	BIGNUM *bnNs  = BN_CTX_get(ctxs);
	BIGNUM *bnEs  = BN_CTX_get(ctxs);
	BIGNUM *bnCTs = BN_CTX_get(ctxs);
	BIGNUM *bnPTs = BN_CTX_get(ctxs);
	BN_bin2bn(&mod50[0], sizeof(mod50), bnNs);
	BN_bin2bn(&reader->cas7expo[0], 0x11, bnEs);
	BN_bin2bn(&reader->stillencrypted[0], 0x50, bnCTs);
	BN_mod_exp(bnPTs, bnCTs, bnEs, bnNs, ctxs);
	BN_bn2bin(bnPTs, reader->resultrsa + (0x50- BN_num_bytes(bnPTs)));
	BN_CTX_end(ctxs);
	BN_CTX_free(ctxs);

	unsigned char mdc_hash[MDC2_DIGEST_LENGTH];
	memset(mdc_hash,0x00,MDC2_DIGEST_LENGTH);

	MDC2_CTX c;
	MDC2_Init(&c);
	MDC2_Update(&c, reader->resultrsa, sizeof(reader->resultrsa));
	MDC2_Final(&(mdc_hash[0]), &c);

	memcpy(&reader->cas7_aes_key[16],mdc_hash,16);
	memcpy(reader->cas7_aes_key,mdc_hash,16);
}

static int32_t nagra7_card_init(struct s_reader *reader, ATR *newatr)
{
	get_atr;
	int8_t is_pure_nagra = 0;
	int8_t is_tiger = 0;
	int8_t is_n3_na = 0;
	memset(reader->irdId, 0xff, 4);
	memset(reader->hexserial, 0, 6);
	reader->cas7_seq=0x00;
	cs_clear_entitlement(reader);
	if(memcmp(atr + 11, "DNASP4", 6) == 0)
	{
		memcpy(reader->rom, atr + 11, 15);
		rdr_log(reader,"Rom revision: %.15s", reader->rom);
	}
	else
	{
		return ERROR;
	}

	if(!reader->csystem_data)
	{
		if(!cs_malloc(&reader->csystem_data, sizeof(struct nagra_data)))
		{
			rdr_log(reader, "cs_malloc error");
			return ERROR;
		}
	}
	struct nagra_data *csystem_data = reader->csystem_data;
	csystem_data->is_pure_nagra = is_pure_nagra;
	csystem_data->is_tiger      = is_tiger;
	csystem_data->is_n3_na      = is_n3_na;

	reader->nprov = 1;
	CAS7GetDataType(reader, 0x09);
	CAS7GetDataType(reader, 0x05);
	CAS7_getCamKey(reader);
	CAS7GetDataType(reader, 0x09);
	CAS7GetDataType(reader, 0x02); // sysid+caid
	CAS7GetDataType(reader, 0x03);
	return OK;
}

typedef struct
{
	char date1[11];
	char date2[11];
	uint8_t type;
	uint16_t value;
	uint16_t price;
} ncmed_rec;

static int32_t nagra7_card_info(struct s_reader *reader)
{
	int32_t i;
	char tmp[64];

	int crcdigits; // checksum digits
	crcdigits = (((unsigned long long) b2ll(6, reader->hexserial + 2) % 2300) / 100 + ((unsigned long long) b2ll(6, reader->hexserial + 2)));
	rdr_log(reader, "ROM:    %c %c %c %c %c %c %c %c", reader->rom[0], reader->rom[1], reader->rom[2], reader->rom[3], reader->rom[4], reader->rom[5], reader->rom[6], reader->rom[7]);
	rdr_log(reader, "REV:    %c %c %c %c %c %c", reader->rom[9], reader->rom[10], reader->rom[11], reader->rom[12], reader->rom[13], reader->rom[14]);
	//rdr_log_sensitive(reader, "SER:    {%s} (%llu-%i)", cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)),(unsigned long long) b2ll(4, reader->hexserial + 2), crcdigits);
	rdr_log_sensitive(reader, "SER:    {%s}  {%llu}", cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)),(unsigned long long) b2ll(4, reader->hexserial + 2));
	rdr_log_dbg(reader, D_READER, "checksum digits: %i", crcdigits);
	rdr_log(reader, "CAID:   %04X", reader->caid);
	rdr_log(reader, "Prv.ID: %s(sysid)", cs_hexdump(1, reader->prid[0], 4, tmp, sizeof(tmp)));

	if (reader->irdId[0] == 0xFF && reader->irdId[1] == 0xFF && reader->irdId[2] == 0xFF && reader->irdId[3] == 0xFF)
		{
			rdr_log(reader, "IRD ID: FF FF FF FF");
		} 
	else 
		{
			rdr_log_sensitive(reader, "IRD ID: {%s}", cs_hexdump(1, reader->irdId, 4, tmp, sizeof(tmp)));
		}

	cs_clear_entitlement(reader); //reset the entitlements
	rdr_log(reader, "-----------------------------------------");
	rdr_log(reader, "|id  |tier    |valid from  |valid to    |");
	rdr_log(reader, "+----+--------+------------+------------+");

	CAS7GetDataType(reader, 0x0C);
	rdr_log(reader, "-----------------------------------------");

	CAS7GetDataType(reader, 0x06);
	for(i = 1; i < reader->nprov; i++)
	{
		rdr_log(reader, "Prv.ID: %s", cs_hexdump(1, reader->prid[i], 4, tmp, sizeof(tmp)));
	}
	if (reader->caid)
		{
			rdr_log(reader, "ready for requests");
		}
	
	return OK;
}

void nagra7_post_process(struct s_reader *reader)
{
	struct nagra_data *csystem_data = reader->csystem_data;
	if((csystem_data->cam_state[0]&64)==64)
	{
		rdr_log(reader, "renew Session Key: CAS7");
		CAS7_getCamKey(reader);
	}
}

static int32_t nagra7_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp;
	struct nagra_data *csystem_data = reader->csystem_data;

	uint8_t ecmreq[0xC0];
	memset(ecmreq,0xCC,0xC0);

	ecmreq[ 7]=0x05;
	ecmreq[ 8]=0x8A;
	ecmreq[ 9]=0x00;
	ecmreq[10]=0x00;
	ecmreq[11]=0x00;
	ecmreq[12]=0x00;
	ecmreq[13]=0x01;
	memcpy(&ecmreq[14],er->ecm + 4, er->ecm[4]+1);

	do_cas7_cmd(reader,cta_res,&cta_lr,ecmreq,sizeof(ecmreq),0xB0);
	if(cta_res[cta_lr-2] != 0x90 && cta_res[cta_lr-1] != 0x00){
		rdr_log(reader, "(ECM) Reader will be restart now cause: %02X %02X card answer!!!", cta_res[cta_lr-2], cta_res[cta_lr-1]);
		reader->card_status = CARD_NEED_INIT;
		add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
	}

	if(cta_res[27]==0x5C)
	{
		uint8_t _cwe0[8];
		uint8_t _cwe1[8];
		int32_t i;
		if (cta_res[78] == 0x01)
		{
			rdr_log (reader,"Swap dcw is at use !");  //; csystem_data->swapCW == 1;
			memcpy(_cwe0,&cta_res[52],0x08);
			memcpy(_cwe1,&cta_res[28],0x08);
		}
		else
		{
			memcpy(_cwe0,&cta_res[28],0x08);
			memcpy(_cwe1,&cta_res[52],0x08);
		}
		if (array_has_nonzero_byte(_cwe_key, 128) > 0)
		{
			i = cta_res[24];
			memcpy(_cwe_key, _cwe_key+(i*16), 16);
			rdr_log_dump_dbg(reader, D_READER, _cwe_key, sizeof(_cwe_key), "Using CWPK-%d from config:",i);
		}
		_3DES(_cwe0,_cwe_key);
		_3DES(_cwe1,_cwe_key);
		int chkok=1;

		if(((_cwe0[0]+_cwe0[1]+_cwe0[2])&0xFF)!=_cwe0[3])
		{
			chkok=0;
			rdr_log_dbg(reader, D_READER, "CW0 checksum error [0]");
		}
		if(((_cwe0[4]+_cwe0[5]+_cwe0[6])&0xFF)!=_cwe0[7])
		{
			chkok=0;
			rdr_log_dbg(reader, D_READER, "CW0 checksum error [1]");
		}
		if(((_cwe1[0]+_cwe1[1]+_cwe1[2])&0xFF)!=_cwe1[3])
		{
			chkok=0;
			rdr_log_dbg(reader, D_READER, "CW1 checksum error [0]");
		}
		if(((_cwe1[4]+_cwe1[5]+_cwe1[6])&0xFF)!=_cwe1[7])
		{
			chkok=0;
			rdr_log_dbg(reader, D_READER, "CW1 checksum error [1]");
		}

		csystem_data->cam_state[0]=cta_res[4];
		if(chkok==1)
		{
			rdr_log_dbg(reader, D_READER, "CW Decrypt ok");
			memcpy(ea->cw,_cwe0,0x08);
			memcpy(ea->cw+8,_cwe1,0x08);
			return OK;
		}
	}

	return ERROR;
}

int32_t nagra7_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)  //returns 1 if shared emm matches SA, unique emm matches serial, or global or unknown
{
	switch(ep->emm[0])
	{
	case 0x83:
	case 0x87:
		memset(ep->hexserial, 0, 8);
		ep->hexserial[0] = ep->emm[5];
		ep->hexserial[1] = ep->emm[4];
		ep->hexserial[2] = ep->emm[3];
		if(ep->emm[7] == 0x10)
		{
			ep->type = SHARED;
			return (!memcmp(rdr->hexserial + 2, ep->hexserial, 3));
		}
		else
		{
			ep->hexserial[3] = ep->emm[6];
			ep->type = UNIQUE;
			return (!memcmp(rdr->hexserial + 2, ep->hexserial, 4));
		}
	case 0x82:
	case 0x84:
		ep->type = GLOBAL;
		return 1;
	default:
		ep->type = UNKNOWN;
		return 1;
	}
}

static int32_t nagra7_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 3;
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
		{
			return ERROR;
		}

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		int32_t idx = 0;

		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x86;
		filters[idx].mask[0]   = 0xF9;   // 0x82, 0x84 and 0x86
		idx++;

		filters[idx].type = EMM_SHARED;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x87;
		filters[idx].filter[1] = rdr->hexserial[4];
		filters[idx].filter[2] = rdr->hexserial[3];
		filters[idx].filter[3] = rdr->hexserial[2];
		filters[idx].filter[4] = 0x00;
		filters[idx].filter[5] = 0x10;
		filters[idx].mask[0]   = 0xFB;   // 0x83 and 0x87
		memset(&filters[idx].mask[1], 0xFF, 5);
		idx++;

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x87;
		filters[idx].filter[1] = rdr->hexserial[4];
		filters[idx].filter[2] = rdr->hexserial[3];
		filters[idx].filter[3] = rdr->hexserial[2];
		filters[idx].filter[4] = rdr->hexserial[5];
		filters[idx].filter[5] = 0x00;
		filters[idx].mask[0]   = 0xFB;   // 0x83 and 0x87
		memset(&filters[idx].mask[1], 0xFF, 5);
		idx++;

		*filter_count = idx;
	}

	return OK;
}

static int32_t nagra7_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	def_resp;
	uint8_t emmreq[0xC0];
	memset(emmreq,0xCC,0xC0);
	emmreq[ 7]=0x05;
	emmreq[ 8]=0x8A;
	emmreq[ 9]=0x00;
	emmreq[10]=0x00;
	emmreq[11]=0x00;
	emmreq[12]=0x00;
	emmreq[13]=0x01;
	memcpy(&emmreq[14],ep->emm + 9, ep->emm[9]+1);
	do_cas7_cmd(reader,cta_res,&cta_lr,emmreq,sizeof(emmreq),0xB0);
	if(cta_res[cta_lr-2] != 0x90 && cta_res[cta_lr-1] != 0x00){
		rdr_log(reader, "(EMM) Reader will be restart now cause: %02X %02X card answer!!!", cta_res[cta_lr-2], cta_res[cta_lr-1]);
		reader->card_status = CARD_NEED_INIT;
		add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
	}
	return OK;
}

const struct s_cardsystem reader_nagracak7 =
{
	.desc           = "Nagra_Merlin",
	.caids          = (uint16_t[]){ 0x18, 0x0 },
	.do_emm         = nagra7_do_emm,
	.do_ecm         = nagra7_do_ecm,
	.post_process   = nagra7_post_process,
	.card_info      = nagra7_card_info,
	.card_init      = nagra7_card_init,
	.get_emm_type   = nagra7_get_emm_type,
	.get_emm_filter = nagra7_get_emm_filter,
};

#endif
