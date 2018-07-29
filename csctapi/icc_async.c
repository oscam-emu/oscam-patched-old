#include "../globals.h"
#ifdef WITH_CARDREADER
#include "../oscam-lock.h"
#include "../oscam-string.h"
#include "icc_async.h"
#include "protocol_t0.h"
#include "io_serial.h"
#include "ifd_phoenix.h"
#include "../oscam-time.h"
#include "../cardlist.h"
#include "../oscam-work.h"
#ifdef READER_NAGRA_MERLIN
#include "../cscrypt/fast_aes.h"
#include "../cscrypt/sha256.h"
#include "../cscrypt/aescbc.h"
#include "../cscrypt/mdc2.h"
#include "../cscrypt/bn.h"
#include "../cscrypt/idea.h"
#endif

#define OK	0
#define ERROR	1

// Default T0/T14 settings
#define DEFAULT_WI	10
// Default T1 settings
#define DEFAULT_IFSC	32
#define MAX_IFSC	251
#define DEFAULT_CWI	13
#define DEFAULT_BWI	4
#define EDC_LRC		0

#define PPS_MAX_LENGTH	6
#define PPS_HAS_PPS1(block) ((block[1] & 0x10) == 0x10)
#define PPS_HAS_PPS2(block) ((block[1] & 0x20) == 0x20)
#define PPS_HAS_PPS3(block) ((block[1] & 0x40) == 0x40)

static uint16_t tempfi; // used to capture FI and use it for rounding or not
static void ICC_Async_InvertBuffer(struct s_reader *reader, uint32_t size, unsigned char *buffer);
static int32_t Parse_ATR(struct s_reader *reader, ATR *atr, uint16_t deprecated);
static int32_t PPS_Exchange(struct s_reader *reader, unsigned char *params, uint32_t *length);
static uint32_t PPS_GetLength(unsigned char *block);
static int32_t InitCard(struct s_reader *reader, ATR *atr, unsigned char FI, uint32_t D, unsigned char N, uint16_t deprecated);
static uint32_t ETU_to_us(struct s_reader *reader, uint32_t ETU);
static unsigned char PPS_GetPCK(unsigned char *block, uint32_t length);
static int32_t SetRightParity(struct s_reader *reader);

#ifdef READER_NAGRA_MERLIN
static uint32_t crctab[256] =
{
	0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
	0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
	0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
	0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
	0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
	0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
	0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
	0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
	0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
	0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
	0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
	0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
	0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
	0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
	0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
	0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
	0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
	0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
	0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
	0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
	0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
	0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
	0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
	0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
	0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
	0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
	0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
	0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
	0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
	0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
	0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
	0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4,
};

uint32_t calc_ccitt32(uint8_t *buf, uint8_t count)
{
#define M1 0xffffffff
#define M2 0xffffff00
	uint32_t crc = M1;
	while(count--)
	{
		crc=((crc<<8)&M2)^crctab[((crc>>24)&0xff)^*buf++];
	}
	return(crc);
}

static void calculate_cas7_vars(struct s_reader *reader, const ATR *atr)
{
	uint8_t aes_key[32];
	const uint8_t aes_iv[] = { 0x4E, 0x61, 0x67, 0x72, 0x61, 0x63, 0x61, 0x72, 0x64, 0x28, 0x63, 0x29, 0x32, 0x30, 0x30, 0x36 }; // Nagracard(c)2006
	mbedtls_sha256_context ctx_sha256;
	mbedtls_sha256_init(&ctx_sha256);
	mbedtls_sha256_starts(&ctx_sha256, 0);
	mbedtls_sha256_update(&ctx_sha256, atr->hb, atr->hbn);
	mbedtls_sha256_finish(&ctx_sha256, aes_key);
	mbedtls_sha256_free(&ctx_sha256);
	memcpy(reader->cas7_aes_key,aes_key,32);
	memcpy(reader->cas7_aes_iv,aes_iv,16);
}

void calculate_cas7_cmd(struct s_reader *reader, uint8_t *cmdin,uint8_t cmdlen,uint8_t *cmdout)
{
	uint32_t crc = calc_ccitt32(cmdin+4, cmdlen-4);
	i2b_buf(4, crc, cmdin);
	AesCtx ctx;
	AesCtxIni(&ctx, reader->cas7_aes_iv, &reader->cas7_aes_key[16], KEY128, CBC);
	AesEncrypt(&ctx, cmdin, cmdout, cmdlen);
}

void do_cas7_cmd(struct s_reader *reader,unsigned char *cta_res, uint16_t *p_cta_lr,uint8_t *data,uint8_t inlen,uint8_t resplen)
{
	reader->cas7_seq++;
	uint8_t req[inlen+5+1]; // +head+len
	memset(req,0x00,sizeof(req));
	// head
	req[0]=0x80;
	req[1]=0xCA;
	// len
	req[4]=inlen;
	req[sizeof(req)-1]=resplen;
	data[4]=(reader->cas7_seq>>16)&0xFF;
	data[5]=(reader->cas7_seq>>8)&0xFF;
	data[6]=(reader->cas7_seq)&0xFF;
	calculate_cas7_cmd(reader,data,inlen,&req[5]);
	if(!ICC_Async_CardWrite(reader, req, sizeof(req), cta_res, p_cta_lr, 0x21))
	{
		AesCtx ctx;
		AesCtxIni(&ctx, reader->cas7_aes_iv, &reader->cas7_aes_key[16], KEY128, CBC);
		AesDecrypt(&ctx, cta_res, cta_res,  *p_cta_lr-2);
	}
	else
	{
		*p_cta_lr=0;
	}
}

static void calculate_changerom_cmd(struct s_reader *reader, const ATR *atr, uint8_t *cmd)
{
	uint8_t cmd_data[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00, 0x01, 0x01, 0x01, 0x95, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
	calculate_cas7_vars(reader,atr);
	calculate_cas7_cmd(reader,cmd_data,sizeof(cmd_data),cmd);
}
#endif

int32_t ICC_Async_Device_Init(struct s_reader *reader)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;
	reader->fdmc = -1;
	rdr_log_dbg(reader, D_IFD, "Opening device %s", reader->device);
	reader->written = 0;
	int32_t ret = crdr_ops->reader_init(reader);
	if(ret == OK)
	{
		rdr_log_dbg(reader, D_IFD, "Device %s succesfully opened", reader->device);
	}
	else
	{
		if(reader->typ != R_SC8in1)
		{
			NULLFREE(reader->crdr_data);
		}
		rdr_log_dbg(reader, D_IFD, "ERROR: Can't open %s device", reader->device);
	}
	return ret;
}

int32_t ICC_Async_Init_Locks(void)
{
	// Init device specific locks here, called from init thread
	// before reader threads are running
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		const struct s_cardreader *crdr_ops = rdr->crdr;
		if (!crdr_ops || !crdr_ops->lock_init) continue;
		crdr_ops->lock_init(rdr);
	}
	return OK;
}

int32_t ICC_Async_GetStatus(struct s_reader *reader, int32_t *card)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops)
	{
		return ERROR;
	}
	if (reader->typ == R_SMART && reader->smartdev_found >= 4)
	{
		reader->statuscnt = reader->statuscnt + 1;
		if (reader->statuscnt == 6)
		{
			int32_t in = 0;
			call(crdr_ops->get_status(reader, &in));
			if(in)
			{
				reader->modemstat = 1;
				*card = 1;
				reader->statuscnt = 0;
			}
			else
			{
				reader->modemstat = 0;
				*card = 0;
				reader->statuscnt = 0;
			}
			return OK;
		}
		else
		{
			*card = reader->modemstat;
			return OK;
		}
	}
	else
	{
		int32_t in = 0;
		call(crdr_ops->get_status(reader, &in));
		if(in)
		{
			*card = 1;
		}
		else
		{
			*card = 0;
		}
		return OK;
	}

}

int32_t ICC_Async_Activate(struct s_reader *reader, ATR *atr, uint16_t deprecated)
{
	rdr_log_dbg(reader, D_IFD, "Activating card");
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;
	reader->current_baudrate = DEFAULT_BAUDRATE;
	if(reader->atr[0] != 0 && !reader->ins7e11_fast_reset)
	{
		rdr_log(reader, "Using ATR from reader config");
		ATR_InitFromArray(atr, reader->atr, ATR_MAX_SIZE);
	}
	else
	{
		reader->crdr_flush = crdr_ops->flush; // Flush flag may be changed for each reader
		call(crdr_ops->activate(reader, atr));
		if(crdr_ops->skip_extra_atr_parsing)
		{
			return OK;
		}
	}

	unsigned char atrarr[ATR_MAX_SIZE];
	uint32_t atr_size;
	ATR_GetRaw(atr, atrarr, &atr_size);
	char tmp1[atr_size * 3 + 1];
	memcpy(current.atr, cs_hexdump(1, atrarr, atr_size, tmp1, sizeof(tmp1)), atr_size * 3 - 1);
	current.atr[atr_size * 3 - 1] = '\0';
	rdr_log(reader, "ATR: %s", current.atr);
	memcpy(reader->card_atr, atrarr, atr_size);
	reader->card_atr_length = atr_size;
	findatr(reader);
	if ( current.found == 1 )
	{
		rdr_log(reader, "%s recognized", current.providername);
	}

	if(current.badcard == 1 )  /* set badcard in cardlist.h */
	{
		current.badcard = 0;
		rdr_log(reader, "Bad Card -> quick restart");
		add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
		return ERROR;
	}
	else
	{

		/* Get ICC reader->convention */
		if(ATR_GetConvention(atr, &(reader->convention)) != ATR_OK)
		{
			rdr_log(reader, "ERROR: Could not read reader->convention");
			reader->convention = 0;
			reader->protocol_type = 0;
			return ERROR;
		}
		reader->protocol_type = ATR_PROTOCOL_TYPE_T0;
		if(crdr_ops->lock)
		{
			crdr_ops->lock(reader);
		}
		int32_t ret = Parse_ATR(reader, atr, deprecated);
		if(crdr_ops->unlock)
		{
			crdr_ops->unlock(reader);
		}
		if(ret)
		{
			rdr_log(reader, "ERROR: Parse_ATR returned error");
		}
		if(ret)
		{
			return ERROR;
		}
	}
	
#ifdef READER_NAGRA_MERLIN

	char tmp[atr_size * 3 + 1];

	if(current.ishd04 == 1)
	{
		rdr_log_dbg(reader, D_READER, "HD04 merlin handling");
		calculate_cas7_vars(reader, atr);
	}
	else if(current.ishd03 == 1 || current.ishd04 == 1)   // Switch ROM
	{

		static uint8_t changerom_handshake[] = { 0x80, 0xCA, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

		calculate_changerom_cmd(reader, atr, &changerom_handshake[5]);
		memset(reader->rom, 0, 15);
		unsigned char cta_res[CTA_RES_LEN];
		memset(cta_res, 0, CTA_RES_LEN);
		uint16_t cta_lr;
		uint8_t block_nad = 0;

		changerom_handshake[4] = 0x11; // 0x11: length of data we will send
		uint8_t cta_res1_ok = 0x61;
		uint8_t cta_res2_ok = 0x10;

		if(reader->protocol_type != ATR_PROTOCOL_TYPE_T0)
		{
			block_nad = 0x21;
			changerom_handshake[0] = 0x80; // fix for mipsel router
			changerom_handshake[4] = 0x10; // 0x10: length of data we will send
			cta_res1_ok = 0x90;
			cta_res2_ok = 0x00;
		}

		//rdr_log_dbg(reader, D_READER, "try to init nagra layer");
		 rdr_log(reader,"try to init nagra layer");
 
		//rdr_log_dump_dbg(reader, D_READER, changerom_handshake, sizeof(changerom_handshake), "changerom_handshake data:");

		if(!ICC_Async_CardWrite(reader, changerom_handshake, sizeof(changerom_handshake), cta_res, &cta_lr, block_nad))
		{
			if(cta_res[cta_lr-2] == cta_res1_ok && cta_res[cta_lr-1] == cta_res2_ok)
			{
				//rdr_log_dbg(reader, D_READER, "switch to nagra layer OK");
				rdr_log(reader, "switch to nagra layer OK");
				uint8_t cmd_data[cta_lr+2] ;
				AES128_CBC_decrypt_buffer(cmd_data,cta_res, (cta_lr-2), &reader->cas7_aes_key[16], reader->cas7_aes_iv);
				memset(atr, 0, 1);
				call(crdr_ops->activate(reader, atr)); //try to read the atr of this layer
				ATR_GetRaw(atr, atrarr, &atr_size);
				//rdr_log_dbg(reader, D_READER, "Nagra layer ATR: %s", cs_hexdump(1, atrarr, atr_size, tmp, sizeof(tmp)));
				rdr_log(reader,"Nagra layer ATR: %s", cs_hexdump(1, atrarr, atr_size, tmp, sizeof(tmp)));
				calculate_cas7_vars(reader, atr);
				if(crdr_ops->lock)
				{
					crdr_ops->lock(reader);
				}
				Parse_ATR(reader, atr, deprecated);
				if(crdr_ops->unlock)
				{
					crdr_ops->unlock(reader);
				}
			}
			else
			{
				//rdr_log_dbg(reader, D_READER, "Switch to nagra layer failed!");
				rdr_log(reader,"Switch to nagra layer failed!");
				return ERROR;
			}
		}
		else
		{
			//rdr_log_dbg(reader, D_READER, "Switch to nagra layer command failed!");
			rdr_log(reader,"Switch to nagra layer command failed!");
			return ERROR;
		}
		memcpy(reader->card_atr, atrarr, atr_size);
		reader->card_atr_length = atr_size;
		memcpy(reader->rom, atr->hb, (atr->hbn>15)?15:atr->hbn);// get historical bytes from atr
	}
#endif	
	rdr_log_dbg(reader, D_READER, "Card succesfully activated");
	
	return OK;
} 

int32_t ICC_Async_CardWrite(struct s_reader *reader, unsigned char *command, uint16_t command_len, unsigned char *rsp, uint16_t *lr, uint8_t block_nad)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;
	int32_t ret;
	*lr = 0; //will be returned in case of error
	if(crdr_ops->card_write)
	{
		call(crdr_ops->card_write(reader, command, rsp, lr, command_len));
		rdr_log_dump_dbg(reader, D_READER, rsp, *lr, "Answer from cardreader:");
		return OK;
	}
	if(crdr_ops->lock)
	{
		crdr_ops->lock(reader);
	}
	int32_t try = 1;
	uint16_t type = 0;
	do
	{
		switch(reader->protocol_type)
		{
			if(try > 1)
					rdr_log(reader, "Warning: needed try nr %i, next ECM has some delay", try);
		case ATR_PROTOCOL_TYPE_T0:
			ret = Protocol_T0_Command(reader, command, command_len, rsp, lr);
			type = 0;
			break;
		case ATR_PROTOCOL_TYPE_T1:
			ret = Protocol_T1_Command(reader, command, command_len, rsp, lr, block_nad);
			type = 1;
			if(ret != OK && !crdr_ops->skip_t1_command_retries)
			{
				//try to resync
				rdr_log(reader, "Resync error: readtimeouts %d/%d (max/min) us, writetimeouts %d/%d (max/min) us", reader->maxreadtimeout, reader->minreadtimeout, reader->maxwritetimeout, reader->minwritetimeout);
				unsigned char resync[] = { 0x21, 0xC0, 0x00, 0xE1 };
				ret = Protocol_T1_Command(reader, resync, sizeof(resync), rsp, lr, 0);
				if(ret == OK)
				{
					//reader->ifsc = DEFAULT_IFSC;
					//tryfix cardtimeouts: ifsc is setup at card init, on resync it should not return to default_ifsc
					rdr_log(reader, "T1 Resync command succesfull ifsc = %i", reader->ifsc);
					ret = ERROR;
				}
				else
				{
					rdr_log(reader, "T1 Resync command error, trying to reactivate!");
					ATR atr;
					ICC_Async_Activate(reader, &atr, reader->deprecated);
					if(crdr_ops->unlock)
					{
						crdr_ops->unlock(reader);
					}
					return ERROR;
				}
			}
			break;
		case ATR_PROTOCOL_TYPE_T14:
			ret = Protocol_T14_ExchangeTPDU(reader, command, command_len, rsp, lr);
			type = 14;
			break;
		default:
			rdr_log(reader, "ERROR: Unknown protocol type %i", reader->protocol_type);
			type = 99; // use 99 for unknown.
			ret = ERROR;
		}
		try++;
	}
	while((try < 3) && (ret != OK)); //always do one retry when failing
	if(crdr_ops->unlock)
	{
		crdr_ops->unlock(reader);
	}
	if(ret)
	{
		rdr_log_dbg(reader, D_TRACE, "ERROR: Protocol_T%d_Command returns error", type);
		return ERROR;
	}
	rdr_log_dump_dbg(reader, D_READER, rsp, *lr, "Answer from cardreader:");
	return OK;
}

int32_t ICC_Async_GetTimings(struct s_reader *reader, uint32_t wait_etu)
{
	int32_t timeout = ETU_to_us(reader, wait_etu)*2;
	rdr_log_dbg(reader, D_IFD, "Setting timeout to %i ETU (%d us)", wait_etu, timeout);
	return timeout;
}

int32_t ICC_Async_Transmit(struct s_reader *reader, uint32_t size, uint32_t expectedlen, unsigned char *data, uint32_t delay, uint32_t timeout)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	if(expectedlen)
	{
		rdr_log_dbg(reader, D_IFD, "Transmit size %d bytes, expected len %d bytes, delay %d us, timeout=%d us", size, expectedlen, delay, timeout);
	}
	else
	{
		rdr_log_dbg(reader, D_IFD, "Transmit size %d bytes, delay %d us, timeout=%d us", size, delay, timeout);
	}
	//rdr_log_dump_dbg(reader, D_IFD, data, size, "Transmit:");
	rdr_log_dump_dbg(reader, D_READER, data, size, "Transmit:");
	unsigned char *sent = data;
	if(reader->convention == ATR_CONVENTION_INVERSE && crdr_ops->need_inverse)
	{
		ICC_Async_InvertBuffer(reader, size, sent);
	}
	call(crdr_ops->transmit(reader, sent, size, expectedlen, delay, timeout));
	rdr_log_dbg(reader, D_IFD, "Transmit succesful");
	if(reader->convention == ATR_CONVENTION_INVERSE && crdr_ops->need_inverse)
	{
		// revert inversion cause the code in protocol_t0 is accessing buffer after transmit
		ICC_Async_InvertBuffer(reader, size, sent);
	}
	return OK;
}

int32_t ICC_Async_Receive(struct s_reader *reader, uint32_t size, unsigned char *data, uint32_t delay, uint32_t timeout)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	rdr_log_dbg(reader, D_IFD, "Receive size %d bytes, delay %d us, timeout=%d us", size, delay, timeout);
	rdr_log_dump_dbg(reader, D_IFD, data, size, "RECEIVED:");
	call(crdr_ops->receive(reader, data, size, delay, timeout));
	rdr_log_dbg(reader, D_IFD, "Receive succesful");
	if(reader->convention == ATR_CONVENTION_INVERSE && crdr_ops->need_inverse == 1)
	{
		ICC_Async_InvertBuffer(reader, size, data);
	}
	return OK;
}

int32_t ICC_Async_Close(struct s_reader *reader)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;
	rdr_log_dbg(reader, D_IFD, "Closing device %s", reader->device);
	call(crdr_ops->close(reader));
	if(reader->typ != R_SC8in1)
	{
		NULLFREE(reader->crdr_data);
		NULLFREE(reader->csystem_data);
	}
	rdr_log_dbg(reader, D_IFD, "Device %s succesfully closed", reader->device);
	return OK;
}

void ICC_Async_DisplayMsg(struct s_reader *reader, char *msg)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops || !crdr_ops->display_msg) return;
	crdr_ops->display_msg(reader, msg);
}

int32_t ICC_Async_Reset(struct s_reader *reader, struct s_ATR *atr,
						int32_t (*rdr_activate_card)(struct s_reader *, struct s_ATR *, uint16_t deprecated),
						int32_t (*rdr_get_cardsystem)(struct s_reader *, struct s_ATR *))
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops || !crdr_ops->do_reset) return 0;
	return crdr_ops->do_reset(reader, atr, rdr_activate_card, rdr_get_cardsystem);
}

static uint32_t ICC_Async_GetClockRate(int32_t cardmhz)
{
	switch(cardmhz)
	{
	case 357:
	case 358:
		return (372L * 9600L);
	case 368:
		return (384L * 9600L);
	default:
		return (cardmhz * 10000L);
	}
}

static int32_t ICC_Async_GetPLL_Divider(struct s_reader *reader)
{
	if(reader->divider != 0)
	{
		return reader->divider;
	}
	if(reader->cardmhz != 8300)  /* Check dreambox is not DM7025 */
	{
		float divider;
		divider = ((float) reader->cardmhz) / ((float) reader->mhz);
		if (tempfi == 9) reader->divider = (int32_t) divider; // some card's runs only when slightly oveclocked like HD02
		else
		{
			reader->divider = (int32_t) divider;
			if(divider > reader->divider)
			{
				reader->divider++;    /* to prevent over clocking, ceil (round up) the divider */
			}
		}
		rdr_log_dbg(reader, D_DEVICE, "PLL maxmhz = %.2f, wanted mhz = %.2f, divider used = %d, actualcardclock=%.2f", (float) reader->cardmhz / 100, (float) reader->mhz / 100,
					reader->divider, (float) reader->cardmhz / reader->divider / 100);
		reader->mhz = reader->cardmhz / reader->divider;
	}
	else
	{
		int32_t i, dm7025_clock_freq[] = {518, 461, 395, 360, 319, 296, 267, 244, 230, 212, 197}, dm7025_PLL_setting[] = {6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, t_cardmhz = reader->mhz;
		for(i = 0; i < 11; i++)
			if(t_cardmhz >= dm7025_clock_freq[i])
			{
				break;
			}
		if(i > 10)
		{
			i = 10;
		}
		reader->mhz = dm7025_clock_freq[i];
		reader->divider = dm7025_PLL_setting[i]; /*Nicer way of codeing is: reader->divider = i + 6;*/
		rdr_log_dbg(reader, D_DEVICE, "DM7025 PLL maxmhz = %.2f, wanted mhz = %.2f, PLL setting used = %d, actualcardclock=%.2f",
					(float) reader->cardmhz / 100,
					(float) t_cardmhz / 100,
					reader->divider,
					(float) reader->mhz / 100);
	}
	return reader->divider;
}


static void ICC_Async_InvertBuffer(struct s_reader *reader, uint32_t size, unsigned char *buffer)
{
	uint32_t i;
	rdr_log_dbg(reader, D_IFD, "%s: size=%u buf[0]=%02x", __func__, size, buffer[0]);
	for(i = 0; i < size; i++)
	{
		buffer[i] = ~(INVERT_BYTE(buffer[i]));
	}
}

static int32_t Parse_ATR(struct s_reader *reader, ATR *atr, uint16_t deprecated)
{
	unsigned char FI = ATR_DEFAULT_FI;
	uint32_t D = ATR_DEFAULT_D;
	uint32_t N = ATR_DEFAULT_N;
	int32_t ret;
	char tmp[256];

	int32_t numprot = atr->pn;
	//if there is a trailing TD, this number is one too high
	unsigned char tx;
	if(ATR_GetInterfaceByte(atr, numprot - 1, ATR_INTERFACE_BYTE_TD, &tx) == ATR_OK)
		if((tx & 0xF0) == 0)
		{
			numprot--;
		}
	int32_t i, point;
	char txt[50];
	bool OffersT[3]; //T14 stored as T2
	for(i = 0; i <= 2; i++)
	{
		OffersT[i] = 0;
	}
	for(i = 1; i <= numprot; i++)
	{
		point = 0;
		if(ATR_GetInterfaceByte(atr, i, ATR_INTERFACE_BYTE_TA, &tx) == ATR_OK)
		{
			snprintf((char *)txt + point, sizeof(txt) - point, "TA%i=%02X ", i, tx);
			point += 7;
		}
		if(ATR_GetInterfaceByte(atr, i, ATR_INTERFACE_BYTE_TB, &tx) == ATR_OK)
		{
			snprintf((char *)txt + point, sizeof(txt) - point, "TB%i=%02X ", i, tx);
			point += 7;
		}
		if(ATR_GetInterfaceByte(atr, i, ATR_INTERFACE_BYTE_TC, &tx) == ATR_OK)
		{
			snprintf((char *)txt + point, sizeof(txt) - point, "TC%i=%02X ", i, tx);
			point += 7;
		}
		if(ATR_GetInterfaceByte(atr, i, ATR_INTERFACE_BYTE_TD, &tx) == ATR_OK)
		{
			snprintf((char *)txt + point, sizeof(txt) - point, "TD%i=%02X ", i, tx);
			point += 7;
			tx &= 0X0F;
			snprintf((char *)txt + point, sizeof(txt) - point, "(T%i)", tx);
			if(tx == 14)
			{
				OffersT[2] = 1;
			}
			else
			{
				OffersT[tx] = 1;
			}
		}
		else
		{
			snprintf((char *)txt + point, sizeof(txt) - point, "no TD%i means T0", i);
			OffersT[0] = 1;
		}
		rdr_log_dbg(reader, D_ATR, "%s", txt);
	}

	int32_t numprottype = 0;
	for(i = 0; i <= 2; i++)
		if(OffersT[i])
		{
			numprottype ++;
		}
	rdr_log_dbg(reader, D_ATR, "%i protocol types detected. Historical bytes: %s", numprottype, cs_hexdump(1, atr->hb, atr->hbn, tmp, sizeof(tmp)));

	ATR_GetParameter(atr, ATR_PARAMETER_N, &(N));
	ATR_GetProtocolType(atr, 1, &(reader->protocol_type)); //get protocol from TD1

	unsigned char TA2;
	bool SpecificMode = (ATR_GetInterfaceByte(atr, 2, ATR_INTERFACE_BYTE_TA, &TA2) == ATR_OK);  //if TA2 present, specific mode, else negotiable mode
	if(SpecificMode)
	{
		reader->protocol_type = TA2 & 0x0F;
		if((TA2 & 0x10) != 0x10)    //bit 5 set to 0 means F and D explicitly defined in interface characters
		{
			unsigned char TA1;
			if(ATR_GetInterfaceByte(atr, 1, ATR_INTERFACE_BYTE_TA, &TA1) == ATR_OK)
			{
				FI = TA1 >> 4;
				ATR_GetParameter(atr, ATR_PARAMETER_D, &(D));
			}
			else
			{
				FI = ATR_DEFAULT_FI;
				D = ATR_DEFAULT_D;
			}
		}
		else
		{
			rdr_log(reader, "Specific mode: speed 'implicitly defined', not sure how to proceed, assuming default values");
			FI = ATR_DEFAULT_FI;
			D = ATR_DEFAULT_D;
		}
		uint32_t F = atr_f_table[FI];
		rdr_log_dbg(reader, D_ATR, "Specific mode: T%i, F=%d, D=%d, N=%d", reader->protocol_type, F, D, N);
	}
	else   //negotiable mode
	{

		reader->read_timeout = 1000000; // in us
		bool PPS_success = 0;
		bool NeedsPTS = ((reader->protocol_type != ATR_PROTOCOL_TYPE_T14) && (numprottype > 1 || (atr->ib[0][ATR_INTERFACE_BYTE_TA].present == 1 && atr->ib[0][ATR_INTERFACE_BYTE_TA].value != 0x11) || N == 255)); //needs PTS according to old ISO 7816
		if(NeedsPTS && deprecated == 0)
		{
			//                       PTSS   PTS0    PTS1    PCK
			unsigned char req[6] = { 0xFF, 0x10, 0x00, 0x00 }; //we currently do not support PTS2, standard guardtimes or PTS3,
			//but spare 2 bytes in arrayif card responds with it
			req[1] = 0x10 | reader->protocol_type; //PTS0 always flags PTS1 to be sent always
			if(ATR_GetInterfaceByte(atr, 1, ATR_INTERFACE_BYTE_TA, &req[2]) != ATR_OK)      //PTS1
			{
				req[2] = 0x11;    //defaults FI and DI to 1
			}
			uint32_t len = 0;
			call(SetRightParity(reader));
			ret = PPS_Exchange(reader, req, &len);
			if(ret == OK)
			{
				FI = req[2] >> 4;
				unsigned char DI = req[2] & 0x0F;
				D = atr_d_table[DI];
				uint32_t F = atr_f_table[FI];
				PPS_success = 1;
				rdr_log_dbg(reader, D_ATR, "PTS Succesfull, selected protocol: T%i, F=%d, D=%d, N=%d", reader->protocol_type, F, D, N);
			}
			else
			{
				rdr_log_dump_dbg(reader, D_ATR, req, len, "PTS Failure, response:");
			}
		}

		//When for SCI, T14 protocol, TA1 is obeyed, this goes OK for mosts devices, but somehow on DM7025 Sky S02 card goes wrong when setting ETU (ok on DM800/DM8000)
		if(!PPS_success)   //last PPS not succesfull
		{
			unsigned char TA1;
			if(ATR_GetInterfaceByte(atr, 1, ATR_INTERFACE_BYTE_TA, &TA1) == ATR_OK)
			{
				FI = TA1 >> 4;
				ATR_GetParameter(atr, ATR_PARAMETER_D, &(D));
			}
			else   //do not obey TA1
			{
				FI = ATR_DEFAULT_FI;
				D = ATR_DEFAULT_D;
			}
			if(NeedsPTS)
			{
				if((D == 32) || (D == 12) || (D == 20))  //those values were RFU in old table
				{
					D = 0;    // viaccess cards that fail PTS need this
				}
			}
			uint32_t F = atr_f_table[FI];
			rdr_log_dbg(reader, D_ATR, "No PTS %s, selected protocol T%i, F=%d, D=%d, N=%d",
						NeedsPTS ? "happened" : "needed", reader->protocol_type, F, D, N);
		}
	}//end negotiable mode

	//make sure no zero values
	uint32_t F = atr_f_table[FI];
	if(!F)
	{
		FI = ATR_DEFAULT_FI;
		rdr_log(reader, "Warning: F=0 is invalid, forcing FI=%d", FI);
	}
	if(!D)
	{
		D = ATR_DEFAULT_D;
		rdr_log(reader, "Warning: D=0 is invalid, forcing D=%d", D);
	}
	rdr_log_dbg(reader, D_ATR, "Init card protocol T%i, FI=%d, F=%d, D=%d, N=%d", reader->protocol_type, FI, F, D, N);
	if(deprecated == 0)
	{
		return InitCard(reader, atr, FI, D, N, deprecated);
	}
	else
	{
		return InitCard(reader, atr, ATR_DEFAULT_FI, ATR_DEFAULT_D, N, deprecated);
	}
}

static int32_t PPS_Exchange(struct s_reader *reader, unsigned char *params, uint32_t *length)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	unsigned char confirm[PPS_MAX_LENGTH];
	uint32_t len_request, len_confirm;
	char tmp[128];
	int32_t ret;

	len_request = PPS_GetLength(params);
	params[len_request - 1] = PPS_GetPCK(params, len_request - 1);
	rdr_log_dbg(reader, D_IFD, "PTS: Sending request: %s",
				cs_hexdump(1, params, len_request, tmp, sizeof(tmp)));

	if(crdr_ops->set_protocol)
	{
		ret = crdr_ops->set_protocol(reader, params, length, len_request);
		return ret;
	}

	/* Send PPS request */
	call(ICC_Async_Transmit(reader, len_request, len_request, params, 0, 1000000));

	/* Get PPS confirm */
	call(ICC_Async_Receive(reader, 2, confirm, 0, 1000000));
	len_confirm = PPS_GetLength(confirm);
	call(ICC_Async_Receive(reader, len_confirm - 2, confirm + 2, 0, 1000000));

	rdr_log_dbg(reader, D_IFD, "PTS: Receiving confirm: %s",
				cs_hexdump(1, confirm, len_confirm, tmp, sizeof(tmp)));
	if((len_request != len_confirm) || (memcmp(params, confirm, len_request)))
	{
		ret = ERROR;
	}
	else
	{
		ret = OK;
	}

	/* Copy PPS handshake */
	memcpy(params, confirm, len_confirm);
	(*length) = len_confirm;
	return ret;
}

static uint32_t PPS_GetLength(unsigned char *block)
{
	uint32_t length = 3;

	if(PPS_HAS_PPS1(block))
	{
		length++;
	}

	if(PPS_HAS_PPS2(block))
	{
		length++;
	}

	if(PPS_HAS_PPS3(block))
	{
		length++;
	}

	return length;
}

static uint32_t ETU_to_us(struct s_reader *reader, uint32_t ETU)
{

	return (uint32_t)((double) ETU * reader->worketu*2);  // in us
}

static int32_t ICC_Async_SetParity(struct s_reader *reader, uint16_t parity)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	if(crdr_ops->set_parity)
	{
		rdr_log_dbg(reader, D_IFD, "Setting right parity");
		call(crdr_ops->set_parity(reader, parity));
	}
	return OK;
}

static int32_t SetRightParity(struct s_reader *reader)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	//set right parity
	uint16_t parity = PARITY_EVEN;
	if(reader->convention == ATR_CONVENTION_INVERSE)
	{
		parity = PARITY_ODD;
	}
	else if(reader->protocol_type == ATR_PROTOCOL_TYPE_T14)
	{
		parity = PARITY_NONE;
	}

	call(ICC_Async_SetParity(reader, parity));

	if(crdr_ops->flush && reader->crdr_flush)
	{
		IO_Serial_Flush(reader);
	}

	return OK;
}

static int32_t InitCard(struct s_reader *reader, ATR *atr, unsigned char FI, uint32_t D, unsigned char N, uint16_t deprecated)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	uint32_t I, F, Fi, BGT = 0, edc, GT = 0, WWT = 0, EGT = 0;
	unsigned char wi = 0;

	//set the amps and the volts according to ATR
	if(ATR_GetParameter(atr, ATR_PARAMETER_I, &I) != ATR_OK)
	{
		I = 0;
	}

	tempfi = FI;

	//set clock speed to max if internal reader
	if(crdr_ops->max_clock_speed == 1 && reader->typ == R_INTERNAL)
	{
		if(reader->autospeed == 1)  //no overclocking
		{
			reader->mhz = atr_fs_table[FI] / 10000;    //we are going to clock the card to this nominal frequency
		}

		if(reader->cardmhz > 2000 && reader->autospeed == 1)  // -1 replaced by autospeed parameter is magic number pll internal reader set cardmhz according to optimal atr speed
		{
			reader->mhz = atr_fs_table[FI] / 10000 ;
			if((!strncmp(boxtype_get(), "vu", 2 ))||(boxtype_is("ini-8000am")))
			{
				reader->mhz = 450;
			}
		}
	}

	if(reader->cardmhz > 2000)
	{
		reader->divider = 0; //reset pll divider so divider will be set calculated again.
		ICC_Async_GetPLL_Divider(reader); // calculate pll divider for target cardmhz.
	}

	Fi = atr_f_table[FI];  //get the frequency divider also called clock rate conversion factor
	if(crdr_ops->set_baudrate)
	{
		reader->current_baudrate = DEFAULT_BAUDRATE;

		if(deprecated == 0)
		{

			if(reader->protocol_type != ATR_PROTOCOL_TYPE_T14)    //dont switch for T14
			{
				uint32_t baud_temp = (double)D * ICC_Async_GetClockRate(reader->cardmhz) / (double)Fi;
				uint32_t baud_temp2 = (double)D * ICC_Async_GetClockRate(reader->mhz) / (double)Fi;
				rdr_log(reader, "Setting baudrate to %d bps", baud_temp2);
				// set_baudrate() increases/decreases baud_temp to baud_temp2 in case of over/underclocking
				call(crdr_ops->set_baudrate(reader, baud_temp));
				reader->current_baudrate = baud_temp2;
			}
		}
	}
	if(reader->cardmhz > 2000 && reader->typ == R_INTERNAL)
	{
		F = reader->mhz;    // for PLL based internal readers
	}
	else
	{
		if (reader->typ == R_SMART || is_smargo_reader(reader))
		{
			if (reader->autospeed == 1)
			{
				uint32_t Fsmart = atr_fs_table[FI];
				reader->mhz = Fsmart/10000;
				if(reader->mhz >= 1600)
				{
					reader->mhz = 1600;
				}
				else if(reader->mhz >= 1200)
				{
					reader->mhz = 1200;
				}
				else if(reader->mhz >= 961)
				{
					reader->mhz =  961;
				}
				else if(reader->mhz >= 800)
				{
					reader->mhz =  800;
				}
				else if(reader->mhz >= 686)
				{
					reader->mhz =  686;
				}
				else if(reader->mhz >= 600)
				{
					reader->mhz =  600;
				}
				else if(reader->mhz >= 534)
				{
					reader->mhz =  534;
				}
				else if(reader->mhz >= 480)
				{
					reader->mhz =  534;
				}
				else if(reader->mhz >= 436)
				{
					reader->mhz =  436;
				}
				else if(reader->mhz >= 400)
				{
					reader->mhz =  400;
				}
				else if(reader->mhz >= 369)
				{
					reader->mhz =  369;
				}
				else if(reader->mhz >= 357)
				{
					reader->mhz =  369;    // 357 not suported by smartreader
				}
				else if(reader->mhz >= 343)
				{
					reader->mhz =  343;
				}
				else
				{
					reader->mhz =  320;
				}
			}
		}
		F = reader->mhz;
	} // all other readers
	reader->worketu = (double)((double)(1 / (double)D) * ((double)Fi / (double)((double)F / 100)));
	rdr_log_dbg(reader, D_ATR, "Calculated work ETU is %.2f us reader mhz = %u", reader->worketu, reader->mhz);

	//set timings according to ATR
	reader->read_timeout = 0;
	reader->block_delay = 0;
	reader->char_delay = 0;

	switch(reader->protocol_type)
	{
	case ATR_PROTOCOL_TYPE_T0:
	case ATR_PROTOCOL_TYPE_T14:
	{
		/* Integer value WI = TC2, by default 10 */
#ifndef PROTOCOL_T0_USE_DEFAULT_TIMINGS
		if(ATR_GetInterfaceByte(atr, 2, ATR_INTERFACE_BYTE_TC, &(wi)) != ATR_OK)
#endif
			wi = DEFAULT_WI;

		WWT = (uint32_t) 960 * D * wi; //in work ETU
		GT = 2; // standard guardtime
		GT += 1; // start bit
		GT += 8; // databits
		GT += 1; // parity bit

		if(N != 255)  //add extra Guard Time by ATR
		{
			EGT += N;    // T0 protocol, if TC1 = 255 then dont add extra guardtime
		}
		reader->CWT = 0; // T0 protocol doesnt have char waiting time (used to detect errors within 1 single block of data)
		reader->BWT = 0; // T0 protocol doesnt have block waiting time (used to detect unresponsive card, this is max time for starting a block answer)

		rdr_log_dbg(reader, D_ATR, "Protocol: T=%i, WWT=%u, Clockrate=%u", reader->protocol_type, WWT, F * 10000);
		reader->read_timeout = WWT; // Work waiting time used in T0 (max time to signal unresponsive card!)
		reader->char_delay = GT + EGT; // Character delay is used on T0
		rdr_log_dbg(reader, D_ATR, "Setting timings: timeout=%u ETU, block_delay=%u ETU, char_delay=%u ETU", reader->read_timeout, reader->block_delay, reader->char_delay);
		break;
	}
	case ATR_PROTOCOL_TYPE_T1:
	{
		unsigned char ta, tb, tc, cwi, bwi;

		// Set IFSC
		if(ATR_GetInterfaceByte(atr, 3, ATR_INTERFACE_BYTE_TA, &ta) == ATR_NOT_FOUND)
		{
			reader->ifsc = DEFAULT_IFSC;
		}
		else if((ta != 0x00) && (ta != 0xFF))
		{
			reader->ifsc = ta;
		}
		else
		{
			reader->ifsc = DEFAULT_IFSC;
		}

		//FIXME workaround for Smargo until native mode works
		if(reader->smargopatch == 1)
		{
			reader->ifsc = MIN(reader->ifsc, 28);
		}
		else
			// Towitoko and smartreaders dont allow IFSC > 251
		{
			reader->ifsc = MIN(reader->ifsc, MAX_IFSC);
		}

#ifndef PROTOCOL_T1_USE_DEFAULT_TIMINGS
		// Calculate CWI and BWI
		if(ATR_GetInterfaceByte(atr, 3, ATR_INTERFACE_BYTE_TB, &tb) == ATR_NOT_FOUND)
		{
#endif
			cwi = DEFAULT_CWI;
			bwi = DEFAULT_BWI;
#ifndef PROTOCOL_T1_USE_DEFAULT_TIMINGS
		}
		else
		{
			cwi = tb & 0x0F;
			bwi = tb >> 4;
		}
#endif

		// Set CWT = 11+(2^CWI) work etu
		reader->CWT = (uint16_t) 11 + (1 << cwi); // in work ETU

		reader->BWT = (uint32_t) ((1<<bwi) * 960 * 372 / (double)((double)F / 100) / (double) reader->worketu) + 11;  // BWT in work ETU

		BGT = 22L; // Block Guard Time in ETU used to interspace between block responses
		GT = 2; // standard guardtime
		GT += 1; // start bit
		GT += 8; // databits
		GT += 1; // parity bit

		if(N == 255)
		{
			GT -= 1;    // special case, ATR says standard 2 etu guardtime is decreased by 1 (in ETU) EGT remains zero!
		}
		else
		{
			EGT += N;    // ATR says add extra guardtime (in ETU)
		}

		// Set the error detection code type
		if(ATR_GetInterfaceByte(atr, 3, ATR_INTERFACE_BYTE_TC, &tc) == ATR_NOT_FOUND)
		{
			edc = EDC_LRC;
		}
		else
		{
			edc = tc & 0x01;
		}

		// Set initial send sequence (NS)
		reader->ns = 1;
#ifdef READER_NAGRA_MERLIN
		cas7_seq=0x00;
#endif
		rdr_log_dbg(reader, D_ATR, "Protocol: T=%i: IFSC=%d, CWT=%d etu, BWT=%d etu, BGT=%d etu, EDC=%s, N=%d",
					reader->protocol_type, reader->ifsc,
					reader->CWT, reader->BWT,
					BGT, (edc == EDC_LRC) ? "LRC" : "CRC", N);
		reader->read_timeout = reader->BWT;
		reader->block_delay = BGT;
		reader->char_delay = GT + EGT;
		rdr_log_dbg(reader, D_ATR, "Setting timings: reader timeout=%u ETU, block_delay=%u ETU, char_delay=%u ETU", reader->read_timeout, reader->block_delay, reader->char_delay);

		break;
	}

	default:
		return ERROR;
		break;
	}//switch
	SetRightParity(reader);  // some reader devices need to get set the right parity

	uint32_t ETU = Fi / D;
	if(atr->hbn >= 6 && !memcmp(atr->hb, "IRDETO", 6) && reader->protocol_type == ATR_PROTOCOL_TYPE_T14)
	{
		ETU = 0;
		reader->worketu *= 2; // overclocked T14 needs this otherwise high ecm reponses
	}

	struct s_cardreader_settings s =
	{
		.ETU = ETU,
		.EGT = EGT,
		.P   = 5,
		.I   = I,
		.F   = Fi,
		.Fi  = (uint16_t) Fi,
		.Ni  = N,
		.D   = D,
		.WWT = WWT,
		.BGT = BGT,
	};

	if(crdr_ops->write_settings)
	{
		call(crdr_ops->write_settings(reader, &s));
	}

	/*
		if(reader->typ == R_INTERNAL)
		{
			if(reader->cardmhz > 2000){
				rdr_log(reader, "PLL Reader: ATR Fsmax is %i MHz, clocking card to %.2f Mhz (nearest possible mhz specified reader->mhz)", atr_fs_table[FI] / 1000000, (float) reader->mhz / 100);
			}else{
				rdr_log(reader, "ATR Fsmax is %i MHz, clocking card to %.2f (specified in reader->mhz)", atr_fs_table[FI] / 1000000, (float) reader->mhz / 100);
			}
		}else{
			if ((reader->typ == R_SMART) && (reader->autospeed == 1)){
				rdr_log(reader, "ATR Fsmax is %i MHz, clocking card to ATR Fsmax for smartreader cardspeed of %.2f MHz (specified in reader->mhz)", atr_fs_table[FI] / 1000000, (float) reader->mhz / 100);
			}else{
				rdr_log(reader, "ATR Fsmax is %i MHz, clocking card to wanted user cardclock of %.2f MHz (specified in reader->mhz)",atr_fs_table[FI] / 1000000, (float) reader->mhz / 100);
			}
		}
	*/

	//Communicate to T1 card IFSD -> we use same as IFSC

	if(reader->protocol_type == ATR_PROTOCOL_TYPE_T1 && reader->ifsc != DEFAULT_IFSC && !crdr_ops->skip_setting_ifsc)
	{
		unsigned char rsp[CTA_RES_LEN];
		uint16_t lr = 0;
		int32_t ret;
		unsigned char tmp[] = { 0x21, 0xC1, 0x01, 0x00, 0x00 };
		tmp[3] = reader->ifsc; // Information Field size
		tmp[4] = reader->ifsc ^ 0xE1;
		ret = Protocol_T1_Command(reader, tmp, sizeof(tmp), rsp, &lr, 0);
		if(ret != OK)
		{
			rdr_log(reader, "Warning: Card returned error on setting ifsd value to %d", reader->ifsc);
		}
		else
		{
			rdr_log_dbg(reader, D_ATR, "Card responded ok for ifsd request of %d", reader->ifsc);
		}
	}
	return OK;
}

static unsigned char PPS_GetPCK(unsigned char *block, uint32_t length)
{
	unsigned char pck;
	uint32_t i;
	pck = block[0];
	for(i = 1; i < length; i++)
	{
		pck ^= block[i];
	}
	return pck;
}
#endif
