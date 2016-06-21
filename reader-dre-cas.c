#include "globals.h"
#ifdef READER_DRECAS
#include "cscrypt/des.h"
#include "reader-common.h"
#include "reader-dre-common.h"
#include "csctapi/icc_async.h"

struct dre_data
{
	uint8_t     provider;
};

struct stm_keys
{
	uint8_t stmcmd34[64][0x30];
} stm_keys_t;

uint8_t stm_curkey[2] = {0,0};
extern char cs_confdir[128];

#define MSP_CMD_BYTE 0x59
#define STM_CMD_BYTE 0x74
#define MOD_CMD_BYTE 0xDB

#define READ  0
#define WRITE 1

static void stm_key_operaion(struct s_reader *reader, int operation)
{
	FILE *file = NULL;
	char stmkeyfile[256];
	int i;
	
	if(reader->stmkeys == NULL) 
	{
		snprintf(stmkeyfile,256,"%sstmkeys.bin",cs_confdir);
	}
	else
	{
		if(strchr(reader->stmkeys, '/') == NULL)
		{
			snprintf(stmkeyfile,256,"%s%s",cs_confdir, reader->stmkeys);
		}
		else
		{
			snprintf(stmkeyfile,256,"%s",reader->stmkeys);
		}
	}
	
	if((file = fopen(stmkeyfile, operation == READ ? "rb":"wb")) == NULL) 
	{
		cs_log("Error: can't' open stm key file (%s)", stmkeyfile);
		return;
	}
	
	if(operation == WRITE)
	{
		i = fwrite(&stm_keys_t, sizeof(stm_keys_t), 1, file);
	}
	else
	{
		i = fread(&stm_keys_t, sizeof(stm_keys_t), 1, file);
	}
	
	fclose(file);
	
	if(!i) cs_log("Error read/write stm key file (%s)", stmkeyfile);
}

static uchar xor(const uchar *cmd, int32_t cmdlen)
{
	int32_t i;
	uchar checksum = 0x00;
	for(i = 0; i < cmdlen; i++)
		{ checksum ^= cmd[i]; }
	return checksum;
}

static int8_t isValidDCW(uint8_t *dw)
{
	if (((dw[0]+dw[1]+dw[2]) & 0xFF) != dw[3])
	{
		return 0;
	}
	if (((dw[4]+dw[5]+dw[6]) & 0xFF) != dw[7])
	{
		return 0;
	}
	if (((dw[8]+dw[9]+dw[10]) & 0xFF) != dw[11])
	{
		return 0;
	}
	if (((dw[12]+dw[13]+dw[14]) & 0xFF) != dw[15])
	{
		return 0;
	}
	return 1;
}

static int32_t drecas_send_cmd(struct s_reader *reader, uchar *cmd, int32_t cmdlen, unsigned char *cta_res, uint16_t *p_cta_lr, uint8_t dest)
{
	uchar startcmd[3] = { 0xDB, 0x00, 0x00 };	//any command starts with this,
												//last byte is nr of bytes of the command that will be sent
	uchar command[260];
	uchar checksum;
	char tmp[256];
	
	startcmd[1] = cmdlen + 2; //command+length + len + checksum bytes
	startcmd[2] = dest;
	
	memcpy(command, startcmd, 3);
	memcpy(command + 3, cmd, cmdlen);
	cmdlen += 3;
	checksum = xor(command+2, cmdlen-2);
	command[cmdlen++] = checksum;
	
	rdr_log_dbg(reader, D_READER, "write to module: %s", cs_hexdump(0, command, cmdlen, tmp, sizeof(tmp)));
	
	ICC_Async_Transmit(reader, (uint32_t) cmdlen, 0, command, 0, 200);
	ICC_Async_Receive(reader, 2, cta_res, 50, 3000000);
	
	ICC_Async_Receive(reader, cta_res[1], cta_res+2, 50, 3000000);
	*p_cta_lr = cta_res[1] + 2;
	
	rdr_log_dbg(reader, D_READER, "answer from module: %s", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
	
	checksum = xor(cta_res + 2, *p_cta_lr - 3);
	
	if(cta_res[*p_cta_lr - 1] != checksum)
	{
		rdr_log(reader, "checksum does not match, expected %02x received %02x:%s", checksum,
				cta_res[*p_cta_lr - 1], cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
		return ERROR;           //error
	}
	
	return OK;
}

static int32_t drecas_MSP_command(struct s_reader *reader, const uchar *cmd, int32_t cmdlen, unsigned char *cta_res, uint16_t *p_cta_lr)
															//attention: inputcommand will be changed!!!! answer will be in cta_res, length cta_lr ; returning 1 = no error, return ERROR = err
{
	uchar startcmd[] = { 0x80, 0xFF, 0x10, 0x01, 0x05 };  //any command starts with this,
	uchar command[256];
	uchar checksum;
	char tmp[256];
	
	startcmd[4] = cmdlen + 3; //command+length + len + checksum bytes
	memcpy(command, startcmd, 5);
	command[5] = MSP_CMD_BYTE;  //type
	command[6] = cmdlen + 1;    //len = command + 1 checksum byte
	memcpy(command + 7, cmd, cmdlen);

	checksum = ~xor(cmd, cmdlen);
	
	cmdlen += 7;
	command[cmdlen++] = checksum;
	
	if(drecas_send_cmd(reader, command, cmdlen, cta_res, p_cta_lr, 1) != OK) return ERROR;
	
	if(cta_res[4] != MSP_CMD_BYTE) return ERROR;
	
	if((cta_res[5] == 0x03) && (cta_res[6] == 0xe2))
	{
		switch(cta_res[7])
		{
		case 0xe1:
			rdr_log(reader, "checksum error: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe2:
			rdr_log(reader, "wrong cmd len: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe3:
			rdr_log(reader, "illegal command: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe4:
			rdr_log(reader, "wrong adress type: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe5:
			rdr_log(reader, "wrong CMD param: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe6:
			rdr_log(reader, "wrong UA: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe7:
			rdr_log(reader, "wrong group: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe8:
			rdr_log(reader, "wrong key num: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xeb:
			rdr_log(reader, "No key or subscribe : %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xec:
			rdr_log(reader, "wrong signature: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xed:
			rdr_log(reader, "wrong provider: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xef:
			rdr_log(reader, "wrong GEO code: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		default:
			rdr_log_dbg(reader, D_READER, "unknown error: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		}
		return ERROR;           //error
	}
	
	int32_t length_excl_leader = *p_cta_lr;

	checksum = ~xor(cta_res + 6, length_excl_leader - 8);

	if(cta_res[length_excl_leader - 2] != checksum)
	{
		rdr_log(reader, "checksum does not match, expected %02x received %02x:%s", checksum,
				cta_res[length_excl_leader - 2], cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
		return ERROR;           //error
	}
	
	return OK;
}

#define drecas_MSP_script(cmd, len) \
    { \
        drecas_MSP_command(reader, cmd, len, cta_res, &cta_lr); \
    }

#define drecas_MSP_cmd(cmd) \
    { \
        drecas_MSP_command(reader, cmd, sizeof(cmd), cta_res, &cta_lr); \
    }

static int32_t drecas_STM_command(struct s_reader *reader, const uchar *cmd, int32_t cmdlen, unsigned char *cta_res, uint16_t *p_cta_lr)
															//attention: inputcommand will be changed!!!! answer will be in cta_res, length cta_lr ; returning 1 = no error, return ERROR = err
{
	uchar command[256];
	uchar checksum;
	char tmp[256];
	
	command[0] = 0xC2;
	command[1] = STM_CMD_BYTE;  //type
	command[2] = cmdlen + 1;    //len = command + 1 checksum byte
	memcpy(command + 3, cmd, cmdlen);

	checksum = ~xor(cmd, cmdlen);
	
	cmdlen += 3;
	command[cmdlen++] = checksum;
	
	if(drecas_send_cmd(reader, command, cmdlen, cta_res, p_cta_lr, 0) != OK) return ERROR;
	
	if(cta_res[4] != STM_CMD_BYTE) return ERROR;
	
	if((cta_res[5] == 0x03) && (cta_res[6] == 0xe2))
	{
		switch(cta_res[7])
		{
		case 0xe1:
			rdr_log(reader, "checksum error: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe2:
			rdr_log(reader, "wrong cmd len: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe3:
			rdr_log(reader, "illegal command: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe4:
			rdr_log(reader, "wrong adress type: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe5:
			rdr_log(reader, "wrong CMD param: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe6:
			rdr_log(reader, "wrong UA: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe7:
			rdr_log(reader, "wrong group: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xe8:
			rdr_log(reader, "wrong key num: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xeb:
			rdr_log(reader, "No key or subscribe : %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xec:
			rdr_log(reader, "wrong signature: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xed:
			rdr_log(reader, "wrong provider: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		case 0xef:
			rdr_log(reader, "wrong GEO code: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		default:
			rdr_log_dbg(reader, D_READER, "unknown error: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
			break;
		}
		return ERROR;           //error
	}
	
	int32_t length_excl_leader = *p_cta_lr;

	checksum = ~xor(cta_res + 6, length_excl_leader - 8);

	if(cta_res[length_excl_leader - 2] != checksum)
	{
		rdr_log(reader, "checksum does not match, expected %02x received %02x:%s", checksum,
				cta_res[length_excl_leader - 2], cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
		return ERROR;           //error
	}
	
	return OK;
}

#define drecas_STM_script(cmd, len) \
    { \
        drecas_STM_command(reader, cmd, len, cta_res, &cta_lr); \
    }

#define drecas_STM_cmd(cmd) \
    { \
        drecas_STM_command(reader, cmd, sizeof(cmd), cta_res, &cta_lr); \
    }

static int32_t drecas_set_provider_info(struct s_reader *reader)
{
	def_resp;
	int32_t i;
	uchar subscr[] = { 0x59, 0x14 };   // subscriptions
	uchar dates[] = { 0x5b, 0x00, 0x14 }; //validity dates
	struct dre_data *csystem_data = reader->csystem_data;
	subscr[1] = csystem_data->provider;
	
	cs_clear_entitlement(reader);
	
	if((drecas_MSP_cmd(subscr)))      //ask subscription packages, returns error on 0x11 card
	{
		uchar pbm[32];
		char tmp_dbg[65];
		memcpy(pbm, cta_res + 7, 32);
		rdr_log_dbg(reader, D_READER, "pbm: %s", cs_hexdump(0, pbm, 32, tmp_dbg, sizeof(tmp_dbg)));

		for(i = 0; i < 32; i++)
			if(pbm[i] != 0xff)
			{
				dates[1] = i;
				dates[2] = csystem_data->provider;
				drecas_MSP_cmd(dates);   //ask for validity dates

				time_t start;
				time_t end;
				start = (cta_res[7] << 24) | (cta_res[8] << 16) | (cta_res[9] << 8) | cta_res[10];
				end = (cta_res[11] << 24) | (cta_res[12] << 16) | (cta_res[13] << 8) | cta_res[14];

				struct tm temp;

				localtime_r(&start, &temp);
				int32_t startyear = temp.tm_year + 1900;
				int32_t startmonth = temp.tm_mon + 1;
				int32_t startday = temp.tm_mday;
				localtime_r(&end, &temp);
				int32_t endyear = temp.tm_year + 1900;
				int32_t endmonth = temp.tm_mon + 1;
				int32_t endday = temp.tm_mday;
				rdr_log(reader, "active package %i valid from %04i/%02i/%02i to %04i/%02i/%02i", i, startyear, startmonth, startday,
						endyear, endmonth, endday);
				cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), 0, i, start, end, 5, 1);
			}
	}
	
	return OK;
}

static int32_t drecas_card_init(struct s_reader *reader, ATR *newatr)
{
	get_atr;
	def_resp;
	uchar ua[] = { 0x43, 0x15 };  // get serial number (UA)
	uchar providers[] = { 0x49, 0x15 };   // get providers
	int32_t i;
	char *card;
	char tmp[9];
	uint8_t module_atr[] = { 0xDB ,0x0B ,0x08 ,0xA3 ,0x3B ,0x15 ,0x11 ,0x12 ,0x01 ,0x01 ,0x11 ,0x07 ,0x90 };
	
	if(memcmp(atr, module_atr, sizeof(module_atr)) != 0) 
		{ return ERROR; }
	
	if(!cs_malloc(&reader->csystem_data, sizeof(struct dre_data)))
		{ return ERROR; }
	struct dre_data *csystem_data = reader->csystem_data;

	csystem_data->provider = atr[10];
	uchar checksum = xor(atr + 5, 6);
	
	if(checksum != atr[11])
		{ rdr_log(reader, "warning: expected ATR checksum %02x, smartcard reports %02x", checksum, atr[7]); }
	
	switch(atr[10])
	{
		case 0x11:
			card = "Tricolor Centr DRE2";
			reader->caid = 0x4ae1;
			break;          //59 type card = MSP (74 type = ATMEL)

		case 0x14:
			card = "Tricolor Syberia DRE2";
			reader->caid = 0x4ae1;
			break;          //59 type card

		default:
			return ERROR;
	}

	memset(reader->prid, 0x00, 8);
	
	reader->prid[0][3] = csystem_data->provider;
	
	uchar cmd54[] = { 0x54, 0x14 };   // geocode
	cmd54[1] = csystem_data->provider;
	uchar geocode = 0;
	if((drecas_MSP_cmd(cmd54)))      //error would not be fatal, like on 0x11 cards
		{ geocode = cta_res[7]; }

	providers[1] = csystem_data->provider;
	if(!(drecas_MSP_cmd(providers)))
		{ return ERROR; }           //fatal error
	if((cta_res[2] != 0x09) || (cta_res[3] != 0xC0))
		{ return ERROR; }
	
	uchar provname[128];
	for(i = 0; ((i < cta_res[6] - 6) && (i < 128)); i++)
	{
		provname[i] = cta_res[10 + i];
		if(provname[i] == 0x00)
			{ break; }
	}
	
	int32_t major_version = cta_res[7];
	int32_t minor_version = cta_res[8];

	ua[1] = csystem_data->provider;
	drecas_MSP_cmd(ua);          //error would not be fatal

	int32_t hexlength = cta_res[5] - 2;   //discard first and last byte, last byte is always checksum, first is answer code

	if(reader->force_ua)
	{
		rdr_log(reader, "WARNING!!!! used UA from force_ua %08X", reader->force_ua);
		memcpy(cta_res + 7, &reader->force_ua, 8);
	}
	
	reader->hexserial[0] = 0;
	reader->hexserial[1] = 0;
	memcpy(reader->hexserial + 2, cta_res + 7, hexlength);
	
	int32_t low_dre_id, dre_chksum;
	uchar buf[32];
	
	low_dre_id = ((cta_res[8] << 16) | (cta_res[9] << 8) | cta_res[10]) - 48608;
	dre_chksum = 0;
	snprintf((char *)buf, sizeof(buf), "%i%i%08i", csystem_data->provider - 16, major_version + 1, low_dre_id);
	
	for(i = 0; i < 32; i++)
	{
		if(buf[i] == 0x00)
			{ break; }
		dre_chksum += buf[i] - 48;
	}
		
	rdr_log(reader, "type: DRE Crypt, caid: %04X, serial: {%s}, dre id: %i%i%i%08i, geocode %i, card: %s v%i.%i",
			reader->caid, cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)), dre_chksum, csystem_data->provider - 16,
			major_version + 1, low_dre_id, geocode, card, major_version, minor_version);
	
	rdr_log(reader, "Provider name:%s.", provname);


	memset(reader->sa, 0, sizeof(reader->sa));
	memcpy(reader->sa[0], reader->hexserial + 2, 1);  //copy first byte of unique address also in shared address, because we dont know what it is...

	rdr_log_sensitive(reader, "SA = %02X%02X%02X%02X, UA = {%s}", reader->sa[0][0], reader->sa[0][1], reader->sa[0][2],
					  reader->sa[0][3], cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)));

	reader->nprov = 1;
	
	// exec user script, wicardd format
	if(reader->userscript != NULL)
	{
		uint8_t *usercmd = NULL;
		int cmd_len;
		int n;
		char *tempbuf = malloc(2048);
		trim2(reader->userscript);
		FILE *pFile = fopen(reader->userscript, "rt");
		
		if(pFile != NULL)
		{
			do
			{
				tempbuf[0] = '\0';
				if(usercmd != NULL) free(usercmd);
				
				if(fgets(tempbuf, 2048, pFile) == NULL) continue;
				
				if(strlen(tempbuf) < 10) continue;
				
				trim2(tempbuf);
				
				if((tempbuf[0] != '5' && tempbuf[1] != '9') && (tempbuf[0] != '7' && tempbuf[1] != '4')) continue;
				
				strtoupper(tempbuf);
				
				cmd_len = strlen(tempbuf) / 2 - 3;
				usercmd = malloc(cmd_len);
				
				for(i=0,n=4; i<cmd_len; i++, n+=2)
				{
					usercmd[i] = ((tempbuf[n] - (tempbuf[n] > 0x39 ? 0x37:0x30)) << 4) + ((tempbuf[n+1] - (tempbuf[n+1] > 0x39 ? 0x37:0x30)) & 0xF);
				}
				
				if(tempbuf[0] != '7' && tempbuf[1] != '4')
				{
					rdr_log(reader, "Script %s", (drecas_MSP_script(usercmd, cmd_len)) ? "done" : "error");
				}
				else
				{
					rdr_log(reader, "Script %s", (drecas_STM_script(usercmd, cmd_len)) ? "done" : "error");
				}
			}
			while(!feof(pFile));
		}
		else
		{
			rdr_log(reader, "Can't open script file (%s)", reader->userscript);
		}
		
		//if(usercmd != NULL) free(usercmd);
		if(tempbuf != NULL) free(tempbuf);
	}
	
	if(csystem_data->provider == 0x11)
	{
		memset(reader->prid[1], 0x00, 8);
		reader->prid[1][3] = 0xFE;
		reader->nprov = 2;
	}
	
	if(!drecas_set_provider_info(reader))
		{ return ERROR; }           //fatal error
		
	stm_key_operaion(reader, READ);

	rdr_log(reader, "ready for requests");
	return OK;
}

static unsigned char DESkeys[16 * 8] =
{
	0x4A, 0x11, 0x23, 0xB1, 0x45, 0x99, 0xCF, 0x10, // 00
	0x21, 0x1B, 0x18, 0xCD, 0x02, 0xD4, 0xA1, 0x1F, // 01
	0x07, 0x56, 0xAB, 0xB4, 0x45, 0x31, 0xAA, 0x23, // 02
	0xCD, 0xF2, 0x55, 0xA1, 0x13, 0x4C, 0xF1, 0x76, // 03
	0x57, 0xD9, 0x31, 0x75, 0x13, 0x98, 0x89, 0xC8, // 04
	0xA3, 0x36, 0x5B, 0x18, 0xC2, 0x83, 0x45, 0xE2, // 05
	0x19, 0xF7, 0x35, 0x08, 0xC3, 0xDA, 0xE1, 0x28, // 06
	0xE7, 0x19, 0xB5, 0xD8, 0x8D, 0xE3, 0x23, 0xA4, // 07
	0xA7, 0xEC, 0xD2, 0x15, 0x8B, 0x42, 0x59, 0xC5, // 08
	0x13, 0x49, 0x83, 0x2E, 0xFB, 0xAD, 0x7C, 0xD3, // 09
	0x37, 0x25, 0x78, 0xE3, 0x72, 0x19, 0x53, 0xD9, // 0A
	0x7A, 0x15, 0xA4, 0xC7, 0x15, 0x49, 0x32, 0xE8, // 0B
	0x63, 0xD5, 0x96, 0xA7, 0x27, 0xD8, 0xB2, 0x68, // 0C
	0x42, 0x5E, 0x1A, 0x8C, 0x41, 0x69, 0x8E, 0xE8, // 0D
	0xC2, 0xAB, 0x37, 0x29, 0xD3, 0xCF, 0x93, 0xA7, // 0E
	0x49, 0xD3, 0x33, 0xC2, 0xEB, 0x71, 0xD3, 0x14  // 0F
};

static void DREover(const uint8_t *ECMdata, uint8_t *DW)
{
	uint32_t key_schedule[32];
	if(ECMdata[2] >= (43 + 4) && ECMdata[40] == 0x3A && ECMdata[41] == 0x4B)
	{
		des_set_key(&DESkeys[(ECMdata[42] & 0x0F) * 8], key_schedule);

		des(DW, key_schedule, 0); // even DW post-process
		des(DW + 8, key_schedule, 0);  // odd DW post-process
	};
};

static int32_t drecas_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp;
	uint16_t overcryptId;
	uint8_t tmp[16];
	char tmp_dbg[256];
	struct dre_data *csystem_data = reader->csystem_data;
	
	if(reader->caid == 0x4ae1)
	{
		if(csystem_data->provider == 0x11 || csystem_data->provider == 0x14)
		{
			uchar ecmcmd51[] = { 0x51, 0x02, 0x56, 0x05, 0x00, 0x4A, 0xE3,  //fixed header?
								 0x9C, 0xDA,       //first three nibbles count up, fourth nibble counts down; all ECMs sent twice
								 0xC1, 0x71, 0x21, 0x06, 0xF0, 0x14, 0xA7, 0x0E,   //next key?
								 0x89, 0xDA, 0xC9, 0xD7, 0xFD, 0xB9, 0x06, 0xFD,   //current key?
								 0xD5, 0x1E, 0x2A, 0xA3, 0xB5, 0xA0, 0x82, 0x11,   //key or signature?
								 0x14          //provider
							   };
			memcpy(ecmcmd51 + 1, er->ecm + 5, 0x21);
			rdr_log_dbg(reader, D_READER, "unused ECM info front:%s", cs_hexdump(0, er->ecm, 5, tmp_dbg, sizeof(tmp_dbg)));
			rdr_log_dbg(reader, D_READER, "unused ECM info back:%s", cs_hexdump(0, er->ecm + 37, 4, tmp_dbg, sizeof(tmp_dbg)));
			
			rdr_log_dbg(reader, D_READER, "ECM: %s",cs_hexdump(0, er->ecm, er->ecm[2]+3, tmp_dbg, sizeof(tmp_dbg)));
			
			ecmcmd51[33] = csystem_data->provider;  //no part of sig
			
			if((drecas_MSP_cmd(ecmcmd51)))     //ecm request
			{
				if((cta_res[2] != 0x09) || (cta_res[3] != 0xC0))
					{ return ERROR; }       //exit if response is not 90 00
				
				if(er->ecm[3] == 0x01)
				{
					uchar ecmcmd33[18] = {  0x33, 0x1F, 
											0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
										 };
										 
					int i;
					
					for(i=0; i<16; i++)
					{
							ecmcmd33[i+2] = cta_res[7+(i^3)];
					}
					
					if(er->ecm[5] != stm_curkey[0] || er->ecm[6] != stm_curkey[1])
					{
						uchar blank[0x30];
						memset(blank, 0, 0x30);
						
						if(memcmp(blank, stm_keys_t.stmcmd34[er->ecm[5]+(er->ecm[6] == 0x3B?0:32)], 0x30) == 0)
							{ 
								rdr_log_dbg(reader, D_READER, "STM key not found");
								return ERROR; 
							}
						
						if(!(drecas_STM_cmd(stm_keys_t.stmcmd34[er->ecm[5]+(er->ecm[6] == 0x3B?0:32)])))
							{ 
								rdr_log_dbg(reader, D_READER, "Error STM set key: %s",cs_hexdump(0, cta_res, cta_lr, tmp_dbg, sizeof(tmp_dbg)));
								return ERROR; 
							}
							
						if((cta_res[cta_lr-4] != 0x02) || (cta_res[cta_lr-3] != 0xA2))
						{
							rdr_log_dbg(reader, D_READER, "Error STM set key: %s",cs_hexdump(0, cta_res, cta_lr, tmp_dbg, sizeof(tmp_dbg)));
							return ERROR;
						}
					}
					
					stm_curkey[0] = er->ecm[5];
					stm_curkey[1] = er->ecm[6];
					
					if(!(drecas_STM_cmd(ecmcmd33)))
						{ return ERROR; }
					
					if(cta_res[1] != 0x17 || cta_res[6] != 0xD2)
						{ return ERROR; }
					
					memcpy(tmp, &cta_res[7], 16);
					
					for(i=0; i<16; i++)
					{
						cta_res[i+7] = tmp[i^3];
					}
				}
						
				if(er->ecm[2] >= 46 && er->ecm[43] == 1 && csystem_data->provider == 0x11)
				{   
					memcpy(&tmp[0], &cta_res[15], 8);
					memcpy(&tmp[8], &cta_res[7], 8);
					
					overcryptId = b2i(2, &er->ecm[44]);
					
					rdr_log_dbg(reader, D_READER, "ICG ID: %04X", overcryptId);
					
					Drecrypt2OverCW(overcryptId,tmp);
					
					if(isValidDCW(tmp))
					{
						memcpy(ea->cw, tmp, 16);
						return OK;
					}
					return ERROR;
				}
				
				DREover(er->ecm, cta_res + 7);
				
				if(isValidDCW(cta_res + 7))
				{
					memcpy(ea->cw, cta_res + 15, 8);
					memcpy(ea->cw + 8, cta_res + 7, 8);
					return OK;
				}
			}
		}
	}
	return ERROR;
}

static int32_t drecas_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	def_resp;
	struct dre_data *csystem_data = reader->csystem_data;
	
	if(reader->caid == 0x4ae1)
	{
		if(reader->caid != b2i(2, ep->caid)) return ERROR;
		
		if(ep->type == UNIQUE && ep->emm[39] == 0x3d)
		{
			/* For new package activation. */
			uchar emmcmd58[26];
			emmcmd58[0] = 0x58;
			memcpy(&emmcmd58[1], &ep->emm[40], 24);
			emmcmd58[25] = csystem_data->provider;
			if((drecas_MSP_cmd(emmcmd58)))
				if((cta_res[2] != 0x09) || (cta_res[3] != 0xC0))
					{ return ERROR; }
		}
		else if(ep->emm[0] == 0x86 && ep->emm[4] == 0x02 /*&& csystem_data->provider != 0x11*/)
		{
			uchar emmcmd52[0x3a];
			emmcmd52[0] = 0x52;
			int32_t i;
			for(i = 0; i < 2; i++)
			{
				memcpy(emmcmd52 + 1, ep->emm + 5 + 32 + i * 56, 56);
				// check for shared address
				if(ep->emm[3] != reader->sa[0][0])
					{ return OK; } // ignore, wrong address
				emmcmd52[0x39] = csystem_data->provider;
				if((drecas_MSP_cmd(emmcmd52)))
					if((cta_res[2] != 0x09) || (cta_res[3] != 0xC0))
						{ return ERROR; } //exit if response is not 90 00
			}
		}
		else if(ep->emm[0] == 0x86 && ep->emm[4] == 0x4D && csystem_data->provider == 0x11)
		{
			uchar emmcmd52[0x3a];
			emmcmd52[0] = 0x52;
			emmcmd52[1] = 0x01;
			emmcmd52[2] = ep->emm[5];
			emmcmd52[3] = 0x01;
			emmcmd52[4] = ep->emm[3];
			emmcmd52[5] = 0;
			emmcmd52[6] = 0;
			emmcmd52[7] = 0;
			emmcmd52[9] = 0x01;
			emmcmd52[10] = 0x01;
			emmcmd52[11] = 0;
			memcpy(emmcmd52 + 13, ep->emm + 0x5C, 4);
			int32_t i;
			
			for(i = 0; i < 2; i++)
			{
				emmcmd52[8] = ep->emm[0x61+i*0x29];
				if(i == 0) emmcmd52[12] = ep->emm[0x60] == 0x56 ? 0x56 : 0x3B;
				else emmcmd52[12] = ep->emm[0x60] == 0x56 ? 0x3B : 0x56;
				memcpy(emmcmd52 + 0x11, ep->emm + 0x62 + i * 0x29, 40);
				
				// check for shared address
				if(ep->emm[3] != reader->sa[0][0])
					{ return OK; } // ignore, wrong address
				emmcmd52[0x39] = csystem_data->provider;
				if((drecas_MSP_cmd(emmcmd52)))
					if((cta_res[2] != 0x09) || (cta_res[3] != 0xC0))
						{ return ERROR; } //exit if response is not 90 00
			}
			
			uchar emmcmd34[0x30] = { 
									0x34, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x10,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
									};
			emmcmd34[1] = ep->emm[0x05];
			emmcmd34[2] = ep->emm[0x5A];
			emmcmd34[3] = ep->emm[0x03];
			uint8_t need_save = 0;
			
			for(i = 0; i < 2; i++)
			{
				memcpy(&emmcmd34[7], &ep->emm[(i*0x29)+8] , 41);
				
				if(memcmp(emmcmd34, stm_keys_t.stmcmd34[ep->emm[0x05] + (ep->emm[7] == 0x3B ? i*32 : (i == 0 ? 32 : 0))], 0x30) != 0)
				{
					memcpy(stm_keys_t.stmcmd34[ep->emm[0x05] + (ep->emm[7] == 0x3B ? i*32 : (i == 0 ? 32 : 0))], emmcmd34, 0x30);
					need_save = 1;
				}
			}
			if(need_save == 1) stm_key_operaion(reader, WRITE);
		}
		else if(ep->type == GLOBAL && ep->emm[0] == 0x91)
		{
			Drecrypt2OverEMM(ep->emm);
			return OK;
		}
		else return OK;
	}

	return ERROR;
}

static int32_t drecas_card_info(struct s_reader *UNUSED(rdr))
{
	return OK;
}

const struct s_cardsystem reader_drecas =
{
	.desc           = "drecas",
	.caids          = (uint16_t[]){ 0x4AE1, 0 },
	.do_emm         = drecas_do_emm,
	.do_ecm         = drecas_do_ecm,
	.card_info      = drecas_card_info,
	.card_init      = drecas_card_init,
	.get_emm_type   = dre_common_get_emm_type,
	.get_emm_filter = dre_common_get_emm_filter,
};

#endif

