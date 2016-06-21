#include "globals.h"
#ifdef READER_DRE
#include "cscrypt/des.h"
#include "reader-common.h"
#include "reader-dre-common.h"

struct dre_data
{
	uint8_t     provider;
};

#define OK_RESPONSE 0x61
#define CMD_BYTE 0x59

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

static int32_t dre_command(struct s_reader *reader, const uchar *cmd, int32_t cmdlen, unsigned char *cta_res, uint16_t *p_cta_lr, 
															uint8_t crypted, uint8_t keynum, uint8_t dre_v, uint8_t cmd_type)
															//attention: inputcommand will be changed!!!! answer will be in cta_res, length cta_lr ; returning 1 = no error, return ERROR = err
{
	uchar startcmd[] = { 0x80, 0xFF, 0x10, 0x01, 0x05 };  //any command starts with this,
	//last byte is nr of bytes of the command that will be sent
	//after the startcmd
	//response on startcmd+cmd:     = { 0x61, 0x05 }  //0x61 = "OK", last byte is nr. of bytes card will send
	uchar reqans[] = { 0x00, 0xC0, 0x00, 0x00, 0x08 };    //after command answer has to be requested,
	//last byte must be nr. of bytes that card has reported to send
	uchar command[256];
	uchar checksum;
	char tmp[256];
	int32_t headerlen = sizeof(startcmd);
	
	if(dre_v > 0)
	{
		startcmd[1] = 0;
		startcmd[2] = crypted;
		startcmd[3] = keynum;
	}
	
	startcmd[4] = cmdlen + 3 - cmd_type; //commandlength + type + len + checksum bytes
	memcpy(command, startcmd, headerlen);
	command[headerlen++] = cmd_type ? 0x86 : CMD_BYTE;  //type
	command[headerlen++] = cmdlen + (cmd_type == 1 ? 0 : 1);    //len = command + 1 checksum byte
	memcpy(command + headerlen, cmd, cmdlen);

	if(!cmd_type)
	{
		checksum = ~xor(cmd, cmdlen);
		//rdr_log_dbg(reader, D_READER, "Checksum: %02x", checksum);
		cmdlen += headerlen;
		command[cmdlen++] = checksum;
	}
	else cmdlen += headerlen;
	
	reader_cmd2icc(reader, command, cmdlen, cta_res, p_cta_lr);

	if((*p_cta_lr != 2) || (cta_res[0] != OK_RESPONSE))
	{
		rdr_log(reader, "command sent to card: %s", cs_hexdump(0, command, cmdlen, tmp, sizeof(tmp)));
		rdr_log(reader, "unexpected answer from card: %s", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
		return ERROR;           //error
	}
	
	rdr_log_dbg(reader, D_READER, "command sent to card: %s", cs_hexdump(0, command, cmdlen, tmp, sizeof(tmp)));
	rdr_log_dbg(reader, D_READER, "answer from card: %s", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));

	reqans[4] = cta_res[1];   //adapt length byte
	reader_cmd2icc(reader, reqans, 5, cta_res, p_cta_lr);

	if(cta_res[0] != CMD_BYTE)
	{
		rdr_log(reader, "unknown response: cta_res[0] expected to be %02x, is %02x", CMD_BYTE, cta_res[0]);
		return ERROR;
	}
	
	if((cta_res[1] == 0x03) && (cta_res[2] == 0xe2))
	{
		switch(cta_res[3+dre_v])
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
	
	if((cta_res[*p_cta_lr - 2] == 0x90) && (cta_res[*p_cta_lr - 1] == 0x00))
		{ length_excl_leader -= 2; }

	checksum = ~xor(cta_res + 2, length_excl_leader - 3);

	if(cta_res[length_excl_leader - 1] != checksum)
	{
		rdr_log(reader, "checksum does not match, expected %02x received %02x:%s", checksum,
				cta_res[length_excl_leader - 1], cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
		return ERROR;           //error
	}
	return OK;
}

#define dre_script(cmd, len, cmd_type, crypted, keynum) \
    { \
        dre_command(reader, cmd, len, cta_res, &cta_lr, crypted, keynum, crypted, cmd_type); \
    }

#define dre_cmd(cmd) \
    { \
        dre_command(reader, cmd, sizeof(cmd), cta_res, &cta_lr, 0, 0, 0, 0); \
    }

#define dre_cmd_c(cmd,crypted,keynum) \
    { \
        dre_command(reader, cmd, sizeof(cmd),cta_res,&cta_lr, crypted, keynum, 1, 0); \
    }

static int32_t dre_set_provider_info(struct s_reader *reader)
{
	def_resp;
	int32_t i;
	int subscr_cmd_len = 4;
	uchar subscr[4];// = { 0x59, 0x14 };   // subscriptions
	uchar dates[] = { 0x5b, 0x00, 0x14 }; //validity dates
	uchar subscr_len = 0, n = 0;
	struct dre_data *csystem_data = reader->csystem_data;

	cs_clear_entitlement(reader);

	switch(csystem_data->provider)
	{
		case 0x02:
		case 0x03:
			subscr[0] = 0x84;
			subscr[1] = 0;
			subscr[2] = 0x5F;
			subscr[3] = csystem_data->provider;
			dates[0] = 0x85;
			subscr_len = 0x5F;
			break;
		case 0x18:
		case 0x19:
		case 0x1A:
			subscr[0] = 0x94;
			subscr[1] = 0;
			subscr[2] = 0x5F;
			subscr[3] = csystem_data->provider;
			dates[0] = 0x95;
			subscr_len = 0x5F;
			break;
		default:
			subscr[0] = 0x59;
			subscr[1] = csystem_data->provider;
			subscr_len = 0x20;
			subscr_cmd_len = 2;
	}

chk_subscr:
	
	if((dre_script(subscr, subscr_cmd_len, 0, 0, 0)))      //ask subscription packages, returns error on 0x11 card
	{
		uchar pbm[subscr_len];
		char tmp_dbg[subscr_len*2+1];
		memcpy(pbm, cta_res + 3, cta_lr - 6);
		rdr_log_dbg(reader, D_READER, "pbm: %s", cs_hexdump(0, pbm, subscr_len, tmp_dbg, sizeof(tmp_dbg)));

		for(i = 0; i < subscr_len; i++)
			if(pbm[i] != 0xff)
			{
				dates[1] = i;
				dates[2] = csystem_data->provider;
				dre_cmd(dates);   //ask for validity dates

				time_t start;
				time_t end;
				start = (cta_res[3] << 24) | (cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6];
				end = (cta_res[7] << 24) | (cta_res[8] << 16) | (cta_res[9] << 8) | cta_res[10];

				struct tm temp;

				localtime_r(&start, &temp);
				int32_t startyear = temp.tm_year + 1900;
				int32_t startmonth = temp.tm_mon + 1;
				int32_t startday = temp.tm_mday;
				localtime_r(&end, &temp);
				int32_t endyear = temp.tm_year + 1900;
				int32_t endmonth = temp.tm_mon + 1;
				int32_t endday = temp.tm_mday;
				rdr_log(reader, "active package %i valid from %04i/%02i/%02i to %04i/%02i/%02i", i+n, startyear, startmonth, startday,
						endyear, endmonth, endday);
				cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), 0, i+n, start, end, 5, 1);
			}
	}
	
	if(subscr_len == 0x5F) // read second part subscription packages, for DRE3 and DRE4
	{
		subscr[1] = 0x5F;
		subscr[2] = 0x21;
		subscr_len = 0x21;
		n = 0x5F;
		goto chk_subscr;
	}
	
	return OK;
}

static void dre_read_ee(struct s_reader *reader, const char *path, uchar provid)
{
	def_resp;
	int i, n;
	uchar *ee = malloc(2048);
	if(ee == NULL) return;
	
	uchar drecmd43[] = { 0x80, 0x00, 0x00, 0x00, 0x05,  0x59, 0x03, 0x43, 0x11, 0xAD };
	uchar drecmd45[] = { 0x45, 0x11 };
	
	drecmd43[8] = drecmd45[1] = provid;
	drecmd43[9] = ~xor(&drecmd43[7], 2);
	
	
	for(i = 0; i < 8; i++)
	{
		for(n = 0; n < 8; n++)
		{
			reader_cmd2icc(reader, drecmd43, 10, cta_res, &cta_lr);
			
			dre_cmd_c(drecmd45, n, i*32);
			
			if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
			{
				free(ee);
				rdr_log(reader, "ERROR read ee.bin from card");
				return;
			}
			
			memcpy(&ee[((n*8)+i)*32] ,&cta_res[2] ,32);
			
		}
	}
	
	FILE *pFile = fopen(path, "wb");
	
	if(pFile == NULL)
	{
		free(ee);
		return ;
	}
	
	fwrite(ee, 2048, 1, pFile);
	fclose(pFile);
	free(ee);
	rdr_log(reader, "ee.bin saved to %s", path);
}
/*
static void cmd_test(struct s_reader *reader)
{
	def_resp;
	int i;
	uchar drecmd[] = { 0x00, 0x02 };
	char tmp[64];
	
	for(i = 0; i <= 0xFF; i++)
	{
		if(i == 0x45) continue;
		drecmd[0] = i;
		dre_cmd(drecmd);
		if(cta_res[2] == 0xE2)
		{
			if(cta_res[3] != 0xE3) rdr_log(reader, "cmd %02X error %02X",i ,cta_res[3]);
		}
		else
		{
			rdr_log(reader, "cmd %02X answer %s",i ,cs_hexdump(0, cta_res, cta_res[1]+2, tmp, sizeof(tmp)));
		}
	}

	uchar drecmd[64];
	
	//memset(drecmd, 0, 64);
	//drecmd[0] = 0x71;
	for(i = 2; i <= 64; i++)
	{
		memset(drecmd, 0, 64);
		drecmd[i-1] = 0x02;
		drecmd[0] = 0x71;
		
		dre_script(drecmd, i, 0, 0, 0);
		
		if(cta_res[2] == 0xE2)
		{
			if((cta_res[3] != 0xE2) & (cta_res[3] != 0xED)) rdr_log(reader, "Len %02X error %02X",i ,cta_res[3]);
			if((cta_res[3] & 0xF0) != 0xE0) rdr_log(reader, "Len %02X answer %s",i ,cs_hexdump(0, cta_res, cta_res[1]+2, tmp, sizeof(tmp)));
		}
		else
		{
			rdr_log(reader, "Len %02X answer %s",i ,cs_hexdump(0, cta_res, cta_res[1]+2, tmp, sizeof(tmp)));
		}
	}
}
*/
static int32_t dre_card_init(struct s_reader *reader, ATR *newatr)
{
	get_atr;
	def_resp;
	uchar ua[] = { 0x43, 0x15 };  // get serial number (UA)
	uchar providers[] = { 0x49, 0x15 };   // get providers
	uchar cmd56[] = { 0x56, 0x00 };
	int32_t i;
	char *card;
	char tmp[9];

	if((atr[0] != 0x3b) || (atr[1] != 0x15) || (atr[2] != 0x11) || (atr[3] != 0x12) || (
				((atr[4] != 0x01) || (atr[5] != 0x01)) &&
				((atr[4] != 0xca) || (atr[5] != 0x07)) &&
				((atr[4] != 0xcb) || (atr[5] != 0x07)) &&
				((atr[4] != 0xcc) || (atr[5] != 0x07)) &&
				((atr[4] != 0xcd) || (atr[5] != 0x07))
			))
		{ return ERROR; }

	if(!cs_malloc(&reader->csystem_data, sizeof(struct dre_data)))
		{ return ERROR; }
	struct dre_data *csystem_data = reader->csystem_data;

	csystem_data->provider = atr[6];
	uchar checksum = xor(atr + 1, 6);

	if(checksum != atr[7])
		{ rdr_log(reader, "warning: expected ATR checksum %02x, smartcard reports %02x", checksum, atr[7]); }
	
	switch(atr[6])
	{
		case 0:
		
			if(!(dre_cmd(cmd56))) { return ERROR; }
			if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }
			
			switch(cta_res[4])
			{
				case 0x02:
					card = "Tricolor Centr DRE3";
					reader->caid = 0x4ae1;
					break;
				case 0x03:
					card = "Tricolor Syberia DRE3";
					reader->caid = 0x4ae1;	
					break;
				case 0x18:
				case 0x19:
					card = "Tricolor Centr DRE4";
					reader->caid = 0x2710;
					break;
				case 0x1A:
					card = "Tricolor Syberia DRE4";
					reader->caid = 0x2710;
					break;
				default:
					return ERROR;
			}
			csystem_data->provider = cta_res[4];
			providers[0] = 0x83;
			break;
		case 0x11:
			card = "Tricolor Centr DRE2";
			reader->caid = 0x4ae1;
			break;          //59 type card = MSP (74 type = ATMEL)
		case 0x12:
			card = "Cable TV";
			reader->caid = 0x4ae1;  //TODO not sure about this one
			break;
		case 0x14:
			card = "Tricolor Syberia DRE2";
			reader->caid = 0x4ae1;
			break;          //59 type card
		case 0x15:
			card = "Platforma HD / DW old";
			reader->caid = 0x4ae1;
			break;          //59 type card
		default:
			return ERROR;
	}

	memset(reader->prid, 0x00, 8);
	
	if(atr[6] > 0)
	{
		reader->prid[0][3] = atr[6];
	}
	else
	{
		reader->prid[0][3] = csystem_data->provider;
	}
	
	uchar cmd54[] = { 0x54, 0x14 };   // geocode
	cmd54[1] = csystem_data->provider;
	uchar geocode = 0;
	if((dre_cmd(cmd54)))      //error would not be fatal, like on 0x11 cards
		{ geocode = cta_res[3]; }

	providers[1] = csystem_data->provider;
	if(!(dre_cmd(providers)))
		{ return ERROR; }           //fatal error
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
		{ return ERROR; }
	
	uchar provname[128];
	for(i = 0; ((i < cta_res[2] - 6) && (i < 128)); i++)
	{
		provname[i] = cta_res[6 + i];
		if(provname[i] == 0x00)
			{ break; }
	}
	
	int32_t major_version = cta_res[3];
	int32_t minor_version = cta_res[4];

	ua[1] = csystem_data->provider;
	dre_cmd(ua);          //error would not be fatal

	int32_t hexlength = cta_res[1] - 2;   //discard first and last byte, last byte is always checksum, first is answer code

	if(reader->force_ua)
	{
		rdr_log(reader, "WARNING!!!! used UA from force_ua %08X", reader->force_ua);
		memcpy(cta_res + 3, &reader->force_ua, 4);
	}
	
	reader->hexserial[0] = 0;
	reader->hexserial[1] = 0;
	memcpy(reader->hexserial + 2, cta_res + 3, hexlength);
	
	int32_t low_dre_id, dre_chksum;
	uchar buf[32];
	
	if(major_version < 0x3)
	{
		low_dre_id = ((cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6]) - 48608;
		dre_chksum = 0;
		snprintf((char *)buf, sizeof(buf), "%i%i%08i", csystem_data->provider - 16, major_version + 1, low_dre_id);
		
		for(i = 0; i < 32; i++)
		{
			if(buf[i] == 0x00)
				{ break; }
			dre_chksum += buf[i] - 48;
		}
		
		if(major_version < 2)
		{
			reader->caid = 0x4ae0;
			card = csystem_data->provider == 0x11 ? "Tricolor Centr DRE1" : "Tricolor Syberia DRE1";
		}
		
		rdr_log(reader, "type: DRE Crypt, caid: %04X, serial: {%s}, dre id: %i%i%i%08i, geocode %i, card: %s v%i.%i",
				reader->caid, cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)), dre_chksum, csystem_data->provider - 16,
				major_version + 1, low_dre_id, geocode, card, major_version, minor_version);
	}
	else
	{
		low_dre_id = ((cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6]);
		dre_chksum = 0;
		snprintf((char *)buf, sizeof(buf), "%i%i%08i", csystem_data->provider, major_version, low_dre_id);
		
		for(i = 0; i < 32; i++)
		{
			if(buf[i] == 0x00)
				{ break; }
			dre_chksum += buf[i] - 48;
		}
		rdr_log(reader, "type: DRE Crypt, caid: %04X, serial: {%s}, dre id: %i%03i%i%08i, geocode %i, card: %s v%i.%i",
				reader->caid, cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)), dre_chksum, csystem_data->provider,
				major_version, low_dre_id, geocode, card, major_version, minor_version);
	}
	
	rdr_log(reader, "Provider name:%s.", provname);


	memset(reader->sa, 0, sizeof(reader->sa));
	memcpy(reader->sa[0], reader->hexserial + 2, 1);  //copy first byte of unique address also in shared address, because we dont know what it is...

	rdr_log_sensitive(reader, "SA = %02X%02X%02X%02X, UA = {%s}", reader->sa[0][0], reader->sa[0][1], reader->sa[0][2],
					  reader->sa[0][3], cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)));

	reader->nprov = 1;
	
//	cmd_test(reader);
	
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
			uchar ignoreProvid = 0;
			uchar crypted = 0;
			uchar cryptkey = 0;
			do
			{
				tempbuf[0] = '\0';
				if(usercmd != NULL) free(usercmd);
				
				if(fgets(tempbuf, 2048, pFile) == NULL) continue;
				
				if(strlen(tempbuf) < 10) continue;
				
				trim2(tempbuf);
				
				ignoreProvid = 0;
				crypted = 0;
				cryptkey = 0;
				
				if(tempbuf[0] == '8' && tempbuf[1] == '6' && csystem_data->provider == 0x11) ignoreProvid = 1;
				else if(strncmp(tempbuf ,"REG2" ,4) == 0)
				{
					dre_read_ee(reader, &tempbuf[4] ,csystem_data->provider);
					continue;
				}
				else if(strncmp(tempbuf ,"CR" ,2) == 0)
				{
					crypted = 1;
					cryptkey = ((tempbuf[2] - (tempbuf[2] > 0x39 ? 0x37:0x30)) << 4) + ((tempbuf[3] - (tempbuf[3] > 0x39 ? 0x37:0x30)) & 0xF);
				}
				else if(tempbuf[0] != '5' && tempbuf[1] != '9') continue;
				
				strtoupper(tempbuf);
				
				cmd_len = strlen(tempbuf) / 2 - 3 + ignoreProvid - (crypted * 2);
				usercmd = malloc(cmd_len);
				
				for(i=0,n= 4+(crypted * 4);i<cmd_len;i++,n+=2)
				{
					usercmd[i] = ((tempbuf[n] - (tempbuf[n] > 0x39 ? 0x37:0x30)) << 4) + ((tempbuf[n+1] - (tempbuf[n+1] > 0x39 ? 0x37:0x30)) & 0xF);
				}
				
				/*if(usercmd[cmd_len-1] != csystem_data->provider && !ignoreProvid)
				{
					rdr_log(reader, "Skip script: current provid %02X , script provid %02X", csystem_data->provider, usercmd[cmd_len-1]);
					continue;
				}
				*/
				rdr_log(reader, "User script: %s", tempbuf);
				
				/*ret =*/ 
				
				rdr_log(reader, "Script %s", (dre_script(usercmd, cmd_len, ignoreProvid, crypted, cryptkey)) ? "done" : "error");
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
	
	if(!dre_set_provider_info(reader))
		{ return ERROR; }           //fatal error
		

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

static int32_t dre_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp;
	uint16_t overcryptId;
	uint8_t tmp[16];
	char tmp_dbg[256];
	struct dre_data *csystem_data = reader->csystem_data;
	if(reader->caid == 0x4ae0)
	{
		uchar ecmcmd41[] = { 0x41,
							 0x58, 0x1f, 0x00,     //fixed part, dont change
							 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,   //0x01 - 0x08: next key
							 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,   //0x11 - 0x18: current key
							 0x3b, 0x59, 0x11      //0x3b = keynumber, can be a value 56 ;; 0x59 number of package = 58+1 - Pay Package ;; 0x11 = provider
						   };
		ecmcmd41[22] = csystem_data->provider;
		memcpy(ecmcmd41 + 4, er->ecm + 8, 16);
		ecmcmd41[20] = er->ecm[6];  //keynumber
		ecmcmd41[21] = 0x58 + er->ecm[25];  //package number
		rdr_log_dbg(reader, D_READER, "unused ECM info front:%s", cs_hexdump(0, er->ecm, 8, tmp_dbg, sizeof(tmp_dbg)));
		rdr_log_dbg(reader, D_READER, "unused ECM info back:%s", cs_hexdump(0, er->ecm + 24, er->ecm[2] + 2 - 24, tmp_dbg, sizeof(tmp_dbg)));
		if((dre_cmd(ecmcmd41)))     //ecm request
		{
			if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
				{ return ERROR; }       //exit if response is not 90 00
			memcpy(ea->cw, cta_res + 11, 8);
			memcpy(ea->cw + 8, cta_res + 3, 8);

			return OK;
		}
	}
	else if(reader->caid == 0x4ae1)
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
			ecmcmd51[33] = csystem_data->provider;  //no part of sig
			
			if((dre_cmd(ecmcmd51)))     //ecm request
			{
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
					{ return ERROR; }       //exit if response is not 90 00
						
				if(er->ecm[2] >= 46 && er->ecm[43] == 1 && csystem_data->provider == 0x11)
				{   
					memcpy(tmp, cta_res + 11, 8);
					memcpy(tmp + 8, cta_res + 3, 8);
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
				
				DREover(er->ecm, cta_res + 3);
				
				if(isValidDCW(cta_res + 3))
				{
					memcpy(ea->cw, cta_res + 11, 8);
					memcpy(ea->cw + 8, cta_res + 3, 8);
					return OK;
				}
			}
		}
		else if((csystem_data->provider == 0x02 || csystem_data->provider == 0x03) && er->ecm[3] == 3)
		{
			// DRE 3
			
			if (er->ecm[4] == 2)
			{
				memcpy( ea->cw   , &er->ecm[42], 8);
				memcpy(&ea->cw[8], &er->ecm[34], 8);
				return OK;
			}
		
			uchar cmdlen;
			uchar crypted = er->ecm[8] & 1;
			uchar cryptkey = (er->ecm[8] & 6) >> 1;
			
			if (crypted == 0)
			{
				cmdlen = 50;
			}
			else
			{
				cmdlen = 57;
			}
			
			uchar ecmcmd[cmdlen];
			
			memcpy(ecmcmd, &er->ecm[17], cmdlen-1);
			ecmcmd[cmdlen-1] = csystem_data->provider;
			
			dre_cmd_c(ecmcmd, crypted, cryptkey);
			
			if(cta_res[2] == 0xD2 && isValidDCW(cta_res + 3))
			{
				memcpy(ea->cw, cta_res+11, 8);
				memcpy(ea->cw+8, cta_res+3, 8);
				return OK;
			}	
		}
	}
	else if(reader->caid == 0x2710 && er->ecm[3] == 4)
	{
		// DRE 4
		
		if (er->ecm[4] == 4)
		{
			memcpy(  ea->cw    , &er->ecm[22], 8);
			memcpy(&ea->cw[8], &er->ecm[14], 8);
			return OK;
		}
		
		uchar cmdlen;
		uchar crypted = er->ecm[8] & 1;
		uchar cryptkey = (er->ecm[8] & 6) >> 1;
		
		if (crypted == 0)
		{
			cmdlen = 58;
		}
		else
		{
			cmdlen = 65;
		}
		
		uchar ecmcmd[cmdlen];
		
		memcpy(ecmcmd, &er->ecm[9], cmdlen-1);
		ecmcmd[cmdlen-1] = csystem_data->provider;
			
		dre_cmd_c(ecmcmd, crypted, cryptkey);
		
		if(cta_res[2] == 0xD2 && isValidDCW(cta_res + 3))
		{
			memcpy(ea->cw, cta_res+11, 8);
			memcpy(ea->cw+8, cta_res+3, 8);
			return OK;
		}	
	}
	return ERROR;
}

static int32_t dre_do_emm(struct s_reader *reader, EMM_PACKET *ep)
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
			if((dre_cmd(emmcmd58)))
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
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
				if((dre_cmd(emmcmd52)))
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
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
				if(i == 0) emmcmd52[12] = ep->emm[0x60] == 0x56 ? 0x56:0x3B;
				else emmcmd52[12] = ep->emm[0x60] == 0x56 ? 0x3B:0x56;
				memcpy(emmcmd52 + 0x11, ep->emm + 0x62 + i * 0x29, 40);
				
				// check for shared address
				if(ep->emm[3] != reader->sa[0][0])
					{ return OK; } // ignore, wrong address
				emmcmd52[0x39] = csystem_data->provider;
				if((dre_cmd(emmcmd52)))
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; } //exit if response is not 90 00
			}
		}
		else if (ep->emm[0] == 0x8c && (csystem_data->provider == 0x02 || csystem_data->provider == 0x03)) //dre3 group emm
		{
			if(ep->emm[3] != reader->sa[0][0])
				{ return OK; } // ignore, wrong address
				
			uchar crypted = ep->emm[10];
			
			if ((crypted & 1) == 1)
			{
				uchar emmcmd[0x49];
				
				memcpy(emmcmd, &ep->emm[0x13], 0x48);
				
				emmcmd[0x48] = csystem_data->provider;
				
				dre_cmd_c(emmcmd, crypted & 1, (crypted & 6) >> 1);
				
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; } //exit if response is not 90 00
				
				memcpy(emmcmd, &ep->emm[0x5B], 0x48);
				
				emmcmd[0x48] = csystem_data->provider;
				
				dre_cmd_c(emmcmd, crypted & 1, (crypted & 6) >>1);
				
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; } //exit if response is not 90 00
				
				return OK;			
			}
			else
			{
				uchar emmcmd[0x42];
				
				memcpy(emmcmd, &ep->emm[0x13], 0x41);
				
				emmcmd[0x41] = csystem_data->provider;
				
				dre_cmd_c(emmcmd, crypted & 1, (crypted & 6) >>1);
				
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; } //exit if response is not 90 00
						
				memcpy(emmcmd, &ep->emm[0x5B], 0x41);
				
				emmcmd[0x41] = csystem_data->provider;
				
				dre_cmd_c(emmcmd, crypted & 1, (crypted & 6) >>1);
				
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; } //exit if response is not 90 00
						
				return OK;
			}
		}
		else if(ep->type == GLOBAL && ep->emm[0] == 0x91)
		{
			Drecrypt2OverEMM(ep->emm);
			return OK;
		}
		else return OK;
	}
	else if(reader->caid == 0x2710)
	{
		// DRE 4
		if(ep->type == UNIQUE)
		{
			uint16_t cmdlen;
			uchar class, hlbUA, KEYindex;
			int i, keycount;
			uchar CMDtype = ep->emm[7];
			uint16_t EMMlen = ep->emm[2] | ((ep->emm[1] & 0xF) << 8);
			uchar cryptflag = ep->emm[10];
			uchar crypted = cryptflag & 1;
			uchar cryptkey = (cryptflag & 6) >> 1;
			
			if ( CMDtype == 0x61 )
			{
				uchar emmcmd91[19];
				
				emmcmd91[0] = 0x91;
				emmcmd91[1] = ep->emm[19];
				emmcmd91[2] = ep->emm[8];
				emmcmd91[3] = ep->emm[20];
				if(reader->force_ua) emmcmd91[3] += 2;
				memcpy(&emmcmd91[4], &reader->hexserial[2], 4);
				emmcmd91[8] = 0xF0;
				emmcmd91[17] = ep->emm[22];
				emmcmd91[18] = csystem_data->provider;
				
				if ( (EMMlen - 24) > 16 )
				{
					hlbUA = reader->hexserial[5] & 0xF;
					
					uint16_t keypos = cryptflag == 2 ? 17 : 9;
					keycount = (EMMlen - 24) / keypos;
					
					for(i=0; i <= keycount ;i++)
					{
						if ( i == keycount ) return OK;
						if ( hlbUA == (ep->emm[23+(keypos*i)] & 0xF) ) break;
					}
					
					keypos = 24 + (keypos*i);
					
					memcpy(&emmcmd91[9], &ep->emm[keypos], 8);
					
					if((dre_cmd(emmcmd91)))
						if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00) || (cta_res[2] != 0xA2) )
							return ERROR; //exit if response is not 90 00
					
					if ( cryptflag == 2 )
					{
						if ( emmcmd91[17] == 0x56 ) KEYindex = 0x3B;
						else KEYindex = 0x56;
						
						keypos += 8;
						memcpy(&emmcmd91[9], &ep->emm[keypos], 8);
						emmcmd91[17] = KEYindex;
						
						dre_cmd(emmcmd91);
						
						if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00) || (cta_res[2] != 0xA2)) 
							{ return ERROR; }  //exit if response is not 90 00

						return OK;
					}
				}
				return ERROR;
			}
			else if ( CMDtype == 0x62 )
			{
				if ( !memcmp(&reader->hexserial[2], &ep->emm[3], 4) )
				{
					if ( crypted )
					{
						cmdlen = 49;
					}
					else
					{
						cmdlen = 42;
					}
					
					uchar emmcmd92[cmdlen];
					
					memcpy(emmcmd92, &ep->emm[19], cmdlen - 1);
					emmcmd92[cmdlen-1] = csystem_data->provider;
					
					if ( crypted )
					{
						dre_cmd_c(emmcmd92, crypted, cryptkey);
					}
					else
					{
						dre_cmd(emmcmd92);
					}
					
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
							{ return ERROR; } //exit if response is not 90 00
					
					
					class = ep->emm[8];
					
					uchar emmcmd95[3];
					
					emmcmd95[0] = 0x95;
					emmcmd95[1] = class;
					emmcmd95[2] = csystem_data->provider;

					dre_cmd(emmcmd95);
					
					uchar emmcmd91[19];
					
					emmcmd91[0] = 0x91;
					emmcmd91[1] = ep->emm[102];
					emmcmd91[2] = ep->emm[8];
					emmcmd91[3] = ep->emm[103];
					if(reader->force_ua) emmcmd91[3] += 2;
					memcpy(&emmcmd91[4], &reader->hexserial[2], 4);
					emmcmd91[8]  = ep->emm[104];
					memcpy(&emmcmd91[9], &ep->emm[72], 8);
					emmcmd91[17] = ep->emm[105];
					emmcmd91[18] = csystem_data->provider;
					
					dre_cmd(emmcmd91);
					
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00) || (cta_res[2] != 0xA2) )
						{ return ERROR; } //exit if response is not 90 00
					
					if ( emmcmd91[17] == 0x56 ) KEYindex = 0x3B;
					else KEYindex = 0x56;
					
					memcpy(&emmcmd91[9], &ep->emm[86], 8);
					emmcmd91[17] = KEYindex;
					
					dre_cmd(emmcmd91);
					
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00) )
						{ return ERROR; } //exit if response is not 90 00
				}
				return OK;
			}
			else
			{
				if ( memcmp(&reader->hexserial[2], &ep->emm[3], 4) ) return OK;
				
				if ( CMDtype == 0x63 )
				{
					uchar emmcmdA5[7];
					
					emmcmdA5[0] = 0xA5;
					emmcmdA5[1] = 0;
					memcpy(&emmcmdA5[2], &reader->hexserial[2], 4);
					emmcmdA5[6] = csystem_data->provider;
					
					dre_cmd(emmcmdA5);
					
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; } //exit if response is not 90 00
				}

				if ( crypted ) cmdlen = EMMlen - 19;
				else cmdlen = ep->emm[11] + 1;
				
				uchar emmcmd[cmdlen];
				
				memcpy(emmcmd, &ep->emm[19], cmdlen-1);
				emmcmd[cmdlen-1] = csystem_data->provider;
				
				if(emmcmd[0] == 0x45)
				{
					cs_log("TRICOLOR Send KILL command for your card");
					return ERROR;
				}
				
				dre_cmd_c(emmcmd, crypted, cryptkey);
				
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
					{ return ERROR; } //exit if response is not 90 00
			}
			return OK;
		}
		return ERROR;
	}
	else if(reader->caid != 0x2710 && reader->caid != 0x4AE1)
	{
		uchar emmcmd42[] =
		{
			0x42, 0x85, 0x58, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x05, 0xB8, 0x0C, 0xBD, 0x7B, 0x07, 0x04, 0xC8,
			0x77, 0x31, 0x95, 0xF2, 0x30, 0xB7, 0xE9, 0xEE, 0x0F, 0x81, 0x39, 0x1C, 0x1F, 0xA9, 0x11, 0x3E,
			0xE5, 0x0E, 0x8E, 0x50, 0xA4, 0x31, 0xBB, 0x01, 0x00, 0xD6, 0xAF, 0x69, 0x60, 0x04, 0x70, 0x3A,
			0x91,
			0x56, 0x58, 0x11
		};
		int32_t i;
		switch(ep->type)
		{
		case UNIQUE:
			for(i = 0; i < 2; i++)
			{
				memcpy(emmcmd42 + 1, ep->emm + 42 + i * 49, 48);
				emmcmd42[49] = ep->emm[i * 49 + 41]; //keynr
				emmcmd42[50] = 0x58 + ep->emm[40]; //package nr
				emmcmd42[51] = csystem_data->provider;
				if((dre_cmd(emmcmd42)))
				{
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; }       //exit if response is not 90 00
				}
			}
			break;
		case SHARED:
		default:
			memcpy(emmcmd42 + 1, ep->emm + 6, 48);
			emmcmd42[51] = csystem_data->provider;
			//emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
			emmcmd42[50] = 0x58;
			emmcmd42[49] = ep->emm[5];  //keynr
			/* response:
			   59 05 A2 02 05 01 5B
			   90 00 */
			if((dre_cmd(emmcmd42)))     //first emm request
			{
				if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
					{ return ERROR; }       //exit if response is not 90 00

				memcpy(emmcmd42 + 1, ep->emm + 55, 7);    //TODO OR next two lines?
				/*memcpy (emmcmd42 + 1, ep->emm + 55, 7);  //FIXME either I cant count or my EMM log contains errors
				   memcpy (emmcmd42 + 8, ep->emm + 67, 41); */
				emmcmd42[51] = csystem_data->provider;
				//emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
				emmcmd42[50] = 0x58;
				emmcmd42[49] = ep->emm[54];   //keynr
				if((dre_cmd(emmcmd42)))       //second emm request
				{
					if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						{ return ERROR; }       //exit if response is not 90 00
				}
			}
		}
		return OK;
	}
	return ERROR;
}

static int32_t dre_card_info(struct s_reader *UNUSED(rdr))
{
	return OK;
}

const struct s_cardsystem reader_dre =
{
	.desc           = "dre",
	.caids          = (uint16_t[]){ 0x4AE0, 0x4AE1, 0x7BE0, 0x7BE1, 0x2710, 0 },
	.do_emm         = dre_do_emm,
	.do_ecm         = dre_do_ecm,
	.card_info      = dre_card_info,
	.card_init      = dre_card_init,
	.get_emm_type   = dre_common_get_emm_type,
	.get_emm_filter = dre_common_get_emm_filter,
};

#endif

