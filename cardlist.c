#include <string.h>
#include "globals.h"
#include "cardlist.h"

struct atrlist current;
struct known_cards
{
//custom name output on webif log
  char providername[32];
  /*
  EMM_UNIQUE: 1
  EMM_SHARED: 2
  EMM_GLOBAL: 4
  EMM_UNKNOWN: 8
  SUM EMM for Value
  */
  int saveemm;
  int blockemm;
//max atrsize incl. spaces
  char atr[80];
  int atrsize;
//boxkey and rsakey if required
  int  boxid;
  char boxkey[9];
  char rsakey[128];
}
mtv       = { "MTV UNLIMITED",0,8,"3B 24 00 30 42 30 30",20,0,"\x00","\x00" },
srg       = { "SRG v5",0,8,"3F 77 18 00 00 C2 7A 44 02 68 90 00",35,0,"\x00","\x00" },
srg6      = { "SRG v6",0,8,"3F 77 18 00 00 D3 8A 40 01 64 90 00",35,0,"\x00","\x00" },
orfice    = { "ORF ICE CW-Mode",0,12,"3B 78 12 00 00 54 C4 03 00 8F F1 90 00",38,0,"\x00","\x00" },
cdnl      = { "CANAL DIGITAAL (NL)",3,12,"3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6",42,0,"\x00","\x00" },
rlmega    = { "Redlight Mega Elite",0,12,"3F 77 18 00 00 C2 EB 41 02 6C 90 00",35,0,"\x01\x4D\x90\x2F\x00","\x00"},
kdg_02    = { "Kabel Deutschland D0x Ix2",0,12,"3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D",59,0,"\x00","\x00"},
kbw_v23   = { "Kabel-BW V23",0,12,"3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00",65,305419896,"\x00","\x00" },
kdg9      = { "Kabel Deutschland G0x",0,12,"3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",62,305419896,"\x00","\x00" },
skyDEv15  = { "Sky Deutschland V15",1,15,"3F FD 13 25 02 50 80 0F 55 B0 02 69 FF 4A 50 F0 80 00 50 31 03",62,305419896,"\x00","\x00" },
skyDEv14  = { "Sky Deutschland V14",1,15,"3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",62,305419896,"\x00","\x00" },
skyDEv13  = { "Sky Deutschland V13",1,15,"3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11",65,305419896,"\x00","\x00" },
tivusatd  = { "Tivusat 183D",0,8,"3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64",80,0,"\x00","\x00"},
tivusate  = { "Tivusat 183E",0,8,"3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14",80,0,"\x00","\x00"},
hdplus01  = { "HD-Plus 01"    ,0,12,"3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",80,0,"\x00","\x00"},
hdplus02  = { "HD-Plus 02"    ,0,12,"3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",80,0,"\x00","\x00"},
hdplus03  = { "HD-Plus 03"    ,0,12,"3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F",80,0,"\x00","\x00"},
hdplus03a = { "HD-Plus 03a"   ,0,12,"3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17",80,0,"\x00","\x00"},
hdplus03b = { "HD-Plus 03b"   ,0,12,"3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17",80,0,"\x00","\x00"},
hdplus04  = { "HD-Plus 04"    ,0,12,"3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13",80,0,"\x00","\x00"},
hdplus04a = { "HD-Plus 04a"   ,0,12,"3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17",80,0,"\x00","\x00"},
unity_01  = { "Unity Media 01",0,12,"3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15",80,0,"\x00","\x00"},
unity_02  = { "Unity Media 02",0,12,"3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12",80,0,"\x00","\x00"};

void findatr(struct s_reader *reader)
{
	current.found = 0;
	current.ishd03 = 0;
	current.ishd04 = 0;

	memset(current.providername, 0, 32);
	if ( strncmp(current.atr, hdplus01.atr, hdplus01.atrsize) == 0 )
	{
		if ( !strncmp(hdplus01.rsakey, "0", 1) == 0 )
	{
			reader->rsa_mod_length = 64;
		}
		memcpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		reader->saveemm = hdplus01.saveemm;
		reader->blockemm = hdplus01.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus02.atr, hdplus02.atrsize) == 0 )
	{
		if ( !strncmp(hdplus02.rsakey, "0", 1) == 0 )
	{
			reader->rsa_mod_length = 64;
		}
		memcpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
		reader->saveemm = hdplus02.saveemm;
		reader->blockemm = hdplus02.blockemm;
		current.found = 1;
		return;

	}
	else if ( strncmp(current.atr, hdplus03.atr, hdplus03.atrsize) == 0 )
	{
		current.ishd03=1;
		memcpy(current.providername, hdplus03.providername, strlen(hdplus03.providername));
		reader->saveemm = hdplus03.saveemm;
		reader->blockemm = hdplus03.blockemm;

		current.found = 1;
		return;

	}
	else if ( strncmp(current.atr, hdplus03a.atr, hdplus03a.atrsize) == 0 )
	{
		current.ishd03=1;
		current.badcard=1;
		memcpy(current.providername, hdplus03a.providername, strlen(hdplus03a.providername));
		reader->saveemm = hdplus03a.saveemm;
		reader->blockemm = hdplus03a.blockemm;

		current.found = 1;
		return;

	}
	else if ( strncmp(current.atr, hdplus03b.atr, hdplus03b.atrsize) == 0 )
	{
		current.ishd03=1;
		memcpy(current.providername, hdplus03b.providername, strlen(hdplus03b.providername));
		reader->saveemm = hdplus03b.saveemm;
		reader->blockemm = hdplus03b.blockemm;

		current.found = 1;
		return;

	}
	else if ( strncmp(current.atr, hdplus04.atr, hdplus04.atrsize) == 0 )
	{
		current.ishd04=1;
		memcpy(current.providername, hdplus04.providername, strlen(hdplus04.providername));
		reader->saveemm = hdplus04.saveemm;
		reader->blockemm = hdplus04.blockemm;

		current.found = 1;
		return;

	}
	else if ( strncmp(current.atr, hdplus04a.atr, hdplus04a.atrsize) == 0 )
	{
		current.ishd04=1;
		memcpy(current.providername, hdplus04a.providername, strlen(hdplus04a.providername));
		reader->saveemm = hdplus04a.saveemm;
		reader->blockemm = hdplus04a.blockemm;

		current.found = 1;
		return;

	}
	else if ( strncmp(current.atr, unity_01.atr, unity_01.atrsize) == 0 )
	{
		if ( !strncmp(unity_01.rsakey, "0", 1) == 0 )
		{
			reader->rsa_mod_length = 64;
		}
		memcpy(current.providername, unity_01.providername, strlen(unity_01.providername));
		reader->saveemm = unity_01.saveemm;
		reader->blockemm = unity_01.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, unity_02.atr, unity_02.atrsize) == 0 )
	{
		if ( !strncmp(unity_02.rsakey, "0", 1) == 0 )
	{
			reader->rsa_mod_length = 64;
		}
		memcpy(current.providername, unity_02.providername, strlen(unity_02.providername));
		reader->saveemm = unity_02.saveemm;
		reader->blockemm = unity_02.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, kdg_02.atr, kdg_02.atrsize) == 0 )
	{
		if ( !strncmp(kdg_02.rsakey, "0", 1) == 0 )
	{
			reader->rsa_mod_length = 64;
		}
		memcpy(current.providername, kdg_02.providername, strlen(kdg_02.providername));
		reader->saveemm = kdg_02.saveemm;
		reader->blockemm = kdg_02.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, rlmega.atr, rlmega.atrsize) == 0 )
	{
		if ( !strncmp(rlmega.rsakey, "0", 1) == 0 )
		{
			reader->des_key_length = 16;
		}
		memcpy(current.providername, rlmega.providername, strlen(rlmega.providername));
		reader->saveemm = rlmega.saveemm;
		reader->blockemm = rlmega.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, mtv.atr, mtv.atrsize) == 0 )
	{
		memcpy(current.providername, mtv.providername, strlen(mtv.providername));
		reader->saveemm = mtv.saveemm;
		reader->blockemm = mtv.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, orfice.atr, orfice.atrsize) == 0 )
	{
		memcpy(current.providername, orfice.providername, strlen(orfice.providername));
		reader->saveemm = orfice.saveemm;
		reader->blockemm = orfice.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, cdnl.atr, cdnl.atrsize) == 0 )
	{
		memcpy(current.providername, cdnl.providername, strlen(cdnl.providername));
		reader->saveemm = cdnl.saveemm;
		reader->blockemm = cdnl.blockemm;
		reader->caid = 0x0100;
		reader->ratelimitecm = 4;
		reader->ratelimittime = 9000;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, tivusatd.atr, tivusatd.atrsize) == 0 )
	{
		if ( !strncmp(tivusatd.rsakey, "0", 1) == 0 )
	{
			reader->rsa_mod_length = 120;
		}
		memcpy(current.providername, tivusatd.providername, strlen(tivusatd.providername));
		reader->saveemm = tivusatd.saveemm;
		reader->blockemm = tivusatd.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, tivusate.atr, tivusate.atrsize) == 0 )
	{
		if ( !strncmp(tivusate.rsakey, "0", 1) == 0 )
		{
			reader->rsa_mod_length = 120;
		}
		memcpy(current.providername, tivusate.providername, strlen(tivusate.providername));
		reader->saveemm = tivusate.saveemm;
		reader->blockemm = tivusate.blockemm;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, srg.atr, srg.atrsize) == 0 )
	{
		memcpy(current.providername, srg.providername, strlen(srg.providername));
		reader->saveemm = srg.saveemm;
		reader->blockemm = srg.blockemm;
		reader->read_old_classes = 0;
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, srg6.atr, srg6.atrsize) == 0 )
	{
		memcpy(current.providername, srg6.providername, strlen(srg6.providername));
		reader->saveemm = srg6.saveemm;
		reader->blockemm = srg6.blockemm;
		reader->read_old_classes = 0;
		current.found = 1;
		return;
	}

	if ( current.found == 0 )
	{
		int i;
		char buf[66];
		for( i = 10; i < 17; i++ )
		{
			snprintf(buf, skyDEv13.atrsize+1, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if ( strncmp(current.atr, buf, skyDEv13.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv13.providername, strlen(skyDEv13.providername));
				reader->saveemm = skyDEv13.saveemm;
				reader->blockemm = skyDEv13.blockemm;
				reader->boxid = skyDEv13.boxid;
				reader->caid = 0x09C4;
				current.found = 1;
				return;
			}
			snprintf(buf, skyDEv14.atrsize+1, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv14.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv14.providername, strlen(skyDEv14.providername));
				reader->saveemm = skyDEv14.saveemm;
				reader->blockemm = skyDEv14.blockemm;
				reader->boxid = skyDEv14.boxid;
				reader->caid = 0x098C;
				current.found = 1;
				return;
			}
			snprintf(buf, skyDEv15.atrsize+1, "3F FD %i 25 02 50 80 0F 55 B0 02 69 FF 4A 50 F0 80 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv15.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv15.providername, strlen(skyDEv15.providername));
				reader->saveemm = skyDEv15.saveemm;
				reader->blockemm = skyDEv15.blockemm;
				reader->boxid = skyDEv15.boxid;
				reader->caid = 0x098D;
				current.found = 1;
				return;
			}
			snprintf(buf, kbw_v23.atrsize+1, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, kbw_v23.atrsize) == 0 )
			{
				memcpy(current.providername, kbw_v23.providername, strlen(kbw_v23.providername));
				reader->saveemm = kbw_v23.saveemm;
				reader->blockemm = kbw_v23.blockemm;
				reader->boxid = kbw_v23.boxid;
				current.found = 1;
				return;
			}
			snprintf(buf, kdg9.atrsize+1, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, kdg9.atrsize) == 0 )
			{
				memcpy(current.providername, kdg9.providername, strlen(kdg9.providername));
				reader->saveemm = kdg9.saveemm;
				reader->blockemm = kdg9.blockemm;
				reader->boxid = kdg9.boxid;
				reader->deprecated = 1;
				current.found = 1;
				return;
			}
		}
	}
}
