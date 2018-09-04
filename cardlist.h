#ifndef _CSCTAPI_CARDLIST_H_
#define _CSCTAPI_CARDLIST_H_

struct known_cards
{
	char providername[32];
//max atrsize incl. spaces
	char atr[80];
	int atrsize;
}
mtv = { "MTV UNLIMITED","3B 24 00 30 42 30 30",20 },
srg = { "SRG v5","3F 77 18 00 00 C2 7A 44 02 68 90 00",35 },
orfice = { "ORF ICE CW-Mode","3B 78 12 00 00 54 C4 03 00 8F F1 90 00",38 },
cdnl = { "CANAL DIGITAAL (NL)","3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6",42 },
kbw_v23 = { "Kabel-BW V23","3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00",65 },
kdg9 = { "Kabel Deutschland G0x","3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",62 },
skyDEv14 = { "Sky Deutschland V14","3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",62 },
skyDEv13 = { "Sky Deutschland V13","3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11",65 },
tivusatd = { "Tivusat 183D","3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64",80 },
tivusate = { "Tivusat 183E","3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14",80 },
rlmega = { "Redlight Mega Elite","3F 77 18 00 00 C2 EB 41 02 6C 90 00",35 },
kdg_02 = { "Kabel Deutschland D0x Ix2","3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D",59 },
hdplus01  = { "HD-Plus 01","3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",80 },
hdplus02  = { "HD-Plus 02","3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",80 },
hdplus03  = { "HD-Plus 03","3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F",80 },
hdplus03a = { "HD-Plus 3A","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17",80 },
hdplus03b = { "HD-Plus 03","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17",80 },
hdplus04  = { "HD-Plus 04","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17",80 },
hdplus04a = { "HD-Plus 04","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13",80 },
unity_01  = { "Unity Media 01","3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15",80 },
unity_02  = { "Unity Media 02","3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12",80 };

struct atrlist
{
	int found;
	int ishd03;
	int badcard;
	int ishd04;
	char providername[32];
	char atr[80];
} current = { 0, 0, 0, 0, "\0", "\0" };

void findatr(struct s_reader *reader)
{
	current.found  = 0;
	current.ishd03 = 0;
	current.ishd04 = 0;

	memset(current.providername, 0, 32);
	if ( strncmp(current.atr, hdplus01.atr, hdplus01.atrsize) == 0 )
	{
		memcpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus02.atr, hdplus02.atrsize) == 0 )
	{
		memcpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus03.atr, hdplus03.atrsize) == 0 )
	{
		current.ishd03=1;
		memcpy(current.providername, hdplus03.providername, strlen(hdplus03.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus03a.atr, hdplus03a.atrsize) == 0 )
	{
		current.ishd03=1;
		current.badcard=1;
		memcpy(current.providername, hdplus03a.providername, strlen(hdplus03a.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus03b.atr, hdplus03b.atrsize) == 0 )
	{
		current.ishd03=1;
		memcpy(current.providername, hdplus03b.providername, strlen(hdplus03b.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus04.atr, hdplus04.atrsize) == 0 )
	{
		current.ishd04=1;
		memcpy(current.providername, hdplus04.providername, strlen(hdplus04.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus04a.atr, hdplus04a.atrsize) == 0 )
	{
		current.ishd04=1;
		memcpy(current.providername, hdplus04a.providername, strlen(hdplus04a.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, unity_01.atr, unity_01.atrsize) == 0 )
	{
		memcpy(current.providername, unity_01.providername, strlen(unity_01.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, unity_02.atr, unity_02.atrsize) == 0 )
	{
		memcpy(current.providername, unity_02.providername, strlen(unity_02.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, kdg_02.atr, kdg_02.atrsize) == 0 )
	{
		memcpy(current.providername, kdg_02.providername, strlen(kdg_02.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, rlmega.atr, rlmega.atrsize) == 0 )
	{
		memcpy(current.providername, rlmega.providername, strlen(rlmega.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, mtv.atr, mtv.atrsize) == 0 )
	{
		memcpy(current.providername, mtv.providername, strlen(mtv.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, orfice.atr, orfice.atrsize) == 0 )
	{
		memcpy(current.providername, orfice.providername, strlen(orfice.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, cdnl.atr, cdnl.atrsize) == 0 )
	{
		memcpy(current.providername, cdnl.providername, strlen(cdnl.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, tivusatd.atr, tivusatd.atrsize) == 0 )
	{
		memcpy(current.providername, tivusatd.providername, strlen(tivusatd.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, tivusate.atr, tivusate.atrsize) == 0 )
	{
		memcpy(current.providername, tivusate.providername, strlen(tivusate.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, srg.atr, srg.atrsize) == 0 )
	{
		memcpy(current.providername, srg.providername, strlen(srg.providername));
		reader->read_old_classes = 0;
		current.found = 1;
		return;
	}

	/* test ATR for ins7e11 12,13,14,15 */
	if ( current.found == 0 )
	{
		int i;
		char buf[66];
		for( i = 11; i < 16; i++ )
		{
			snprintf(buf, skyDEv13.atrsize+1, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if ( strncmp(current.atr, buf, skyDEv13.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv13.providername, strlen(skyDEv13.providername));
				reader->caid = 0x09C4;
				current.found = 1;
				break;
			}
			snprintf(buf, skyDEv14.atrsize+1, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv14.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv14.providername, strlen(skyDEv14.providername));
				reader->caid = 0x098C;
				current.found = 1;
				break;
			}
			snprintf(buf, kbw_v23.atrsize+1, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, kbw_v23.atrsize) == 0 )
			{
				memcpy(current.providername, kbw_v23.providername, strlen(kbw_v23.providername));
				current.found = 1;
				break;
			}
			snprintf(buf, kdg9.atrsize+1, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, kdg9.atrsize) == 0 )
			{
				memcpy(current.providername, kdg9.providername, strlen(kdg9.providername));
				current.found = 1;
				break;
			}
		}
	}
}

#endif
