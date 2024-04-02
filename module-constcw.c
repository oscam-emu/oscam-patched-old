#define MODULE_LOG_PREFIX "constcw"

//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#ifdef MODULE_CONSTCW
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"

static int32_t pserver;

int32_t constcw_file_available(void)
{
	FILE *fp;

	fp = fopen(cur_client()->reader->device, "r");
	if(!fp)
	{
		cs_log("ERROR: Can't open %s (errno=%d %s)", cur_client()->reader->device, errno, strerror(errno));
		return (0);
	}
	fclose(fp);
	return (1);
}

int32_t constcw_analyse_file(uint16_t c_caid, uint32_t c_prid, uint16_t c_sid, uint16_t c_pmtpid, uint32_t c_vpid, uint16_t c_ecmpid, uint8_t *dcw)
{
	//CAID:PROVIDER:SID:PMTPID:ECMPID:VPID:XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
	FILE *fp;
	char token[512];
	uint32_t caid, provid, sid, vpid, pmtpid, ecmpid;
	int32_t cw[16];

	fp = fopen(cur_client()->reader->device, "r");
	if(!fp)
	{
		cs_log("ERROR: Can't open %s (errno=%d %s)", cur_client()->reader->device, errno, strerror(errno));
		return (0);
	}

	cs_log("Searching CW for CAID %04X PROVID %06X SRVID %04X ECMPID %04X PMTPID %04X VPID %04X", c_caid, c_prid, c_sid, c_ecmpid, c_pmtpid, c_vpid);

	while(fgets(token, sizeof(token), fp))
	{
		if(token[0] == '#') { continue; }
		vpid = 0;
		int ret = sscanf(token, "%4x:%6x:%4x:%4x:%4x::%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x", &caid, &provid, &sid, &pmtpid, &ecmpid,
			   &cw[0], &cw[1], &cw[2], &cw[3], &cw[4], &cw[5], &cw[6], &cw[7],
			   &cw[8], &cw[9], &cw[10], &cw[11], &cw[12], &cw[13], &cw[14], &cw[15]);

		if(ret != 21){
			ret = sscanf(token, "%4x:%6x:%4x:%4x:%4x:%4x:%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x", &caid, &provid, &sid, &pmtpid, &ecmpid, &vpid,
				   &cw[0], &cw[1], &cw[2], &cw[3], &cw[4], &cw[5], &cw[6], &cw[7],
				   &cw[8], &cw[9], &cw[10], &cw[11], &cw[12], &cw[13], &cw[14], &cw[15]);
			if(ret != 22) continue;
		}

		//cs_log("Line found: %s", token);
		if(c_caid == caid && c_sid == sid && (!provid || provid == c_prid) && (!pmtpid || !c_pmtpid || pmtpid == c_pmtpid) && (!vpid || !c_vpid || vpid == c_vpid)
				&& (!ecmpid || !c_ecmpid || ecmpid == c_ecmpid))
		{
			fclose(fp);
			int8_t i;
			for(i = 0; i < 16; ++i)
				{ dcw[i] = (uint8_t) cw[i]; }
			cs_log("Entry found: %04X@%06X:%04X:%04X:%04X:%04X:%s", caid, provid, sid, pmtpid, ecmpid, vpid, cs_hexdump(1, dcw, 16, token, sizeof(token)));
			return 1;
		}
	}

	fclose(fp);
	return 0;
}
//************************************************************************************************************************
//* client/server common functions
//************************************************************************************************************************
static int32_t constcw_recv(struct s_client *client, uint8_t *buf, int32_t l)
{
	int32_t ret;

	if(!client->udp_fd) { return (-9); }
	ret = read(client->udp_fd, buf, l);
	if(ret < 1) { return (-1); }
	client->last = time(NULL);
	return (ret);
}

//************************************************************************************************************************
//*       client functions
//************************************************************************************************************************
int32_t constcw_client_init(struct s_client *client)
{
	int32_t fdp[2];

	client->pfd = 0;
	if(socketpair(PF_LOCAL, SOCK_STREAM, 0, fdp))
	{
		cs_log("ERROR: Socket creation failed: %s", strerror(errno));
		return 1;
	}
	client->udp_fd = fdp[0];
	pserver = fdp[1];

	memset((char *) &client->udp_sa, 0, sizeof(client->udp_sa));
	SIN_GET_FAMILY(client->udp_sa) = AF_INET;

	// Oscam has no reader.au in s_reader like ki's mpcs ;)
	// reader[ridx].au = 0;
	// cs_log("local reader: %s (file: %s) constant cw au=0", reader[ridx].label, reader[ridx].device);
	cs_log("Local reader: %s (file: %s)", client->reader->label, client->reader->device);

	client->pfd = client->udp_fd;

	if(constcw_file_available())
	{
		client->reader->tcp_connected = 2;
		client->reader->card_status = CARD_INSERTED;
	}

	return (0);
}

static int32_t constcw_send_ecm(struct s_client *client, ECM_REQUEST *er)
{
	time_t t;
	struct s_reader *rdr = client->reader;
	uint8_t cw[16];

	t = time(NULL);
	// Check if DCW exist in the files
	//cs_log("Searching ConstCW for ECM: %04X@%06X:%04X (%d)", er->caid, er->prid, er->srvid, er->l);

	if(constcw_analyse_file(er->caid, er->prid, er->srvid, er->pmtpid, er->vpid, er->pid, cw) == 0)
	{
		write_ecm_answer(rdr, er, E_NOTFOUND, (E1_READER << 4 | E2_SID), NULL, NULL, 0);
	}
	else
	{
		write_ecm_answer(rdr, er, E_FOUND, 0, cw, NULL, 0);
	}

	client->last = t;
	rdr->last_g = t;
	return (0);
}

static int32_t constcw_recv_chk(struct s_client *UNUSED(client), uint8_t *UNUSED(dcw), int32_t *rc, uint8_t *UNUSED(buf), int32_t UNUSED(n))
{
	//dcw = dcw;
	//n = n;
	//buf = buf;

	*rc = 0;
	return (-1);
}

void module_constcw(struct s_module *ph)
{
	ph->desc = "constcw";
	ph->type = MOD_NO_CONN;
	ph->listenertype = LIS_CONSTCW;
	ph->recv = constcw_recv;

	ph->c_init = constcw_client_init;
	ph->c_recv_chk = constcw_recv_chk;
	ph->c_send_ecm = constcw_send_ecm;
	ph->num = R_CONSTCW;
}
#endif
