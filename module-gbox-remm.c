#define MODULE_LOG_PREFIX "gbox/remm"

#include "globals.h"

#ifdef MODULE_GBOX
#include "module-gbox-remm.h"
#include "module-gbox.h"
#include "module-gbox-helper.h"
#include "oscam-string.h"
#include "oscam-client.h"
#include "oscam-lock.h"
#include "oscam-time.h"
#include "oscam-reader.h"
#include "oscam-files.h"
#include "module-dvbapi.h"
#include "oscam-emm.h"

static void gbox_send_remm_ack_msg(struct s_client *cli, uint16_t caid, uint32_t provider, uint8_t dvbapi_stat, uint8_t ack)
{
	uint8_t outbuf[32];
	struct gbox_peer *peer = cli->gbox;
	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();

	gbox_message_header(outbuf, MSG_REM_EMM, peer->gbox.password, local_gbox_pw);
	outbuf[10] = MSGID_REMM_ACK;
	i2b_buf(2, peer->gbox.id, outbuf +11);
	i2b_buf(2, local_gbox_id, outbuf + 13);
	outbuf[15] = ack;
	outbuf[16] = dvbapi_stat;
	i2b_buf(2, caid, outbuf +17);
	i2b_buf(4, provider, outbuf +19);
	outbuf[23] = 0;
	outbuf[24] = 0;
	outbuf[25] = 0;
	outbuf[26] = 0;

	gbox_send(cli, outbuf, 27);

	if (ack == PEER_AU_BLOCKED)
		{ cs_log("<- send REJECT REMM msg to peer %04X for caid: %04X", peer->gbox.id, caid); }

	if (ack == PEER_AU_READY)
		{ cs_log("<- send ACCEPT REMM msg to peer %04X for caid: %04X", peer->gbox.id, caid); }

	if (ack == PEER_AU_UNREADY)
		{ cs_log("<- send WARNING to peer %04X: my dvbapi unready for AU caid: %04X", peer->gbox.id, caid); }

	return;
}

static void gbox_recvd_remm_ack_msg(struct s_client *cli, uint8_t *buf, int32_t n)
{
	if (!cli || !cli->gbox || !buf || n != 27) { return; }
	struct gbox_peer *peer;
	peer = cli->gbox;

	uint8_t ack = buf[15];
	uint8_t dvbapi_stat = buf[16];
	uint16_t rpeer = b2i(2, buf +11);
	uint16_t rcaid = b2i(2, buf +17);
	//uint32_t rprovid = b2i(4, buf +19);

	if (ack == PEER_AU_BLOCKED)
		{ cs_log("-> Peer %04X %s rejected REMM for caid %04X - requesting peer %04X blocked", peer->gbox.id, cli->reader->label, rcaid, rpeer ); }

	if (ack == PEER_AU_READY)
		{ cs_log("-> MSG from peer %04X %s: Accept REMM REQ for caid %04X", peer->gbox.id, cli->reader->label, rcaid); }

	if (ack == PEER_AU_UNREADY)
	{
		cs_log("-> WARNING: Peer %04X %s dvbapi AU unready for caid %04X", peer->gbox.id, cli->reader->label, rcaid);
		cs_log_dbg(D_EMM,"Peer %04X dvbapi AU status: dvbapi_au: %1d - dvbapi_usr_autoau: %1d - dvbapi_usr_aulist: %1d",
				peer->gbox.id, (dvbapi_stat & 1) ? 1 : 0, (dvbapi_stat & 2) ? 1 : 0, (dvbapi_stat & 4) ? 1 : 0 );
	}
}

static uint8_t check_dvbapi_au_ready( void)
{
#ifdef HAVE_DVBAPI
	uint8_t dvbapi_stat = 0;
	if (module_dvbapi_enabled())
	{
		if(cfg.dvbapi_au)
			{ dvbapi_stat |= 1; }

		struct s_client *cl;
		cs_readlock(__func__, &clientlist_lock);

		for(cl = first_client; cl; cl = cl->next)
		{
			if(cl->typ == 'c' && cl->account && is_dvbapi_usr(cl->account->usr))
			{
				if(cl->account->autoau)
				{
					dvbapi_stat |= 2;
					break;
				}

				if(ll_count(cl->account->aureader_list))
				{
					dvbapi_stat |= 4;
					break;
				}
			}
		}
		cs_readunlock(__func__, &clientlist_lock);
	}
	return dvbapi_stat;
#else
	return 0;
#endif
}

uint8_t check_valid_remm_peer(uint16_t peer_id)
{
	if (cfg.accept_remm_peer_num > 0)
	{
		int i;
		for (i = 0; i < cfg.accept_remm_peer_num; i++)
		{
			if (cfg.accept_remm_peer[i] == peer_id)
				{ return 1; }
		}
	}
	return 0;
}

static void gbox_recvd_remm_req(struct s_client *cli, uint8_t *buf, int32_t n)
{
	if (!cli || !cli->gbox || !buf || !cli->reader || n != 122) { return; }

	struct gbox_peer *peer;
	peer = cli->gbox;

	uint16_t rcaid = b2i(2, buf +23);
	uint32_t rprovid = b2i(4, buf +17);
	//uint16_t tcli_peer = b2i(2, buf +11);
	//uint16_t tsrv_peer = b2i(2, buf +13);

	uint8_t dvbapi_stat = check_dvbapi_au_ready();

	if (!check_valid_remm_peer( peer->gbox.id))
	{
		gbox_send_remm_ack_msg(cli, rcaid, rprovid, dvbapi_stat, PEER_AU_BLOCKED);
		handle_attack(cli, GBOX_ATTACK_REMM_REQ_BLOCKED, peer->gbox.id);
		cs_log("Reject REMM REQ for caid %04X) - peer %04X blocked for AU", rcaid, peer->gbox.id);
		return;
	}

	//if (tcli_peer != local_gbox.id)
	//	{ forward remm req to target client peer}

	struct s_reader *rdr = cli->reader;
	rdr->gbox_remm_peer = peer->gbox.id;
	rdr->last_g = time(NULL); // last receive is now

	rdr->auprovid = rprovid;
	rdr->caid = rcaid;

	memcpy(rdr->hexserial, buf + 29, 6);
	rdr->hexserial[6] = 0;
	rdr->hexserial[7] = 0;
	rdr->nprov = buf[37];

	int32_t i;
	for(i = 0; i < rdr->nprov; i++)
	{
		if(caid_is_betacrypt(rdr->caid) || caid_is_irdeto(rdr->caid))
		{
			rdr->prid[i][0] = buf[38 + (i * 5)];
			memcpy(&rdr->prid[i][1], &buf[40 + (i * 5)], 3);
		}
		else
		{
			rdr->prid[i][2] = buf[38 + (i * 5)];
			rdr->prid[i][3] = buf[39 + (i * 5)];
			memcpy(&rdr->sa[i][0], &buf[40 + (i * 5)], 4);
		}
	}

	rdr->blockemm = 0;
	rdr->blockemm |= (buf[117] == 1) ? 0 : 0x80; // remm marker bit
	rdr->blockemm |= (buf[118] == 1) ? 0 : EMM_GLOBAL;
	rdr->blockemm |= (buf[119] == 1) ? 0 : EMM_SHARED;
	rdr->blockemm |= (buf[120] == 1) ? 0 : EMM_UNIQUE;
	rdr->blockemm |= (buf[121] == 1) ? 0 : EMM_UNKNOWN;

	cs_log("-> received REMM REQ for type %s%s%s%s caid %04X from peer %04X:%s",
		buf[120]==1 ? "UQ ":"", buf[119]==1 ? "SH ":"", buf[118]==1 ? "GL ":"", buf[121]==1 ? "UK":"",
		rdr->caid, peer->gbox.id, rdr->label);

	if (dvbapi_stat == 3 || dvbapi_stat == 5)
	{
		gbox_send_remm_ack_msg(cli, rdr->caid, rdr->auprovid, dvbapi_stat, PEER_AU_READY);
		cs_log_dbg(D_EMM,"my dvbapi ready for AU: dvbapi_au: %1d - dvbapi_usr_autoau: %1d - dvbapi_usr_aulist: %1d",
			(dvbapi_stat & 1) ? 1 : 0, (dvbapi_stat & 2) ? 1 : 0, (dvbapi_stat & 4) ? 1 : 0 );
	}
	else
	{
		gbox_send_remm_ack_msg(cli, rdr->caid, rdr->auprovid, dvbapi_stat, PEER_AU_UNREADY);
		cs_log_dbg(D_EMM,"dvbapi status: dvbapi_au: %1d - dvbapi_usr_autoau: %1d - dvbapi_usr_aulist: %1d",
			(dvbapi_stat & 1) ? 1 : 0, (dvbapi_stat & 2) ? 1 : 0, (dvbapi_stat & 4) ? 1 : 0 );
	}
	write_msg_info(cli, MSGID_REMM, 0, 1);
}

static void gbox_recvd_remm_data(struct s_client *cli, uint8_t *buf, int32_t buflen, int32_t emmlen)
{
	if(!cli || !cli->gbox || !buf || buflen < 30 || emmlen +27 > buflen || emmlen < 3 || emmlen + 27 > MAX_EMM_SIZE)
		{ return; }

	struct gbox_peer *peer;
	peer = cli->gbox;

	uint16_t rcaid = b2i(2, buf + 15);
	uint32_t recvd_remm_crc = b2i(4, buf + 23);
	uint32_t calc_remm_crc = gbox_get_checksum(&buf[0] +27, emmlen);
	cs_log_dbg(D_EMM,"received remm from peer: %04X caid: %04X (remm_crc = %08X - calc_remm_crc = %08X)",
		peer->gbox.id, rcaid, recvd_remm_crc, calc_remm_crc);

	if(recvd_remm_crc == calc_remm_crc)
	{
		EMM_PACKET remm;
		memset(&remm, 0, sizeof(remm));
		remm.emmlen = emmlen;
		memcpy(remm.caid, buf +15, 2);
		memcpy(remm.provid, buf +17 , 4);
		memcpy(remm.emm, buf +27, remm.emmlen);
		do_emm(cur_client(), &remm);
	}
	else
	{
		cs_log_dbg(D_EMM,"reject received REMM from peer %04X caid: %04X - crc failed - %08X != %08X",
		peer->gbox.id, rcaid, recvd_remm_crc, calc_remm_crc);
	}

	return;
}

void gbox_recvd_remm_cmd_switch(struct s_client *cli, uint8_t *buf, int32_t n)
{
	if (!cli || !cli->gbox || !buf ||  n < 26) { return; }

	struct gbox_peer *peer;
	peer = cli->gbox;
	uint8_t cmd_id = buf[10];

	switch(cmd_id)
	{
		case MSGID_REMM_REQ:
			cs_log_dbg(D_EMM,"-> Incoming REMM request (%d bytes) from %04X %s - %s",
				n, peer->gbox.id, username(cli), cli->reader->device);
			gbox_recvd_remm_req(cli, buf, n);
			break;

		case MSGID_REMM_DATA:
			cs_log_dbg(D_EMM,"-> Incoming gbox remote EMM data (%d bytes total - %d bytes emm-len) from %04X %s - %s",
				n, buf[21], peer->gbox.id, username(cli), cli->reader->device);
			gbox_recvd_remm_data(cli, buf, n, buf[21]); // buf[21]) = emm lenght
			break;

		case MSGID_REMM_ACK:
			cs_log_dbg(D_EMM,"-> Incoming REMM ACK (%d bytes) from %04X %s - %s",
				n, peer->gbox.id, username(cli), cli->reader->device);
			gbox_recvd_remm_ack_msg(cli, buf, n);
			break;

		default:
			cs_log("received unknown remm cmd_id: %d %d bytes from %04X %s - %s",
				cmd_id, n, peer->gbox.id, username(cli), cli->reader->device);
			return;
	}
}

void gbox_send_remm_req(struct s_client *cli, ECM_REQUEST *er)
{
	if (!cli || !cli->gbox || !er) { return; }
	int32_t i;
	uint8_t mbuf[1024];
	struct s_client *cl = cur_client();
	struct gbox_peer *peer = cli->gbox;
	struct s_reader *aureader = NULL, *rdr = NULL;

	if(er->selected_reader && !er->selected_reader->audisabled && ll_contains(cl->aureader_list, er->selected_reader))
		{ aureader = er->selected_reader; }

	if(!aureader && cl->aureader_list)
	{
		LL_ITER itr = ll_iter_create(cl->aureader_list);
		while((rdr = ll_iter_next(&itr)))
		{
			if(emm_reader_match(rdr, er->caid, er->prid))
			{
				aureader = rdr;
				break;
			}
		}
	}

	if(!aureader)
		{ return; }

	uint16_t au_caid = aureader->caid;

	if(!au_caid && caid_is_bulcrypt(er->caid)) // Bulcrypt has 2 caids and aureader->caid can't be used. Use ECM_REQUEST caid for AU.
		{ au_caid = er->caid; }

	if(cl->lastcaid != er->caid)
		{ cl->disable_counter = 0; }

	cl->lastcaid = er->caid;
	cl->disable_counter++;

	if (!cli->reader->gbox_force_remm && cl->disable_counter < 6) // delay 6 ecm
		{ return; }

	if(!memcmp(cl->lastserial, aureader->hexserial, 8))
	{
		cl->disable_counter = 0;
		return;
	}

	memcpy(cl->lastserial, aureader->hexserial, 8);

	if(au_caid)
		{ cl->disable_counter = 0; }
	else
		{ return; }

	uint8_t total_ent = 0;
	uint8_t active_ent = 0;

	if(aureader->ll_entitlements) // check for active entitlements
		{
			time_t now = time((time_t *)0);
			LL_ITER itr = ll_iter_create(aureader->ll_entitlements);
			S_ENTITLEMENT *ent;

			while((ent = ll_iter_next(&itr)))
				{
					total_ent++;
					if((ent->end > now) && (ent->type != 7))
						{
							active_ent++;
						}
				}
					//cs_log("AU card %s: Total entitlements: %d - active entitlements: %d", aureader->label, total_ent,  active_ent);
		}

	if(total_ent && cli->reader->gbox_force_remm)
		{
			if(active_ent >= cli->reader->gbox_force_remm)
				{
					cs_log("WARNING: Card '%s' got %d active entitlements - consider to disable 'force_remm'", aureader->label, active_ent);
				}
		}

	memset(mbuf, 0, sizeof(mbuf));

	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();

	gbox_message_header(mbuf, MSG_REM_EMM, peer->gbox.password, local_gbox_pw);
	mbuf[10] = MSGID_REMM_REQ;
	i2b_buf(2, peer->gbox.id, mbuf + 11);
	i2b_buf(2, local_gbox_id, mbuf + 13);
	i2b_buf(2, er->srvid, mbuf + 15);

	// override emm provid with auprovid if set in server reader config
	if(aureader->auprovid)
	{
		if(aureader->auprovid != er->prid)
			{ i2b_buf(4, aureader->auprovid, mbuf +17); }
		else
			{ i2b_buf(4, er->prid, mbuf +17); }
	}
	else
	{
		i2b_buf(4, er->prid, mbuf +17);
	}

	i2b_buf(2, er->pid, mbuf +21);
	i2b_buf(2, au_caid, mbuf +23);

	memcpy(mbuf +29, aureader->hexserial, 6); // serial 6 bytes
	mbuf[37] = aureader->nprov;

	for(i = 0; i < aureader->nprov; i++)
	{
		if(caid_is_betacrypt(au_caid) || caid_is_irdeto(au_caid))
		{
			mbuf[38 + (i * 5)] = aureader->prid[i][0];
			memcpy(&mbuf[40 + (i * 5)], &aureader->prid[i][1], 3);
		}
		else
		{
			mbuf[38 + (i * 5)] = aureader->prid[i][2];
			mbuf[39 + (i * 5)] = aureader->prid[i][3];
			memcpy(&mbuf[40 + (i * 5)], &aureader->sa[i][0], 4); // for conax we need at least 4 Bytes
		}
		if(i >= 15) { break; }
	}

	mbuf[117] = aureader->blockemm | 0x80; // set remm marker bit

	if(au_caid == 0x0D96 || au_caid == 0x0D98 ) // these caids needs globals
		{ mbuf[118] = (aureader->blockemm & EMM_GLOBAL && !(aureader->saveemm & EMM_GLOBAL)) ? 0 : 1; }
	else
		{ mbuf[118] = 0; }

	mbuf[119] = (aureader->blockemm & EMM_SHARED && !(aureader->saveemm & EMM_SHARED)) ? 0 : 1;
	mbuf[120] = (aureader->blockemm & EMM_UNIQUE && !(aureader->saveemm & EMM_UNIQUE)) ? 0 : 1;
	mbuf[121] = 0; // (aureader->blockemm & EMM_UNKNOWN && !(aureader->saveemm & EMM_UNKNOWN)) ? 0 : 1;

	cs_log("<- %04X sends REMM REQ for type = %s%s%s%s to %s peer-id=%04X for reader=%s, caid=%04X", local_gbox_id,
		mbuf[120] == 1 ? "UQ " : "", mbuf[119] == 1 ? "SH " : "", mbuf[118] == 1 ? "GL " : "", mbuf[121] == 1 ? "UK" : "",
		username(cur_client()), peer->gbox.id, aureader->label, au_caid );

	cs_log_dump_dbg(D_EMM, mbuf, 122, "<- send remm request, (data_len=%d):", 122);
	gbox_send(cli, mbuf, 122);
	return;
}

int32_t gbox_send_remm_data(EMM_PACKET *ep)
{
	struct s_client *cli = cur_client();
	struct gbox_peer *peer = cli->gbox;

	if(!cli->gbox || !cli->reader->tcp_connected || !ep || !cli->reader->gbox_remm_peer)
	{ return 0; }

	uint32_t remm_crc = gbox_get_checksum(&ep->emm[0], ep->emmlen);

	if(remm_crc == peer->last_remm_crc)
		{ return 0; }

	peer->last_remm_crc = remm_crc;

	uint8_t *buf;

	if(!cs_malloc(&buf, ep->emmlen +27 +15))
		{ return -1; }

	memset(buf, 0, 26);
	memset(buf +27, 0xff, ep->emmlen + 15);

	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();

	gbox_message_header(buf, MSG_REM_EMM, peer->gbox.password, local_gbox_pw);
	buf[10] = MSGID_REMM_DATA;
	i2b_buf(2, peer->gbox.id, buf +11);
	i2b_buf(2, local_gbox_id, buf +13);
	memcpy(buf +15, ep->caid, 2);
	memcpy(buf +17, ep->provid, 4);
	buf[21] = ep->emmlen;
	i2b_buf(4, remm_crc, buf +23);
	memcpy(buf +27, ep->emm, ep->emmlen);
	cs_log("<- send remm to: %s peer: %04X emmlength: %d crc: %08X",
		username(cur_client()), peer->gbox.id, ep->emmlen, remm_crc);
	cs_log_dump_dbg(D_EMM, buf, 27 + ep->emmlen, "<- gbox send emm, (data-len=%d):", 27 + ep->emmlen);
	gbox_send(cli, buf, 27 + ep->emmlen);

	NULLFREE(buf);
	return 1;
}
#endif

