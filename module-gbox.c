#define MODULE_LOG_PREFIX "gbox"

#include "globals.h"
#ifdef MODULE_GBOX

#include "module-gbox.h"
#include "module-gbox-helper.h"
#include "module-gbox-sms.h"
#include "module-gbox-cards.h"
#include "module-cccam.h"
#include "module-cccam-data.h"
#include "oscam-failban.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-chk.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-reader.h"
#include "oscam-files.h"
#include "module-gbox-remm.h"
#include "module-dvbapi.h"
#include "oscam-work.h"

static struct gbox_data local_gbox;
static int8_t local_gbox_initialized = 0;
static uint8_t local_cards_initialized = 0;
uint8_t local_gbx_rev = 0x30;
uint32_t startup = 0;

static uint32_t gbox_add_local_cards(void);
static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er);
void start_gbx_ticker(void);

char *get_gbox_tmp_fname(char *fext)
{
	static char gbox_tmpfile_buf[128];
	memset(gbox_tmpfile_buf, 0, sizeof(gbox_tmpfile_buf));
	const char *slash = "/";

	if(!cfg.gbox_tmp_dir)
	{
		snprintf(gbox_tmpfile_buf, sizeof(gbox_tmpfile_buf), "%s%s%s",get_tmp_dir(), slash, fext);
	}
	else
	{
		if(cfg.gbox_tmp_dir[cs_strlen(cfg.gbox_tmp_dir) - 1] == '/') { slash = ""; }
		snprintf(gbox_tmpfile_buf, sizeof(gbox_tmpfile_buf), "%s%s%s", cfg.gbox_tmp_dir, slash, fext);
	}
	return gbox_tmpfile_buf;
}

uint16_t gbox_get_local_gbox_id(void)
{
	return local_gbox.id;
}

uint32_t gbox_get_local_gbox_password(void)
{
	return local_gbox.password;
}

static uint8_t gbox_get_my_cpu_api (void)
{
	return(cfg.gbox_my_cpu_api);
}

static void write_attack_file (struct s_client *cli, uint8_t txt_id, uint16_t rcvd_id)
{
	if (cfg.dis_attack_txt) {return;}
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	char *fext= FILE_ATTACK_INFO;
	char *fname = get_gbox_tmp_fname(fext);
	FILE *fhandle = fopen(fname, "a");

	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}

	if(txt_id == GBOX_ATTACK_UNKWN_HDR)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - peer sends unknown Header CMD - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	if(txt_id == GBOX_ATTACK_LOCAL_PW)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - peer sends wrong local password - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	if(txt_id == GBOX_ATTACK_PEER_IGNORE)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - peer ignored by conf - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	if(txt_id == GBOX_ATTACK_PEER_PW)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - peer sends unknown peer password - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	if(txt_id == GBOX_ATTACK_AUTH_FAIL)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - authentification failed - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	if(txt_id == GBOX_ATTACK_ECM_BLOCKED)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - ECM is blocked - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	if(txt_id == GBOX_ATTACK_REMM_REQ_BLOCKED)
	{
		fprintf(fhandle, "ATTACK ALERT FROM %04X  %s - unaccepted peer sent REMM REQ - %s",
			rcvd_id, cs_inet_ntoa(cli->ip), tsbuf);
	}

	fclose(fhandle);
	return;
}

void write_msg_info(struct s_client *cli, uint8_t msg_id, uint8_t txt_id, uint16_t misc)
{
	if (msg_id == MSGID_GSMS && misc == 0x31) {return;}
	char *fext= FILE_MSG_INFO;
	char *fname = get_gbox_tmp_fname(fext);

	if (file_exists(fname))
	{
		char buf[120];
		memset(buf, 0, sizeof(buf));

		if (msg_id == MSGID_ATTACK)
		{
			snprintf(buf, sizeof(buf), "%s %d %04X %d %s %d",
				fname, msg_id, misc, 0, cs_inet_ntoa(cli->ip), txt_id);

			cs_log_dbg(D_READER, "found driver %s - write msg (msg_id = %d - txt-id = %d) Attack Alert from %s %04X",
				fname, msg_id, txt_id, cs_inet_ntoa(cli->ip), misc);
		}
		else
		{
			snprintf(buf, sizeof(buf), "%.24s %d %.24s %.24s %s %d",
				fname, msg_id, username(cli), cli->reader->device, cs_inet_ntoa(cli->ip), misc);

			cs_log_dbg(D_READER, "found driver %s - write msg (id = %d) related to %s %s",
				fname, msg_id, username(cli),cli->reader->device);
		}

		char *cmd = buf;
		FILE *p;
		if((p = popen(cmd, "w")) == NULL)
		{
			cs_log("Error popen: %s",fname);
			return;
		}
		if(pclose(p) == -1)
		{
			cs_log("Error pclose(): %s",fname);
			return;
		}
	}
	return;
}

void handle_attack(struct s_client *cli, uint8_t txt_id, uint16_t rcvd_id)
{
	write_attack_file(cli, txt_id, rcvd_id);
	write_msg_info(cli, MSGID_ATTACK, txt_id, rcvd_id);
	return;
}

void gbox_write_peer_onl(void)
{
	char *fext = FILE_GBOX_PEER_ONL;
	char *fname = get_gbox_tmp_fname(fext);
	FILE *fhandle = fopen(fname, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}

	cs_readlock(__func__, &clientlist_lock);

	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p')
		{
			struct gbox_peer *peer = cl->gbox;
			if (peer->online)
			{
				fprintf(fhandle, "1 %s %s %04X 2.%02X %s\n", cl->reader->device,
					cs_inet_ntoa(cl->ip), peer->gbox.id, peer->gbox.minor_version, cl->reader->description ? cl->reader->description : "");

				if (!peer->onlinestat)
				{
					peer->onlinestat = 1;
					cs_log("comeONLINE: %s %s boxid: %04X (%s) v2.%02X cards:%d", cl->reader->device,
						cs_inet_ntoa(cl->ip), peer->gbox.id, cl->reader->description ? cl->reader->description : "-", peer->gbox.minor_version, peer->filtered_cards);
					write_msg_info(cl, MSGID_COMEONLINE, 0, peer->filtered_cards);
				}
			}
			else
			{
				fprintf(fhandle, "0 %s %s %04X 0.00 %s\n", cl->reader->device, cs_inet_ntoa(cl->ip),peer->gbox.id, cl->reader->description ? cl->reader->description : "");
				if (peer->onlinestat)
				{
					peer->onlinestat = 0;
					cs_log("goneOFFLINE: %s %s boxid: %04X (%s)",cl->reader->device, cs_inet_ntoa(cl->ip),peer->gbox.id, cl->reader->description ? cl->reader->description : "-");
					write_msg_info(cl, MSGID_GONEOFFLINE, 0, 0);
				}
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	fclose(fhandle);
	return;
}

void gbox_write_version(void)
{
	char *fext = FILE_GBOX_VERSION;
	char *fname = get_gbox_tmp_fname(fext);
	FILE *fhandle = fopen(fname, "w");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", get_gbox_tmp_fname(FILE_GBOX_VERSION), strerror(errno));
		return;
	}
	fprintf(fhandle, "%02X.%02X  my-id: %04X rev: %01X.%01X\n", LOCAL_GBOX_MAJOR_VERSION, cfg.gbox_my_vers, local_gbox.id, local_gbx_rev >> 4, local_gbx_rev & 0xf);
	fclose(fhandle);
}

void hostname2ip(char *hostname, IN_ADDR_T *ip)
{
	cs_resolve(hostname, ip, NULL, NULL);
}

uint16_t gbox_convert_password_to_id(uint32_t password)
{
	return (((password >> 24) & 0xff) ^ ((password >> 8) & 0xff)) << 8 | (((password >> 16) & 0xff) ^ (password & 0xff));
}

static int8_t gbox_remove_all_bad_sids(ECM_REQUEST *er, uint16_t sid)
{
	if (!er)
	{
		return -1;
	}

	struct gbox_card_pending *pending = NULL;
	LL_LOCKITER *li = ll_li_create(er->gbox_cards_pending, 0);

	while ((pending = ll_li_next(li)))
	{
		gbox_remove_bad_sid(pending->id.peer, pending->id.slot, sid);
	}
	ll_li_destroy(li);
	return 0;
}

void gbox_free_cards_pending(ECM_REQUEST *er)
{
	ll_destroy_free_data(&er->gbox_cards_pending);
}

void gbox_init_ecm_request_ext(struct gbox_ecm_request_ext *ere)
{
	ere->gbox_slot = 0;
	ere->gbox_version = 0;
	ere->gbox_rev = 0;
	ere->gbox_type = 0;
}

struct s_client *get_gbox_proxy(uint16_t gbox_id)
{
	struct s_client *cl;
	struct s_client *found = NULL;
	cs_readlock(__func__, &clientlist_lock);

	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'p' && cl->gbox && cl->gbox_peer_id == gbox_id)
		{
			found = cl;
			break;
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return found;
}

void remove_peer_crd_file(struct s_client *proxy)
{
	char buff[64];
	snprintf(buff, sizeof(buff),"cards_to_%.24s", proxy->reader->label);
	char *fname = get_gbox_tmp_fname(buff);

	if(file_exists(fname))
		{
			if(unlink(fname) < 0)
				{
					cs_log("Error removing peer_crd_file %s (errno=%d %s)!", fname, errno, strerror(errno));
				}
		}
}

static int8_t gbox_peer_online(struct gbox_peer *peer, uint8_t online)
{
	if (!peer) { return -1; }

	peer->online = online;
	gbox_write_peer_onl();
	return 0;
}

static int8_t gbox_clear_peer(struct gbox_peer *peer)
{
	if (!peer)
	{
		return -1;
	}

	peer->ecm_idx = 0;
	peer->next_hello = 0;
	peer->authstat = 0;

	gbox_delete_cards(GBOX_DELETE_FROM_PEER, peer->gbox.id);
	gbox_peer_online(peer, GBOX_PEER_OFFLINE);

	return 0;
}

static int8_t gbox_reinit_proxy(struct s_client *proxy)
{
	if (!proxy)
	{
		return -1;
	}

	struct gbox_peer *peer = proxy->gbox;
	gbox_clear_peer(peer);

	if (!proxy->reader)
	{
		return -1;
	}

	remove_peer_crd_file(proxy);
	proxy->reader->tcp_connected = 0;
	proxy->reader->card_status = CARD_NEED_INIT;
	proxy->reader->last_s = proxy->reader->last_g = 0;

	return 0;
}

//gbox.net doesn't accept slots >18
static uint8_t calc_slot(uint8_t slot)
{
	int8_t i;
	uint8_t cslot = slot;

	for(i=0 ; i < 9 ; i++)
	{
		if(slot > i*18)
			{
				cslot = slot - i*18;
			}
	}
	return cslot;
}

uint16_t count_send_cards(struct s_client *proxy)
{
	uint16_t nbcards = 0;
	struct gbox_peer *peer = proxy->gbox;
	struct gbox_card *card;
	if(gbox_count_cards() > 0)
	{
		GBOX_CARDS_ITER *gci = gbox_cards_iter_create();
		while((card = gbox_cards_iter_next(gci)))
		{
			if(chk_ctab(gbox_get_caid(card->caprovid), &peer->my_user->account->ctab) && (card->lvl > 0) &&
#ifdef MODULE_CCCAM
				(card->dist <= peer->my_user->account->cccmaxhops)  &&
#endif
				(!card->origin_peer || (card->origin_peer && card->origin_peer->gbox.id != peer->gbox.id)))
			{
				if(card->type == GBOX_CARD_TYPE_GBOX)
				{
					nbcards++;
					continue;
				}
				else if(card->type == GBOX_CARD_TYPE_CCCAM) //&& cfg.cc_gbx_reshare_en
				{
					if(proxy->reader->gbox_cccam_reshare < 0)
						{ continue; }
					else
					{
						if(chk_ident_filter(gbox_get_caid(card->caprovid), gbox_get_provid(card->caprovid), &proxy->reader->ccc_gbx_reshare_ident))
						{
							nbcards++;
							continue;
						}
					}
				}
				else if(card->type == GBOX_CARD_TYPE_LOCAL || card->type == GBOX_CARD_TYPE_BETUN || card->type ==  GBOX_CARD_TYPE_PROXY)
				{
					if(proxy->reader->gbox_reshare > 0)
					{
						nbcards++;
						continue;
					}
					else
					{
						continue;
					}
				}

				if(nbcards == MAX_GBOX_CARDS )
				{
					break;
				}
			}
		} // while cards exist
			gbox_cards_iter_destroy(gci);
	}
	return nbcards;
}

void gbox_send(struct s_client *cli, uint8_t *buf, int32_t l)
{
	struct gbox_peer *peer = cli->gbox;

	cs_log_dump_dbg(D_READER, buf, l, "<- data to %s (%d bytes):", cli->reader->label, l);

	hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));
	SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
	SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)cli->reader->r_port);

	gbox_encrypt(buf, l, peer->gbox.password);
	sendto(cli->udp_fd, buf, l, 0, (struct sockaddr *)&cli->udp_sa, cli->udp_sa_len);
	cs_log_dump_dbg(D_READER, buf, l, "<- encrypted data to %s (%d bytes):", cli->reader->label, l);
}

void gbox_send_hello_packet(struct s_client *cli, int8_t packet, uint8_t *outbuf, uint8_t *ptr, int32_t nbcards, uint8_t hello_stat)
{
	struct gbox_peer *peer = cli->gbox;
	int32_t hostname_len = cs_strlen(cfg.gbox_hostname);
	int32_t len;

	gbox_message_header(outbuf, MSG_HELLO, peer->gbox.password, local_gbox.password);

	if(hello_stat > GBOX_STAT_HELLOS) // hello_stat == HelloR
	{
		outbuf[10] = 1;
	}
	else
	{
		outbuf[10] = 0;
	}
	outbuf[11] = packet;

	if((packet & 0x0F) == 0) // first packet
	{
		memcpy(++ptr, gbox_get_my_checkcode(), 7);

		ptr += 7;
		*ptr = local_gbox.minor_version;
		*(++ptr) = local_gbox.cpu_api;
		memcpy(++ptr, cfg.gbox_hostname, hostname_len);
		ptr += hostname_len;
		*ptr = hostname_len;
	}
	len = ptr - outbuf + 1;

	switch(hello_stat)
	{
		case GBOX_STAT_HELLOL:
			if(cfg.log_hello)
				{ cs_log("<- HelloL to %s", cli->reader->label); }
			else
				{ cs_log_dbg(D_READER,"<- HelloL to %s", cli->reader->label); }
			break;

		case GBOX_STAT_HELLOS:
			if(cfg.log_hello)
				{ cs_log("<- HelloS #%d total cards %d to %s", (packet & 0xf) +1, nbcards, cli->reader->label); }
			else
				{ cs_log_dbg(D_READER,"<- HelloS #%d total cards %d to %s", (packet & 0xf) +1, nbcards, cli->reader->label); }
			break;

		case GBOX_STAT_HELLOR:
			if(cfg.log_hello)
				{ cs_log("<- HelloR #%d total cards %d to %s", (packet & 0xf) +1, nbcards, cli->reader->label); }
			else
				{ cs_log_dbg(D_READER,"<- HelloR #%d total cards %d to %s", (packet & 0xf) +1, nbcards, cli->reader->label); }
			break;

		default:
			if(cfg.log_hello)
				{ cs_log("<- hello #%d total cards %d to %s", (packet & 0xf) +1, nbcards, cli->reader->label); }
			else
				{ cs_log_dbg(D_READER,"<- hello #%d total cards %d to %s", (packet & 0xf) +1, nbcards, cli->reader->label); }
			break;
	}
	cs_log_dump_dbg(D_READER, outbuf, len, "<- hello #%d to %s, (len=%d):", (packet & 0xf) +1, cli->reader->label, len);

	gbox_compress(outbuf, len, &len);
	gbox_send(cli, outbuf, len);
}

void gbox_send_hello(struct s_client *proxy, uint8_t hello_stat)
{
	if(!proxy)
	{
		cs_log("ERROR: Invalid proxy try to call 'gbox_send_hello'");
		return;
	}

	struct gbox_peer *peer = proxy->gbox;

	if(!peer)
	{
		cs_log("ERROR: Invalid peer try to call 'gbox_send_hello'");
		return;
	}

	if(hello_stat > GBOX_STAT_HELLOL && (!peer->my_user || !peer->my_user->account))
	{
		cs_log("ERROR: Invalid peer try to call 'gbox_send_hello'");
		return;
	}

	uint16_t sendcrds = 0;
	uint16_t nbcards = 0;
	uint16_t nbcards_cnt = 0;
	uint8_t packet = 0;
	uint8_t buf[1024];
	uint8_t *ptr = buf + 11;

	struct gbox_card *card;
	memset(buf, 0, sizeof(buf));
	if(gbox_count_cards() > 0)
	{
		if(hello_stat > GBOX_STAT_HELLOL)
		{
			uint16_t nb_send_cards = count_send_cards(proxy);

			char buff[64];
			snprintf(buff, sizeof(buff),"cards_to_%.24s", proxy->reader->label);
			char *fname = get_gbox_tmp_fname(buff);

			FILE *fhandle = fopen(fname, "w");
			if(!fhandle)
			{
				cs_log("Couldn't open %s: %s", fname, strerror(errno));
				return;
			}

			fprintf(fhandle, "Cards forwarded to peer %04X - %s\n\n", peer->gbox.id, proxy->reader->label);

			GBOX_CARDS_ITER *gci = gbox_cards_iter_create();
			while((card = gbox_cards_iter_next(gci)))
			{
				//send to user only cards which matching CAID from account and lvl > 0
				//and cccmaxhops from account
				//do not send peer cards back
				if(chk_ctab(gbox_get_caid(card->caprovid), &peer->my_user->account->ctab) && (card->lvl > 0) &&
#ifdef MODULE_CCCAM
				(card->dist <= peer->my_user->account->cccmaxhops) &&
#endif
				(!card->origin_peer || (card->origin_peer && card->origin_peer->gbox.id != peer->gbox.id)))
			{
				if(card->type == GBOX_CARD_TYPE_GBOX)
				{
					// cs_log_dbg(D_READER,"send to peer gbox-card %04X - level=%d crd-owner=%04X", card->caprovid >> 16, card->lvl, card->id.peer);
					*(++ptr) = card->caprovid >> 24;
					*(++ptr) = card->caprovid >> 16;
					*(++ptr) = card->caprovid >> 8;
					*(++ptr) = card->caprovid & 0xff;
					*(++ptr) = 1; // note: original gbx is more efficient and sends all cards of one caid as package
					*(++ptr) = calc_slot(card->id.slot);
					*(++ptr) = ((card->lvl - 1) << 4) + card->dist + 1;

						fprintf(fhandle, "#%03d Peer Crd to %04X - crd %08X - level %d - dist %d - slot %02d - crd owner %04X\n", ++sendcrds, peer->gbox.id, card->caprovid, card->lvl -1, card->dist + 1, calc_slot(card->id.slot), card->id.peer);
				}
				else if(card->type == GBOX_CARD_TYPE_CCCAM)
				{
					if(proxy->reader->gbox_cccam_reshare < 0)
						{ continue; }
					else
					{
						if(chk_ident_filter(gbox_get_caid(card->caprovid), gbox_get_provid(card->caprovid), &proxy->reader->ccc_gbx_reshare_ident))
						{
							if(proxy->reader->gbox_cccam_reshare > proxy->reader->gbox_reshare)
							{
								proxy->reader->gbox_cccam_reshare = proxy->reader->gbox_reshare;
							}
							// cs_log_dbg(D_READER,"send to peer %04X - ccc-card %04X - level=%d crd-owner=%04X", peer->gbox.id, card->caprovid >> 16, proxy->reader->gbox_cccam_reshare, card->id.peer);
						*(++ptr) = card->caprovid >> 24;
						*(++ptr) = card->caprovid >> 16;
						*(++ptr) = card->caprovid >> 8;
						*(++ptr) = card->caprovid & 0xff;
						*(++ptr) = 1;
						*(++ptr) = calc_slot(card->id.slot);
						*(++ptr) = ((proxy->reader->gbox_cccam_reshare) << 4) + card->dist + 1;

							fprintf(fhandle, "#%03d CCCM crd to %04X - crd %08X - level %d - dist %d - slot %02d - crd owner %04X\n", ++sendcrds, peer->gbox.id, card->caprovid, proxy->reader->gbox_cccam_reshare, card->dist + 1, calc_slot(card->id.slot), card->id.peer);
						}
						else
						{ continue; }
					}
				}
				else if(card->type == GBOX_CARD_TYPE_LOCAL || card->type == GBOX_CARD_TYPE_BETUN || card->type ==  GBOX_CARD_TYPE_PROXY)
				{
					if(proxy->reader->gbox_reshare > 0)
					{
					//cs_log_dbg(D_READER,"send local crd %04X reshare=%d crd-owner=%04X", card->caprovid >> 16, proxy->reader->gbox_reshare, card->id.peer);
					*(++ptr) = card->caprovid >> 24;
					*(++ptr) = card->caprovid >> 16;
					*(++ptr) = card->caprovid >> 8;
					*(++ptr) = card->caprovid & 0xff;
					*(++ptr) = 1;
					*(++ptr) = calc_slot(card->id.slot);
					*(++ptr) = ((proxy->reader->gbox_reshare - 1) << 4) + card->dist + 1;

						fprintf(fhandle, "#%03d Locl Crd to %04X - crd %08X - level %d - dist %d - slot %02d - crd owner %04X\n", ++sendcrds, peer->gbox.id, card->caprovid, proxy->reader->gbox_reshare - 1, card->dist + 1, calc_slot(card->id.slot), card->id.peer);
					}
					else
					{
						cs_log_dbg(D_READER,"WARNING: local card %04X NOT be shared - !! reshare=%d !! crd-owner=%04X", card->caprovid >> 16, proxy->reader->gbox_reshare, card->id.peer);
						continue;
					}
				}

				*(++ptr) = card->id.peer >> 8;
				*(++ptr) = card->id.peer & 0xff;
				nbcards++;
				nbcards_cnt++;

				if(nbcards_cnt == MAX_GBOX_CARDS)
				{
					cs_log("max card limit [%d] send to peer %04X is exceeded", MAX_GBOX_CARDS, peer->gbox.id);
					break;
				}

				if(nbcards_cnt == nb_send_cards)
				{
					break;
				}

				if(nbcards == 74)
				{
					gbox_send_hello_packet(proxy, packet, buf, ptr, nbcards, hello_stat);
					packet++;
					nbcards = 0;
					ptr = buf + 11;
					memset(buf, 0, sizeof(buf));
				}
			}
		} // while cards exist

		gbox_cards_iter_destroy(gci);
		fclose(fhandle);
	} // end if > HelloL
	else
		{
			GBOX_CARDS_ITER *gci = gbox_cards_iter_create();
			while((card = gbox_cards_iter_next(gci)))
			{
				if(card->lvl > 0 && card->type != GBOX_CARD_TYPE_CCCAM && card->type != GBOX_CARD_TYPE_GBOX)
				{
					if(proxy->reader->gbox_reshare > 0)
					{
						*(++ptr) = card->caprovid >> 24;
						*(++ptr) = card->caprovid >> 16;
						*(++ptr) = card->caprovid >> 8;
						*(++ptr) = card->caprovid & 0xff;
						*(++ptr) = 1;
						*(++ptr) = calc_slot(card->id.slot);
						*(++ptr) = ((proxy->reader->gbox_reshare - 1) << 4) + card->dist + 1;
						*(++ptr) = card->id.peer >> 8;
						*(++ptr) = card->id.peer & 0xff;
					}
						nbcards++;
					if(nbcards >= GBOX_MAX_LOCAL_CARDS )
					{
						cs_log("gbox_send_HelloL - local crds = %d - max allowed = %d ", nbcards, GBOX_MAX_LOCAL_CARDS);
						break;
					}
				}
			} // end while local cards exist
			gbox_cards_iter_destroy(gci);
		} // end if HelloL
	}// end if gbox_count_cards > 0

	gbox_send_hello_packet(proxy, 0x80 | packet, buf, ptr, nbcards, hello_stat); //last packet has bit 0x80 set
}

void gbox_reconnect_peer(struct s_client *cl)
{
	struct gbox_peer *peer = cl->gbox;
	hostname2ip(cl->reader->device, &SIN_GET_ADDR(cl->udp_sa));
	SIN_GET_FAMILY(cl->udp_sa) = AF_INET;
	SIN_GET_PORT(cl->udp_sa) = htons((uint16_t)cl->reader->r_port);
	hostname2ip(cl->reader->device, &(cl->ip));
	gbox_reinit_proxy(cl);
	cs_log("reconnect %s  peer: %04X", username(cl), peer->gbox.id);
	gbox_send_hello(cl, GBOX_STAT_HELLOS);
	return;
}

void restart_gbox_peer(char *rdrlabel, uint8_t allrdr, uint16_t gbox_id)
{
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);

	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p' &&
			((rdrlabel && !strcmp(rdrlabel, cl->reader->label)) ||
			allrdr || (gbox_id && cl->gbox_peer_id == gbox_id)))
		{ gbox_reconnect_peer(cl); }
	}
	cs_readunlock(__func__, &clientlist_lock);
}

static void *gbox_server(struct s_client *cli, uint8_t *UNUSED(b), int32_t l)
{
	if(l > 0)
	{
		cs_log("gbox_server %s/%d", cli->reader->label, cli->port);
		//gbox_check_header_recvd(cli, NULL, b, l);
	}
	return NULL;
}

char *gbox_username(struct s_client *client)
{
	if(!client)
	{
		return "anonymous";
	}

	if(client->reader)
	{
		if(client->reader->r_usr[0])
		{
			return client->reader->r_usr;
		}
	}
	return "anonymous";
}

static int8_t gbox_disconnect_double_peers(struct s_client *cli)
{
	struct s_client *cl;
	cs_writelock(__func__, &clientlist_lock);

	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'c' && cl->gbox_peer_id == cli->gbox_peer_id && cl != cli)
		{
			cl->reader = NULL;
			cl->gbox = NULL;
			cs_log_dbg(D_READER, "disconnected double client %s - %s", username(cl), cs_inet_ntoa(cli->ip));
			//cs_log("disconnected double client %s - %s",username(cl), cs_inet_ntoa(cli->ip));
			cs_disconnect_client(cl);
		}
	}
	cs_writeunlock(__func__, &clientlist_lock);
	return 0;
}

static int8_t gbox_auth_client(struct s_client *cli, uint32_t gbox_password)
{
	if(!cli) { return -1; }

	uint16_t gbox_id = gbox_convert_password_to_id(gbox_password);
	struct s_client *cl = get_gbox_proxy(gbox_id);

	if(cl->typ == 'p' && cl->gbox && cl->reader)
	{
		struct gbox_peer *peer = cl->gbox;
		struct s_auth *account = get_account_by_name(gbox_username(cl));

		if ((peer->gbox.password == gbox_password) && account)
		{
			cli->crypted = 1; // display as crypted
			cli->gbox = cl->gbox; // point to the same gbox as proxy
			cli->reader = cl->reader; // point to the same reader as proxy
			cli->gbox_peer_id = cl->gbox_peer_id; // signal authenticated
			gbox_disconnect_double_peers(cli);
			cs_auth_client(cli, account, NULL);
			cli->account = account;
			cli->grp = account->grp;
			cli->lastecm = time(NULL);
			peer->my_user = cli;
			return 0;
		}
	}
	return -1;
}

static void gbox_server_init(struct s_client *cl)
{
	cs_writelock(__func__, &clientlist_lock);
	if(!cl->init_done)
	{
		if(IP_ISSET(cl->ip))
		{
			cs_log("new connection from %s", cs_inet_ntoa(cl->ip));
		}
		// We cannot authenticate here, because we don't know gbox pw
		cl->gbox_peer_id = NO_GBOX_ID;
		cl->init_done = 1;
		cl->last = time((time_t *)0);
		start_gbx_ticker();
	}
	cs_writeunlock(__func__, &clientlist_lock);
	return;
}

static uint16_t gbox_decode_cmd(uint8_t *buf)
{
	return buf[0] << 8 | buf[1];
}

int8_t gbox_message_header(uint8_t *buf, uint16_t cmd, uint32_t peer_password, uint32_t local_password)
{
	if (!buf) { return -1; }
	i2b_buf(2, cmd, buf);
	i2b_buf(4, peer_password, buf + 2);
	if (cmd == MSG_CW) { return 0; }
	i2b_buf(4, local_password, buf + 6);
	return 0;
}

// returns number of cards in a hello packet or -1 in case of error
int16_t read_cards_from_hello(uint8_t *ptr, uint8_t *len, CAIDTAB *ctab, uint8_t maxdist, struct gbox_peer *peer)
{
	uint8_t *current_ptr = 0;
	uint32_t caprovid;
	int16_t ncards_in_msg = 0;

	while(ptr < len)
	{
		caprovid = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];

		ncards_in_msg += ptr[4];
		//caid check
		if(chk_ctab(gbox_get_caid(caprovid), ctab))
		{
			current_ptr = ptr;
			ptr += 5;

			// for all cards of current caid/provid,
			while (ptr < current_ptr + 5 + current_ptr[4] * 4)
			{
				if ((ptr[1] & 0xf) <= maxdist)
				{
					gbox_add_card(ptr[2] << 8 | ptr[3], caprovid, ptr[0], ptr[1] >> 4, ptr[1] & 0xf, GBOX_CARD_TYPE_GBOX, peer);
				}
				ptr += 4; // next card
			} // end while cards for provider
		}
		else
		{
			ptr += 5 + ptr[4] * 4; // skip cards because caid
		}
	} // end while < len
	return ncards_in_msg;
}

// returns 1 if checkcode changed / 0 if not
static uint8_t gbox_checkcode_recvd(struct s_client *cli, uint8_t *checkcode, uint8_t updcrc)
{
	struct gbox_peer *peer = cli->gbox;
	if(memcmp(peer->checkcode, checkcode, 7))
	{
		if (updcrc)
			{
				cs_log_dump_dbg(D_READER, peer->checkcode, 7, "-> old checkcode from %04X %s:", peer->gbox.id, cli->reader->label);
				cs_log_dump_dbg(D_READER, checkcode, 7, "-> new checkcode from %04X %s:", peer->gbox.id, cli->reader->label);
				memcpy(peer->checkcode, checkcode, 7);
			}
		return 1;
	}
	return 0;
}

static void disable_remm(struct s_client *cli)
{
	if (cli->reader->blockemm & 0x80) // if remm marker bit set
	{
		struct gbox_peer *peer = cli->gbox;
		cs_log("-> Disable REMM Req for %04X %s %s", peer->gbox.id, cli->reader->label, cli->reader->device);
		cli->reader->gbox_remm_peer = 0;
		cli->reader->blockemm = 15;
		write_msg_info(cli, MSGID_REMM, 0, 0);
	}
	return;
}

static void gbox_revd_goodnight(struct s_client *cli)
{
	cs_log("-> Good Night received from %s %s", cli->reader->label, cli->reader->device);
	disable_remm(cli);
	write_msg_info(cli, MSGID_GOODNIGHT, 0, 0);
	gbox_reinit_proxy(cli);
	gbox_write_share_cards_info();
	gbox_update_my_checkcode();
	//gbox_send_peer_crd_update();
	cli->last = time((time_t *)0);
	return;
}

static void gbox_send_my_checkcode(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	uint8_t outbuf[20];
	gbox_message_header(outbuf, MSG_CHECKCODE, peer->gbox.password, local_gbox.password);
	memcpy(outbuf + 10, gbox_get_my_checkcode(), 7);
	gbox_send(cli, outbuf, 17);
	cs_log_dump_dbg(D_READER, gbox_get_my_checkcode(), 7, "<- my checkcode to %s:", cli->reader->label);
		if (cfg.log_hello)
			{ cs_log("<- HelloC my checkcode to %s (%s:%d)", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port);}
		else
			{ cs_log_dbg(D_READER,"<- HelloC my checkcode to %s (%s:%d)", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port);}
	return;
}

int32_t gbox_cmd_hello_rcvd(struct s_client *cli, uint8_t *data, int32_t n)
{
	if (!cli || !cli->gbox || !cli->reader || !data) { return -1; }

	struct gbox_peer *peer = cli->gbox;
	int16_t cards_number = 0;
	int32_t payload_len = n;
	int32_t hostname_len = 0;
	int32_t footer_len = 0;
	uint8_t *ptr = 0;
	uint8_t diffcheck = 0;
	uint8_t is_helloL = 0;

	if(!(gbox_decode_cmd(data) == MSG_HELLO1))
	{
		gbox_decompress(data, &payload_len);
		cs_log_dump_dbg(D_READER, data, payload_len, "-> data decompressed (%d bytes):", payload_len);
		ptr = data + 12;
	}
	else
	{
		ptr = data + 11;
		cs_log_dump_dbg(D_READER, data, payload_len, "decrypted data (%d bytes):", payload_len);
	}

	if ((data[11] & 0xf) != peer->next_hello) // out of sync hellos
	{
		cs_log("-> out of sync hello from %s %s, expected: %02X, received: %02X",
				username(cli), cli->reader->device, peer->next_hello, data[11] & 0xf);

		peer->next_hello = 0;
		gbox_send_hello(cli, GBOX_STAT_HELLOL);
		return 0;
	}

	if (!(data[11] & 0xf)) // is first packet
	{
		gbox_delete_cards(GBOX_DELETE_FROM_PEER, peer->gbox.id);
		hostname_len = data[payload_len - 1];
		footer_len = hostname_len + 2 + 7;

		if(peer->hostname && memcmp(peer->hostname, data + payload_len - 1 - hostname_len, hostname_len))
			{
				cs_log("WARNING - Received Hello from Peer %04X - hostname in cfg is different to received hostname", peer->gbox.id);
			}

		if(!peer->hostname || memcmp(peer->hostname, data + payload_len - 1 - hostname_len, hostname_len))
		{
			NULLFREE(peer->hostname);
			if(!cs_malloc(&peer->hostname, hostname_len + 1))
			{
				return -1;
			}
			memcpy(peer->hostname, data + payload_len - 1 - hostname_len, hostname_len);
			peer->hostname[hostname_len] = '\0';
		}

		diffcheck=gbox_checkcode_recvd(cli, data + payload_len - footer_len - 1, 1);
			if(diffcheck)
				{
					peer->crd_crc_change = 1;
					cs_log_dbg(D_READER,"-> first packet of hello from %04X - diffcheck=1 -> peer-card changed", peer->gbox.id);
				}
		peer->gbox.minor_version = data[payload_len - footer_len - 1 + 7];
		peer->gbox.cpu_api = data[payload_len - footer_len + 7];
		peer->total_cards = 0;
	}

	// read cards from hello
	cards_number = read_cards_from_hello(ptr, data + payload_len - footer_len - 1, &cli->reader->ctab, cli->reader->gbox_maxdist, peer);

	if (cards_number < 0)
		{ return -1; }
	else
		{
			peer->total_cards += cards_number;
			cs_log_dbg(D_READER,"-> Hello packet no. %d received - %d unfiltered card(s) - from %s %s", (data[11] & 0xF) + 1, cards_number, username(cli), cli->reader->device);
		}

	if(peer->crd_crc_change && cards_number)
		{ gbox_update_my_checkcode(); }

	if(data[11] & 0x80) // last packet
	{
		uint8_t tmpbuf[8];
		memset(&tmpbuf[0], 0xff, 7);

		if(data[10] == 0x01 && !memcmp(data + 12, tmpbuf, 7)) // good night message
		{
			gbox_revd_goodnight(cli);
		}
		else // last packet of Hello
		{
			peer->filtered_cards = gbox_count_peer_cards(peer->gbox.id);

			if(!data[10])
			{
				memset(&tmpbuf[0], 0, 7);
				if(data[11] == 0x80 && !memcmp(data + 12, tmpbuf, 7)) //is HelloL rev < 3.0
				{
					gbox_peer_online(peer, GBOX_PEER_ONLINE);
					if(cfg.log_hello)
						{ cs_log("-> HelloL from %s (%s:%d) v2.%02X", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version);}
					else
						{ cs_log_dbg(D_READER,"-> HelloL from %s (%s:%d) v2.%02X", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version);}
				}
				else
				{
					if(peer->crd_crc_change)
						{
							peer->crd_crc_change = 0;
							cs_log_dbg(D_READER,"-> last packet of HelloS from %04X, peer-card changed -> write shared cards.info", peer->gbox.id);
							if(peer->filtered_cards)
								{
									gbox_write_share_cards_info();
								}
							if(!peer->online)
								{
									is_helloL = 1;
									gbox_peer_online(peer, GBOX_PEER_ONLINE);
									if(cfg.log_hello)
										{ cs_log("-> HelloL from %s (%s:%d) v2.%02X with %d cards", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->filtered_cards); }
									else
										{cs_log_dbg(D_READER,"-> HelloL from %s (%s:%d) v2.%02X with %d cards", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->filtered_cards); }
								}
						}
					if(!is_helloL)
						{
							if(cfg.log_hello)
								{ cs_log("-> HelloS from %s (%s:%d) v2.%02X with %d cards", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->filtered_cards); }
							else
								{ cs_log_dbg(D_READER,"-> HelloS in %d packets from %s (%s:%d) v2.%02X with %d cards filtered to %d cards", (data[0x0B] & 0x0f)+1, cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->total_cards, peer->filtered_cards); }
						}
				}
				cli->last = time((time_t *)0);
				gbox_send_hello(cli, GBOX_STAT_HELLOR);
			}
			else
			{
				if(peer->crd_crc_change)
					{
						peer->crd_crc_change = 0;
						cs_log_dbg(D_READER,"-> last packet of HelloR from %04X, peer-card changed -> write shared cards.info", peer->gbox.id);
						if(peer->filtered_cards)
							{
								gbox_write_share_cards_info();
							}
						if(!peer->online)
							{
								gbox_peer_online(peer, GBOX_PEER_ONLINE);
							}
					}
			cli->last = time((time_t *)0);

				if (cfg.log_hello)
					{ cs_log("-> HelloR from %s (%s:%d) v2.%02X with %d cards", cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->filtered_cards); }
				else
					{ cs_log_dbg(D_READER,"-> HelloR in %d packets from %s (%s:%d) v2.%02X with %d cards filtered to %d cards", (data[0x0B] & 0x0f)+1, cli->reader->label, cs_inet_ntoa(cli->ip), cli->reader->r_port, peer->gbox.minor_version, peer->total_cards, peer->filtered_cards);}
//				cs_sleepms(1000); //add some delay like gbox.net?
				gbox_send_my_checkcode(cli);
			}

			if(!peer->online)
			{
				gbox_peer_online(peer, GBOX_PEER_ONLINE);
				gbox_send_hello(cli, GBOX_STAT_HELLOS);
			}

			cli->reader->tcp_connected = CARD_INSERTED;

			if(!peer->filtered_cards)
			{
				cli->reader->card_status = NO_CARD;
			}
			else
			{
				cli->reader->card_status = CARD_INSERTED;
			}
		}
			peer->crd_crc_change = 0;
			peer->next_hello = 0;
			cli->last = time((time_t *)0);
	}
	else
	{
		peer->next_hello++;
	}

	return 0;
}

uint8_t get_peer_onl_status(uint16_t peer_id)
{
	cs_readlock(__func__, &clientlist_lock);
	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p')
		{
			struct gbox_peer *peer = cl->gbox;
			if((peer->gbox.id == peer_id) && peer->online)
			{
				cs_readunlock(__func__, &clientlist_lock);
				return 1;
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return 0;
}

static int8_t is_blocked_peer(uint16_t peer_id)
{
	int i;
	if (cfg.gbox_block_ecm_num > 0)
	{
		for (i = 0; i < cfg.gbox_block_ecm_num; i++)
		{
			if (cfg.gbox_block_ecm[i] == peer_id)
			{
				return 1;
			}
		}
	}
	return 0;
}

int8_t check_peer_ignored(uint16_t peer_id)
{
	int i;
	if (cfg.gbox_ignored_peer_num > 0)
	{
		for (i = 0; i < cfg.gbox_ignored_peer_num; i++)
		{
			if (cfg.gbox_ignored_peer[i] == peer_id)
			{
				return 1;
			}
		}
	}
	return 0;
}

static int8_t validate_peerpass(uint32_t rcvd_peer_pw)
{
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);

	for(cli = first_client; cli; cli = cli->next)
	{
		if(cli->gbox && cli->typ == 'p')
		{
			struct s_reader *rdr = cli->reader;

			if (rcvd_peer_pw == a2i(rdr->r_pwd, 4))
			{
				cs_readunlock(__func__, &clientlist_lock);
				return 1;
			} // valid peerpass
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return 0;
}

static int8_t gbox_incoming_ecm(struct s_client *cli, uint8_t *data, int32_t n)
{
	if(!cli || !cli->gbox || !data || !cli->reader) { return -1; }

	struct gbox_peer *peer;
	struct s_client *cl;
	uint8_t diffcheck = 0;

	peer = cli->gbox;
	if (!peer || !peer->my_user)
	{
		return -1;
	}
	cl = peer->my_user;

	if(n < 21)
	{
		return -1;
	}

	// No ECMs with length < MIN_LENGTH expected
	if ((((data[19] & 0x0f) << 8) | data[20]) < MIN_ECM_LENGTH)
	{
		return -1;
	}

	// GBOX_MAX_HOPS not violated
	if (data[n - 15] + 1 > GBOX_MAXHOPS)
	{
		cs_log("-> incoming ECM distance: %d > max ECM distance: %d", data[n - 15] + 1, GBOX_MAXHOPS);
		return -1;
	}

	// ECM must not take more hops than allowed by gbox_reshare
	if (data[n - 15] + 1 > cli->reader->gbox_reshare)
	{
		cs_log("-> incoming ECM dist: %d more than allowed from specified gbox_reshare: %d", data[n - 15] + 1, cli->reader->gbox_reshare);
		return -1;
	}

	// Check for blocked peers
	uint16_t requesting_peer = data[(((data[19] & 0x0f) << 8) | data[20]) + 21] << 8 |
								data[(((data[19] & 0x0f) << 8) | data[20]) + 22];

	if (is_blocked_peer(requesting_peer))
	{
		handle_attack(cli, GBOX_ATTACK_ECM_BLOCKED, requesting_peer);
		cs_log("ECM from peer %04X blocked by config", requesting_peer);
		return -1;
	}

	ECM_REQUEST *er;
	if(!(er = get_ecmtask()))
	{
		return -1;
	}

	struct gbox_ecm_request_ext *ere;
	if(!cs_malloc(&ere, sizeof(struct gbox_ecm_request_ext)))
	{
		NULLFREE(er);
		return -1;
	}

	uint8_t *ecm = data + 18; // offset of ECM in gbx message

	er->src_data = ere;
	gbox_init_ecm_request_ext(ere);

	if(peer->ecm_idx == 100)
	{
		peer->ecm_idx = 0;
	}

	er->idx = peer->ecm_idx++;
	er->ecmlen = SCT_LEN(ecm);

	if(er->ecmlen < 3 || er->ecmlen > MAX_ECM_SIZE || er->ecmlen + 18 > n)
	{
		NULLFREE(ere);
		NULLFREE(er);
		return -1;
	}

	er->pid = b2i(2, data + 10);
	er->srvid = b2i(2, data + 12);

	if(ecm[er->ecmlen + 5] == 0x05)
	{
		er->caid = (ecm[er->ecmlen + 5] << 8);
	}
	else
	{
		er->caid = b2i(2, ecm + er->ecmlen + 5);
	}

	memcpy(er->ecm, data + 18, er->ecmlen);

	er->gbox_ecm_src_peer = b2i(2, ecm + er->ecmlen); //boxid which ORIGINALLY broadcasted the ECM
	ere->gbox_version = ecm[er->ecmlen + 2];
	ere->gbox_rev = ecm[er->ecmlen + 3];
	ere->gbox_type = ecm[er->ecmlen + 4];
	uint32_t caprovid = b2i(4, ecm + er->ecmlen + 5);
	er->gbox_cw_src_peer = b2i(2, ecm + er->ecmlen + 10); //boxid to send ECM to (cw source peer)
	ere->gbox_slot = ecm[er->ecmlen + 12];
	diffcheck = gbox_checkcode_recvd(cl, data + n - 14, 0);
	er->gbox_crc = gbox_get_checksum(&er->ecm[0], er->ecmlen);
	er->gbox_ecm_dist = data[n - 15] + 1;

	memcpy(&ere->gbox_routing_info[0], &data[n - 15 - er->gbox_ecm_dist + 1], er->gbox_ecm_dist - 1);

	er->caid = gbox_get_caid(caprovid);
	er->prid = gbox_get_provid(caprovid);

	peer->gbox_rev = ecm[er->ecmlen + 3];

	cs_log_dbg(D_READER,"-> ECM (->%d) - ecm-requesting-peer: %04X - cw_src_peer: %04X caid: %04X sid: %04X from_peer: %04X rev: %01X.%01X (%s:%d)",
			er->gbox_ecm_dist, er->gbox_ecm_src_peer, er->gbox_cw_src_peer, er->caid, er->srvid, peer->gbox.id, peer->gbox_rev >> 4,
			peer->gbox_rev & 0xf, peer->hostname, cli->port);

	get_cw(cl, er);

	// checkcode did not match gbox->peer checkcode
	if(diffcheck)
	{
		cs_log_dbg(D_READER,"checkcode in ECM CHANGED - Peer %04X ", peer->gbox.id);
		gbox_send_hello(cli, GBOX_STAT_HELLOS); //peer will send back HelloR with cards, new checkcode etc
	}
	return 0;
}

static uint32_t gbox_get_pending_time(ECM_REQUEST *er, uint16_t peer_id, uint8_t slot)
{
	if(!er)
	{
		return 0;
	}

	uint32_t ret_time = 0;
	struct gbox_card_pending *pending = NULL;
	LL_LOCKITER *li = ll_li_create(er->gbox_cards_pending, 0);

	while((pending = ll_li_next(li)))
	{
		if ((pending->id.peer == peer_id) && (pending->id.slot == slot))
		{
			ret_time = pending->pending_time;
			er->gbox_cw_src_peer = peer_id;
			break;
		}
	}
	ll_li_destroy(li);
	return ret_time;
}

static int32_t gbox_chk_recvd_dcw(struct s_client *cli, uint8_t *dcw, int32_t *rc, uint8_t *data, int32_t n)
{
	if(!cli || gbox_decode_cmd(data) != MSG_CW || n < 44)
	{
		return -1;
	}

	int i;
	uint16_t id_card = 0;
	struct s_client *proxy;

	if(cli->typ != 'p')
	{
		proxy = get_gbox_proxy(cli->gbox_peer_id);
	}
	else
	{
		proxy = cli;
	}

	if (!proxy || !proxy->reader)
	{
		cs_log("error, gbox_chk_recvd_dcw, proxy not found");
		gbox_send_goodbye(cli);
		return -1;
	}

	proxy->last = time((time_t *)0);
	*rc = 1;
	memcpy(dcw, data + 14, 16);
	uint32_t crc = b2i(4, data + 30);
	char tmp[33];
	cs_log_dbg(D_READER,"-> CW (->%d) received cw: %s from CW-source-peer=%04X, caid=%04X, slot= %d, ecm_pid=%04X, sid=%04X, crc=%08X, cw-src-type=%d, cw-dist=%d, hw-type=%d, rev=%01X.%01X, chid=%04X", data[42] & 0x0f,
			cs_hexdump(0, dcw, 16, tmp, sizeof(tmp)), data[10] << 8 | data[11], data[34] << 8 | data[35], data[36], data[6] << 8 | data[7],
			data[8] << 8 | data[9], crc, data[41], data[42] & 0x0f, data[42] >> 4, data[43] >> 4,
			data[43] & 0x0f, data[37] << 8 | data[38]);

	struct timeb t_now;
	cs_ftime(&t_now);
	int64_t cw_time = GBOX_DEFAULT_CW_TIME;

	for(i = 0; i < cfg.max_pending; i++)
	{
		if(proxy->ecmtask[i].gbox_crc == crc)
		{
			id_card = b2i(2, data + 10);
			cw_time = comp_timeb(&t_now, &proxy->ecmtask[i].tps) - gbox_get_pending_time(&proxy->ecmtask[i], id_card, data[36]);
			gbox_add_good_sid(id_card, proxy->ecmtask[i].caid, data[36], proxy->ecmtask[i].srvid, cw_time);
			gbox_remove_all_bad_sids(&proxy->ecmtask[i], proxy->ecmtask[i].srvid);

			if(proxy->ecmtask[i].gbox_ecm_status == GBOX_ECM_NEW_REQ || proxy->ecmtask[i].gbox_ecm_status == GBOX_ECM_ANSWERED)
			{
				return -1;
			}

			proxy->ecmtask[i].gbox_ecm_status = GBOX_ECM_ANSWERED;
			proxy->ecmtask[i].gbox_cw_src_peer = id_card;
			proxy->reader->currenthops = gbox_get_crd_dist_lev(id_card) & 0xf;
			proxy->reader->gbox_cw_src_peer = id_card;
			proxy->reader->gbox_crd_slot_lev = (data[36] << 4) | ((gbox_get_crd_dist_lev(id_card) >> 4) & 0xf);
			*rc = 1;
			return proxy->ecmtask[i].idx;
		}
	}

	// late answers from other peers,timing not possible
	gbox_add_good_sid(id_card, data[34] << 8 | data[35], data[36], data[8] << 8 | data[9], GBOX_DEFAULT_CW_TIME);
	cs_log_dbg(D_READER, "no task found for crc=%08x", crc);

	return -1;
}

static int8_t gbox_received_dcw(struct s_client *cli, uint8_t *data, int32_t n)
{
	int32_t rc = 0, i = 0, idx = 0;
	uint8_t dcw[16];

	idx = gbox_chk_recvd_dcw(cli, dcw, &rc, data, n);

	if(idx < 0) // no dcw received
	{
		return -1;
	}

	if(!idx)
	{
		idx = cli->last_idx;
	}

	cli->reader->last_g = time((time_t *)0); // for reconnect timeout

	for(i = 0; i < cfg.max_pending; i++)
	{
		if(cli->ecmtask[i].idx == idx)
		{
			cli->pending--;
			casc_check_dcw(cli->reader, i, rc, dcw);
			return 0;
		}
	}
	return -1;
}

static void gbox_send_peer_crd_update(void)
{
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);

	for (cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p' && !check_peer_ignored(cl->gbox_peer_id))
		{
			struct gbox_peer *peer = cl->gbox;
			if(peer->online)
			{
				gbox_send_hello(cl, GBOX_STAT_HELLOS);
				cl->last = time((time_t *)0);
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return;
}

int32_t gbox_recv_cmd_switch(struct s_client *proxy, uint8_t *data, int32_t n)
{
	if (!data || !proxy)
	{
		return -1;
	}

	uint16_t cmd = gbox_decode_cmd(data);
	uint8_t diffcheck = 0;
	//struct gbox_peer *peer = proxy->gbox;

	switch(cmd)
	{
		case MSG_HERE:
			cs_log_dbg(D_READER,"-> HERE? from %s %s - check reader port: %d might be wrong", username(proxy), proxy->reader->device, proxy->reader->r_port);
			// todo: what to reply??
			break;

		case MSG_GOODBYE:
			cs_log("-> goodbye message from %s %s",username(proxy), proxy->reader->device);
			//msg goodbye is an indication from peer that requested ECM failed (not found/rejected...)
			//TODO: implement on suitable place - rebroadcast ECM to other peers
			write_msg_info(proxy, MSGID_GOODBYE, 0, 0);
			break;

		case MSG_GSMS:
			if(!cfg.gsms_dis)
			{
				cs_log("-> MSG_GSMS from %s %s", username(proxy), proxy->reader->device);
				gbox_send_gsms_ack(proxy);
				write_gsms_msg(proxy, data +16, data[14], data[15]);
				write_msg_info(proxy, MSGID_GSMS, 0, data[14]);
			}
			else
			{
				gsms_unavail();
			}
			break;

		case MSG_GSMS_ACK:
			if(!cfg.gsms_dis)
			{
				cs_log("-> MSG_GSMS_ACK from %s %s", username(proxy), proxy->reader->device);
				write_gsms_ack(proxy);
			}
			else
			{
				gsms_unavail();
			}
			break;

		case MSG_HELLO1:
		case MSG_HELLO:
			if(gbox_cmd_hello_rcvd(proxy, data, n) < 0)
			{
				return -1;
			}
			break;

		case MSG_CW:
			gbox_received_dcw(proxy, data, n);
			break;

		case MSG_CHECKCODE:
			diffcheck = gbox_checkcode_recvd(proxy, data + 10, 0);

			if (cfg.log_hello)
			{
				cs_log("-> HelloC checkcode from %s - %s %s", username(proxy), proxy->reader->device, diffcheck ? "- crc diff":"");
			}
			else
			{
				cs_log_dbg(D_READER,"-> HelloC checkcode from %s - %s %s", username(proxy), proxy->reader->device, diffcheck ? "- crc diff":"");
			}

			if(diffcheck)
				{
					gbox_write_share_cards_info(); //need that for gbox.net peer @ local crd change
					cs_log_dbg(D_READER,"peer %s - %s checkcode changed", username(proxy), proxy->reader->device);
				}
			break;

		case MSG_ECM:
			gbox_incoming_ecm(proxy, data, n);
			break;

		case MSG_REM_EMM:
			//cs_log_dbg(D_EMM,"-> Incoming REMM MSG (%d bytes) from %s - %s", n, username(proxy), proxy->reader->device);
			cs_log_dump_dbg(D_EMM, data, n, "-> gbox incoming REMM MSG - (len=%d bytes):", n);
			gbox_recvd_remm_cmd_switch(proxy, data, n);
			break;

		default:
			cs_log("-> unknown command %04X received from %s %s",
					cmd, username(proxy), proxy->reader->device);

			write_msg_info(proxy, MSGID_UNKNOWNMSG, 0, 0);

			cs_log_dump_dbg(D_READER, data, n, "unknown data (%d bytes) received from %s %s",
							n, username(proxy), proxy->reader->device);
	} // end switch
	return 0;
}

uint8_t add_betatunnel_card(uint16_t caid, uint8_t slot)
{
	int32_t i;
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);

	for(cli = first_client; cli; cli = cli->next)
	{
		TUNTAB *ttab;
		ttab = &cli->ttab;

		for(i = 0; i < ttab->ttnum; i++)
		{
			// Check for Betatunnel on gbox account in oscam.user
			if(cli->gbox && ttab->ttdata && caid == ttab->ttdata[i].bt_caidto)
			{
				gbox_add_card(local_gbox.id, gbox_get_caprovid(ttab->ttdata[i].bt_caidfrom, i), slot, DEFAULT_GBOX_RESHARE, 0, GBOX_CARD_TYPE_BETUN, NULL);
				cs_log_dbg(D_READER, "gbox created betatunnel card for caid: %04X->%04X",	ttab->ttdata[i].bt_caidfrom, caid);
				cs_readunlock(__func__, &clientlist_lock);
				return 1;
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return 0;
}

static uint32_t gbox_add_local_cards(void)
{
	int32_t i;
	uint32_t prid = 0;
	uint8_t slot = 0;
	uint16_t crdnb = 0;
	uint16_t cccrdnb = 0;
#ifdef MODULE_CCCAM
	LL_ITER it, it2;
	struct cc_card *card = NULL;
	struct cc_data *cc;
	uint32_t checksum = 0;
	uint16_t cc_peer_id = 0;
	struct cc_provider *provider;
	uint8_t *node1 = NULL;
	uint8_t offset = 0;

	gbox_delete_cards(GBOX_DELETE_WITH_TYPE, GBOX_CARD_TYPE_CCCAM);
#endif
	gbox_delete_cards(GBOX_DELETE_WITH_ID, local_gbox.id);
	struct s_client *cl;

	cs_readlock(__func__, &clientlist_lock);
	for(cl = first_client; cl; cl = cl->next)
	{
		if(cl->typ == 'r' && cl->reader && cl->reader->card_status == CARD_INSERTED && cl->reader->enable)
		{
			slot = gbox_next_free_slot(local_gbox.id);

			// SECA, Viaccess and Cryptoworks have multiple providers
			if(caid_is_seca(cl->reader->caid) || caid_is_cryptoworks(cl->reader->caid))
			{
				for(i = 0; i < cl->reader->nprov; i++)
				{
					prid = cl->reader->prid[i][1] << 16 | cl->reader->prid[i][2] << 8 | cl->reader->prid[i][3];
					gbox_add_card(local_gbox.id, gbox_get_caprovid(cl->reader->caid, prid), slot, DEFAULT_GBOX_RESHARE, 0, GBOX_CARD_TYPE_LOCAL, NULL);
				}
			}
			else if(caid_is_viaccess(cl->reader->caid))
			{
				for(i = 1; i < cl->reader->nprov; i++)  //skip via issuer
				{
					prid = cl->reader->prid[i][1] << 16 | cl->reader->prid[i][2] << 8 | cl->reader->prid[i][3];
					gbox_add_card(local_gbox.id, gbox_get_caprovid(cl->reader->caid, prid), slot, DEFAULT_GBOX_RESHARE, 0, GBOX_CARD_TYPE_LOCAL, NULL);
				}
			}
			else
			{
				gbox_add_card(local_gbox.id, gbox_get_caprovid(cl->reader->caid, 0), slot, DEFAULT_GBOX_RESHARE, 0, GBOX_CARD_TYPE_LOCAL, NULL);
				if(chk_is_betatunnel_caid(cl->reader->caid) == 1) // 1702 1722
					{
						if(add_betatunnel_card(cl->reader->caid, gbox_next_free_slot(local_gbox.id)))
							{ crdnb++; }
					}
			}
			crdnb++;
		} // end local readers
#ifdef MODULE_CCCAM
		if(cfg.cc_gbx_reshare_en &&	cfg.cc_reshare > -1 && cl->typ == 'p' && cl->reader && cl->reader->typ == R_CCCAM && cl->cc)
		{
			cc = cl->cc;
			it = ll_iter_create(cc->cards);

			while((card = ll_iter_next(&it)))
			{
				// calculate gbox id from cc node
				node1 = ll_has_elements(card->remote_nodes);
				checksum = ((node1[0] ^ node1[7]) << 8) | ((node1[1] ^ node1[6]) << 24) | (node1[2] ^ node1[5]) | ((node1[3] ^ node1[4]) << 16);
				cc_peer_id = ((((checksum >> 24) & 0xFF) ^ ((checksum >> 8) & 0xFF)) << 8 | (((checksum >> 16) & 0xFF) ^ (checksum & 0xFF))) + offset;

				slot = gbox_next_free_slot(cc_peer_id);

				if(caid_is_seca(card->caid) || caid_is_viaccess(card->caid) || caid_is_cryptoworks(card->caid))
				{
					it2 = ll_iter_create(card->providers);
					while((provider = ll_iter_next(&it2)))
					{
						gbox_add_card(cc_peer_id, gbox_get_caprovid(card->caid, provider->prov), slot, DEFAULT_CCC_GBOX_RESHARE, card->hop, GBOX_CARD_TYPE_CCCAM, NULL);
					}
				}
				else
				{
					gbox_add_card(cc_peer_id, gbox_get_caprovid(card->caid, 0), slot, DEFAULT_CCC_GBOX_RESHARE, card->hop, GBOX_CARD_TYPE_CCCAM, NULL);
				}
				cccrdnb++;
				crdnb++;

				if(slot % 18 == 0)
					{
						//offset++;
						offset += (rand() % 18) +1;
						//cs_log("cccrdnum: %d, slot: %d, offset: %d, caid: %04X, peer: %04X", cccrdnb, slot, offset, card->caid, cc_peer_id);
					}
			}
		} // end cccam
#endif
	} // end for clients

	cs_readunlock(__func__, &clientlist_lock);

	if (cfg.gbox_proxy_cards_num > 0)
	{
		for (i = 0; i < cfg.gbox_proxy_cards_num; i++)
		{
			slot = gbox_next_free_slot(local_gbox.id);
			gbox_add_card(local_gbox.id, cfg.gbox_proxy_card[i], slot, DEFAULT_GBOX_RESHARE, 0, GBOX_CARD_TYPE_PROXY, NULL);
			cs_log_dbg(D_READER,"add proxy card: slot %d %04X:%06X", slot, gbox_get_caid(cfg.gbox_proxy_card[i]), gbox_get_provid(cfg.gbox_proxy_card[i]));
			crdnb++;
		}
	} //end add proxy reader cards

	gbox_update_my_checkcode();
	gbox_write_local_cards_info();
	if (!local_cards_initialized)
		{
			local_cards_initialized = 1;
			if(cfg.cc_gbx_reshare_en)
			{ cs_log("Local gbox cards initialized - cards: %d - filtered cccards: %d", crdnb - cccrdnb, cccrdnb); }
			else
			{ cs_log("Local gbox cards initialized - cards: %d", crdnb); }
		}
	return (cccrdnb << 16) | (crdnb - cccrdnb);
} //end add local gbox cards

void gbx_local_card_stat(uint8_t crdstat, uint16_t caid)
{
	if(crdstat && local_cards_initialized)
	{
		if(crdstat == LOCALCARDEJECTED)
		{
			cs_sleepms(100);
		}
		else if(crdstat == LOCALCARDUP)
		{
			cs_sleepms(2000);
			cs_log("New local card ready - caid = %04X", caid);
		}
		else if(crdstat == LOCALCARDDISABLED)
		{
			cs_log_dbg(D_READER,"Local Gbox Card disabled by WebIF");
		}
		else
		{
			return;
		}

		cs_log("Card update send to peer(s) online - Local/Proxy crd(s):%d", gbox_add_local_cards() & 0xffff);
		//gbox_write_local_cards_info(); //done by gbox_add_local_cards()
		gbox_send_peer_crd_update();
	}
	return;
}

uint8_t chk_gbx_hdr_rcvd(uint16_t rcvd_header_cmd)
{
	switch(rcvd_header_cmd)
	{
		case MSG_HERE:
		case MSG_HELLO1:
		case MSG_HELLO:
		case MSG_GOODBYE:
		case MSG_GSMS:
		case MSG_GSMS_ACK:
		case MSG_CW:
		case MSG_CHECKCODE:
		case MSG_ECM:
		case MSG_REM_EMM:
			return 1;

		default:
			return 0;
	}
}

// returns -1 in case of error, 1 if authentication was performed, 0 else
static int8_t gbox_check_header_recvd(struct s_client *cli, struct s_client *proxy, uint8_t *data, int32_t l)
{
	struct gbox_peer *peer = NULL;
	if (proxy) { peer = proxy->gbox; }

	char tmp[128];
	int32_t n = l;
	uint8_t authentication_done = 0;
	uint16_t peer_recvd_id = 0;
	uint32_t my_received_pw = 0;
	uint32_t peer_received_pw = 0;
	uint16_t rcvd_header_cmd;

	cs_log_dump_dbg(D_READER, data, n, "-> crypted data (%d bytes) from %s:", n, cs_inet_ntoa(cli->ip));
	gbox_decrypt(data, n, local_gbox.password);
	cs_log_dump_dbg(D_READER, data, n, "-> decrypted data (%d bytes) from %s:", n, cs_inet_ntoa(cli->ip));

	peer_received_pw = b2i(4, data + 6);
	my_received_pw = b2i(4, data + 2);
	rcvd_header_cmd = b2i(2, data);

	if(!chk_gbx_hdr_rcvd(rcvd_header_cmd))
		{
		 cs_log("-> ATTACK ALERT from IP %s - Received unknown Header: %02X", cs_inet_ntoa(cli->ip), b2i(2, data));
		//cs_log_dbg(D_READER,"-> received data: %s", cs_hexdump(1, data, n, tmp, sizeof(tmp)));
		cs_log("-> received data: %s", cs_hexdump(1, data, n, tmp, sizeof(tmp)));
		handle_attack(cli, GBOX_ATTACK_UNKWN_HDR, 0);
		return -1;
		}

	if (my_received_pw == local_gbox.password)
	{
		if (gbox_decode_cmd(data) != MSG_CW)
		{
			//peer_received_pw = b2i(4, data + 6);
			peer_recvd_id = gbox_convert_password_to_id(peer_received_pw);

			//cs_log_dbg(D_READER, "-> data from IP: %s", cs_inet_ntoa(cli->ip));
			cs_log_dbg(D_READER, "-> data from peer: %04X data: %s", peer_recvd_id, cs_hexdump(0, data, l, tmp, sizeof(tmp)));
			//cs_log_dbg(D_READER,"my_received pw: %08X - peer_recvd pw: %08X - peer_recvd_id: %04X ", my_received_pw, peer_received_pw, peer_recvd_id);

			if (check_peer_ignored(peer_recvd_id))
			{
				handle_attack(cli, GBOX_ATTACK_PEER_IGNORE, peer_recvd_id);
				cs_log("Peer blocked by conf - ignoring gbox peer_id: %04X",  peer_recvd_id);
				return -1;
			}

			if (!validate_peerpass(peer_received_pw))
			{
				handle_attack(cli, GBOX_ATTACK_PEER_PW, peer_recvd_id);
				cs_log("peer: %04X - peerpass: %08X unknown -> enable reader and check oscam.server->[reader]->password",
					peer_recvd_id, peer_received_pw);

				return -1;
			}

			if (cli->gbox_peer_id == NO_GBOX_ID && gbox_decode_cmd(data) != MSG_HERE)
			//if (cli->gbox_peer_id == NO_GBOX_ID)
			{
				if (gbox_auth_client(cli, peer_received_pw) < 0)
				{
					handle_attack(cli, GBOX_ATTACK_AUTH_FAIL, peer_recvd_id);
					cs_log ("Peer %04X:%s authentication failed. Check user in [account] or {reader] section", peer_recvd_id, cs_inet_ntoa(cli->ip));
					return -1;
				}

				authentication_done = 1;
				proxy = get_gbox_proxy(cli->gbox_peer_id);
				peer = proxy->gbox;
			}

			if (!peer)
			{
				return -1;
			}

			if (peer_received_pw != peer->gbox.password)
			{
				cs_log("gbox peer: %04X sends wrong own password", peer->gbox.id);
				return -1;
			}
		}
		else // is MSG_CW
		{
			cs_log_dbg(D_READER, "-> CW MSG from peer: %04X data: %s",
				cli->gbox_peer_id, cs_hexdump(0, data, l, tmp, sizeof(tmp)));

			if((data[39] != ((local_gbox.id >> 8) & 0xff)) || (data[40] != (local_gbox.id & 0xff)))
			{
				cs_log_dbg(D_READER,"peer: %04X sends CW not to my id: %04X -> forwarding CW to requesting peer %02X%02X ", cli->gbox_peer_id, local_gbox.id, data[39], data[40]);
			}
		}
	}
	else // error my passw
	{
		cs_log("-> ATTACK ALERT from IP %s - received corrupted data - local password: %08X - peer password: %08X", cs_inet_ntoa(cli->ip), my_received_pw, peer_received_pw);
		//cs_log_dbg(D_READER,"-> received data: %s", cs_hexdump(1, data, n, tmp, sizeof(tmp)));
		cs_log("-> received data: %s", cs_hexdump(1, data, n, tmp, sizeof(tmp)));
		handle_attack(cli, GBOX_ATTACK_LOCAL_PW, 0);
		return -1;
	}

	if(!proxy)
	{
		return -1;
	}

	if(!IP_EQUAL(cli->ip, proxy->ip))
	{
		cs_log("IP change received - peer %04X. New IP = %s. Reconnecting...", cli->gbox_peer_id, cs_inet_ntoa(cli->ip));
		restart_gbox_peer(NULL, 0, cli->gbox_peer_id);
		//gbox_reconnect_peer(proxy);
		write_msg_info(cli, MSGID_IPCHANGE, 0, 0);
		return -1;
	}

	if(!peer)
	{
		return -1;
	}

	if(!peer->authstat)
	{
		peer->authstat = 1;
		cli->last = time((time_t *)0);
		cs_log("peer %04X authenticated successfully", cli->gbox_peer_id);
	}
	return authentication_done;
}

static int32_t gbox_recv(struct s_client *cli, uint8_t *buf, int32_t l)
{
	uint8_t data[RECEIVE_BUFFER_SIZE];
	int32_t n = l, chkcmd;
	int8_t ret = 0;

	if(!cli->udp_fd || !cli->is_udp || cli->typ != 'c')
	{
		return -1;
	}

	n = recv_from_udpipe(buf);
	if (n < MIN_GBOX_MESSAGE_LENGTH || n >= RECEIVE_BUFFER_SIZE) // protect against too short or too long messages
	{
		return -1;
	}

	struct s_client *proxy = get_gbox_proxy(cli->gbox_peer_id);

	memcpy(&data[0], buf, n);

	ret = gbox_check_header_recvd(cli, proxy, &data[0], n);
	if (ret < 0)
	{
		return -1;
	}

	// in case of new authentication the proxy gbox can now be found
	if (ret)
	{
		proxy = get_gbox_proxy(cli->gbox_peer_id);
	}

	if (!proxy)
	{
		return -1;
	}

	cli->last = time((time_t *)0);
	cli->gbox = proxy->gbox; // point to the same gbox as proxy
	cli->reader = proxy->reader; // point to the same reader as proxy
	struct gbox_peer *peer = proxy->gbox;
	cs_writelock(__func__, &peer->lock);
	chkcmd = gbox_recv_cmd_switch(proxy, data, n);
	cs_writeunlock(__func__, &peer->lock);

	if(chkcmd < 0)
	{
		return -1;
	}

	return 0;
}

static uint8_t check_setup( void)
{
#ifdef HAVE_DVBAPI
	if (module_dvbapi_enabled())
		{ return 0x30; } //stb
	else
		{ return 0x50; }
#else
	return 0x50; //server
#endif
}

static void gbox_send_dcw(struct s_client *cl, ECM_REQUEST *er)
{
	if (!cl || !er)
	{
		return;
	}

	struct s_client *cli = get_gbox_proxy(cl->gbox_peer_id);
	if (!cli || !cli->gbox)
	{
		return;
	}
	struct gbox_peer *peer = cli->gbox;

	struct gbox_ecm_request_ext *ere = er->src_data;

	if(er->rc == E_NOTFOUND && cli->reader->gbox_force_remm && ere->gbox_rev >> 4)
	{
		gbox_send_remm_req(cli, er);
		return;
	}

	if(er->rc >= E_NOTFOUND)
	{
		cs_log_dbg(D_READER, "unable to decode!");
		gbox_send_goodbye(cli);
		return;
	}

	uint8_t buf[60];
	memset(buf, 0, sizeof(buf));

	gbox_message_header(buf, MSG_CW , peer->gbox.password, 0);
	i2b_buf(2, er->pid, buf + 6); // PID
	i2b_buf(2, er->srvid, buf + 8); // SrvID
	i2b_buf(2, er->gbox_cw_src_peer, buf + 10); // From peer - source of cw
	buf[12] = (ere->gbox_slot << 4) | (er->ecm[0] & 0x0f); // slot << 4 | even/odd
	buf[13] = er->caid >> 8; // CAID first byte
	memcpy(buf + 14, er->cw, 16); // CW
	i2b_buf(4, er->gbox_crc, buf + 30); // CRC
	i2b_buf(2, er->caid, buf + 34); // CAID
	buf[36] = ere->gbox_slot; // Slot

	if (buf[34] == 0x06) // if irdeto
	{
		i2b_buf(2, er->chid, buf + 37); // CHID
	}
	else
	{
		if (local_gbox.minor_version == 0x2A)
		{
			buf[37] = 0xff; // gbox.net sends 0xff
			buf[38] = 0xff; // gbox.net sends 0xff
		}
		else
		{
			buf[37] = 0; // gbox sends 0
			buf[38] = 0; // gbox sends 0
		}
	}

	i2b_buf(2, er->gbox_ecm_src_peer, buf + 39); // Target peer to recv cw

	if(er->rc == E_CACHE1 || er->rc == E_CACHE2 || er->rc == E_CACHEEX)
		{ buf[41] = 0x03; } // source of cw -> cache
	else
		{ buf[41] = 0x01; } // source of cw -> card, emu

	uint8_t cw_dist = gbox_get_crd_dist_lev(er->gbox_cw_src_peer) & 0xf;

	buf[42] = ((check_setup()) | (cw_dist + 1));
	buf[43] = ere->gbox_rev & 0xf0;

	// This copies the routing info from ECM to cw answer.
	memcpy(&buf[44], &ere->gbox_routing_info, er->gbox_ecm_dist - 1);
	buf[44 + er->gbox_ecm_dist - 1] = er->gbox_ecm_dist - 1;	//act. dist
/*
  uint8_t i;
		for(i = 0; i < er->gbox_ecm_dist; i++)
		{
			buf[44 +i] = i;
		}
*/
	gbox_send(cli, buf, 44 + er->gbox_ecm_dist);

	/*
	char tmp[0x50];
	cs_log("sending dcw to peer : %04x data: %s", er->gbox_ecm_src_peer, cs_hexdump(0, buf, er->gbox_ecm_dist + 44, tmp, sizeof(tmp)));
	*/

	if(ere->gbox_rev >> 4)
		{ gbox_send_remm_req(cli, er); }

	cs_log_dbg(D_READER,"<- CW (<-%d) caid; %04X from cw-source-peer: %04X forward to ecm-requesting-peer: %04X - forwarding peer: %04X %s rev:%01X.%01X port:%d",
			er->gbox_ecm_dist, er->caid, er->gbox_cw_src_peer, er->gbox_ecm_src_peer, peer->gbox.id, cli->reader->label,
			ere->gbox_rev >> 4,	ere->gbox_rev & 0xf, cli->port);
}

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er)
{
	if(!cli || !cli->reader || !er || !er->ecmlen)
	{
		return -1;
	}

	if(!cli->gbox || !cli->reader->tcp_connected)
	{
		cs_log_dbg(D_READER, "%s server not init!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL, 0, NULL);
		return -1;
	}

	struct gbox_peer *peer = cli->gbox;

	if(!peer->filtered_cards)
	{
		cs_log_dbg(D_READER, "Send ECM failed, %s NO CARDS!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, E2_CCCAM_NOCARD, NULL, NULL, 0, NULL);
		return -1;
	}

	if(!peer->online)
	{
		cs_log_dbg(D_READER, "Send ECM failed, peer is OFFLINE!");
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL, 0, NULL);
		return -1;
	}

	if(er->gbox_ecm_status == GBOX_ECM_ANSWERED)
	{
		cs_log_dbg(D_READER, "%s replied to this ecm already", cli->reader->label);
	}

	if(er->gbox_ecm_status == GBOX_ECM_NEW_REQ)
	{
		er->gbox_cards_pending = ll_create("pending_gbox_cards");
	}

	uint8_t send_buf[1024];
	int32_t buflen, len1;

	len1 = er->ecmlen + 18; // length till end of ECM

	er->gbox_crc = gbox_get_checksum(&er->ecm[0], er->ecmlen);

	memset(send_buf, 0, sizeof(send_buf));

	uint8_t nb_matching_crds = 0;
	uint32_t current_avg_card_time = 0;

	gbox_message_header(send_buf, MSG_ECM , peer->gbox.password, local_gbox.password);
	i2b_buf(2, er->pid, send_buf + 10);
	i2b_buf(2, er->srvid, send_buf + 12);
	send_buf[14] = 0x00;
	send_buf[15] = 0x00;
	send_buf[17] = 0x00;
	memcpy(send_buf + 18, er->ecm, er->ecmlen);

	if(!er->gbox_ecm_dist)
		{
			er->gbox_ecm_src_peer = local_gbox.id;
			i2b_buf(2, local_gbox.id, send_buf + len1); //local boxid first broadcasted the ECM
			send_buf[len1 + 3] = 0x4;
		}
	else
		{
			i2b_buf(2, er->gbox_ecm_src_peer, send_buf + len1); //forward boxid that originally broadcasted the ECM
			send_buf[len1 + 3] = 0;
		}

	send_buf[len1 + 2] = cfg.gbox_my_vers;

	if(check_valid_remm_peer( peer->gbox.id))
	{
		send_buf[len1 + 3] = local_gbx_rev;
	}

	send_buf[len1 + 4] = gbox_get_my_cpu_api();

	uint32_t caprovid = gbox_get_caprovid(er->caid, er->prid);
	i2b_buf(4, caprovid, send_buf + len1 + 5);

	send_buf[len1 + 9] = 0x00;
	buflen = len1 + 10;

	nb_matching_crds = gbox_get_cards_for_ecm(&send_buf[0], len1 + 10, cli->reader->gbox_maxecmsend, er, &current_avg_card_time, peer->gbox.id, cli->reader->gbox_force_remm);

	buflen += nb_matching_crds * 3;

	if(!nb_matching_crds && er->gbox_ecm_status == GBOX_ECM_NEW_REQ)
	{
		cs_log_dbg(D_READER, "no valid card found for CAID: %04X PROV: %06X", er->caid, er->prid);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, E2_CCCAM_NOCARD, NULL, NULL, 0, NULL);
		return -1;
	}

	if(nb_matching_crds)
	{
		send_buf[16] = nb_matching_crds; // Number of cards the ECM should be forwarded to

		// distance ECM
		uint8_t i;
		for(i = 0; i < er->gbox_ecm_dist + 1; i++)
			{
				send_buf[buflen] = i;
				buflen++;
			}

		memcpy(&send_buf[buflen], gbox_get_my_checkcode(), 7);
		buflen = buflen + 7;
		memcpy(&send_buf[buflen], peer->checkcode, 7);
		buflen = buflen + 7;

		struct gbox_card_pending *pending = NULL;
		struct timeb t_now;
		cs_ftime(&t_now);

		for (i = 0; i < nb_matching_crds; i++)
		{
			if(!cs_malloc(&pending, sizeof(struct gbox_card_pending)))
			{
				cs_log("Can't allocate gbox card pending");
				return -1;
			}
			pending->id.peer = (send_buf[len1+10+i*3] << 8) | send_buf[len1+11+i*3];
			pending->id.slot = send_buf[len1+12+i*3];
			pending->pending_time = comp_timeb(&t_now, &er->tps);

			ll_append(er->gbox_cards_pending, pending);
			cs_log_dbg(D_READER, "matching gbox card(s): %d, ID: %04X, Slot: %02X",
				i + 1, (send_buf[len1 + 10 + i * 3] << 8) | send_buf[len1 + 11 + i * 3], send_buf[len1 + 12 + i * 3]);
		}

		LL_LOCKITER *li = ll_li_create(er->gbox_cards_pending, 0);
		while ((pending = ll_li_next(li)))
		{
			cs_log_dbg(D_READER, "Pending Card ID: %04X Slot: %02X time: %d", pending->id.peer, pending->id.slot, pending->pending_time);
			er->gbox_cw_src_peer = pending->id.peer;
			cs_log_dbg(D_READER,"<- ECM (<-%d) - caid: %04X prov: %06X sid: %04X to cw-src-peer: %04X - ecm_src_peer: %04X",
				gbox_get_crd_dist_lev(er->gbox_cw_src_peer) & 0xf, er->caid, er->prid, er->srvid, er->gbox_cw_src_peer, er->gbox_ecm_src_peer);
		}
		ll_li_destroy(li);

		if(er->gbox_ecm_status == GBOX_ECM_NEW_REQ)
		{
			er->gbox_ecm_status++;
			cli->pending++;
		}

		gbox_send(cli, send_buf, buflen);
		cli->reader->last_s = time((time_t *) 0);
	}
	return 0;
}

// init my gbox with id, password etc
static int8_t init_local_gbox(void)
{
	int32_t i;
	local_gbox.id = 0;
	local_gbox.password = 0;
	local_gbox.minor_version = cfg.gbox_my_vers;
	local_gbox.cpu_api = gbox_get_my_cpu_api();
	init_gbox_cards_list();

	if(!cfg.gbox_port[0])
	{
		cs_log("error, no/invalid port=%d configured in oscam.conf!", cfg.gbox_port[0] ? cfg.gbox_port[0] : 0);
		return -1;
	}

	if(!cfg.gbox_hostname || cs_strlen(cfg.gbox_hostname) > 128)
	{
		cs_log("error, no/invalid hostname '%s' configured in oscam.conf!",
			cfg.gbox_hostname ? cfg.gbox_hostname : "");
		return -1;
	}

	if(!cfg.gbox_password)
	{
		cs_log("error, 'my_password' not configured in oscam.conf!");
		return -1;
	}

	if(!cfg.gbox_reconnect || cfg.gbox_reconnect > GBOX_MAX_RECONNECT || cfg.gbox_reconnect < GBOX_MIN_RECONNECT)
	{
		cs_log("Invalid 'gbox_reconnect = %d' Using default: %d sec", cfg.gbox_reconnect, DEFAULT_GBOX_RECONNECT);
		cfg.gbox_reconnect = DEFAULT_GBOX_RECONNECT;
	}

	local_gbox.password = cfg.gbox_password;
	local_gbox.id = gbox_convert_password_to_id(local_gbox.password);

	if(!local_gbox.id)
	{
		cs_log("invalid 'my_password' %08X -> local gbox id: %04X, choose another 'my_password'",
				cfg.gbox_password, local_gbox.id);
		return -1;
	}

	local_gbox_initialized = 1;

	for(i = 0; i < CS_MAXPORTS; i++)
	{
		if(!cfg.gbox_port[i])
		{
			cs_log("we are online - %d port(s) to monitor", i);
			break;
		}
	}

	gbox_write_version();

	return local_gbox_initialized;
}

static int32_t gbox_peer_init(struct s_client *cli)
{
	if(!cli || cli->typ != 'p' || !cli->reader)
	{
		cs_log("error, wrong call to gbox_peer_init!");
		return -1;
	}

	if (local_gbox_initialized < 0)
	{
		return -1;
	}

	int8_t ret;
	if(!local_gbox_initialized)
	{
		local_gbox_initialized = 1;
		ret = init_local_gbox();
		if (ret < 0)
		{
			local_gbox_initialized = -1;
			cs_log("local gbox initialization failed");
			write_msg_info(cli, MSGID_GBOXONL, 0, 0);
			return -1;
		}
		write_msg_info(cli, MSGID_GBOXONL, 0, 1);
	}

	if(!cs_malloc(&cli->gbox, sizeof(struct gbox_peer)))
	{
		return -1;
	}

	struct s_reader *rdr = cli->reader;
	struct gbox_peer *peer = cli->gbox;

	memset(peer, 0, sizeof(struct gbox_peer));

	peer->gbox.password = a2i(rdr->r_pwd, 4);
	//cs_log_dbg(D_READER,"peer-reader-label: %s peer-reader-password: %s", cli->reader->label, rdr->r_pwd);
	peer->gbox.id = gbox_convert_password_to_id(peer->gbox.password);

	if (get_gbox_proxy(peer->gbox.id) || peer->gbox.id == NO_GBOX_ID || peer->gbox.id == local_gbox.id)
	{
		cs_log("error, double/invalid gbox id: %04X", peer->gbox.id);
		return -1;
	}
	cs_lock_create(__func__, &peer->lock, "gbox_lock", 5000);

	gbox_clear_peer(peer);

	cli->gbox_peer_id = peer->gbox.id;

	cli->pfd = 0;
	cli->crypted = 1;

	rdr->card_status = CARD_NEED_INIT;
	rdr->tcp_connected = 0;

	set_null_ip(&cli->ip);

	if((cli->udp_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		cs_log("socket creation failed (errno=%d %s)", errno, strerror(errno));
		cs_disconnect_client(cli);
	}

	int32_t opt = 1;
	setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	set_so_reuseport(cli->udp_fd);

	set_socket_priority(cli->udp_fd, cfg.netprio);

	memset((char *)&cli->udp_sa, 0, sizeof(cli->udp_sa));

	if(!hostResolve(rdr))
	{
		return 0;
	}

	cli->port = rdr->r_port;
	SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
	SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)rdr->r_port);
	hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));

	cs_log("proxy %s (fd=%d, peer id=%04X, my id=%04X, my hostname=%s, peer's listen port=%d)",
		rdr->device, cli->udp_fd, peer->gbox.id, local_gbox.id, cfg.gbox_hostname, rdr->r_port);

	cli->pfd = cli->udp_fd;

	if(!cli->reader->gbox_maxecmsend)
	{
		cli->reader->gbox_maxecmsend = DEFAULT_GBOX_MAX_ECM_SEND;
	}

	if(!cli->reader->gbox_maxdist)
	{
		cli->reader->gbox_maxdist = DEFAULT_GBOX_MAX_DIST;
	}

	// value > GBOX_MAXHOPS not allowed in gbox network
	if(cli->reader->gbox_reshare > GBOX_MAXHOPS)
	{
		cli->reader->gbox_reshare = GBOX_MAXHOPS;
	}

	if(cli->reader->gbox_cccam_reshare > GBOX_MAXHOPS)
	{
		cli->reader->gbox_cccam_reshare = GBOX_MAXHOPS;
	}

	return 0;
}

static void gbox_send_HERE(struct s_client *cli)
{
	struct gbox_peer *peer = cli->gbox;
	uint8_t outbuf[64];
	int32_t hostname_len = cs_strlen(cli->reader->device);
	gbox_message_header(outbuf, MSG_HERE, peer->gbox.password, local_gbox.password);
	outbuf[0xA] = cfg.gbox_my_vers;
	outbuf[0xB] = gbox_get_my_cpu_api();
	memcpy(&outbuf[0xC], cli->reader->device, hostname_len);
	gbox_send(cli, outbuf, hostname_len + 0xC);
		if(cfg.log_hello)
			{ cs_log("<- send Keep Alive MSG HERE to boxid: %04X - %s", peer->gbox.id, cli->reader->label); }
		else
			{ cs_log_dbg(D_READER,"<- send Keep Alive MSG HERE to boxid: %04X - %s", peer->gbox.id, cli->reader->label); }
	cs_log_dump_dbg(D_READER, outbuf, hostname_len + 0xC, "<- send HERE?, (len=%d):", hostname_len + 0xC);
}

uint8_t k = 0;
void gbox_send_idle_msg(void)
{
	if(k > 8) //10s
	{
		struct s_client *cl;
		cs_readlock(__func__, &clientlist_lock);

		for(cl = first_client; cl; cl = cl->next)
		{
			struct gbox_peer *peer = cl->gbox;
			if(cl->gbox && cl->typ == 'p' && !peer->online && !check_peer_ignored(cl->gbox_peer_id) && cl->reader->send_offline_cmd)
			{
				gbox_send_HERE(cl);
			}
		}
		cs_readunlock(__func__, &clientlist_lock);
		k = 0;
	}
	else { k++; }
}

void gbox_send_init_hello(void)
{
	if(local_gbox_initialized)
	{
		struct s_client *cl;
		gbox_add_local_cards();
		cs_sleepms(1000);
		cs_readlock(__func__, &clientlist_lock);

		for(cl = first_client; cl; cl = cl->next)
		{
			if(cl->gbox && cl->typ == 'p')
			{
				gbox_send_hello(cl, GBOX_STAT_HELLOL);
			}
		}
		cs_readunlock(__func__, &clientlist_lock);
	}
	else
		{ cs_log("local gbox failed init"); }
}

static void gbox_peer_idle (struct s_client *cl)
{
	uint32_t ptime_elapsed, etime_elapsed;
	struct s_client *proxy = get_gbox_proxy(cl->gbox_peer_id);
	struct gbox_peer *peer;
	peer = proxy->gbox;

	if (proxy && proxy->gbox)
	{
		etime_elapsed = llabs(cl->lastecm - time(NULL));

		if (llabs(proxy->last - time(NULL)) > etime_elapsed)
		{
			ptime_elapsed = etime_elapsed;
		}
		else
		{
			ptime_elapsed = llabs(proxy->last - time(NULL));
		}

		if (ptime_elapsed > (cfg.gbox_reconnect *2) && cl->gbox_peer_id != NO_GBOX_ID)
		{
			// gbox peer apparently died without saying goodnight
			cs_writelock(__func__, &peer->lock);

			if (peer->online)
			{
				disable_remm(cl);
				cs_log("Lost connection to: %s %s - taking peer %04X %s offline",
					proxy->reader->device, cs_inet_ntoa(proxy->ip), cl->gbox_peer_id, username(cl));

				cs_log_dbg(D_READER, "time since last proxy activity: %d sec > %d => lost connection - taking peer %04X - %s offline",
					ptime_elapsed, cfg.gbox_reconnect *2, cl->gbox_peer_id, username(cl));

				write_msg_info(proxy, MSGID_LOSTCONNECT, 0, 0);
				gbox_reinit_proxy(proxy);
				gbox_write_share_cards_info();
				gbox_update_my_checkcode();
			}
			cs_writeunlock(__func__, &peer->lock);
		}

		if (etime_elapsed > cfg.gbox_reconnect && cl->gbox_peer_id != NO_GBOX_ID)
		{
			cs_writelock(__func__, &peer->lock);

			if (!(check_peer_ignored(cl->gbox_peer_id)))
			{
				if (!peer->online && ptime_elapsed < cfg.gbox_reconnect *3)
				{
					cs_log_dbg(D_READER, "%04X - %s -> offline - time since last ecm / proxy_act: %d sec / %d sec => trigger HELLOL",
					cl->gbox_peer_id, username(cl), etime_elapsed, ptime_elapsed);
					gbox_send_hello(proxy, GBOX_STAT_HELLOL);
				}

				if (peer->online)
				{
					cs_log_dbg(D_READER, "%04X - %s -> online - time since last ecm /proxy activity: %d sec / %d sec => trigger keepalive HELLOS",
						cl->gbox_peer_id, username(cl), etime_elapsed, ptime_elapsed);

					gbox_send_hello(proxy, GBOX_STAT_HELLOS);
				}
			}
			cs_writeunlock(__func__, &peer->lock);
		}
	}
	cl->last = time((time_t *)0);
}

static int8_t gbox_send_peer_good_night(struct s_client *proxy)
{
	uint8_t outbuf[64];
	int32_t hostname_len = 0;

	if (cfg.gbox_hostname)
	{
		hostname_len = cs_strlen(cfg.gbox_hostname);
	}

	int32_t len = hostname_len + 22;

	if(proxy->gbox && proxy->typ == 'p')
	{
		struct gbox_peer *peer = proxy->gbox;
		struct s_reader *rdr = proxy->reader;

		if (peer->online)
		{
			gbox_message_header(outbuf, MSG_HELLO, peer->gbox.password, local_gbox.password);
			outbuf[10] = 0x01;
			outbuf[11] = 0x80;
			memset(&outbuf[12], 0xff, 7);
			outbuf[19] = cfg.gbox_my_vers;
			outbuf[20] = gbox_get_my_cpu_api();
			memcpy(&outbuf[21], cfg.gbox_hostname, hostname_len);
			outbuf[21 + hostname_len] = hostname_len;
			cs_log("<- good night to %s:%d id: %04X", rdr->device, rdr->r_port, peer->gbox.id);
			gbox_compress(outbuf, len, &len);
			gbox_send(proxy, outbuf, len);
			gbox_reinit_proxy(proxy);
		}
	}
	return 0;
}

void gbox_send_good_night(void)
{
	gbox_free_cardlist();
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);

	for(cli = first_client; cli; cli = cli->next)
	{
		if(cli->gbox && cli->typ == 'p')
		{
			gbox_send_peer_good_night(cli);
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
}

void gbox_send_goodbye(struct s_client *cli) // indication that requested ECM failed
{
	if (local_gbox.minor_version != 0x2A)
	{
		uint8_t outbuf[15];
		struct gbox_peer *peer = cli->gbox;
		gbox_message_header(outbuf, MSG_GOODBYE, peer->gbox.password, local_gbox.password);
		cs_log_dbg(D_READER,"<- goodbye - requested ecm failed. Send info to requesting boxid: %04X", peer->gbox.id);
		gbox_send(cli, outbuf, 10);
	}
	else
	{
		return;
	}
}

static void delayed_crd_update(void)
{
	struct s_client *cli;
	cs_readlock(__func__, &clientlist_lock);

	for (cli = first_client; cli; cli = cli->next)
	{
		if(cli->gbox && cli->typ == 'p' && !check_peer_ignored(cli->gbox_peer_id))
		{
			uint32_t timediff = llabs(cli->last - time(NULL));
			struct gbox_peer *peer = cli->gbox;
			if(peer->online && peer->authstat == 1 && timediff > 3)
			{
				peer->authstat = 2;
				//cs_log("<- send %d sec delayed HelloS to %04X", timediff, cli->gbox_peer_id);
				gbox_send_hello(cli, GBOX_STAT_HELLOS);
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return;
}

static pthread_t gbx_tick_thread;
static int32_t gbx_tick_active = 0;
static pthread_cond_t gbx_tick_sleep_cond;
static pthread_mutex_t gbx_tick_sleep_cond_mutex;
static pthread_mutex_t gbx_tick_mutex;

static void gbx_tick_mutex_init(void)
{
	static int8_t mutex_init = 0;
	if(!mutex_init)
	{
		SAFE_MUTEX_INIT(&gbx_tick_mutex, NULL);
		cs_pthread_cond_init(__func__, &gbx_tick_sleep_cond_mutex, &gbx_tick_sleep_cond);
		mutex_init = 1;
	}
}

static void gbx_ticker(void)
{
	char *fext= FILE_GSMS_TXT;
	char *fname = get_gbox_tmp_fname(fext);

	while(gbx_tick_active)
	{
		if(file_exists(fname) && !cfg.gsms_dis)
		{
			gbox_init_send_gsms();
		}

		startup++;

		if(startup < GBOX_START_TIME)
			{
				delayed_crd_update();
			}
		else if(startup == GBOX_START_TIME -10)
			{
				gbox_add_local_cards();
			}
		else if(startup % STATS_WRITE_TIME == 0)
			{
				gbox_write_stats();
			}

		gbox_send_idle_msg();

		sleepms_on_cond(__func__, &gbx_tick_sleep_cond_mutex, &gbx_tick_sleep_cond, 1000);
	}
	pthread_exit(NULL);
}

void start_gbx_ticker(void)
{
	int32_t is_active;

	gbx_tick_mutex_init();
	SAFE_MUTEX_LOCK(&gbx_tick_mutex);

	is_active = gbx_tick_active;
	if(!gbx_tick_active)
	{
		gbx_tick_active = 1;
	}

	if(is_active)
	{
		SAFE_MUTEX_UNLOCK(&gbx_tick_mutex);
		return;
	}

	int32_t ret = start_thread("gbox ticker", (void *)&gbx_ticker, NULL, &gbx_tick_thread, 0, 1);
	if(ret)
	{
		gbx_tick_active = 0;
	}

	SAFE_MUTEX_UNLOCK(&gbx_tick_mutex);
}

void stop_gbx_ticker(void)
{
	gbx_tick_mutex_init();
	SAFE_MUTEX_LOCK(&gbx_tick_mutex);

	if(gbx_tick_active)
	{
		gbx_tick_active = 0;
		SAFE_COND_SIGNAL(&gbx_tick_sleep_cond);
		SAFE_THREAD_JOIN(gbx_tick_thread, NULL);
	}

	SAFE_MUTEX_UNLOCK(&gbx_tick_mutex);
}

void module_gbox(struct s_module *ph)
{
	int32_t i;

	for(i = 0; i < CS_MAXPORTS; i++)
	{
		if(!cfg.gbox_port[i])
		{
			break;
		}

		ph->ptab.nports++;
		ph->ptab.ports[i].s_port = cfg.gbox_port[i];
	}

	ph->desc = "gbox";
	ph->num = R_GBOX;
	ph->type = MOD_CONN_UDP;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_GBOX;
	ph->s_handler = gbox_server;
	ph->s_init = gbox_server_init;
	ph->send_dcw = gbox_send_dcw;
	ph->recv = gbox_recv;
	ph->c_init = gbox_peer_init;
	ph->c_send_ecm = gbox_send_ecm;
	ph->c_send_emm = gbox_send_remm_data;
	ph->s_peer_idle = gbox_peer_idle;
}
#endif
