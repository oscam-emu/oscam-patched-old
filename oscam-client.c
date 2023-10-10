#define MODULE_LOG_PREFIX "client"

#include "globals.h"

#include "cscrypt/md5.h"
#include "module-anticasc.h"
#include "module-cccam.h"
#include "module-webif.h"
#include "oscam-array.h"
#include "oscam-conf-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-failban.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"
#include "reader-common.h"
#include "oscam-chk.h"

extern CS_MUTEX_LOCK fakeuser_lock;

static char *processUsername;
static struct s_client *first_client_hashed[CS_CLIENT_HASHBUCKETS]; // Alternative hashed client list

/* Gets the unique thread number from the client. Used in monitor and newcamd. */
int32_t get_threadnum(struct s_client *client)
{
	struct s_client *cl;
	int32_t count = 0;

	for(cl = first_client->next; cl; cl = cl->next)
	{
		if(cl->typ == client->typ)
		{
			count++;
		}

		if(cl == client)
		{
			return count;
		}
	}
	return 0;
}

struct s_auth *get_account_by_name(char *name)
{
	struct s_auth *account;
	for(account = cfg.account; (account); account = account->next)
	{
		if(streq(name, account->usr))
		{
			return account;
		}
	}
	return NULL;
}

int8_t is_valid_client(struct s_client *client)
{
	struct s_client *cl;
	int32_t bucket = (uintptr_t)client / 16 % CS_CLIENT_HASHBUCKETS;

	for(cl = first_client_hashed[bucket]; cl; cl = cl->nexthashed)
	{
		if(cl == client)
		{
			return 1;
		}
	}
	return 0;
}

const char *remote_txt(void)
{
	return cur_client()->typ == 'c' ? "client" : "remote server";
}

const char *client_get_proto(struct s_client *cl)
{
	const char *ctyp = "unknown";
	switch(cl->typ)
	{
		case 's':
			ctyp = "server";
			break;

		case 'h':
			ctyp = "http";
			break;

		case 'p':
		case 'r':
			ctyp = reader_get_type_desc(cl->reader, 1);
			break;

#ifdef CS_ANTICASC
		case 'a':
			ctyp = "anticascader";
			break;

#endif
		case 'c':
			if(cccam_client_extended_mode(cl))
			{
				ctyp = "cccam_ext";
				break;
			} /* fallthrough */

		default:
			ctyp = get_module(cl)->desc;
			break;
	}
	return ctyp;
}

static void cs_fake_client(struct s_client *client, char *usr, int32_t uniq, IN_ADDR_T ip)
{
	/* Uniq = 1: only one connection per user
	 *
	 * Uniq = 2: set (new connected) user only to fake if source
	 *           ip is different (e.g. for newcamd clients with
	 *           different CAID's -> Ports)
	 *
	 * Uniq = 3: only one connection per user, but only the last
	 *           login will survive (old mpcs behavior)
	 *
	 * Uniq = 4: set user only to fake if source ip is
	 *           different, but only the last login will survive
	 */

	struct s_client *cl;
	struct s_auth *account;
	uint32_t con_count = 1;
	cs_writelock(__func__, &fakeuser_lock);

	for(cl = first_client->next; cl; cl = cl->next)
	{
		account = cl->account;
		if(cl != client && cl->typ == 'c' && !cl->dup && account && streq(account->usr, usr)
			&& uniq < 5 && ((uniq % 2) || !IP_EQUAL(cl->ip, ip)))
		{
			char buf[20];

			con_count++;
			if(con_count <= account->max_connections)
			{
				continue;
			}

			if(uniq == 3 || uniq == 4)
			{
				cl->dup = 1;
				cl->aureader_list = NULL;
				cs_strncpy(buf, cs_inet_ntoa(cl->ip), sizeof(buf));
				cs_log("client(%8lX) duplicate user '%s' from %s (prev %s) set to fake (uniq=%d)",
						(unsigned long)cl->thread, usr, cs_inet_ntoa(ip), buf, uniq);

				if(cl->failban & BAN_DUPLICATE)
				{
					cs_add_violation(cl, usr);
				}

				if(cfg.dropdups)
				{
					cs_writeunlock(__func__, &fakeuser_lock);
					cs_sleepms(120); // sleep a bit to prevent against saturation from fast reconnecting clients
					kill_thread(cl);
					cs_writelock(__func__, &fakeuser_lock);
				}
			}
			else
			{
				client->dup = 1;
				client->aureader_list = NULL;
				cs_strncpy(buf, cs_inet_ntoa(ip), sizeof(buf));
				cs_log("client(%8lX) duplicate user '%s' from %s (current %s) set to fake (uniq=%d)",
						(unsigned long)pthread_self(), usr, cs_inet_ntoa(cl->ip), buf, uniq);

				if(client->failban & BAN_DUPLICATE)
				{
					cs_add_violation_by_ip(ip, get_module(client)->ptab.ports[client->port_idx].s_port, usr);
				}

				if(cfg.dropdups)
				{
					cs_writeunlock(__func__, &fakeuser_lock); // we need to unlock here as cs_disconnect_client kills the current thread!
					cs_sleepms(120); // sleep a bit to prevent against saturation from fast reconnecting clients
					cs_disconnect_client(client);
					cs_writelock(__func__, &fakeuser_lock);
				}
				break;
			}
		}
	}
	cs_writeunlock(__func__, &fakeuser_lock);
}

/* Resolves the ip of the hostname of the specified account and saves it in account->dynip.
   If the hostname is not configured, the ip is set to 0. */
static void cs_user_resolve(struct s_auth *account)
{
	if(account->dyndns)
	{
		IN_ADDR_T lastip;
		IP_ASSIGN(lastip, account->dynip);
		cs_resolve(account->dyndns, &account->dynip, NULL, NULL);

		if(!IP_EQUAL(lastip, account->dynip))
		{
			cs_log("%s: resolved ip=%s", account->dyndns, cs_inet_ntoa(account->dynip));
		}
	}
	else
	{
		set_null_ip(&account->dynip);
	}
}

/* Returns the username from the client. You will always get a char reference back (no NULLs but it may be string containting "NULL")
   which you should never modify and not free()! */
const char *username(struct s_client *client)
{
	if(!check_client(client))
	{
		return "NULL";
	}

	if(client->typ == 's' || client->typ == 'h' || client->typ == 'a')
	{
		return processUsername ? processUsername : "NULL";
	}

	if(client->typ == 'c' || client->typ == 'm')
	{
		struct s_auth *acc = client->account;
		if(acc)
		{
			if(acc->usr[0])
			{
				return acc->usr;
			}
			else
			{
				return "anonymous";
			}
		}
		else
		{
			return "NULL";
		}
	}
	else if(client->typ == 'r' || client->typ == 'p')
	{
		struct s_reader *rdr = client->reader;
		if(rdr)
		{
			return rdr->label;
		}
	}
	return "NULL";
}


struct s_client *create_client(IN_ADDR_T ip)
{
	struct s_client *cl;
	if(!cs_malloc(&cl, sizeof(struct s_client)))
	{
		cs_log("max connections reached (out of memory) -> reject client %s",
				IP_ISSET(ip) ? cs_inet_ntoa(ip) : "with null address");

		return NULL;
	}

	//client part
	IP_ASSIGN(cl->ip, ip);
	cl->account = first_client->account;

	//master part
	SAFE_MUTEX_INIT(&cl->thread_lock, NULL);
	cl->login = cl->last = time(NULL);
	cl->tid = (uint32_t)rand();

	//Now add new client to the list:
	struct s_client *last;
	cs_writelock(__func__, &clientlist_lock);

	for(last = first_client; last && last->next; last = last->next)
		{ ; } //ends with cl on last client

	if (last)
	{
		last->next = cl;
	}

	int32_t bucket = (uintptr_t)cl / 16 % CS_CLIENT_HASHBUCKETS;
	cl->nexthashed = first_client_hashed[bucket];
	first_client_hashed[bucket] = cl;

	cs_writeunlock(__func__, &clientlist_lock);

	return cl;
}

/* Creates the master client of OSCam and inits some global variables/mutexes. */
void init_first_client(void)
{
	// get username OScam is running under
	struct passwd pwd;
	struct passwd *pwdbuf;

#ifdef __ANDROID__
	pwdbuf = getpwuid(getuid()); // This is safe
	if(pwdbuf)
	{
		memcpy(&pwd, pwdbuf, sizeof(pwd));
		processUsername = cs_strdup(pwd.pw_name);
	}
#else
	char buf[256];
	if(getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &pwdbuf) == 0)
	{
		processUsername = cs_strdup(pwd.pw_name);
	}
#endif

	if(!cs_malloc(&first_client, sizeof(struct s_client)))
	{
		fprintf(stderr, "Could not allocate memory for master client, exiting...");
		exit(1);
	}

	memset(first_client_hashed, 0, sizeof(first_client_hashed));
	int32_t bucket = (uintptr_t)first_client / 16 % CS_CLIENT_HASHBUCKETS;
	first_client_hashed[bucket] = first_client;

	first_client->next = NULL; // terminate clients list with NULL
	first_client->login = time(NULL);
	first_client->typ = 's';
	first_client->thread = pthread_self();
	set_localhost_ip(&first_client->ip);

	struct s_auth *null_account;
	if(!cs_malloc(&null_account, sizeof(struct s_auth)))
	{
		fprintf(stderr, "Could not allocate memory for master account, exiting...");
		exit(1);
	}

	first_client->account = null_account;
	if(pthread_setspecific(getclient, first_client))
	{
		fprintf(stderr, "Could not setspecific getclient in master process, exiting...");
		exit(1);
	}
}

int32_t cs_auth_client(struct s_client *client, struct s_auth *account, const char *e_txt)
{
	int32_t rc = 0;
	uint8_t md5tmp[MD5_DIGEST_LENGTH];
	uint8_t i;
	uint8_t j;
	char buf[32];
	char *t_crypt = "encrypted";
	char *t_plain = "plain";
	char *t_grant = " granted";
	char *t_reject = " rejected";
	char *t_msg[] = { buf, "invalid access", "invalid ip", "unknown reason", "protocol not allowed" };
	struct s_module *module = get_module(client);

	memset(&client->grp, 0xff, sizeof(uint64_t));
	//client->grp=0xffffffffffffff;
	if((intptr_t)account != 0 && (intptr_t)account != -1 && account->disabled)
	{
		cs_add_violation(client, account->usr);
		cs_log("%s %s-client %s%s (%s%sdisabled account)",
				client->crypted ? t_crypt : t_plain,
				module->desc,
				IP_ISSET(client->ip) ? cs_inet_ntoa(client->ip) : "",
				IP_ISSET(client->ip) ? t_reject : t_reject + 1,
				e_txt ? e_txt : "",
				e_txt ? " " : "");
		return 1;
	}

	// check whether client comes in over allowed protocol
	if((intptr_t)account != 0 && (intptr_t)account != -1 && (intptr_t)account->allowedprotocols &&
			(((intptr_t)account->allowedprotocols & module->listenertype) != module->listenertype))
	{
		cs_add_violation(client, account->usr);
		cs_log("%s %s-client %s%s (%s%sprotocol not allowed)",
				client->crypted ? t_crypt : t_plain,
				module->desc,
				IP_ISSET(client->ip) ? cs_inet_ntoa(client->ip) : "",
				IP_ISSET(client->ip) ? t_reject : t_reject + 1,
				e_txt ? e_txt : "",
				e_txt ? " " : "");
		return 1;
	}

	client->account = first_client->account;
	switch((intptr_t)account)
	{
		case 0: // reject access
		{
			rc = 1;
			cs_add_violation(client, NULL);
			cs_log("%s %s-client %s%s (%s)",
					client->crypted ? t_crypt : t_plain,
					module->desc,
					IP_ISSET(client->ip) ? cs_inet_ntoa(client->ip) : "",
					IP_ISSET(client->ip) ? t_reject : t_reject + 1,
					e_txt ? e_txt : t_msg[rc]);
			break;
		}

		default: // grant/check access
		{
			if(IP_ISSET(client->ip) && account->dyndns)
			{
				if(!IP_EQUAL(client->ip, account->dynip))
					{ cs_user_resolve(account); }
				if(!IP_EQUAL(client->ip, account->dynip))
				{
					cs_add_violation(client, account->usr);
					rc = 2;
				}
			}

			client->monlvl = account->monlvl;
			client->account = account;

			if(!rc)
			{
				client->dup = 0;
				if(client->typ == 'c' || client->typ == 'm')
				{
					client->pcrc = crc32(0L, MD5((uint8_t *)(ESTR(account->pwd)), cs_strlen(ESTR(account->pwd)), md5tmp), MD5_DIGEST_LENGTH);
				}

				if(client->typ == 'c')
				{
					client->last_caid = NO_CAID_VALUE;
					client->last_provid = NO_PROVID_VALUE;
					client->last_srvid = NO_SRVID_VALUE;
					client->expirationdate = account->expirationdate;
					client->disabled = account->disabled;
					client->allowedtimeframe_set=account->allowedtimeframe_set;

					for(i = 0; i < SIZE_SHORTDAY; i++)
					{
						for(j = 0; j < 24; j++)
						{
							client->allowedtimeframe[i][j][0] = account->allowedtimeframe[i][j][0];
							client->allowedtimeframe[i][j][1] = account->allowedtimeframe[i][j][1];
						}
					}

					if(account->firstlogin == 0)
					{
						account->firstlogin = time((time_t *)0);
					}

					client->failban = account->failban;
					client->c35_suppresscmd08 = account->c35_suppresscmd08;
					client->ncd_keepalive = account->ncd_keepalive;
					client->grp = account->grp;
					client->aureader_list = account->aureader_list;
					client->autoau = account->autoau;
					client->tosleep = (60 * account->tosleep);
					client->c35_sleepsend = account->c35_sleepsend;
					caidtab_clone(&account->ctab, &client->ctab);

					if(account->uniq)
					{
						cs_fake_client(client, account->usr, account->uniq, client->ip);
					}

					client->cltab = account->cltab; // CLASS filter
					ftab_clone(&account->ftab, &client->ftab); // IDENT filter
					ftab_clone(&account->fchid, &client->fchid); // CHID filter
					client->sidtabs.ok = account->sidtabs.ok; // services
					client->sidtabs.no = account->sidtabs.no; // services
					tuntab_clone(&account->ttab, &client->ttab);
					ac_init_client(client, account);
				}
			}
		} /* fallthrough */

		case -1: // anonymous grant access
		{
			if(rc)
			{
				t_grant = t_reject;
			}
			else
			{
				if(client->typ == 'm')
				{
					snprintf(t_msg[0], sizeof(buf), "lvl=%d", client->monlvl);
				}
				else
				{
					int32_t rcount = ll_count(client->aureader_list);
					snprintf(buf, sizeof(buf), "au=");

					if(!rcount)
					{
						snprintf(buf + 3, sizeof(buf) - 3, "off");
					}
					else
					{
						if(client->autoau)
						{
							snprintf(buf + 3, sizeof(buf) - 3, "auto (%d reader)", rcount);
						}
						else
						{
							snprintf(buf + 3, sizeof(buf) - 3, "on (%d reader)", rcount);
						}
					}
				}
			}

			cs_log("%s %s-client %s%s (%s, %s)",
					client->crypted ? t_crypt : t_plain,
					e_txt ? e_txt : module->desc,
					IP_ISSET(client->ip) ? cs_inet_ntoa(client->ip) : "",
					IP_ISSET(client->ip) ? t_grant : t_grant + 1,
					username(client), t_msg[rc]);

			break;
		}
	}
	return rc;
}

void cs_disconnect_client(struct s_client *client)
{
	char buf[32] = { 0 };

	if(IP_ISSET(client->ip))
	{
		snprintf(buf, sizeof(buf), " from %s", cs_inet_ntoa(client->ip));
	}

	cs_log("%s disconnected%s", username(client), buf);

	if(client == cur_client())
	{
		cs_exit(0);
	}
	else
	{
		kill_thread(client);
	}
}

void kill_all_clients(void)
{
	struct s_client *cl;
	for(cl = first_client->next; cl; cl = cl->next)
	{
		if(cl->typ == 'c' || cl->typ == 'm')
		{
			if(cl->account)
			{
				cs_log("killing client %s", cl->account->usr);
			}
			kill_thread(cl);
#ifdef CS_CACHEEX_AIO
			ll_destroy_data(&cl->ll_cacheex_stats);
#endif
		}
	}
	NULLFREE(processUsername);
}

void cs_reinit_clients(struct s_auth *new_accounts)
{
	struct s_auth *account;
	uint8_t md5tmp[MD5_DIGEST_LENGTH];
	uint8_t i;
	uint8_t j;

	struct s_client *cl;
	for(cl = first_client->next; cl; cl = cl->next)
	{
		if((cl->typ == 'c' || cl->typ == 'm') && cl->account)
		{
			for(account = new_accounts; (account) ; account = account->next)
			{
				if(!strcmp(cl->account->usr, account->usr))
				{
					break;
				}
			}

			if(account && !account->disabled && cl->pcrc == crc32(0L, MD5((uint8_t *)ESTR(account->pwd), cs_strlen(ESTR(account->pwd)), md5tmp), MD5_DIGEST_LENGTH))
			{
				cl->account = account;
#ifdef CS_CACHEEX_AIO
				cl->cacheex_aio_checked = 0;
#endif
				if(cl->typ == 'c')
				{
					cl->grp = account->grp;
					cl->aureader_list = account->aureader_list;
					cl->autoau = account->autoau;
					cl->expirationdate = account->expirationdate;
					cl->allowedtimeframe_set = account->allowedtimeframe_set;

					for(i = 0; i < SIZE_SHORTDAY; i++)
					{
						for(j = 0; j < 24; j++)
						{
							cl->allowedtimeframe[i][j][0] = account->allowedtimeframe[i][j][0];
							cl->allowedtimeframe[i][j][1] = account->allowedtimeframe[i][j][1];
						}
					}

					cl->ncd_keepalive = account->ncd_keepalive;
					cl->c35_suppresscmd08 = account->c35_suppresscmd08;
					cl->tosleep = (60 * account->tosleep);
					cl->c35_sleepsend = account->c35_sleepsend;
					cl->monlvl = account->monlvl;
					cl->disabled = account->disabled;
					cl->cltab = account->cltab; // Class

					// newcamd module doesn't like ident reloading
					if(!cl->ncd_server)
					{
						ftab_clone(&account->ftab, &cl->ftab); // IDENT filter
						ftab_clone(&account->fchid, &cl->fchid); // CHID filter
					}

					cl->sidtabs.ok = account->sidtabs.ok; // services
					cl->sidtabs.no = account->sidtabs.no; // services
					cl->failban = account->failban;

					caidtab_clone(&account->ctab, &cl->ctab);
					tuntab_clone(&account->ttab, &cl->ttab);

					webif_client_reset_lastresponsetime(cl);

					if(account->uniq)
					{
						cs_fake_client(cl, account->usr, (account->uniq == 1 || account->uniq == 2) ? account->uniq + 2 : account->uniq, cl->ip);
					}

					ac_init_client(cl, account);
				}
			}
			else
			{
				if(get_module(cl)->type & MOD_CONN_NET)
				{
					cs_log_dbg(D_TRACE, "client '%s', thread=%8lX not found in db (or password changed)", cl->account->usr, (unsigned long)cl->thread);
					kill_thread(cl);
				}
				else
				{
					cl->account = first_client->account;
				}
			}
		}
		else
		{
			cl->account = NULL;
		}
	}
}

void client_check_status(struct s_client *cl)
{
	if(!cl || cl->kill || !cl->init_done)
	{
		return;
	}

	switch(cl->typ)
	{
		case 'm':
		case 'c':
			if((get_module(cl)->listenertype & LIS_CCCAM) && cl->last && (time(NULL) - cl->last) > (time_t)12)
			{
				add_job(cl, ACTION_CLIENT_IDLE, NULL, 0);
			}

			// Check umaxidle to avoid client is killed for inactivity, it has priority than cmaxidle
			if(!cl->account->umaxidle)
			{
				break;
			}

			// Check user for exceeding umaxidle by checking cl->last, except Newcamd & Gbox
			if(!(cl->ncd_keepalive && (get_module(cl)->listenertype & LIS_NEWCAMD)) && !(get_module(cl)->listenertype & LIS_GBOX) && cl->account->umaxidle>0 && cl->last && (time(NULL) - cl->last) > (time_t)cl->account->umaxidle)
			{
				add_job(cl, ACTION_CLIENT_IDLE, NULL, 0);
			}

			// Check clients for exceeding cmaxidle by checking cl->last, except Newcamd & Gbox
			if(!(cl->ncd_keepalive && (get_module(cl)->listenertype & LIS_NEWCAMD)) && !(get_module(cl)->listenertype & LIS_GBOX) && cl->last && cl->account->umaxidle==-1 && cfg.cmaxidle && (time(NULL) - cl->last) > (time_t)cfg.cmaxidle)
			{
				add_job(cl, ACTION_CLIENT_IDLE, NULL, 0);
			}

#ifdef MODULE_GBOX
			if((get_module(cl)->listenertype & LIS_GBOX) &&	cl->last && (time(NULL) - cl->last) > (time_t)cfg.gbox_reconnect)
			{
				add_job(cl, ACTION_PEER_IDLE, NULL, 0);
			}
#endif
			break;

		case 'r':
			cardreader_checkhealth(cl, cl->reader);
			break;

		case 'p':
		{
			struct s_reader *rdr = cl->reader;
			if(!rdr || !rdr->enable || !rdr->active) // reader is disabled or restarting at this moment
			{
				break;
			}

			// execute reader do idle on proxy reader after a certain time (rdr->tcp_ito = inactivitytimeout)
			// disconnect when no keepalive available
			if((rdr->tcp_ito && is_cascading_reader(rdr)) || (rdr->typ == R_CCCAM) || (rdr->typ == R_CAMD35) || (rdr->typ == R_CS378X) || (rdr->typ == R_SCAM) || (rdr->tcp_ito != 0 && rdr->typ == R_RADEGAST))
			{
				time_t now = time(NULL);
				int32_t time_diff = llabs(now - rdr->last_check);

				if(time_diff > 60 || (time_diff > 12 && (rdr->typ == R_CCCAM || rdr->typ == R_CAMD35 || rdr->typ == R_CS378X)) || ((time_diff > (rdr->tcp_rto?rdr->tcp_rto:60)) && rdr->typ == R_RADEGAST))     //check 1x per minute or every 10s for cccam/camd35 or reconnecttimeout radegast if 0 defaut 60s
				{
					add_job(rdr->client, ACTION_READER_IDLE, NULL, 0);
					rdr->last_check = now;
				}
			}
			break;
		}
	}
}

void free_client(struct s_client *cl)
{
	if(!cl)
	{
		return;
	}

	struct s_reader *rdr = cl->reader;

	// Remove client from client list. kill_thread also removes this client, so here just if client exits itself...
	struct s_client *prev, *cl2;
	cs_writelock(__func__, &clientlist_lock);

	if(!cl->kill_started)
	{
		cl->kill_started = 1;
	}
	else
	{
		cs_writeunlock(__func__, &clientlist_lock);
		cs_log("[free_client] ERROR: free already started!");
		return;
	}
	cl->kill = 1;

	for(prev = first_client, cl2 = first_client->next; prev->next != NULL; prev = prev->next, cl2 = cl2->next)
	{
		if(cl == cl2)
		{
			break;
		}
	}

	if(cl == cl2) // Remove client from list
	{
		prev->next = cl2->next;
	}

	int32_t bucket = (uintptr_t)cl / 16 % CS_CLIENT_HASHBUCKETS;

	// Remove client from hashed list
	if(first_client_hashed[bucket] == cl)
	{
		first_client_hashed[bucket] = cl->nexthashed;
	}
	else
	{
		for(prev = first_client_hashed[bucket], cl2 = first_client_hashed[bucket]->nexthashed;
			prev->nexthashed != NULL; prev = prev->nexthashed, cl2 = cl2->nexthashed)
		{
			if(cl == cl2)
			{
				break;
			}
		}

		if(cl == cl2)
		{
			prev->nexthashed = cl2->nexthashed;
		}
	}

	cs_writeunlock(__func__, &clientlist_lock);
	cleanup_ecmtasks(cl);

	// Clean reader. The cleaned structures should be only used by the reader thread, so we should be save without waiting
	if(rdr)
	{
		ll_destroy_data(&rdr->emmstat);
		remove_reader_from_active(rdr);

		cs_sleepms(1000); // just wait a bit that really really nobody is accessing client data

		if(rdr->ph.cleanup)
		{
			rdr->ph.cleanup(cl);
		}

		if(cl->typ == 'r')
		{
			cardreader_close(rdr);
		}

		if(cl->typ == 'p')
		{
			network_tcp_connection_close(rdr, "cleanup");
		}

		cl->reader = NULL;
	}

	// Clean client specific data
	if(cl->typ == 'c')
	{
		cs_statistics(cl);
		cl->last_caid = NO_CAID_VALUE;
		cl->last_provid = NO_PROVID_VALUE;
		cl->last_srvid = NO_SRVID_VALUE;
		cs_statistics(cl);

		cs_sleepms(1000); // just wait a bit that really really nobody is accessing client data
	}

	struct s_module *module = get_module(cl);
	if(module->cleanup)
	{
		module->cleanup(cl);
	}

	// Close network socket if not already cleaned by previous cleanup functions
	if(cl->pfd)
	{
		close(cl->pfd);
	}

	// Clean all remaining structures
	free_joblist(cl);
	NULLFREE(cl->work_mbuf);

	if(cl->ecmtask)
	{
		add_garbage(cl->ecmtask);
		cl->ecmtask = NULL;
	}

	ll_destroy_data(&cl->cascadeusers);

	ftab_clear(&cl->ftab);
	ftab_clear(&cl->fchid);
	tuntab_clear(&cl->ttab);
	caidtab_clear(&cl->ctab);

	NULLFREE(cl->cltab.aclass);
	NULLFREE(cl->cltab.bclass);

	NULLFREE(cl->cw_rass);
	ll_destroy_data(&cl->ra_buf);
	NULLFREE(cl->aes_keys);

#ifdef MODULE_CCCAM
	add_garbage(cl->cc);
#endif
#ifdef MODULE_SERIAL
	add_garbage(cl->serialdata);
#endif
	add_garbage(cl);
}
