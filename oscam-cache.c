#define MODULE_LOG_PREFIX "cache"

#include "globals.h"
#include "module-cacheex.h"
#include "module-cw-cycle-check.h"
#include "oscam-cache.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-hashtable.h"
#include "oscam-log.h"


// CACHE functions **************************************************************+
struct s_pushclient
{
	struct s_client *cl;
	struct s_pushclient *next_push;
};

typedef struct cw_t
{
	uint8_t             cw[16];
	uint8_t             odd_even;            // odd/even byte (0x80 0x81)
	uint8_t             cwc_cycletime;
	uint8_t             cwc_next_cw_cycle;
	uint8_t             got_bad_cwc;         // used by cycle check
	uint16_t            caid;                // first caid received
	uint32_t            prid;                // first prid received
	uint16_t            srvid;               // first srvid received
	struct s_reader     *selected_reader;    // first answering: reader
	struct s_client     *cacheex_src;        // first answering: cacheex client
	uint64_t            grp;                 // updated grp
	uint8_t             csp;                 // updated if answer from csp
	uint8_t             cacheex;             // updated if answer from cacheex
	uint8_t             localcards;          // updated if answer from local cards (or proxy using localcards option)
	uint8_t             proxy;               // updated if answer from local reader
	uint32_t            count;               // count of same cws receved
	uint8_t				localgenerated;      // flag for local generated CWs
	// for push out
	pthread_rwlock_t    pushout_client_lock;
	struct s_pushclient *pushout_client;     // list of clients that pushing cw
	// end push out
	node                ht_node;             // node for hash table
	node                ll_node;             // node for linked list
} CW;

typedef struct cache_t
{
	hash_table          ht_cw;
	list                ll_cw;
	struct timeb        upd_time;            // updated time. Update time at each cw got
	struct timeb        first_recv_time;     // time of first cw received
	uint32_t            csp_hash;
	node                ht_node;             // node for hash table
	node                ll_node;             // node for linked list
} ECMHASH;

typedef struct cw_cache_t
{
	uint8_t             cw[16];
	uint16_t            caid;
	uint32_t            prid;
	uint16_t            srvid;
	struct timeb        first_recv_time;     // time of first cw received
	struct timeb        upd_time;            // updated time. Update time at each cw got
	node				ht_node;
	node				ll_node;
} CW_CACHE;

typedef struct cw_cache_setting_t
{
	int8_t			mode;
	uint16_t		timediff_old_cw;
} CW_CACHE_SETTING;

static pthread_rwlock_t cache_lock;
static pthread_rwlock_t cw_cache_lock;
static hash_table ht_cache;
static hash_table ht_cw_cache;
static list ll_cache;
static list ll_cw_cache;
static int8_t cache_init_done = 0;
static int8_t cw_cache_init_done = 0;

void init_cw_cache(void)
{
#ifdef CS_CACHEEX
	if(cfg.cw_cache_size > 0 || cfg.cw_cache_memory > 0)
	{
		init_hash_table(&ht_cw_cache, &ll_cw_cache);
		if (pthread_rwlock_init(&cw_cache_lock,NULL) != 0)
			{ cs_log("Error creating lock cw_cache_lock!"); }
		else
			{ cw_cache_init_done = 1; }
	}
#endif
}

void init_cache(void)
{
	init_hash_table(&ht_cache, &ll_cache);
	if (pthread_rwlock_init(&cache_lock,NULL) != 0)
		{ cs_log("Error creating lock cache_lock!"); }
	else
		{ cache_init_done = 1; }
}

void free_cache(void)
{
	cleanup_cache(true);
#ifdef CS_CACHEEX
	cw_cache_cleanup(true);
	ecm_cache_cleanup(true);
	cw_cache_init_done = 0;
	deinitialize_hash_table(&ht_cw_cache);
	pthread_rwlock_destroy(&cw_cache_lock);
#endif
	cache_init_done = 0;
	deinitialize_hash_table(&ht_cache);
	pthread_rwlock_destroy(&cache_lock);
}

uint32_t cache_size(void)
{
	if(!cache_init_done)
		{ return 0; }

	return count_hash_table(&ht_cache);
}

static uint8_t count_sort(CW *a, CW *b)
{
	if (a->count == b->count) return 0;
	return (a->count > b->count) ? -1 : 1; // DESC order by count
}

static uint8_t time_sort(CW_CACHE *a, CW_CACHE *b)
{
	if (((int64_t)(a->upd_time.time) * 1000ull + (int64_t) a->upd_time.millitm) == ((int64_t)(b->upd_time.time) * 1000ull + (int64_t) b->upd_time.millitm)) return 0;
	return (((int64_t)(a->upd_time.time) * 1000ull + (int64_t) a->upd_time.millitm) > ((int64_t)(b->upd_time.time) * 1000ull + (int64_t) b->upd_time.millitm)) ? -1 : 1;
}

uint8_t check_is_pushed(void *cwp, struct s_client *cl)
{
	struct s_pushclient *cl_tmp;
	CW* cw = (CW*)cwp;
	bool pushed=false;

	SAFE_RWLOCK_RDLOCK(&cw->pushout_client_lock);
	for (cl_tmp = cw->pushout_client; cl_tmp; cl_tmp = cl_tmp->next_push)
	{
		if(cl_tmp->cl==cl)
		{
			pushed=true;
			break;
		}
	}

	if(!pushed)
	{
		SAFE_RWLOCK_UNLOCK(&cw->pushout_client_lock);
		SAFE_RWLOCK_WRLOCK(&cw->pushout_client_lock);

		struct s_pushclient *new_push_client;
		if(cs_malloc(&new_push_client, sizeof(struct s_pushclient)))
		{
			new_push_client->cl=cl;

			new_push_client->next_push=cw->pushout_client;
			cw->pushout_client=new_push_client;
		}

		SAFE_RWLOCK_UNLOCK(&cw->pushout_client_lock);
		return 0;
	}
	else
	{
		SAFE_RWLOCK_UNLOCK(&cw->pushout_client_lock);
		return 1;
	}
}

uint8_t get_odd_even(ECM_REQUEST *er)
{
	return (er->ecm[0] != 0x80 && er->ecm[0] != 0x81 ? 0 : er->ecm[0]);
}


CW *get_first_cw(ECMHASH *ecmhash, ECM_REQUEST *er)
{
	if(!ecmhash) return NULL;

	node *j;
	CW *cw;

	j = get_first_node_list(&ecmhash->ll_cw);
	while (j) {
		cw = get_data_from_node(j);

		if(cw && cw->odd_even == get_odd_even(er) && !cw->got_bad_cwc)
			return cw;

		j = j->next;
	}

	return NULL;
}

int compare_csp_hash(const void *arg, const void *obj)
{
	uint32_t h = ((const ECMHASH*)obj)->csp_hash;
	return memcmp(arg, &h, 4);
}

static int compare_cw(const void *arg, const void *obj)
{
	return memcmp(arg, ((const CW*)obj)->cw, 16);
}

#ifdef CS_CACHEEX
static int compare_cw_cache(const void *arg, const void *obj)
{
	return memcmp(arg, ((const CW_CACHE*)obj)->cw, 16);
}
#endif

static bool cwcycle_check_cache(struct s_client *cl, ECM_REQUEST *er, CW *cw)
{
	(void)cl; (void)er; (void)cw;

#ifdef CW_CYCLE_CHECK
	if(cw->got_bad_cwc)
		return 0;

	uint8_t cwc_ct   = cw->cwc_cycletime > 0 ? cw->cwc_cycletime : 0;
	uint8_t cwc_ncwc = cw->cwc_next_cw_cycle < 2 ? cw->cwc_next_cw_cycle : 2;
	if(checkcwcycle(cl, er, NULL, cw->cw, 0, cwc_ct, cwc_ncwc) != 0)
	{
		cs_log_dbg(D_CWC | D_LB, "{client %s, caid %04X, srvid %04X} [check_cache] cyclecheck passed ecm in INT. cache.", (cl ? cl->account->usr : "-"), er->caid, er->srvid);
	}
	else
	{
		if(!er->localgenerated)
		{
			cs_log_dbg(D_CWC, "cyclecheck [BAD CW Cycle] from Int. Cache detected.. {client %s, caid %04X, srvid %04X} [check_cache] -> skip cache answer", (cl ? cl->account->usr : "-"), er->caid, er->srvid);
			cw->got_bad_cwc = 1; // no need to check it again
			return 0;
		}
		else
		{
			cs_log_dbg(D_CWC, "cyclecheck [BAD CW Cycle] from Int. Cache detected.. {client %s, caid %04X, srvid %04X} [check_cache] -> lg-flagged CW -> do nothing", (cl ? cl->account->usr : "-"), er->caid, er->srvid);
		}
	}
#endif
	return 1;
}

/*
 * This function returns cw (mostly received) in cache for er, or NULL if not found.
 * IMPORTANT:
 * 		- If found, DON'T forget to free returned ecm, because it is a copy useful to get data
 * 		- If found, and cacheex_src client of returned ecm is not NULL, and we want to access it,
 *        remember to check for its validity (client structure is still existent)
 *        E.g.: if(ecm->cacheex_src && is_valid_client(ecm->cacheex_src) && !ecm->cacheex_src->kill)
 *        We don't want make this stuff here to avoid useless cpu time if outside function we would not access to it.
 */
struct ecm_request_t *check_cache(ECM_REQUEST *er, struct s_client *cl)
{
	if(!cache_init_done || !er->csp_hash) return NULL;

	ECM_REQUEST *ecm = NULL;
	ECMHASH *result;
	CW *cw;
	uint64_t grp = cl?cl->grp:0;

	SAFE_RWLOCK_RDLOCK(&cache_lock);

	result = find_hash_table(&ht_cache, &er->csp_hash, sizeof(uint32_t),&compare_csp_hash);
	cw = get_first_cw(result, er);
	if (!cw)
		goto out_err;

	if(cw->csp // csp have no grp!
		|| !grp // csp client(no grp) searching for cache
		|| (grp && cw->grp // ecm group --> only when readers/ex-clients answer (e_found) it
		&& (grp & cw->grp)))
	{
#ifdef CS_CACHEEX
		//if preferlocalcards=2 for this ecm request, we can server ONLY cw from localcards readers until stage<3
		if(er->preferlocalcards==2 && !cw->localcards && er->stage<3){
			goto out_err;
		}

		CWCHECK check_cw = get_cwcheck(er);

		if((!cw->proxy && !cw->localcards) // cw received from ONLY cacheex/csp peers
			&& check_cw.counter>1
			&& cw->count < check_cw.counter
			&& (check_cw.mode == 1 || !er->cacheex_wait_time_expired))
		{
			goto out_err;
		}

		// client
		if( cl && !cw->localgenerated 
			&& !(chk_srvid_localgenerated_only_exception(er)) // service-based exception
			&& (cl->account->cacheex.localgenerated_only 
				|| (chk_lg_only(er, &cl->account->cacheex.lg_only_tab))
				) // only lg-flagged CWs
		)
		{
			goto out_err;
		}
#endif

		if (!cwcycle_check_cache(cl, er, cw))
			goto out_err;

		if (cs_malloc(&ecm, sizeof(ECM_REQUEST)))
		{
			ecm->rc = E_FOUND;
			ecm->rcEx = 0;
			memcpy(ecm->cw, cw->cw, 16);
			ecm->grp = cw->grp;
			ecm->selected_reader = cw->selected_reader;
			ecm->cwc_cycletime = cw->cwc_cycletime;
			ecm->cwc_next_cw_cycle = cw->cwc_next_cw_cycle;
			ecm->cacheex_src = cw->cacheex_src;
			ecm->localgenerated = (cw->localgenerated) ? 1:0;
			ecm->cw_count = cw->count;
		}
	}

out_err:
	SAFE_RWLOCK_UNLOCK(&cache_lock);
	return ecm;
}

#ifdef CS_CACHEEX
uint16_t get_cacheex_nopushafter(ECM_REQUEST *er)
{
	return caidvaluetab_get_value(&cfg.cacheex_nopushafter_tab, er->caid, 0);
}
#endif

static void cacheex_cache_add(ECM_REQUEST *er, ECMHASH *result, CW *cw, bool add_new_cw)
{
	(void)er; (void)result; (void)cw; (void)add_new_cw;
#ifdef CS_CACHEEX
	er->cw_cache = cw;
	cacheex_cache_push(er);

	// cacheex debug log lines and cw diff stuff
	if(!check_client(er->cacheex_src))
		return;

	if (D_CACHEEX & cs_dblevel)
	{
		uint8_t remotenodeid[8];
		cacheex_get_srcnodeid(er, remotenodeid);
		
		if(!add_new_cw)
		{
			debug_ecm(D_CACHEEX| D_CSP, "got duplicate pushed ECM %s from %s - hop %i %s, src-nodeid %" PRIu64 "X", buf, er->from_csp ? "csp" : username(er->cacheex_src), ll_count(er->csp_lastnodes), er->localgenerated ? "(lg)" : "", cacheex_node_id(remotenodeid));
			return;
		}

		debug_ecm(D_CACHEEX|D_CSP, "got pushed ECM %s from %s - hop %i %s, src-nodeid %" PRIu64 "X", buf, er->from_csp ? "csp" : username(er->cacheex_src), ll_count(er->csp_lastnodes), er->localgenerated ? "(lg)" : "", cacheex_node_id(remotenodeid));
	}
	else
	{
		if(!add_new_cw)
		{
			debug_ecm(D_CACHEEX| D_CSP, "got duplicate pushed ECM %s from %s - hop %i %s", buf, er->from_csp ? "csp" : username(er->cacheex_src), ll_count(er->csp_lastnodes), er->localgenerated ? "(lg)" : "");
			return;
		}
			debug_ecm(D_CACHEEX|D_CSP, "got pushed ECM %s from %s - hop %i %s", buf, er->from_csp ? "csp" : username(er->cacheex_src), ll_count(er->csp_lastnodes), er->localgenerated ? "(lg)" : "");
	}

	CW *cw_first = get_first_cw(result, er);
	if(!cw_first)
		return;

	// compare er cw with mostly counted cached cw
	if(memcmp(er->cw, cw_first->cw, sizeof(er->cw)) != 0)
	{
		er->cacheex_src->cwcacheexerrcw++;
		if (er->cacheex_src->account)
			er->cacheex_src->account->cwcacheexerrcw++;

		if (((0x0200| 0x0800) & cs_dblevel)) // avoid useless operations if debug is not enabled
		{
			char cw1[16*3+2], cw2[16*3+2];
			cs_hexdump(0, er->cw, 16, cw1, sizeof(cw1));
			cs_hexdump(0, cw_first->cw, 16, cw2, sizeof(cw2));

			char ip1[20]="", ip2[20]="";
			if (check_client(er->cacheex_src))
				cs_strncpy(ip1, cs_inet_ntoa(er->cacheex_src->ip), sizeof(ip1));
			if (check_client(cw_first->cacheex_src))
				cs_strncpy(ip2, cs_inet_ntoa(cw_first->cacheex_src->ip), sizeof(ip2));
			else if (cw_first->selected_reader && check_client(cw_first->selected_reader->client))
				cs_strncpy(ip2, cs_inet_ntoa(cw_first->selected_reader->client->ip), sizeof(ip2));

			uint8_t remotenodeid[8];
			cacheex_get_srcnodeid(er, remotenodeid);
			
			uint8_t fakeF0 = 0, offset = 0;
			
			if(get_odd_even(er) == 0x81)
				offset = 8;

			if(
				(cw_first->cw[7+offset] != 0x00 && er->cw[7+offset] != 0x00) 
				&& (cw_first->cw[7+offset] ^ 0xF0) == er->cw[7+offset]
			)
			{
				fakeF0 = 1;
			}

			debug_ecm(D_CACHEEX| D_CSP, "WARNING: Different CWs %s from %s(%s)<>%s(%s): %s<>%s lg: %i<>%i, hop:%02i, src-nodeid: %" PRIu64 "X%s", buf,
				er->from_csp ? "csp" : username(er->cacheex_src), ip1,
				check_client(cw_first->cacheex_src)?username(cw_first->cacheex_src):(cw_first->selected_reader?cw_first->selected_reader->label:"unknown/csp"), ip2,
				cw1, cw2, er->localgenerated, cw_first->localgenerated, er->csp_lastnodes ? ll_count(er->csp_lastnodes) : 0, er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0, fakeF0 ? " [last byte xor 0xF0]" : "");

			LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
			uint8_t *nodeid;
			uint8_t hops = 0;
			while((nodeid = ll_li_next(li)))
			{
				cs_log_dbg(D_CACHEEX, "Different CW-nodelist hop%02u: %" PRIu64 "X", ++hops, cacheex_node_id(nodeid));
			}
			ll_li_destroy(li);
		}
	}
#endif
}

#ifdef CS_CACHEEX
CW_CACHE_SETTING get_cw_cache(ECM_REQUEST *er)
{
	int32_t i, timediff_old_cw = 0;
	int8_t mode = 0;

	for(i = 0; i < cfg.cw_cache_settings.cwchecknum; i++)
	{
		CWCHECKTAB_DATA *d = &cfg.cw_cache_settings.cwcheckdata[i];

		if(i == 0 && d->caid <= 0)
		{
			mode = d->mode;
			timediff_old_cw = d->counter;
			continue; //check other, only valid for unset
		}

		if(d->caid == er->caid || d->caid == er->caid >> 8 || ((d->cmask >= 0 && (er->caid & d->cmask) == d->caid) || d->caid == -1))
		{
			if((d->prid >= 0 && d->prid == (int32_t)er->prid) || d->prid == -1)
			{
				if((d->srvid >= 0 && d->srvid == er->srvid) || d->srvid == -1)
				{
					mode = d->mode;
					timediff_old_cw = d->counter;
					break;
				}
			}
		}
	}

	//check for correct values
	if(mode>3 || mode<0) mode=0;
	if(timediff_old_cw<1) timediff_old_cw=0;
	
	CW_CACHE_SETTING cw_cache_setting;
	memset(&cw_cache_setting, 0, sizeof(CW_CACHE_SETTING));
	cw_cache_setting.mode = mode;
	cw_cache_setting.timediff_old_cw = timediff_old_cw;

	return cw_cache_setting;
}

static bool cw_cache_check(ECM_REQUEST *er)
{
	if(cw_cache_init_done)
	{
		CW_CACHE_SETTING cw_cache_setting = get_cw_cache(er);
		if(cw_cache_setting.mode > 0)
		{
			CW_CACHE *cw_cache = NULL;
			SAFE_RWLOCK_WRLOCK(&cw_cache_lock);
			cw_cache = find_hash_table(&ht_cw_cache, &er->cw, sizeof(er->cw), &compare_cw_cache);
			// add cw to ht_cw_cache if < cw_cache_size
			if(!cw_cache)
			{
				// cw_cache-size(count/memory) pre-check
				if(
					(cfg.cw_cache_size && (cfg.cw_cache_size > tommy_hashlin_count(&ht_cw_cache)))
					|| 	(cfg.cw_cache_memory && (cfg.cw_cache_memory*1024*1024 > (2 * tommy_hashlin_memory_usage(&ht_cw_cache))))
				)
				{
					if(cs_malloc(&cw_cache, sizeof(CW_CACHE)))
					{
						memcpy(cw_cache->cw, er->cw, sizeof(er->cw));
						cw_cache->caid = er->caid;
						cw_cache->prid = er->prid;
						cw_cache->srvid = er->srvid;
						cs_ftime(&cw_cache->first_recv_time);
						cs_ftime(&cw_cache->upd_time);
						
						tommy_hashlin_insert(&ht_cw_cache, &cw_cache->ht_node, cw_cache, tommy_hash_u32(0, &er->cw, sizeof(er->cw)));
						tommy_list_insert_tail(&ll_cw_cache, &cw_cache->ll_node, cw_cache);
						
						SAFE_RWLOCK_UNLOCK(&cw_cache_lock);
						return true;
					}
					else
					{
						SAFE_RWLOCK_UNLOCK(&cw_cache_lock);
						cs_log("[cw_cache] ERROR: NO added HASH to cw_cache!!");
						return false;
					}
				}
				else
				{
					// clean cache call;
					SAFE_RWLOCK_UNLOCK(&cw_cache_lock);
					cw_cache_cleanup(false);
					return false;
				}
			}
			// cw found
			else
			{
				char cw1[16*3+2];
				char cw2[16*3+2];
				int8_t drop_cw = 0;
				int64_t gone_diff = 0;

				gone_diff = comp_timeb(&er->tps, &cw_cache->first_recv_time);

				if(D_CW_CACHE & cs_dblevel)
				{
					cs_hexdump(0, cw_cache->cw, 16, cw1, sizeof(cw1));
					cs_hexdump(0, er->cw, 16, cw2, sizeof(cw2));
				}

				if(cw_cache_setting.timediff_old_cw > 0 && gone_diff > cw_cache_setting.timediff_old_cw) // late (>cw_cache_setting.timediff_old_cw) cw incoming
				{
					// log every dupe cw 
					if(D_CW_CACHE & cs_dblevel)
					{
						uint8_t remotenodeid[8];
						cacheex_get_srcnodeid(er, remotenodeid);
						cs_log_dbg(D_CW_CACHE,"[dupe CW] cache: %04X:%06X:%04X:%s | in: %04X:%06X:%04X:%s | diff(now): %"PRIi64" ms > %"PRIu16" - %s - hop %i%s, src-nodeid %" PRIu64 "X", cw_cache->caid, cw_cache->prid, cw_cache->srvid, cw1, er->caid, er->prid, er->srvid, cw2, gone_diff, cw_cache_setting.timediff_old_cw, (er->selected_reader && strlen(er->selected_reader->label)) ? er->selected_reader->label : username(er->cacheex_src), ll_count(er->csp_lastnodes), (er->localgenerated) ? " (lg)" : "", er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0);
					}

					if(cw_cache->srvid == er->srvid && cw_cache->caid == er->caid) // same cw for same caid&srvid
					{
						cs_ftime(&cw_cache->upd_time);
						cs_log_dbg(D_CW_CACHE,"[late CW] cache: %04X:%06X:%04X:%s | in: %04X:%06X:%04X:%s | diff(now): %"PRIi64" ms > %"PRIu16" - %s - hop %i%s", cw_cache->caid, cw_cache->prid, cw_cache->srvid, cw1, er->caid, er->prid, er->srvid, cw2, gone_diff, cw_cache_setting.timediff_old_cw, (er->selected_reader && strlen(er->selected_reader->label)) ? er->selected_reader->label : username(er->cacheex_src), ll_count(er->csp_lastnodes), (er->localgenerated) ? " (lg)" : "");
						drop_cw=1;

					}
					else if(cw_cache->srvid != er->srvid) // same cw for different srvid & late
					{
						cs_ftime(&cw_cache->upd_time);
						cs_log_dbg(D_CW_CACHE,"[dupe&late CW] cache: %04X:%06X:%04X:%s | in: %04X:%06X:%04X:%s| diff(now): %"PRIi64" ms - %s - hop %i%s", cw_cache->caid, cw_cache->prid, cw_cache->srvid, cw1, er->caid, er->prid, er->srvid, cw2, gone_diff, (er->selected_reader && strlen(er->selected_reader->label)) ? er->selected_reader->label : username(er->cacheex_src), ll_count(er->csp_lastnodes), (er->localgenerated) ? " (lg)" : "");
						drop_cw = 1;
					}
					else if(gone_diff > 15000) // same cw later as 15 secs
					{
						uint8_t remotenodeid[8];
						cacheex_get_srcnodeid(er, remotenodeid);
						cs_log_dbg(D_CW_CACHE,"[late-15sec+ CW] cache: %04X:%06X:%04X:%s | in: %04X:%06X:%04X:%s | diff(now): %"PRIi64" ms > %"PRIu16" - %s - hop %i%s, src-nodeid %" PRIu64 "X", cw_cache->caid, cw_cache->prid, cw_cache->srvid, cw1, er->caid, er->prid, er->srvid, cw2, gone_diff, cw_cache_setting.timediff_old_cw, (er->selected_reader && strlen(er->selected_reader->label)) ? er->selected_reader->label : username(er->cacheex_src), ll_count(er->csp_lastnodes), (er->localgenerated) ? " (lg)" : "", er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0);
						drop_cw = 1;
					}

					if(cw_cache_setting.mode > 1 && drop_cw)
					{
						// cw_cache->drop_count++;
						cs_log_dbg(D_CW_CACHE,"incoming CW dropped - current cw_cache_size: %i - cw_cache-mem-size: %iMiB", count_hash_table(&ht_cw_cache), 2*(int)tommy_hashlin_memory_usage(&ht_cw_cache)/1024/1024);
						SAFE_RWLOCK_UNLOCK(&cw_cache_lock);
						return false;
					}
				}
			}
			
			SAFE_RWLOCK_UNLOCK(&cw_cache_lock);
			return true;
		}
	}
	else
	{
		cs_log_dbg(D_CW_CACHE,"[cw_cache] cw_cache_init_done %i cfg.cw_cache_size: %u cfg.cw_cache_memory %u", cw_cache_init_done, cfg.cw_cache_size, cfg.cw_cache_memory);
		return true;
	}
	return true;
}
#endif

void add_cache(ECM_REQUEST *er)
{
	if(!cache_init_done || !er->csp_hash) return;
#ifdef CS_CACHEEX
	// cw_cache_check
	if(!cw_cache_check(er))
	{
		return;
	}
#endif
	ECMHASH *result = NULL;
	CW *cw = NULL;
	bool add_new_cw=false;

	SAFE_RWLOCK_WRLOCK(&cache_lock);

	// add csp_hash to cache
	result = find_hash_table(&ht_cache, &er->csp_hash, sizeof(uint32_t), &compare_csp_hash);
	if(!result)
	{
		if(cs_malloc(&result, sizeof(ECMHASH)))
		{
			result->csp_hash = er->csp_hash;
			init_hash_table(&result->ht_cw, &result->ll_cw);
			cs_ftime(&result->first_recv_time);
			add_hash_table(&ht_cache, &result->ht_node, &ll_cache, &result->ll_node, result, &result->csp_hash, sizeof(uint32_t));
		}
		else
		{
			SAFE_RWLOCK_UNLOCK(&cache_lock);
			cs_log("ERROR: NO added HASH to cache!!");
			return;
		}
	}

	cs_ftime(&result->upd_time); // need to be updated at each cw! We use it for deleting this hash when no more cws arrive inside max_cache_time!

	//add cw to this csp hash
	cw = find_hash_table(&result->ht_cw, er->cw, sizeof(er->cw), &compare_cw);

	if(!cw)
	{
		if(count_hash_table(&result->ht_cw) >= 10) // max 10 different cws stored
		{
			SAFE_RWLOCK_UNLOCK(&cache_lock);
			return;
		}

		while(1)
		{
			if(cs_malloc(&cw, sizeof(CW)))
			{
				memcpy(cw->cw, er->cw, sizeof(er->cw));
				cw->odd_even = get_odd_even(er);
				cw->cwc_cycletime = er->cwc_cycletime;
				cw->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
				cw->count= 0;
				cw->csp = 0;
				cw->cacheex = 0;
				cw->localcards=0;
				cw->proxy=0;
				cw->grp = 0;
				cw->caid = er->caid;
				cw->prid = er->prid;
				cw->srvid = er->srvid;
				cw->selected_reader=er->selected_reader;
				cw->cacheex_src=er->cacheex_src;
				cw->pushout_client = NULL;

				while(1)
				{
					if (pthread_rwlock_init(&cw->pushout_client_lock, NULL) == 0)
						break;

					cs_log("Error creating lock pushout_client_lock!");
					cs_sleepms(1);
				}

				add_hash_table(&result->ht_cw, &cw->ht_node, &result->ll_cw, &cw->ll_node, cw, cw->cw, sizeof(er->cw));
				add_new_cw=true;
				break;
			}

			cs_log("ERROR: NO added CW to cache!! Re-trying...");
			cs_sleepms(1);
		}
	}

	// update if answered from csp/cacheex/local_proxy
	if(er->from_cacheex) cw->cacheex = 1;
	if(er->from_csp) cw->csp = 1;
	if(!er->cacheex_src)
	{
		if(is_localreader(er->selected_reader, er)) cw->localcards=1;
		else cw->proxy = 1;
	}

#ifdef CS_CACHEEX
	// copy flag for local generated CW
	if(er->localgenerated || (er->selected_reader && !is_network_reader(er->selected_reader)))
	{
		cw->localgenerated = 1;
		er->localgenerated = 1;
		// to favorite CWs with this flag while sorting
		if(cw->count < 0x0F000000)
			cw->count |= 0x0F000000;
	}
	else
	{
		cw->localgenerated = 0;
	}
#endif

	// always update group and counter
	cw->grp |= er->grp;
	cw->count++;

	// add count to er for checking @ cacheex_push
	er->cw_count += cw->count;
	// sort cw_list by counter (DESC order)
	if(cw->count>1)
		sort_list(&result->ll_cw, count_sort);

#ifdef CS_CACHEEX
	// dont push not flagged CWs - global
	if(!er->localgenerated && 
		(
			!chk_srvid_localgenerated_only_exception(er)
			&& (cfg.cacheex_localgenerated_only || chk_lg_only(er, &cfg.cacheex_lg_only_tab))
		)	)
	{
		cs_log_dbg(D_CACHEEX, "cacheex: push denied, cacheex_localgenerated_only->global");
		SAFE_RWLOCK_UNLOCK(&cache_lock);
		return;
	}

	// dont push CW if time for caid > x  && from local reader | proxy
	if(er->rc < 3 && er->ecm_time && get_cacheex_nopushafter(er) != 0 &&(get_cacheex_nopushafter(er) < er->ecm_time ))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: push denied, cacheex_nopushafter %04X:%u < %i, reader: %s", er->caid, get_cacheex_nopushafter(er), er->ecm_time, er->selected_reader->label);
		SAFE_RWLOCK_UNLOCK(&cache_lock);
		return;
	}

	// no cacheex-push on diff-cw's if no localgenerated flag exist
	if(cfg.cacheex_dropdiffs && (count_hash_table(&result->ht_cw) > 1) && !er->localgenerated)
	{
		cs_log_dbg(D_CACHEEX,"cacheex: diff CW - cacheex push denied src: %s", er->selected_reader->label);
		SAFE_RWLOCK_UNLOCK(&cache_lock);
		return;
	}
#endif

	SAFE_RWLOCK_UNLOCK(&cache_lock);

	cacheex_cache_add(er, result, cw, add_new_cw);
}

void cw_cache_cleanup(bool force)
{
	if(!cw_cache_init_done)
		{ return; }

	SAFE_RWLOCK_WRLOCK(&cw_cache_lock);

	CW_CACHE *cw_cache;
	node *i, *i_next;
		
	uint32_t ll_c = 0;
	uint32_t ll_ten_percent = (uint)tommy_list_count(&ll_cw_cache)*0.1; // 10 percent of cache

	if(!force)
		sort_list(&ll_cw_cache, time_sort);

	i = get_first_node_list(&ll_cw_cache);
	while(i)
	{
		i_next = i->next;
		
		cw_cache = get_data_from_node(i);

		if(!cw_cache)
		{
			i = i_next;
			continue;
		}
		if(!force)
		{
			++ll_c;

			if(ll_c < ll_ten_percent)
			{
				remove_elem_list(&ll_cw_cache, &cw_cache->ll_node);
				remove_elem_hash_table(&ht_cw_cache, &cw_cache->ht_node);
				NULLFREE(cw_cache);
			}
			else{
				break;
			}
		}
		else
		{
			remove_elem_list(&ll_cw_cache, &cw_cache->ll_node);
			remove_elem_hash_table(&ht_cw_cache, &cw_cache->ht_node);
			NULLFREE(cw_cache);
		}

		i = i_next;
	}
	
	SAFE_RWLOCK_UNLOCK(&cw_cache_lock);
}

void cleanup_cache(bool force)
{
	ECMHASH *ecmhash;
	CW *cw;
	struct s_pushclient *pc, *nxt;
	node *i,*i_next,*j,*j_next;

	struct timeb now;
	int64_t gone_first, gone_upd;

	if(!cache_init_done)
		{ return; }

	SAFE_RWLOCK_WRLOCK(&cache_lock);

	i = get_first_node_list(&ll_cache);
	while(i)
	{
		i_next = i->next;
		ecmhash = get_data_from_node(i);

		if(!ecmhash)
		{
			i = i_next;
			continue;
		}

		cs_ftime(&now);
		gone_first = comp_timeb(&now, &ecmhash->first_recv_time);
		gone_upd = comp_timeb(&now, &ecmhash->upd_time);

		if(!force && gone_first<=(cfg.max_cache_time*1000)) // not continue, useless check for nexts one!
		{
			break;
		}

		if(force || gone_upd>(cfg.max_cache_time*1000))
		{
			j = get_first_node_list(&ecmhash->ll_cw);
			while(j)
			{
				j_next = j->next;
				cw = get_data_from_node(j);
				if(cw)
				{
					pthread_rwlock_destroy(&cw->pushout_client_lock);
					pc = cw->pushout_client;
					cw->pushout_client=NULL;
					while(pc)
					{
						nxt = pc->next_push;
						NULLFREE(pc);
						pc = nxt;
					}
					remove_elem_list(&ecmhash->ll_cw, &cw->ll_node);
					remove_elem_hash_table(&ecmhash->ht_cw, &cw->ht_node);
					NULLFREE(cw);
				}
				j = j_next;
			}

			deinitialize_hash_table(&ecmhash->ht_cw);
			remove_elem_list(&ll_cache, &ecmhash->ll_node);
			remove_elem_hash_table(&ht_cache, &ecmhash->ht_node);
			NULLFREE(ecmhash);
		}
		i = i_next;
	}
	SAFE_RWLOCK_UNLOCK(&cache_lock);
}

#ifdef CS_CACHEEX
void cacheex_get_srcnodeid(ECM_REQUEST *er, uint8_t *remotenodeid)
{
	uint8_t *data;
	data = ll_last_element(er->csp_lastnodes);
	if(data)
	{ 
		memcpy(remotenodeid, data, 8);
	}
	else
	{ 
		memset(remotenodeid, 0 , 8);
	}
}
#endif