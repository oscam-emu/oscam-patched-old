#ifndef OSCAM_ECM_H_
#define OSCAM_ECM_H_

void cw_process_thread_start(void);
void cw_process_thread_wakeup(void);

void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto);
void convert_to_nagra(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto);

int32_t write_ecm_answer(struct s_reader *reader, ECM_REQUEST *er, int8_t rc, uint8_t rcEx, uint8_t *cw, char *msglog, uint16_t used_cardtier);

void get_cw(struct s_client *, ECM_REQUEST *);

void update_chid(ECM_REQUEST *ecm);
uint32_t get_subid(ECM_REQUEST *er);
uint32_t chk_provid(uint8_t *ecm, uint16_t caid);

int32_t send_dcw(struct s_client *client, ECM_REQUEST *er);
void free_ecm(ECM_REQUEST *ecm);
void free_push_in_ecm(ECM_REQUEST *ecm);
void write_ecm_answer_fromcache(struct s_write_from_cache *wfc);
void fallback_timeout(ECM_REQUEST *er);
void ecm_timeout(ECM_REQUEST *er);
void reader_get_ecm(struct s_reader *reader, ECM_REQUEST *er);
ECM_REQUEST *get_ecmtask(void);
struct s_ecm_answer *get_ecm_answer(struct s_reader *reader, ECM_REQUEST *er);
void cleanup_ecmtasks(struct s_client *cl);
void remove_reader_from_ecm(struct s_reader *rdr);

void chk_dcw(struct s_ecm_answer *ea);
void request_cw_from_readers(ECM_REQUEST *er, uint8_t stop_stage);

void checkCW(ECM_REQUEST *er);
uint8_t checkCWpart(uint8_t *cw, int8_t part);

#ifdef CS_CACHEEX_AIO
void init_ecm_cache(void);
void free_ecm_cache(void);

void ecm_cache_cleanup(bool force);
#endif

#define debug_ecm(mask, args...) \
	do { \
		if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) { \
			char buf[ECM_FMT_LEN]; \
			format_ecm(er, buf, ECM_FMT_LEN); \
			cs_log_dbg(mask, ##args); \
		} \
	} while(0)

int32_t ecmfmt(char *result, size_t size, uint16_t caid, uint16_t onid, uint32_t prid, uint16_t chid, uint16_t pid,
			uint16_t srvid, uint16_t l, char *ecmd5hex, char *csphash, char *cw, uint16_t origin_peer, uint8_t distance, char *payload, char *tier);

int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size);

#endif
