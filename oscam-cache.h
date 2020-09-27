#ifndef OSCAM_CACHE_H_
#define OSCAM_CACHE_H_

void init_cache(void);
#ifdef CS_CACHEEX_AIO
void init_cw_cache(void);
#endif
void free_cache(void);
void add_cache(ECM_REQUEST *er);
struct ecm_request_t *check_cache(ECM_REQUEST *er, struct s_client *cl);
void cleanup_cache(bool force);
void remove_client_from_cache(struct s_client *cl);
uint32_t cache_size(void);
#ifdef CS_CACHEEX_AIO
uint32_t cache_size_lg(void);
#endif
uint8_t get_odd_even(ECM_REQUEST *er);
uint8_t check_is_pushed(void *cw, struct s_client *cl);
#ifdef CS_CACHEEX_AIO
void cw_cache_cleanup(bool force);
int compare_csp_hash(const void *arg, const void *obj);
void cacheex_get_srcnodeid(ECM_REQUEST *er, uint8_t *remotenodeid);
#endif
#endif
