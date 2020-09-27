#ifndef MODULE_CCCAM_CACHEEX_H_
#define MODULE_CCCAM_CACHEEX_H_

#ifdef CS_CACHEEX
void cc_cacheex_filter_out(struct s_client *cl);
void cc_cacheex_filter_in(struct s_client *cl, uint8_t *buf);
void cc_cacheex_push_in(struct s_client *cl, uint8_t *buf);
void cc_cacheex_module_init(struct s_module *ph);
#ifdef CS_CACHEEX_AIO
void cc_cacheex_feature_request(struct s_client *cl);
void cc_cacheex_feature_request_reply(struct s_client *cl);
void cc_cacheex_feature_request_save(struct s_client *cl, uint8_t *buf);
void cc_cacheex_feature_trigger_in(struct s_client *cl, uint8_t *buf);
#endif
#else
static inline void cc_cacheex_filter_out(struct s_client *UNUSED(cl)) { }
static inline void cc_cacheex_filter_in(struct s_client *UNUSED(cl), uint8_t *UNUSED(buf)) { }
static inline void cc_cacheex_push_in(struct s_client *UNUSED(cl), uint8_t *UNUSED(buf)) { }
static inline void cc_cacheex_module_init(struct s_module *UNUSED(ph)) { }
#endif

#endif
