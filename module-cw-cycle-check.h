#ifndef MODULE_CW_CYCLE_CHECK_H_
#define MODULE_CW_CYCLE_CHECK_H_

uint8_t checkcwcycle(struct s_client *client, ECM_REQUEST *er, struct s_reader *reader, uchar *cw, int8_t rc, uint8_t cycletime_fr, uint8_t next_cw_cycle_fr);

#ifdef CW_CYCLE_CHECK
void cleanupcwcycle(void);
void cwc_destroy(void);
int32_t cache_size_cwc(void);
int16_t cache_size_cwc_selected(int8_t test);
void cwc_init_lock(void);
int8_t get_ecmofs(uint16_t caid);
#else
static inline void cleanupcwcycle(void) { }
#endif

#endif
