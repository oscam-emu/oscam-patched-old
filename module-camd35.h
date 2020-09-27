#ifndef MODULE_CAMD35_H_
#define MODULE_CAMD35_H_

int32_t camd35_send(struct s_client *cl, uint8_t *buf, int32_t buflen);
int32_t camd35_send_without_timeout(struct s_client *cl, uint8_t *buf, int32_t buflen);
int32_t camd35_tcp_connect(struct s_client *cl);
#ifdef CS_CACHEEX_AIO
void camd35_send_extmode(struct s_client *cl, bool answer);
#endif

#endif
