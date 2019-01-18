#ifndef MODULE_GBOX_REMM_H_
#define MODULE_GBOX_REMM_H_

#ifdef MODULE_GBOX

#define MSG_REM_EMM 0x49BF

#define MSGID_REMM_REQ  1
#define MSGID_REMM_DATA 2
#define MSGID_REMM_ACK  3

#define PEER_AU_BLOCKED 1
#define PEER_AU_READY   2
#define PEER_AU_UNREADY 3

void gbox_send_remm_req(struct s_client *cli, ECM_REQUEST *er);
void gbox_recvd_remm_cmd_switch(struct s_client *cli, uint8_t *buf, int32_t n);
int32_t gbox_send_remm_data(EMM_PACKET *ep);
uint8_t check_valid_remm_peer(uint16_t peer_id);

#endif

#endif
