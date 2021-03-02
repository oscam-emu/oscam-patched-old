#ifndef MODULE_GBOX_H_
#define MODULE_GBOX_H_

#ifdef MODULE_GBOX

#define NO_GBOX_ID                   0
#define GBOX_MAXHOPS                 8
#define DEFAULT_GBOX_MAX_DIST        2
#define DEFAULT_GBOX_MAX_ECM_SEND    5
#define DEFAULT_GBOX_RESHARE         2
#define DEFAULT_CCC_GBOX_RESHARE     1
#define DEFAULT_GBOX_RECONNECT     180
#define GBOX_MIN_RECONNECT          60
#define GBOX_MAX_RECONNECT         300
#define GBOX_MAX_LOCAL_CARDS        32
#define GBOX_SID_CONFIRM_TIME     3600
#define GBOX_DEFAULT_CW_TIME       500
#define RECEIVE_BUFFER_SIZE       1024
#define MIN_GBOX_MESSAGE_LENGTH     10 // CMD + pw + pw. TODO: Check if is really min
#define MIN_ECM_LENGTH               8
#define STATS_WRITE_TIME           300 // write stats file every 5 min
#define MAX_GBOX_CARDS            1024 // send max. 1024 cards to peer
#define LOCAL_GBOX_MAJOR_VERSION  0x02

#define MSG_ECM       0x445C
#define MSG_CW        0x4844
#define MSG_HELLO     0xDDAB
#define MSG_HELLO1    0x4849
#define MSG_CHECKCODE 0x41C0
#define MSG_GOODBYE   0x9091
#define MSG_GSMS_ACK  0x9099
#define MSG_GSMS      0x0FFF
#define MSG_HERE      0xA0A1

#define GBOX_ECM_NEW_REQ     0
#define GBOX_ECM_SENT        1
#define GBOX_ECM_ANSWERED    2

#define GBOX_CARD_TYPE_GBOX  0
#define GBOX_CARD_TYPE_LOCAL 1
#define GBOX_CARD_TYPE_BETUN 2
#define GBOX_CARD_TYPE_CCCAM 3
#define GBOX_CARD_TYPE_PROXY 4

#define FILE_GBOX_VERSION       "gbox.ver"
#define FILE_SHARED_CARDS_INFO  "share.info"
#define FILE_BACKUP_CARDS_INFO  "expired.info"
#define FILE_ATTACK_INFO        "attack.txt"
#define FILE_GBOX_PEER_ONL      "share.onl"
#define FILE_STATS              "stats.info"
#define FILE_MSG_INFO           "msg.info"
#define FILE_LOCAL_CARDS_INFO   "sc.info"

#define	MSGID_GOODNIGHT   0
#define	MSGID_GSMS        1
#define	MSGID_GONEOFFLINE 2
#define	MSGID_COMEONLINE  3
#define	MSGID_GOODBYE     4
#define	MSGID_LOSTCONNECT 5
#define	MSGID_ATTACK      6
#define	MSGID_IPCHANGE    7
#define	MSGID_GBOXONL     8
#define	MSGID_UNKNOWNMSG  9
#define	MSGID_REMM       12

#define GBOX_STAT_HELLOL 0
#define GBOX_STAT_HELLOS 1
#define GBOX_STAT_HELLOR 2

#define GBOX_DELETE_FROM_PEER 0
#define GBOX_DELETE_WITH_ID   1
#define GBOX_DELETE_WITH_TYPE 2

#define GBOX_PEER_OFFLINE 0
#define GBOX_PEER_ONLINE  1

#define GBOX_ATTACK_LOCAL_PW         0
#define GBOX_ATTACK_PEER_IGNORE      1
#define GBOX_ATTACK_PEER_PW          2
#define GBOX_ATTACK_AUTH_FAIL        3
#define GBOX_ATTACK_ECM_BLOCKED      4
#define GBOX_ATTACK_REMM_REQ_BLOCKED 5
#define GBOX_ATTACK_UNKWN_HDR        6

#define LOCALCARDEJECTED  1
#define LOCALCARDUP       2
#define LOCALCARDDISABLED 3

struct gbox_srvid
{
	uint16_t sid;
	uint32_t provid_id;
};

struct gbox_good_srvid
{
	struct gbox_srvid srvid;
	time_t last_cw_received;
};

struct gbox_bad_srvid
{
	struct gbox_srvid srvid;
	uint8_t bad_strikes;
};

struct gbox_card_id
{
	uint16_t peer;
	uint8_t slot;
};

struct gbox_card_pending
{
	struct gbox_card_id id;
	uint32_t pending_time;
};

struct gbox_card
{
	struct gbox_card_id id;
	uint32_t caprovid;
	uint8_t dist;
	uint8_t lvl;
	uint8_t type;
	LLIST *badsids; // sids that have failed to decode (struct gbox_srvid)
	LLIST *goodsids; // sids that could be decoded (struct gbox_srvid)
	uint32_t no_cws_returned;
	uint32_t average_cw_time;
	struct gbox_peer *origin_peer;
};

struct gbox_data
{
	uint16_t id;
	uint32_t password;
	uint8_t minor_version;
	uint8_t cpu_api;
};

struct gbox_peer
{
	struct gbox_data gbox;
	uint8_t *hostname;
	uint8_t checkcode[7];
	int8_t online;
	uint8_t onlinestat;
	uint8_t authstat;
	uint8_t next_hello;
	uint8_t gbox_rev;
	uint8_t crd_crc_change;
	uint8_t ecm_idx;
	CS_MUTEX_LOCK lock;
	struct s_client *my_user;
	uint16_t filtered_cards;
	uint16_t total_cards;
	uint32_t last_remm_crc;
};

struct gbox_ecm_request_ext
{
	uint8_t gbox_slot;
	uint8_t gbox_version;
	uint8_t gbox_rev;
	uint8_t gbox_type;
	uint8_t gbox_routing_info[GBOX_MAXHOPS];
};

void handle_attack(struct s_client *cli, uint8_t txt_id, uint16_t rcvd_id);
char *get_gbox_tmp_fname(char *fext);
uint16_t gbox_get_local_gbox_id(void);
uint16_t gbox_convert_password_to_id(uint32_t password);
uint8_t get_peer_onl_status(uint16_t peer_id);
uint32_t gbox_get_local_gbox_password(void);
void gbox_send(struct s_client *cli, uint8_t *buf, int32_t l);
int8_t gbox_message_header(uint8_t *buf, uint16_t cmd, uint32_t peer_password, uint32_t local_password);
void gbox_free_cards_pending(ECM_REQUEST *er);
void gbox_send_good_night(void);
void gbox_send_goodbye(struct s_client *cli);
void restart_gbox_peer(char *rdrlabel, uint8_t all, uint16_t gbox_id);
void write_msg_info(struct s_client *cli, uint8_t msg_id, uint8_t txt_id, uint16_t misc);
extern void gbx_local_card_stat(uint8_t crdstat, uint16_t caid);
extern void gbox_send_init_hello(void);
extern void stop_gbx_ticker(void);
#else
static inline void gbox_free_cards_pending(ECM_REQUEST *UNUSED(er)) { }
static inline void gbox_send_good_night(void) { }
static inline void gbx_local_card_stat(uint8_t UNUSED(crdstat), uint16_t UNUSED(caid) ) { }
static inline void gbox_send_init_hello(void) { }
static inline void stop_gbx_ticker(void) { }

#endif

#endif
