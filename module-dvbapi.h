#ifndef MODULE_DVBAPI_H_
#define MODULE_DVBAPI_H_

#ifdef HAVE_DVBAPI
#include <sys/un.h>

#define TYPE_ECM 1
#define TYPE_EMM 2
#define TYPE_SDT 3
#define TYPE_PAT 4
#define TYPE_PMT 5

//api
#define DVBAPI_3    0
#define DVBAPI_1    1
#define STAPI       2
#define COOLAPI     3

#ifdef __CYGWIN__
#define TMPDIR  "./"
#define STANDBY_FILE    "./.pauseoscam"
#define ECMINFO_FILE    "./ecm.info"
#else
#define TMPDIR  "/tmp/"
#define STANDBY_FILE    "/tmp/.pauseoscam"
#define ECMINFO_FILE    "/tmp/ecm.info"
#endif

#define MAX_DEMUX 16
#define MAX_CAID 50
#define ECM_PIDS 30
#define MAX_FILTER 32

#ifdef WITH_EXTENDED_CW	
#define MAX_STREAM_INDICES 32
#else
#define MAX_STREAM_INDICES 1
#endif

#define BOX_COUNT 7

#define BOXTYPE_DREAMBOX    1
#define BOXTYPE_DUCKBOX 2
#define BOXTYPE_UFS910  3
#define BOXTYPE_DBOX2   4
#define BOXTYPE_IPBOX   5
#define BOXTYPE_IPBOX_PMT   6
#define BOXTYPE_DM7000  7
#define BOXTYPE_QBOXHD  8
#define BOXTYPE_COOLSTREAM  9
#define BOXTYPE_NEUMO   10
#define BOXTYPE_PC      11
#define BOXTYPE_PC_NODMX    12
#define BOXTYPE_SAMYGO  13
#define BOXTYPES        13
#define DMXMD5HASHSIZE  16  // use MD5() 

// we store the results of remove_streampid_from_list()
// and update_streampid_list() in one variable, so make sure
// the return values do not collide

// remove_streampid_from_list()
#define NO_STREAMPID_LISTED                 0x00
#define REMOVED_STREAMPID_INDEX             0x01
#define REMOVED_STREAMPID_LASTINDEX         0x02
#define REMOVED_DECODING_STREAMPID_INDEX    0x03

// update_streampid_list():
#define FOUND_STREAMPID_INDEX               0x10
#define ADDED_STREAMPID_INDEX               0x11
#define FIRST_STREAMPID_INDEX               0x12

// remove_streampid_from_list() and update_streampid_list()
#define INVALID_STREAMPID_INDEX             0x20


#define DUMMY_FD    0xFFFF

//constants used int socket communication:
#define DVBAPI_PROTOCOL_VERSION         3

#define DVBAPI_CA_SET_PID         0x40086f87
#define DVBAPI_CA_SET_DESCR       0x40106f86                         
#define DVBAPI_CA_SET_DESCR_MODE  0x400c6f88
#define DVBAPI_DMX_SET_FILTER     0x403c6f2b
#define DVBAPI_DMX_STOP           0x00006f2a

#define DVBAPI_AOT_CA             0x9F803000
#define DVBAPI_AOT_CA_PMT         0x9F803200  //least significant byte is length (ignored)
#define DVBAPI_AOT_CA_STOP        0x9F803F04
#define DVBAPI_FILTER_DATA        0xFFFF0000
#define DVBAPI_CLIENT_INFO        0xFFFF0001
#define DVBAPI_SERVER_INFO        0xFFFF0002
#define DVBAPI_ECM_INFO           0xFFFF0003

#define DVBAPI_MAX_PACKET_SIZE 262         //maximum possible packet size

#define DVBAPI_INDEX_DISABLE      0xFFFFFFFF // only used for ca_pid_t


typedef uint32_t ca_index_t;

// INDEX_MAX is limited by sizeof(uint64_t * 8) - 1  [ == 63 ]
#define INDEX_MAX_LOCAL     15
#define INDEX_MAX_NET       63
#define INDEX_MAX INDEX_MAX_NET

#define INDEX_DISABLE_ALL   0xEFFFFFFD // used for remove_streampid_from_list(), dvbapi_set_pid()
#define INDEX_INVALID       0xEFFFFFFF

struct box_devices
{
	char *path;
	char *ca_device;
	char *demux_device;
	char *cam_socket_path;
	int8_t api;
};

struct s_ecmpids
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t ECM_PID;
	uint32_t CHID;
	uint16_t EMM_PID;
	uint32_t VPID; // videopid
	uint8_t irdeto_maxindex; // max irdeto indexes always fresh fetched from current ecm
	uint8_t irdeto_curindex; // current irdeto index we want to handle
	uint8_t irdeto_cycle; // temp var that holds the irdeto index we started with to detect if we cycled trough all indexes
	int8_t checked;
	int8_t status;
	uint8_t tries;
	unsigned char table;
	ca_index_t index[MAX_STREAM_INDICES];
	int8_t useMultipleIndices;
	uint32_t streams;
	uint32_t cadata;
	int16_t pvu_counter;
};

typedef struct filter_s
{
	uint32_t fd; //FilterHandle
	int32_t pidindex;
	int32_t pid;
	uint16_t caid;
	uint32_t provid;
	uint16_t type;
	int32_t count;
	uchar	filter[16];
	uchar	mask[16];
	uchar   lastecmd5[CS_ECMSTORESIZE]; // last requested ecm md5
	int32_t lastresult;
	uchar	prevecmd5[CS_ECMSTORESIZE]; // previous requested ecm md5
	int32_t prevresult;
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	int32_t NumSlots;
	uint32_t    SlotHandle[10];
	uint32_t    BufferHandle[10];
#endif
#ifdef WITH_EMU
	uint32_t cadata;
#endif
} FILTERTYPE;

struct s_emmpids
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t PID;
	uint8_t type;
	uint32_t cadata;
};

#define PTINUM 10
#define SLOTNUM 20

typedef struct demux_s
{
	int8_t demux_index;
	FILTERTYPE demux_fd[MAX_FILTER];
	uint32_t ca_mask;
	int8_t adapter_index;
	int32_t socket_fd;
	uint16_t client_proto_version;
	int8_t ECMpidcount;
	struct timeb emmstart; // last time emm cat was started
	struct s_ecmpids ECMpids[ECM_PIDS];
	int8_t EMMpidcount;
	struct s_emmpids EMMpids[ECM_PIDS];
	uint16_t max_emm_filter;
	int8_t STREAMpidcount;
	uint16_t STREAMpids[ECM_PIDS];
	uint8_t STREAMpidsType[ECM_PIDS];
	int16_t pidindex;
	int16_t curindex;
	int8_t max_status;
	uint16_t program_number;
	uint16_t onid;
	uint16_t tsid;
	uint16_t pmtpid;
	uint32_t enigma_namespace;
	unsigned char lastcw[2][8];
	int8_t emm_filter;
	int8_t sdt_filter;
	uchar hexserial[8];
	struct s_reader *rdr;
	char pmt_file[30];
	time_t pmt_time;
	uint8_t stopdescramble;
	uint8_t running;
	uint8_t old_ecmfiltercount; // previous ecm filtercount
	uint8_t old_emmfiltercount; // previous emm filtercount
	pthread_mutex_t answerlock; // requestmode 1 avoid race
#ifdef WITH_STAPI
	uint32_t DescramblerHandle[PTINUM];
	int32_t desc_pidcount;
	uint32_t slot_assc[PTINUM][SLOTNUM];
#endif
#ifdef WITH_STAPI5
	uint32_t dev_index;
#endif
	int8_t decodingtries; // -1 = first run
	struct timeb decstart,decend;
} DEMUXTYPE;

typedef struct s_streampid
{
	uint8_t		cadevice; // holds ca device
	uint16_t 	streampid; // holds pids
	uint64_t	activeindexers; // bitmask indexers if streampid enabled for index bit is set
	ca_index_t	caindex; // holds index that is used to decode on ca device
	bool		use_des;
}STREAMPIDTYPE;

struct s_dvbapi_priority
{
	char type; // p or i
	uint16_t caid;
	uint32_t provid;
	uint16_t srvid;
	uint32_t chid;
	uint16_t ecmpid;
	uint32_t cadata;
	uint16_t mapcaid;
	uint32_t mapprovid;
	uint16_t mapecmpid;
	int16_t delay;
	int8_t force;
	int8_t pidx;
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	char devname[30];
	char pmtfile[30];
	int8_t disablefilter;
#endif
	struct s_dvbapi_priority *next;
};


#define DMX_FILTER_SIZE 16


//dvbapi 1
typedef struct dmxFilter
{
	uint8_t     filter[DMX_FILTER_SIZE];
	uint8_t     mask[DMX_FILTER_SIZE];
} dmxFilter_t;

struct dmxSctFilterParams
{
	uint16_t            pid;
	dmxFilter_t          filter;
	uint32_t             timeout;
	uint32_t             flags;
#define DMX_CHECK_CRC       1
#define DMX_ONESHOT     2
#define DMX_IMMEDIATE_START 4
#define DMX_BUCKET      0x1000  /* added in 2005.05.18 */
#define DMX_KERNEL_CLIENT   0x8000
};

#define DMX_START1        _IOW('o',41,int)
#define DMX_STOP1         _IOW('o',42,int)
#define DMX_SET_FILTER1       _IOW('o',43,struct dmxSctFilterParams *)
//------------------------------------------------------------------


//dbox2+ufs
typedef struct dmx_filter
{
	uint8_t  filter[DMX_FILTER_SIZE];
	uint8_t  mask[DMX_FILTER_SIZE];
	uint8_t  mode[DMX_FILTER_SIZE];
} dmx_filter_t;


struct dmx_sct_filter_params
{
	uint16_t        pid;
	dmx_filter_t        filter;
	uint32_t        timeout;
	uint32_t        flags;
#define DMX_CHECK_CRC       1
#define DMX_ONESHOT     2
#define DMX_IMMEDIATE_START 4
#define DMX_KERNEL_CLIENT   0x8000
};

typedef struct ca_descr
{
	uint32_t index;
	uint32_t parity;    /* 0 == even, 1 == odd */
	unsigned char cw[8];
} ca_descr_t;

typedef struct ca_pid
{
	uint32_t pid;
	int32_t index;      /* -1 == disable*/
} ca_pid_t;

enum ca_descr_algo {
	CA_ALGO_DVBCSA,
	CA_ALGO_DES,
	CA_ALGO_AES128,
};
 
enum ca_descr_cipher_mode {
	CA_MODE_ECB,
	CA_MODE_CBC,
};

typedef struct ca_descr_mode {
	uint32_t index;
	enum ca_descr_algo algo;
	enum ca_descr_cipher_mode cipher_mode;
} ca_descr_mode_t;

#define DMX_START       _IO('o', 41)
#define DMX_STOP        _IO('o', 42)
#define DMX_SET_FILTER  _IOW('o', 43, struct dmx_sct_filter_params)

#define CA_SET_DESCR       _IOW('o', 134, ca_descr_t)
#define CA_SET_PID         _IOW('o', 135, ca_pid_t)
#define CA_SET_DESCR_MODE  _IOW('o', 136, ca_descr_mode_t)
// --------------------------------------------------------------------

void dvbapi_stop_descrambling(int32_t demux_id, uint32_t msgid);
void dvbapi_stop_all_descrambling(uint32_t msgid);
void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uchar *buffer, int32_t len, uint32_t msgid);
int32_t dvbapi_open_device(int32_t, int32_t, int);
int32_t dvbapi_stop_filternum(int32_t demux_index, int32_t num, uint32_t msgid);
int32_t dvbapi_stop_filter(int32_t demux_index, int32_t type, uint32_t msgid);
struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type);
void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er);
void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t pid, int32_t stream_id, enum ca_descr_algo algo, enum ca_descr_cipher_mode cipher_mode, uint32_t msgid);
int32_t dvbapi_parse_capmt(unsigned char *buffer, uint32_t length, int32_t connfd, char *pmtfile, int8_t is_real_pmt, uint16_t existing_demux_id, uint16_t client_proto_version, uint32_t msgid);
void request_cw(struct s_client *client, ECM_REQUEST *er, int32_t demux_id, uint8_t delayed_ecm_check);
void dvbapi_try_next_caid(int32_t demux_id, int8_t checked, uint32_t msgid);
void dvbapi_read_priority(void);
int32_t dvbapi_set_section_filter(int32_t demux_index, ECM_REQUEST *er, int32_t n);
int32_t dvbapi_activate_section_filter(int32_t demux_index, int32_t num, int32_t fd, int32_t pid, uchar *filter, uchar *mask, uint32_t msgid);
int32_t dvbapi_check_ecm_delayed_delivery(int32_t demux_index, ECM_REQUEST *er);
int32_t dvbapi_get_filternum(int32_t demux_index, ECM_REQUEST *er, int32_t type);
ca_index_t dvbapi_ca_setpid(int32_t demux_index, int32_t pid, int32_t stream_id, bool use_des, uint32_t msgid);
void dvbapi_set_pid(int32_t demux_id, int32_t num, ca_index_t idx, bool enable, bool use_des, uint32_t msgid);
int8_t update_streampid_list(uint8_t cadevice, uint16_t pid, ca_index_t idx, bool use_des);
int8_t remove_streampid_from_list(uint8_t cadevice, uint16_t pid, ca_index_t idx);
void disable_unused_streampids(int16_t demux_id);
ca_index_t is_ca_used(uint8_t cadevice, int32_t pid);
uint16_t dvbapi_get_client_proto_version(void);
const char *dvbapi_get_client_name(void);
void rotate_emmfilter(int32_t demux_id);
int32_t filtermatch(uchar *buffer, int32_t filter_num, int32_t demux_id, int32_t len);
void delayer(ECM_REQUEST *er, uint32_t delay);
void check_add_emmpid(int32_t demux_index, uchar *filter, int32_t l, int32_t emmtype);
void *dvbapi_start_handler(struct s_client *cl, uchar *mbuf, int32_t module_idx, void * (*_main_func)(void *));
ca_index_t dvbapi_get_descindex(int32_t demux_index, int32_t pid, int32_t stream_id);
void dvbapi_write_ecminfo_file(struct s_client *client, ECM_REQUEST *er, uint8_t* lastcw0, uint8_t* lastcw1);

#if defined(WITH_AZBOX) || defined(WITH_MCA)
#define USE_OPENXCAS 1
extern int32_t openxcas_provid;
extern uint16_t openxcas_sid, openxcas_caid, openxcas_ecm_pid;
static inline void openxcas_set_caid(uint16_t _caid) { openxcas_caid = _caid; }
static inline void openxcas_set_ecm_pid(uint16_t _pid) { openxcas_ecm_pid = _pid; }
static inline void openxcas_set_sid(uint16_t _sid) { openxcas_sid = _sid; }
static inline void openxcas_set_provid(uint32_t _provid) { openxcas_provid = _provid; }
#else
#define USE_OPENXCAS 0
static inline void openxcas_set_caid(uint16_t UNUSED(_caid)) { }
static inline void openxcas_set_ecm_pid(uint16_t UNUSED(_pid)) { }
static inline void openxcas_set_sid(uint16_t UNUSED(_sid)) { }
static inline void openxcas_set_provid(uint32_t UNUSED(_provid)) { }
#endif

bool is_dvbapi_usr(char *usr);
static inline bool module_dvbapi_enabled(void) { return cfg.dvbapi_enabled; }
#else
static inline void dvbapi_stop_all_descrambling(uint32_t UNUSED(msgid)) { }
static inline void dvbapi_read_priority(void) { }
static inline bool is_dvbapi_usr(char *UNUSED(usr)) { return 0; }
static inline bool module_dvbapi_enabled(void) { return 0; }
#endif // WITH_DVBAPI

#endif // MODULE_DVBAPI_H_
