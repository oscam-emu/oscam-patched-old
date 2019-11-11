#ifndef MODULE_DVBAPI_H_
#define MODULE_DVBAPI_H_

#ifdef HAVE_DVBAPI
#include <sys/un.h>

#define TYPE_ECM 1
#define TYPE_EMM 2
#define TYPE_SDT 3
#define TYPE_PAT 4
#define TYPE_PMT 5
#define TYPE_CAT 6

// api
#define DVBAPI_3    0
#define DVBAPI_1    1
#define STAPI       2
#define COOLAPI     3

#ifdef __CYGWIN__
#define TMPDIR          "./"
#define STANDBY_FILE    "./.pauseoscam"
#define ECMINFO_FILE    "./ecm.info"
#else
#define TMPDIR          "/tmp/"
#define STANDBY_FILE    "/tmp/.pauseoscam"
#define ECMINFO_FILE    "/tmp/ecm.info"
#endif

#define BOX_COUNT 7

#define BOXTYPE_DREAMBOX    1
#define BOXTYPE_DUCKBOX     2
#define BOXTYPE_UFS910      3
#define BOXTYPE_DBOX2       4
#define BOXTYPE_IPBOX       5
#define BOXTYPE_IPBOX_PMT   6
#define BOXTYPE_DM7000      7
#define BOXTYPE_QBOXHD      8
#define BOXTYPE_COOLSTREAM  9
#define BOXTYPE_NEUMO      10
#define BOXTYPE_PC         11
#define BOXTYPE_PC_NODMX   12
#define BOXTYPE_SAMYGO     13
#define BOXTYPES           13
#define DMXMD5HASHSIZE     16 // use MD5()

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

#define INDEX_DISABLE_ALL         0xEFFFFFFD // used for remove_streampid_from_list(), dvbapi_set_pid()
#define INDEX_INVALID             0xEFFFFFFF

#define DUMMY_FD    0xFFFF

//-----------------------------------------------------------------------------
// constants used in socket communication
//-----------------------------------------------------------------------------

#define DVBAPI_PROTOCOL_VERSION   3
#define DVBAPI_MAX_PACKET_SIZE    262        // maximum possible packet size

#define DVBAPI_CA_GET_DESCR_INFO  0x80086F83
#define DVBAPI_CA_SET_DESCR       0x40106F86
#define DVBAPI_CA_SET_PID         0x40086F87
#define DVBAPI_CA_SET_DESCR_MODE  0x400C6F88
#define DVBAPI_CA_SET_DESCR_DATA  0x40186F89
//#define DVBAPI_DMX_START          0x00006F29 // in case we ever need this
#define DVBAPI_DMX_STOP           0x00006F2A
#define DVBAPI_DMX_SET_FILTER     0x403C6F2B

#define DVBAPI_AOT_CA             0x9F803000
#define DVBAPI_AOT_CA_PMT         0x9F803200 // least significant byte is length (ignored)
#define DVBAPI_AOT_CA_STOP        0x9F803F04
#define DVBAPI_FILTER_DATA        0xFFFF0000
#define DVBAPI_CLIENT_INFO        0xFFFF0001
#define DVBAPI_SERVER_INFO        0xFFFF0002
#define DVBAPI_ECM_INFO           0xFFFF0003

#define DVBAPI_INDEX_DISABLE      0xFFFFFFFF // only used for ca_pid_t

//-----------------------------------------------------------------------------
// CA PMT defined values according to EN 50221
// https://www.dvb.org/resources/public/standards/En50221.V1.pdf
// https://www.dvb.org/resources/public/standards/R206-001.V1.pdf
//-----------------------------------------------------------------------------

// ca_pmt_list_management: This parameter is used to indicate whether the user has selected a single program or several
// programs. The following values can be used:

#define CA_PMT_LIST_MORE   0x00 // The CA PMT object is neither the first one, nor the last one of the list.

#define CA_PMT_LIST_FIRST  0x01 // The CA PMT object is the first one of a new list of more than one CA PMT object.
								// All previously selected programs are being replaced by the programs of the new list.

#define CA_PMT_LIST_LAST   0x02 // The CA PMT object is the last of the list.

#define CA_PMT_LIST_ONLY   0x03 // The list is made of a single CA PMT object.

#define CA_PMT_LIST_ADD    0x04 // The CA PMT has to be added to an existing list, that is, a new program has been seleced
								// by the user, but all previously selected programs remain selected.

#define CA_PMT_LIST_UPDATE 0x05 // The CA PMT of a program already in the list is sent again because the version_number or
								// the current_next_indicator has changed.

// ca_pmt_cmd_id: This parameter indicates what response is required from the application to a CA PMT object. It can
// take the following values:

#define CA_PMT_CMD_OK_DESCRAMBLING 0x01 // The host does not expect answer to the CA PMT and the application can start
										// descrambling the program or start an MMI dialogue immediately.

#define CA_PMT_CMD_OK_MMI          0x02 // The application can start an MMI dialogue, but shall not start descrambling
										// before reception of a new CA PMT object with "ca_pmt_cmd_id" set to
										// "ok_descrambling". In this case the host shall quarantee that an MMI session
										// can be opened by the CA application.

#define CA_PMT_CMD_QUERY           0x03 // The host expects to receive a CA PMT reply. In this case, the applicaiton is
										// not allowed to start descrambling or MMI dialogue before reception of a new
										// CA PMT object with "ca_pmt_cmd_id" set to "ok_descrambling or "ok_mmi".

#define CA_PMT_CMD_NOT_SELECTED    0x04 // It indicates to the CA application that the host no longer requires that CA
										// application to attempt to descramble the service. The CA application shall
										// close any MMI dialogue it has opened.
//----------------
// ca descriptors
//----------------

#define CA			     		   		0x09
#define ENIGMA_NAMESPACE				0x81
#define DEMUX_CA_MASK_ADAPTER			0x82 // deprecated - applications should use descriptors ADAPTER_DEVICE, DEMUX_DEVICE and CA_DEVICE instead
#define ADAPTER_DEVICE					0x83
#define PMT_PID							0x84
#define SERVICE_TYPE_MASK				0x85 // not used by OSCam
#define DEMUX_DEVICE					0x86
#define CA_DEVICE						0x87

//-----------------------------------------------------------------------------
// api used for internal device communication
//-----------------------------------------------------------------------------

#define DMX_FILTER_SIZE 16

// The following is part of the linux dvb api (v1),
// but modifed to overcome some bugs in specific devices

typedef struct dmxFilter
{
	uint8_t filter[DMX_FILTER_SIZE];
	uint8_t mask[DMX_FILTER_SIZE];
} dmxFilter_t;

struct dmxSctFilterParams
{
	uint16_t    pid;
	dmxFilter_t filter;
	uint32_t    timeout;
	uint32_t    flags;

#define DMX_CHECK_CRC       1
#define DMX_ONESHOT         2
#define DMX_IMMEDIATE_START 4
};

#define DMX_START1        _IOW('o', 41, int)
#define DMX_STOP1         _IOW('o', 42, int)
#define DMX_SET_FILTER1   _IOW('o', 43, struct dmxSctFilterParams *)

// The following is part of the linux dvb api
// https://www.kernel.org/doc/html/latest/media/uapi/dvb/demux.html
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/dvb/dmx.h

typedef struct dmx_filter
{
	uint8_t filter[DMX_FILTER_SIZE];
	uint8_t mask[DMX_FILTER_SIZE];
	uint8_t mode[DMX_FILTER_SIZE];
} dmx_filter_t;

struct dmx_sct_filter_params
{
	uint16_t     pid;
	dmx_filter_t filter;
	uint32_t     timeout;
	uint32_t     flags;

#define DMX_CHECK_CRC       1
#define DMX_ONESHOT         2
#define DMX_IMMEDIATE_START 4
};

#define DMX_START         _IO('o', 41)
#define DMX_STOP          _IO('o', 42)
#define DMX_SET_FILTER    _IOW('o', 43, struct dmx_sct_filter_params)

// The following is part of the linux dvb api
// https://www.kernel.org/doc/html/latest/media/uapi/dvb/ca.html
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/dvb/ca.h

typedef struct ca_descr_info
{
	uint32_t num;
	uint32_t type; /* bitmask: 1 == ECD, 2 == NDS, 4 == DDS */
} ca_descr_info_t;

typedef struct ca_descr
{
	uint32_t index;
	uint32_t parity; /* 0 == even, 1 == odd */
	uint8_t cw[8];
} ca_descr_t;

// ca_pid has been removed from the api, but we still use it
typedef struct ca_pid
{
	uint32_t pid;
	int32_t index; /* -1 == disable */
} ca_pid_t;

enum ca_descr_algo
{
	CA_ALGO_DVBCSA,
	CA_ALGO_DES,
	CA_ALGO_AES128,
};

enum ca_descr_cipher_mode
{
	CA_MODE_ECB,
	CA_MODE_CBC,
};

// Structs "ca_descr_mode" and "ca_descr_data" and respective ioctl
// commands are part of a custom api

/*
* struct ca_descr_mode - Used to select a crypto algorithm and mode
* for a key slot.
*
* @index: Key slot allocated for a PID or service.
* See CA_SET_PID and struct ca_pid.
* @algo: Algorithm to select for @index.
* @cipher_mode: Cipher mode to use with @algo.
*/

typedef struct ca_descr_mode
{
	uint32_t index;
	enum ca_descr_algo algo;
	enum ca_descr_cipher_mode cipher_mode;
} ca_descr_mode_t;

/*
* struct ca_descr_data - Used to write Keys and IVs to a descrambler.
*
* @index: Key slot allocated for a PID or service.
* See CA_SET_PID and struct ca_pid.
* @parity: Indicates even or odd parity for control words.
* @data_type: Key or IV.
* @length: Size of @data array; depends on selected algorithm and
* key or block size.
* @data: Pointer to variable @length key or initialization vector data.
*/

enum ca_descr_data_type
{
	CA_DATA_IV,
	CA_DATA_KEY,
};

enum ca_descr_parity
{
	CA_PARITY_EVEN,
	CA_PARITY_ODD,
};

typedef struct ca_descr_data
{
	uint32_t index;
	enum ca_descr_parity parity;
	enum ca_descr_data_type data_type;
	uint32_t length;
	uint8_t *data;
} ca_descr_data_t;

#define CA_GET_DESCR_INFO _IOR('o', 131, ca_descr_info_t)
#define CA_SET_DESCR      _IOW('o', 134, ca_descr_t)
#define CA_SET_PID        _IOW('o', 135, ca_pid_t)
#define CA_SET_DESCR_MODE _IOW('o', 136, ca_descr_mode_t)
#define CA_SET_DESCR_DATA _IOW('o', 137, ca_descr_data_t)

//-----------------------------------------------------------------------------
// OSCam defined structures
//-----------------------------------------------------------------------------

struct box_devices
{
	char *path;
	char *ca_device;
	char *demux_device;
	char *cam_socket_path;
	int8_t api;
};

typedef struct filter_s
{
	uint32_t         fd;                                 // filter handle
	int32_t          pidindex;
	int32_t          pid;
	uint16_t         caid;
	uint32_t         provid;
	uint16_t         type;
	int32_t          count;
	uint8_t          filter[16];
	uint8_t          mask[16];
	uint8_t          lastecmd5[CS_ECMSTORESIZE];         // last requested ecm md5
	int32_t          lastresult;
	uint8_t          prevecmd5[CS_ECMSTORESIZE];         // previous requested ecm md5
	int32_t          prevresult;
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	int32_t          NumSlots;
	uint32_t         SlotHandle[10];
	uint32_t         BufferHandle[10];
#endif
#ifdef WITH_EMU
	uint32_t cadata;
#endif
} FILTERTYPE;

#ifdef WITH_EXTENDED_CW
#define MAX_STREAM_INDICES  32 // In practice, 5 is the maximum ever used
#else
#define MAX_STREAM_INDICES   1
#endif

#define CA_MAX              32 // Max ca devices supported by oscam - limited by sizeof(ca_mask) of struct demux_s (32 bits)
#define INDEX_MAX           64 // Max descramblers per ca device - limited by sizeof(activeindexers) of struct s_streampid (64 bits)
#define INDEX_MAX_LOCAL     16 // Max total descramblers to use for enigma2 and other STBs when dvbapi_get_descrambler_info() fails
#define INDEX_MAX_NET       64 // Max total descramblers to use for PC (VDR, Tvheadend, etc)

typedef struct s_ecmpid
{
	uint16_t         CAID;
	uint32_t         PROVID;                             // provider
	uint16_t         ECM_PID;
	uint32_t         CHID;
	uint16_t         EMM_PID;
	uint32_t         VPID;                               // video pid
	uint8_t          irdeto_maxindex;                    // max irdeto indices always fresh fetched from current ecm
	uint8_t          irdeto_curindex;                    // current irdeto index we want to handle
	uint8_t          irdeto_cycle;                       // temp var that holds the irdeto index we started with to detect if we cycled trough all indices
	int8_t           checked;
	int8_t           status;
	uint8_t          tries;
	uint8_t          table;
	int8_t           useMultipleIndices;                 // whether or not to use multiple indices for this ecm pid
	uint32_t         index[MAX_STREAM_INDICES];          // ca indices used for this ecm pid (index[0] holds ca index for STREAMmpids[0] and so on)
	uint32_t         streams;                            // bit mask of STREAMpids enabled for this ECMpid
	uint32_t         cadata;
#ifdef WITH_EMU
	int16_t pvu_counter;
#endif
} ECMPIDTYPE;

typedef struct s_emmpid
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t PID;
	uint8_t type;
	uint32_t cadata;
} EMMPIDTYPE;

enum stream_type
{
	STREAM_UNDEFINED,
	STREAM_VIDEO,
	STREAM_AUDIO,
	STREAM_SUBTITLE
};

#define MAX_DEMUX       32 // Max number of demuxes supported by OSCam - each channel/service occupies one demux
#define MAX_ECM_PIDS    24 // Max number of ECM pids per demux
#define MAX_EMM_PIDS    24 // Max number of EMM pids per demux
#define MAX_STREAM_PIDS 32 // Max number of pids other than ECM and EMM (e.g. audio, video, subtitle, etc) per demux (hardware descramblers might have a capacity of 30 pids)
#define MAX_FILTER      64

#define PTINUM          10
#define SLOTNUM         20

typedef struct demux_s
{
	int8_t           demux_index;                        // ID of the (hardware) demux device carrying this program - we get this via CA PMT
	int8_t           adapter_index;                      // ID of the adapter device carrying this program - we get this via CA PMT
	uint32_t         ca_mask;                            // Bit mask of ca devices used for descrambling this program - we get this via CA PMT
	int32_t          socket_fd;                          // Connection identifier through which we received the CA PMT object
	uint16_t         client_proto_version;
	FILTERTYPE       demux_fd[MAX_FILTER];
	int8_t           ECMpidcount;                        // Count of ECM pids in this program
	ECMPIDTYPE       ECMpids[MAX_ECM_PIDS];
	int8_t           EMMpidcount;                        // Count of EMM pids in this program
	EMMPIDTYPE       EMMpids[MAX_EMM_PIDS];
	struct timeb     emmstart;                           // last time emm cat was started
	uint16_t         max_emm_filter;
	int8_t           STREAMpidcount;
	uint16_t         STREAMpids[MAX_STREAM_PIDS];
	enum stream_type STREAMpidsType[MAX_STREAM_PIDS];    // type (audio, video, subtitle, etc) of the corresponding stream pid
	int16_t          pidindex;                           // ECMpid used for descrambling - holds index of the ECMpids[] array
	int16_t          curindex;
	int8_t           max_status;
	uint16_t         program_number;                     // also called service id (srvid)
	uint16_t         onid;                               // original network id
	uint16_t         tsid;                               // transport stream id
	uint16_t         pmtpid;                             // PMT pid for the program_number
	uint32_t         ens;                                // enigma namespace
	uint8_t          last_cw[MAX_STREAM_INDICES][2][16]; // even/odd pairs of 16 byte CWs used for descrambling on the last crypto period
	int8_t           emm_filter;
	int8_t           sdt_filter;
	uint8_t          hexserial[8];
	struct s_reader  *rdr;
	char             pmt_file[30];
	time_t           pmt_time;
	bool             stop_descrambling;                  // Program is marked to stop descrambling (not selected in the new CA PMT list)
	bool             running;                            // Descrambling is currently running for this program
	uint8_t          old_ecmfiltercount;                 // previous ecm filter count
	uint8_t          old_emmfiltercount;                 // previous emm filter count
	pthread_mutex_t  answerlock;                         // request mode 1 avoid race
#ifdef WITH_STAPI
	uint32_t         DescramblerHandle[PTINUM];
	int32_t          desc_pidcount;
	uint32_t         slot_assc[PTINUM][SLOTNUM];
#endif
#ifdef WITH_STAPI5
	uint32_t         dev_index;
#endif
	int8_t           decodingtries;                      // -1 = first run
	struct timeb     decstart;
	struct timeb     decend;
} DEMUXTYPE;

typedef struct s_streampid
{
	uint16_t         streampid;                          // pid of this stream
	uint8_t          cadevice;                           // CA device used for descramlbing
	uint32_t         caindex;                            // index (slot) of the CA device used
	uint64_t         activeindexers;                     // bitmask indexers if streampid enabled for index, bit is set
	bool             use_des;                            // whether to use DES for descrambling this streampid
} STREAMPIDTYPE;

struct s_dvbapi_priority
{
	char             type;                               // can be 'p', 'i', 'm', 'd', 's', 'l', 'j', 'a' or 'x'
	uint16_t         caid;
	uint32_t         provid;
	uint16_t         srvid;
	uint32_t         chid;
	uint16_t         ecmpid;
	uint32_t         cadata;
	uint16_t         mapcaid;
	uint32_t         mapprovid;
	uint16_t         mapecmpid;
	int16_t          delay;
	int8_t           force;
	int8_t           pidx;
#if defined(WITH_STAPI) || defined(WITH_STAPI5)
	char             devname[30];
	char             pmtfile[30];
	int8_t           disablefilter;
#endif
	struct s_dvbapi_priority *next;
};

//-----------------------------------------------------------------------------
// function declarations
//-----------------------------------------------------------------------------

void dvbapi_stop_descrambling(int32_t demux_id, uint32_t msgid);
void dvbapi_stop_all_descrambling(uint32_t msgid);
void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uint8_t *buffer, int32_t len, uint32_t msgid);
int32_t dvbapi_open_device(int32_t, int32_t, int);
int32_t dvbapi_stop_filternum(int32_t demux_id, int32_t num, uint32_t msgid);
int32_t dvbapi_stop_filter(int32_t demux_id, int32_t type, uint32_t msgid);
struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type);
void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er);
void dvbapi_write_cw(int32_t demux_id, int32_t pid, int32_t stream_id, uint8_t *cw, uint8_t cw_length, uint8_t *iv, uint8_t iv_length, enum ca_descr_algo algo, enum ca_descr_cipher_mode cipher_mode, uint32_t msgid);
int32_t dvbapi_parse_capmt(const uint8_t *buffer, uint32_t length, int32_t connfd, char *pmtfile, uint16_t client_proto_version, uint32_t msgid);
void request_cw(struct s_client *client, ECM_REQUEST *er, int32_t demux_id, uint8_t delayed_ecm_check);
void dvbapi_try_next_caid(int32_t demux_id, int8_t checked, uint32_t msgid);
void dvbapi_read_priority(void);
int32_t dvbapi_set_section_filter(int32_t demux_id, ECM_REQUEST *er, int32_t n);
int32_t dvbapi_activate_section_filter(int32_t demux_id, int32_t num, int32_t fd, int32_t pid, uint8_t *filter, uint8_t *mask, uint32_t msgid);
int32_t dvbapi_check_ecm_delayed_delivery(int32_t demux_id, ECM_REQUEST *er);
int32_t dvbapi_get_filternum(int32_t demux_id, ECM_REQUEST *er, int32_t type);
uint32_t dvbapi_ca_set_pid(int32_t demux_id, int32_t pid, int32_t stream_id, bool use_des, uint32_t msgid);
void dvbapi_set_pid(int32_t demux_id, int32_t num, uint32_t idx, bool enable, bool use_des, uint32_t msgid);
int8_t update_streampid_list(uint8_t cadevice, uint16_t pid, uint32_t idx, bool use_des);
int8_t remove_streampid_from_list(uint8_t cadevice, uint16_t pid, uint32_t idx);
void disable_unused_streampids(int16_t demux_id);
uint32_t is_ca_used(uint8_t cadevice, int32_t pid);
uint32_t count_active_indexers(void);
uint16_t dvbapi_get_client_proto_version(void);
const char *dvbapi_get_client_name(void);
void rotate_emmfilter(int32_t demux_id);
int32_t filtermatch(uint8_t *buffer, int32_t filter_num, int32_t demux_id, int32_t len);
void delayer(ECM_REQUEST *er, uint32_t delay);
void check_add_emmpid(int32_t demux_id, uint8_t *filter, int32_t l, int32_t emmtype);
void *dvbapi_start_handler(struct s_client *cl, uint8_t *mbuf, int32_t module_idx, void *(*_main_func)(void *));
uint32_t dvbapi_get_desc_index(int32_t demux_id, int32_t pid, int32_t stream_id);
void dvbapi_write_ecminfo_file(struct s_client *client, ECM_REQUEST *er, uint8_t *lastcw0, uint8_t *lastcw1, uint8_t cw_length);

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
