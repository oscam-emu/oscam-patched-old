#ifndef MODULE_STREAMRELAY_H_
#define MODULE_STREAMRELAY_H_

#ifdef MODULE_STREAMRELAY

#define STREAM_SERVER_MAX_CONNECTIONS 16

#define DVB_MAX_TS_PACKETS 278
#define DVB_BUFFER_SIZE_CSA 188*DVB_MAX_TS_PACKETS
#define DVB_BUFFER_WAIT_CSA 188*(DVB_MAX_TS_PACKETS-128)
#define DVB_BUFFER_SIZE DVB_BUFFER_SIZE_CSA

#ifdef WITH_EMU
#define EMU_STREAM_MAX_AUDIO_SUB_TRACKS 4
#define EMU_DVB_BUFFER_SIZE_CSA DVB_BUFFER_SIZE_CSA
#define EMU_DVB_BUFFER_WAIT_CSA DVB_BUFFER_WAIT_CSA
#define EMU_DVB_BUFFER_SIZE_DES 188*32
#define EMU_DVB_BUFFER_WAIT_DES 188*29
#define EMU_STREAM_SERVER_MAX_CONNECTIONS STREAM_SERVER_MAX_CONNECTIONS
#define emu_fixed_key_srvid_mutex fixed_key_srvid_mutex
#define emu_stream_cur_srvid stream_cur_srvid
#define emu_stream_client_data stream_client_data
#endif

//#define __BISS__
#ifdef __BISS__
#define MAX_STREAM_PIDS 32 
#endif

#include "cscrypt/md5.h"
#include <dvbcsa/dvbcsa.h>

#define EVEN 0
#define ODD 1

typedef struct
{
#ifdef WITH_EMU
	struct dvbcsa_bs_key_s *key[EMU_STREAM_MAX_AUDIO_SUB_TRACKS + 2][2];
#else
	struct dvbcsa_bs_key_s *key[2];
#endif
} stream_client_key_data;

#ifdef WITH_EMU
typedef struct
{
	uint32_t pvu_des_ks[EMU_STREAM_MAX_AUDIO_SUB_TRACKS + 2][2][32];
	int8_t csa_used;
	int32_t connid;
} emu_stream_client_key_data;
#endif

typedef struct
{
	int32_t connid;
	int8_t have_cat_data;
	int8_t have_pat_data;
	int8_t have_pmt_data;
	int8_t have_ecm_data;
	int8_t have_emm_data;
	uint8_t cat_data[1024+208];
	uint8_t pat_data[1024+208];
	uint8_t pmt_data[1024+208];
	uint8_t ecm_data[1024+208];
	uint8_t emm_data[1024+208];
	uint16_t cat_data_pos;
	uint16_t pat_data_pos;
	uint16_t pmt_data_pos;
	uint16_t ecm_data_pos;
	uint16_t emm_data_pos;
	uint16_t srvid;
	uint16_t caid;
	uint16_t tsid;
	uint16_t onid;
	uint32_t ens;
	uint16_t pmt_pid;
	uint16_t ecm_pid;
	uint16_t emm_pid;
	uint16_t pcr_pid;
#ifdef __BISS__
	uint8_t STREAMpidcount;
	uint16_t STREAMpids[MAX_STREAM_PIDS];
#endif
	uint8_t ecm_md5[MD5_DIGEST_LENGTH];
#ifdef WITH_EMU
	int16_t ecm_nb;
	int8_t reset_key_data;
	uint16_t video_pid;
	uint16_t teletext_pid;
	uint16_t audio_pids[EMU_STREAM_MAX_AUDIO_SUB_TRACKS];
	uint8_t audio_pid_count;
	emu_stream_client_key_data key;
#endif
} stream_client_data;

void *stream_server(void *a);
void init_stream_server(void);
void stop_stream_server(void);

bool stream_write_cw(ECM_REQUEST *er);

#ifdef WITH_EMU
extern int8_t stream_server_thread_init;
extern pthread_mutex_t fixed_key_srvid_mutex;
extern uint16_t stream_cur_srvid[STREAM_SERVER_MAX_CONNECTIONS];
extern int8_t stream_server_has_ecm[STREAM_SERVER_MAX_CONNECTIONS];
extern uint8_t emu_stream_server_mutex_init;
extern bool has_dvbcsa_ecm;

typedef struct
{
	struct timeb write_time;
	int8_t csa_used;
	int8_t is_even;
	uint8_t cw[8][8];
} emu_stream_cw_item;

extern pthread_mutex_t emu_fixed_key_data_mutex[EMU_STREAM_SERVER_MAX_CONNECTIONS];
extern stream_client_key_data key_data[STREAM_SERVER_MAX_CONNECTIONS];
extern emu_stream_client_key_data emu_fixed_key_data[EMU_STREAM_SERVER_MAX_CONNECTIONS];

extern LLIST *ll_emu_stream_delayed_keys[EMU_STREAM_SERVER_MAX_CONNECTIONS];
void *stream_key_delayer(void *arg);
#endif // WITH_EMU

#endif // MODULE_STREAMRELAY

#endif // MODULE_STREAMRELAY_H_
