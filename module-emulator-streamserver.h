#ifndef MODULE_EMULATOR_STREAMSERVER_H_
#define MODULE_EMULATOR_STREAMSERVER_H_

#ifdef WITH_EMU

#define EMU_STREAM_SERVER_MAX_CONNECTIONS 8
#define EMU_STREAM_MAX_AUDIO_SUB_TRACKS 16

#define EMU_DVB_MAX_TS_PACKETS 278
#define EMU_DVB_BUFFER_SIZE_CSA 188*EMU_DVB_MAX_TS_PACKETS
#define EMU_DVB_BUFFER_WAIT_CSA 188*(EMU_DVB_MAX_TS_PACKETS-128)
#define EMU_DVB_BUFFER_SIZE_DES 188*32
#define EMU_DVB_BUFFER_WAIT_DES 188*29
#define EMU_DVB_BUFFER_SIZE EMU_DVB_BUFFER_SIZE_CSA

typedef struct
{
	uint32_t pvu_des_ks[8][2][32];
	int8_t pvu_csa_used;
	void* pvu_csa_ks[8];
	int8_t icam_csa_used;
	uint32_t* icam_csa_ks;
} emu_stream_client_key_data;

typedef struct
{
	int32_t connid;
	int8_t have_cat_data;
	int8_t have_pat_data;
	int8_t have_pmt_data;
	int8_t have_ecm_data;
	int8_t have_emm_data;
	int8_t reset_key_data;
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
	uint16_t video_pid;
	uint16_t teletext_pid;
	uint16_t pcr_pid;
	uint16_t audio_pids[EMU_STREAM_MAX_AUDIO_SUB_TRACKS];
	uint8_t audio_pid_count;
	int16_t ecm_nb;
	emu_stream_client_key_data key;
} emu_stream_client_data;

extern char emu_stream_source_host[256];
extern int32_t emu_stream_source_port;
extern char *emu_stream_source_auth;
extern int32_t emu_stream_relay_port;
extern int8_t emu_stream_emm_enabled;

extern int8_t stream_server_thread_init;

void *stream_server(void *a);
void stop_stream_server(void);

typedef struct
{
	struct timeb write_time;
	int8_t csa_used;
	int8_t is_even;
	uint8_t cw[8][8];
} emu_stream_cw_item;

extern pthread_mutex_t emu_fixed_key_srvid_mutex;
extern uint16_t emu_stream_cur_srvid[EMU_STREAM_SERVER_MAX_CONNECTIONS];
extern int8_t stream_server_has_ecm[EMU_STREAM_SERVER_MAX_CONNECTIONS];

extern pthread_mutex_t emu_fixed_key_data_mutex[EMU_STREAM_SERVER_MAX_CONNECTIONS];
extern emu_stream_client_key_data emu_fixed_key_data[EMU_STREAM_SERVER_MAX_CONNECTIONS];
extern LLIST *ll_emu_stream_delayed_keys[EMU_STREAM_SERVER_MAX_CONNECTIONS];

void *stream_key_delayer(void *arg);
bool stream_write_cw(ECM_REQUEST *er);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_STREAMSERVER_H_
