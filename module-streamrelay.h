#ifndef MODULE_STREAMRELAY_H_
#define MODULE_STREAMRELAY_H_

#ifdef MODULE_STREAMRELAY

#define STREAM_SERVER_MAX_CONNECTIONS 16

#define DVB_MAX_TS_PACKETS 278
#define DVB_BUFFER_SIZE_CSA 188*DVB_MAX_TS_PACKETS
#define DVB_BUFFER_WAIT_CSA 188*(DVB_MAX_TS_PACKETS-128)
#define DVB_BUFFER_SIZE DVB_BUFFER_SIZE_CSA

//#define __BISS__
#ifdef __BISS__
#define MAX_STREAM_PIDS 32 
#endif

#include "cscrypt/md5.h"
#include <dvbcsa/dvbcsa.h>
#if DVBCSA_KEY_ECM > 0
#define dvbcsa_bs_key_set(a,b) dvbcsa_bs_key_set_ecm(ecm,a,b)
#define DVBCSA_ECM_HEADER 1
#endif
#ifndef DVBCSA_ECM_HEADER
#define DVBCSA_ECM_HEADER 0
#endif
#ifndef LIBDVBCSA_LIB
#define LIBDVBCSA_LIB ""
#endif

#define EVEN 0
#define ODD 1

typedef struct
{
	struct dvbcsa_bs_key_s *key[2];
} stream_client_key_data;

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
} stream_client_data;

void *stream_server(void *a);
void init_stream_server(void);
void stop_stream_server(void);

bool stream_write_cw(ECM_REQUEST *er);

#endif // MODULE_STREAMRELAY

#endif // MODULE_STREAMRELAY_H_
