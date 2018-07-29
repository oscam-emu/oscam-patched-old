#define MODULE_LOG_PREFIX "emu"

#include "globals.h"
#include "cscrypt/des.h"

#ifdef WITH_EMU
#include "oscam-string.h"
#include "oscam-config.h"
#include "oscam-time.h"
#include "oscam-net.h"

extern int32_t exit_oscam;
#endif

#include "ffdecsa/ffdecsa.h"
#include "module-emulator-osemu.h"
#include "module-emulator-stream.h"

typedef struct
{
	int32_t connfd;
	int32_t connid;	
} emu_stream_client_conn_data;

int8_t stream_server_thread_init = 0;
char emu_stream_source_host[256] = {"127.0.0.1"};
int32_t emu_stream_source_port = 8001;
char *emu_stream_source_auth = NULL;
int32_t emu_stream_relay_port = 17999;
int8_t emu_stream_emm_enabled = 0;
uint32_t cluster_size = 50;

static uint8_t emu_stream_server_mutex_init = 0;
static pthread_mutex_t emu_stream_server_mutex;
static int32_t glistenfd, gconncount = 0, gconnfd[EMU_STREAM_SERVER_MAX_CONNECTIONS];

#ifdef WITH_EMU
pthread_mutex_t emu_fixed_key_srvid_mutex;
uint16_t emu_stream_cur_srvid[EMU_STREAM_SERVER_MAX_CONNECTIONS];
int8_t stream_server_has_ecm[EMU_STREAM_SERVER_MAX_CONNECTIONS];

pthread_mutex_t emu_fixed_key_data_mutex[EMU_STREAM_SERVER_MAX_CONNECTIONS];
emu_stream_client_key_data emu_fixed_key_data[EMU_STREAM_SERVER_MAX_CONNECTIONS];
LLIST *ll_emu_stream_delayed_keys[EMU_STREAM_SERVER_MAX_CONNECTIONS];
#endif

static void SearchTsPackets(uint8_t *buf, uint32_t bufLength, uint16_t *packetSize, uint16_t *startOffset)
{
	uint32_t i;
	
	(*packetSize) = 0;
	(*startOffset) = 0;

	for(i=0; i<bufLength; i++) {
		if(buf[i] == 0x47) {
			if((buf[i+188] == 0x47) & (buf[i+376] == 0x47)) { // if three packets align, probably safe to assume correct size.
				(*packetSize) = 188;
				(*startOffset) = i;
				return;
			}
			else if((buf[i+204] == 0x47) & (buf[i+408] == 0x47)) {
				(*packetSize) = 204;
				(*startOffset) = i;
				return;
			}
			else if((buf[i+208] == 0x47) & (buf[i+416] == 0x47)) {
				(*packetSize) = 208;
				(*startOffset) = i;
				return;
			}
		}
	}
}

typedef void (*ts_data_callback)(emu_stream_client_data *cdata);

static void ParseTSData(uint8_t table_id, uint8_t table_mask, uint8_t min_table_length, int8_t* flag, uint8_t* data,
							uint16_t data_length, uint16_t* data_pos, int8_t payloadStart, uint8_t* buf, int32_t len,
							ts_data_callback func, emu_stream_client_data *cdata)
{
	uint16_t section_length;
	int32_t i;
	int8_t found_start = 0;
	uint16_t offset = 0;
	int32_t free_data_length;
	int32_t copySize;
	
	if(len < 1)
		{ return; }
	
	if(*flag == 0 && !payloadStart)
		{ return; }

	if(*flag == 0)
	{
		*data_pos = 0;
		 offset = 1 + buf[0];
	}
	else if(payloadStart)
	{
		offset = 1;
	}
	
	if(len-offset < 1)
		{ return; }
	
	free_data_length = data_length - *data_pos;
	copySize = (len-offset) > free_data_length ? free_data_length : (len-offset);
	
	memcpy(data+(*data_pos), buf+offset, copySize);
	(*data_pos) += copySize;

	found_start = 0;
	for(i=0; i < *data_pos; i++)
	{
		if((data[i] & table_mask) == table_id)
		{
			if(i != 0)
			{
				if((*data_pos)-i > i)
					{ memmove(data, &data[i], (*data_pos)-i); }
				else
					{ memcpy(data, &data[i], (*data_pos)-i); }
				
				*data_pos -= i;
			}
			found_start = 1;
			break;
		}
	}
	if(!found_start)
		{ *flag = 0; return; }

	*flag = 2;

	if(*data_pos < 3)
		{ return; }

	section_length = SCT_LEN(data);

	if(section_length > data_length || section_length < min_table_length)
		{ *flag = 0; return; }
	
	if((*data_pos) < section_length)
		{ return; }

	func(cdata);
	
	found_start = 0;
	for(i=section_length; i < *data_pos; i++)
	{
		if((data[i] & table_mask) == table_id)
		{
			if((*data_pos)-i > i)
				{ memmove(data, &data[i], (*data_pos)-i); }
			else
				{ memcpy(data, &data[i], (*data_pos)-i); }
			
			*data_pos -= i;
			found_start = 1;
			break;
		}	
	}	
	if(!found_start)
		{ *data_pos = 0; }
	
	*flag = 1;
}

static void ParsePATData(emu_stream_client_data *cdata)
{
	uint8_t* data = cdata->pat_data;
	uint16_t section_length = SCT_LEN(data);
	uint16_t srvid;
	int32_t i;

	for(i=8; i+7<section_length; i+=4)
	{
		srvid = b2i(2, data+i);
		
		if(srvid == 0)
			{ continue; }
		
		if(cdata->srvid == srvid)
		{
			cdata->pmt_pid = b2i(2, data+i+2) & 0x1FFF;
			cs_log_dbg(D_READER, "Stream %i found pmt pid: 0x%04X (%i)",cdata->connid, cdata->pmt_pid, cdata->pmt_pid);
			break;
		}
	}
}

static void ParsePMTData(emu_stream_client_data *cdata)
{
	uint8_t* data = cdata->pmt_data;
	
	uint16_t section_length = SCT_LEN(data);
	int32_t i;
	uint16_t program_info_length = 0, es_info_length = 0;
	uint8_t descriptor_tag = 0, descriptor_length = 0;
	uint8_t stream_type;
	uint16_t stream_pid, caid;

	cdata->pcr_pid = b2i(2, data+8) &0x1FFF;
	if(cdata->pcr_pid != 0x1FFF)
	{
		cs_log_dbg(D_READER, "Stream %i found pcr pid: 0x%04X (%i)",cdata->connid, cdata->pcr_pid, cdata->pcr_pid);
	}
	
	program_info_length = b2i(2, data+10) &0xFFF;
	
	if(12+program_info_length >= section_length)
		{ return; }
	
	for(i=12; i+1 < 12+program_info_length; i+=descriptor_length+2)
	{
		descriptor_tag = data[i];
		descriptor_length = data[i+1];
		
		if(descriptor_length < 1)
			{ break; }
			
		if(i+1+descriptor_length >= 12+program_info_length)
			{ break; }
		
		if(descriptor_tag == 0x09 && descriptor_length >= 4)
		{
			caid = b2i(2, data+i+2);
			
			if(caid>>8 == 0x0E)
			{
				cdata->ecm_pid = b2i(2, data+i+4) &0x1FFF;
				cs_log_dbg(D_READER, "Stream %i found ecm pid: 0x%04X (%i)", cdata->connid, cdata->ecm_pid, cdata->ecm_pid);
				break;
			}
		}
	}
	
	for(i=12+program_info_length; i+4<section_length; i+=5+es_info_length)
	{
		stream_type = data[i];
		stream_pid = b2i(2, data+i+1) &0x1FFF;
		es_info_length = b2i(2, data+i+3) &0xFFF;
		
		if(stream_type == 0x01 || stream_type == 0x02 || stream_type == 0x10 || stream_type == 0x1B 
			|| stream_type == 0x24 || stream_type == 0x42 || stream_type == 0x80 || stream_type == 0xD1 
			|| stream_type == 0xEA)
		{
			cdata->video_pid = stream_pid;
			cs_log_dbg(D_READER, "Stream %i found video pid: 0x%04X (%i)",cdata->connid, stream_pid, stream_pid);
		}
		
		else if(stream_type == 0x03 || stream_type == 0x04 || stream_type == 0x05 || stream_type == 0x06 ||
				stream_type == 0x0F || stream_type == 0x11 || (stream_type >= 0x81 && stream_type <= 0x87) || stream_type == 0x8A)
		{
			if(cdata->audio_pid_count >= EMU_STREAM_MAX_AUDIO_SUB_TRACKS)
				{ continue; }
			
			cdata->audio_pids[cdata->audio_pid_count] = stream_pid;
			cdata->audio_pid_count++;
			cs_log_dbg(D_READER, "Stream %i found audio pid: 0x%04X (%i)", cdata->connid, stream_pid, stream_pid);
		}
	}
}

static void ParseCATData(emu_stream_client_data *cdata)
{
	uint8_t* data = cdata->cat_data;
	uint32_t i;
	
	for(i = 8; i < (b2i(2, data + 1)&0xFFF) - 1; i += data[i + 1] + 2)
	{
		if(data[i] != 0x09) { continue; }
		
		uint16_t caid = b2i(2, data + i + 2);
		uint16_t emm_pid = b2i(2, data + i +4)&0x1FFF;
		
		if(caid>>8 == 0x0E)
		{
			cdata->emm_pid = emm_pid;
			cs_log_dbg(D_READER, "Stream %i found audio pid: 0x%04X (%i)", cdata->connid, emm_pid, emm_pid);
			break;
		}
	}
}

static void ParseEMMData(emu_stream_client_data *cdata)
{
	uint8_t* data = cdata->emm_data;
	uint32_t keysAdded = 0;
	
	ProcessEMM(NULL, 0x0E00, 0, data, &keysAdded);
	
	if(keysAdded)
	{
		cs_log("Stream %i found %i keys", cdata->connid, keysAdded);
	}
}

static void ParseECMData(emu_stream_client_data *cdata)
{
	uint8_t* data = cdata->ecm_data;
	uint16_t section_length = SCT_LEN(data);
	uint8_t dcw[16];
	
	if(section_length < 0xb)
		{ return; }

	if(data[0xb] > cdata->ecm_nb || (cdata->ecm_nb == 255 && data[0xb] == 0)
		|| ((cdata->ecm_nb - data[0xb]) > 5))
	{
		cdata->ecm_nb = data[0xb];
#ifdef WITH_EMU
		PowervuECM(data, dcw, cdata->srvid, &cdata->key, NULL);
#else
		PowervuECM(data, dcw, &cdata->key);
#endif
	}
}

static void ParseTSPackets(emu_stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
{
	uint32_t i, j, k;
	uint32_t tsHeader;
	uint16_t pid, offset;
	uint8_t scramblingControl, payloadStart, oddeven;
	int8_t oddKeyUsed;
	uint32_t *deskey;
	uint8_t *pdata;
	uint8_t *packetClusterA[EMU_STREAM_MAX_AUDIO_SUB_TRACKS][64]; // separate cluster arrays for video and each audio track
	uint8_t *packetClusterV[256];
	void *csakeyA[EMU_STREAM_MAX_AUDIO_SUB_TRACKS] = {0};
	void *csakeyV = 0;
	emu_stream_client_key_data *keydata;
	uint32_t scrambled_packets = 0;
	uint32_t scrambled_packetsA[EMU_STREAM_MAX_AUDIO_SUB_TRACKS] = {0};
	packetClusterV[0] = NULL;
	uint32_t cs =0; // video cluster start
	uint32_t ce =1; // video cluster end
	uint32_t csa[EMU_STREAM_MAX_AUDIO_SUB_TRACKS] = {0}; // cluster index for audio tracks
	
	for(i=0; i<bufLength; i+=packetSize)
	{
		tsHeader = b2i(4, stream_buf+i);
		pid = (tsHeader & 0x1fff00) >> 8;
		scramblingControl = tsHeader & 0xc0;
		payloadStart = (tsHeader & 0x400000) >> 22;
		
		if(tsHeader & 0x20)
			{ offset = 4 + stream_buf[i+4] + 1; }
		else
			{ offset = 4; }
		
		if(packetSize-offset < 1)
			{ continue; }
		
		if(pid == 1)
		{
			// set to null pid
			stream_buf[i+1] |= 0x1f;
			stream_buf[i+2]  = 0xff;
			
			if(emu_stream_emm_enabled && !data->emm_pid)
			{
				ParseTSData(0x01, 0xFF, 8, &data->have_cat_data, data->cat_data, sizeof(data->cat_data), &data->cat_data_pos, payloadStart, 
											stream_buf+i+offset, packetSize-offset, ParseCATData, data);
				continue;
			}
		}
		
		if(emu_stream_emm_enabled && data->emm_pid && pid == data->emm_pid)
		{	
			// set to null pid
			stream_buf[i+1] |= 0x1f;
			stream_buf[i+2]  = 0xff;
			
			ParseTSData(0x80, 0xF0, 3, &data->have_emm_data, data->emm_data, sizeof(data->emm_data), &data->emm_data_pos, payloadStart, 
										stream_buf+i+offset, packetSize-offset, ParseEMMData, data);
			continue;
		}
		
		if(pid == 0 && !data->pmt_pid)
		{
			ParseTSData(0x00, 0xFF, 16, &data->have_pat_data, data->pat_data, sizeof(data->pat_data), &data->pat_data_pos, payloadStart, 
										stream_buf+i+offset, packetSize-offset, ParsePATData, data);		
			continue;
		}
		
		if(!data->ecm_pid && pid == data->pmt_pid)
		{
			ParseTSData(0x02, 0xFF, 21, &data->have_pmt_data, data->pmt_data, sizeof(data->pmt_data), &data->pmt_data_pos, payloadStart, 
										stream_buf+i+offset, packetSize-offset, ParsePMTData, data);	
			continue;
		}
		
		if(data->ecm_pid && pid == data->ecm_pid)
		{
#ifdef WITH_EMU
			stream_server_has_ecm[data->connid] = 1;
#endif
			
			// set to null pid
			stream_buf[i+1] |= 0x1f; 
			stream_buf[i+2]  = 0xff;
			
			ParseTSData(0x80, 0xFE, 3, &data->have_ecm_data, data->ecm_data, sizeof(data->ecm_data), &data->ecm_data_pos, payloadStart, 
										stream_buf+i+offset, packetSize-offset, ParseECMData, data);
			continue;
		}
		
		if(scramblingControl == 0)
			{ continue; }
		
		if(!(stream_buf[i+3] & 0x10))
		{
			stream_buf[i+3] &= 0x3F;
			continue;
		}
		
		oddKeyUsed = scramblingControl == 0xC0 ? 1 : 0;
		
#ifdef WITH_EMU
		if(!stream_server_has_ecm[data->connid])
		{
			keydata = &emu_fixed_key_data[data->connid];
			SAFE_MUTEX_LOCK(&emu_fixed_key_data_mutex[data->connid]);
			data->key.pvu_csa_used = keydata->pvu_csa_used;
		}
		else
		{
#endif
			keydata = &data->key;
#ifdef WITH_EMU
		}
#endif
		
		if(keydata->pvu_csa_used)
		{
			oddeven = scramblingControl; // for detecting odd/even switch
			
			if(pid == data->video_pid) // start with video pid, since it is most dominant
			{
				csakeyV = keydata->pvu_csa_ks[PVU_CW_VID];
				
				if(csakeyV !=NULL)
				{
					cs=0;
					ce=1;
					packetClusterV[cs] = stream_buf+i; // set first cluster start
					packetClusterV[ce] = stream_buf+i+packetSize-1;
					scrambled_packets=1;
					
					for(j = i+packetSize; j < bufLength; j += packetSize) // Now iterate through the rest of the packets and create clusters for batch decryption
					{
						tsHeader = b2i(4, stream_buf+j);
						pid = (tsHeader & 0x1fff00) >> 8;
						if(pid == data->video_pid)
						{
							if(oddeven != (tsHeader & 0xc0)) // changed key so stop adding clusters
							{
								break;
							}
							if(cs > ce) // First video packet for each cluster
							{
								packetClusterV[cs] = stream_buf+j;
								ce = cs+1;
							}
							
							scrambled_packets++;
						}
						else
						{
							if(cs < ce) // First non-video packet - need to set end of video cluster
							{
								packetClusterV[ce] = stream_buf+j-1;
								cs = ce+1;
							}
							
							if((tsHeader & 0xc0) == 0) {
								continue;
							}
							
							if(oddeven != (tsHeader & 0xc0)) // changed key so stop adding clusters
							{
								j = bufLength; // to break out of outer loop also
								break;
							}
							
							for(k = 0; k < data->audio_pid_count; k++) // Check for audio tracks and create single packet clusters
							{
								if(pid == data->audio_pids[k])
								{
									packetClusterA[k][csa[k]] = stream_buf+j;
									csa[k]++;
									packetClusterA[k][csa[k]] = stream_buf+j+packetSize-1;
									csa[k]++;
									scrambled_packetsA[k]++;
								}
							}
						}
					}
					
					if( cs > ce ) // last packet was not a video packet, so set null for end of all clusters
						{ packetClusterV[cs] = NULL; }
					else 
					{
						if(scrambled_packets > 1) // last packet was a video packet, so set end of cluster to end of last packet
						{
							packetClusterV[ce] = stream_buf+j-1;
						}
						packetClusterV[ce+1] = NULL; // add null to end of cluster list
					}
					
					while( j >= cluster_size )
						{ j = decrypt_packets(csakeyV, packetClusterV); }
					
					for(k = 0; k < data->audio_pid_count; k++)
					{
						if(scrambled_packetsA[k]) // if audio track has scrambled packets, set null to mark end and decrypt
						{
							csakeyA[k] = keydata->pvu_csa_ks[PVU_CW_A1+k];
							packetClusterA[k][csa[k]] = NULL;
							decrypt_packets(csakeyA[k], packetClusterA[k]);
							csa[k]=0;
							scrambled_packetsA[k] = 0;
						}
					}
				}
			}
			else
			{
				for(j = 0; j < data->audio_pid_count; j++)
					if(pid == data->audio_pids[j])
						{ csakeyA[0] = keydata->pvu_csa_ks[PVU_CW_A1+j]; }
				
				if(csakeyA[0] != NULL)
				{
					packetClusterA[0][0] = stream_buf+i;
					packetClusterA[0][1] = stream_buf+i+packetSize -1;
					packetClusterA[0][2] = NULL;
					decrypt_packets(csakeyA[0], packetClusterA[0]);
				}
			}
		}
		else
		{
			deskey = NULL;
			
			if(pid == data->video_pid)
				{ deskey = keydata->pvu_des_ks[PVU_CW_VID][oddKeyUsed]; }
			else
			{
				for(j = 0; j < data->audio_pid_count; j++)
					if(pid == data->audio_pids[j])
						{ deskey = keydata->pvu_des_ks[PVU_CW_A1+j][oddKeyUsed]; }
			}
			
			if(deskey == NULL)
			{
				deskey = keydata->pvu_des_ks[PVU_CW_HSD][oddKeyUsed];
			}
			
			for(j = offset; j+7 < 188; j += 8)
			{
				pdata = stream_buf+i+j;
				des(pdata, deskey, 0);
			}
			
			stream_buf[i+3] &= 0x3F;
		}
		
#ifdef WITH_EMU
		if(!stream_server_has_ecm[data->connid])
		{
			SAFE_MUTEX_UNLOCK(&emu_fixed_key_data_mutex[data->connid]);
		}
#endif
	}
}

static int32_t connect_to_stream(char *http_buf, int32_t http_buf_len, char *stream_path)
{
	struct sockaddr_in cservaddr;
	IN_ADDR_T in_addr;
	
	int32_t streamfd = socket(AF_INET, SOCK_STREAM, 0);
	if(streamfd == -1)
		{ return -1; }

	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if(setsockopt(streamfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv))
	{
		cs_log("ERROR: setsockopt() failed for SO_RCVTIMEO");
		return -1;
	}

	bzero(&cservaddr, sizeof(cservaddr));
	cservaddr.sin_family = AF_INET;
	cs_resolve(emu_stream_source_host, &in_addr, NULL, NULL);
	SIN_GET_ADDR(cservaddr) = in_addr;
	cservaddr.sin_port = htons(emu_stream_source_port);
	
	if(connect(streamfd, (struct sockaddr *)&cservaddr, sizeof(cservaddr)) == -1)
		{ return -1; }
	if(emu_stream_source_auth)
	{
		snprintf(http_buf, http_buf_len, "GET %s HTTP/1.1\nHost: %s:%u\n"
				"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0\n"
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
				"Accept-Language: en-US\n"
				"Authorization: Basic %s\n"
				"Connection: keep-alive\n\n", stream_path, emu_stream_source_host, emu_stream_source_port, emu_stream_source_auth);
	}
	else
	{
		snprintf(http_buf, http_buf_len, "GET %s HTTP/1.1\nHost: %s:%u\n"
				"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0\n"
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
				"Accept-Language: en-US\n"
				"Connection: keep-alive\n\n", stream_path, emu_stream_source_host, emu_stream_source_port);
	}

	if(send(streamfd, http_buf, strlen(http_buf), 0) == -1)
		{ return -1; }
	
	return streamfd;
}

static void stream_client_disconnect(emu_stream_client_conn_data *conndata)
{
	int32_t i;
	
#ifdef WITH_EMU
	SAFE_MUTEX_LOCK(&emu_fixed_key_srvid_mutex);
	emu_stream_cur_srvid[conndata->connid] = NO_SRVID_VALUE;
	stream_server_has_ecm[conndata->connid] = 0;
	SAFE_MUTEX_UNLOCK(&emu_fixed_key_srvid_mutex);
#endif
	
	SAFE_MUTEX_LOCK(&emu_stream_server_mutex);
	for(i=0; i<EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if(gconnfd[i] == conndata->connfd)
		{
			gconnfd[i] = -1;
			gconncount--;
		}
	}
	SAFE_MUTEX_UNLOCK(&emu_stream_server_mutex);
	
	shutdown(conndata->connfd, 2);
	close(conndata->connfd);
	
	cs_log("Stream client %i disconnected",conndata->connid);
	
	NULLFREE(conndata);
}

static void *stream_client_handler(void *arg)
{
#define EMU_DVB_MAX_TS_PACKETS 278
#define EMU_DVB_BUFFER_SIZE_CSA 188*EMU_DVB_MAX_TS_PACKETS
#define EMU_DVB_BUFFER_WAIT_CSA 188*(EMU_DVB_MAX_TS_PACKETS-128)
#define EMU_DVB_BUFFER_SIZE_DES 188*32
#define EMU_DVB_BUFFER_WAIT_DES 188*29
#define EMU_DVB_BUFFER_SIZE EMU_DVB_BUFFER_SIZE_CSA

	emu_stream_client_conn_data *conndata = (emu_stream_client_conn_data *)arg;
	char *http_buf, stream_path[255], stream_path_copy[255];
	int32_t streamfd;
	int32_t clientStatus, streamStatus;
	uint8_t *stream_buf;
	uint16_t packetCount = 0, packetSize = 0, startOffset = 0;
	uint32_t remainingDataPos, remainingDataLength;
	int32_t cur_dvb_buffer_size, cur_dvb_buffer_wait;
	int32_t bytesRead = 0;
	emu_stream_client_data *data;
	int8_t streamConnectErrorCount = 0;
	int8_t streamDataErrorCount = 0;
	int32_t i, srvidtmp;
	char *saveptr, *token;
	char http_version[4];
	int32_t http_status_code = 0;

	cs_log("Stream client %i connected", conndata->connid);
	
	if(!cs_malloc(&http_buf, 1024))
	{
		stream_client_disconnect(conndata);
		return NULL;
	}
	
	if(!cs_malloc(&stream_buf, EMU_DVB_BUFFER_SIZE))
	{
		NULLFREE(http_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}
	
	if(!cs_malloc(&data, sizeof(emu_stream_client_data)))
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}
	
	clientStatus = recv(conndata->connfd, http_buf, 1024, 0);
	if(clientStatus < 1)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}
	
	http_buf[1023] = '\0';
	if(sscanf(http_buf, "GET %254s ", stream_path) < 1)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}
	
	cs_strncpy(stream_path_copy, stream_path, sizeof(stream_path));
	
	token = strtok_r(stream_path_copy, ":", &saveptr);

	for(i=0; token != NULL && i<3; i++)
	{
		token = strtok_r(NULL, ":", &saveptr);
		if(token == NULL)
			{ break; }
	}
	if(token != NULL)
	{
		if(sscanf(token, "%x", &srvidtmp) < 1)
		{
			token = NULL;
		}
		else
		{
			data->srvid = srvidtmp & 0xFFFF;
		}
	}

	if(token == NULL)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

#ifdef WITH_EMU
	SAFE_MUTEX_LOCK(&emu_fixed_key_srvid_mutex);
	emu_stream_cur_srvid[conndata->connid] = data->srvid;
	stream_server_has_ecm[conndata->connid] = 0;
	SAFE_MUTEX_UNLOCK(&emu_fixed_key_srvid_mutex);
#endif

	cs_log("Stream client %i request %s", conndata->connid, stream_path);

	snprintf(http_buf, 1024, "HTTP/1.0 200 OK\nConnection: Close\nContent-Type: video/mpeg\nServer: stream_enigma2\n\n");
	clientStatus = send(conndata->connfd, http_buf, strlen(http_buf), 0);

	data->connid = conndata->connid;

	while(!exit_oscam && clientStatus != -1 && streamConnectErrorCount < 3 && streamDataErrorCount < 15)
	{
		streamfd = connect_to_stream(http_buf, 1024, stream_path);
		if(streamfd == -1)
		{
			cs_log("WARNING: stream client %i cannot connect to stream source", conndata->connid);
			streamConnectErrorCount++;
			cs_sleepms(500);
			continue;
		}
		
		streamStatus = 0;
		bytesRead = 0;
		
		while(!exit_oscam && clientStatus != -1 && streamStatus != -1 && streamConnectErrorCount < 3 && streamDataErrorCount < 15)
		{
			if(data->key.pvu_csa_used)
			{
				cur_dvb_buffer_size = EMU_DVB_BUFFER_SIZE_CSA;
				cur_dvb_buffer_wait = EMU_DVB_BUFFER_WAIT_CSA;
			}
			else
			{
				cur_dvb_buffer_size = EMU_DVB_BUFFER_SIZE_DES;
				cur_dvb_buffer_wait = EMU_DVB_BUFFER_WAIT_DES;
			}
			
			streamStatus = recv(streamfd, stream_buf+bytesRead, cur_dvb_buffer_size-bytesRead, MSG_WAITALL);
			if(streamStatus == 0) // socket closed
			{
				cs_log("WARNING: stream client %i - stream source closed connection", conndata->connid);
				streamConnectErrorCount++;
				cs_sleepms(100);
				break;
			}
			
			if(streamStatus < 0) // error
			{
				if ((errno == EWOULDBLOCK) | (errno == EAGAIN)) {
					cs_log("WARNING: stream client %i no data from stream source", conndata->connid);
					streamDataErrorCount++; // 2 sec timeout * 15 = 30 seconds no data -> close
					cs_sleepms(100);
					continue;
				}
				
				cs_log("WARNING: stream client %i error receiving data from stream source", conndata->connid);
				streamConnectErrorCount++;
				cs_sleepms(100);
				break;
			}
			
			if(streamStatus < cur_dvb_buffer_size-bytesRead) // probably just received header but no stream
			{
				if(!bytesRead && streamStatus > 13 &&
					sscanf((const char*)stream_buf, "HTTP/%3s %d ", http_version , &http_status_code) == 2 &&
					http_status_code != 200)
				{
					cs_log("ERROR: stream client %i got %d response from stream source", conndata->connid, http_status_code);
					streamConnectErrorCount++;
					cs_sleepms(100);
					break;
				}
				else
				{
					cs_log_dbg(0, "WARNING: stream client %i non-full buffer from stream source", conndata->connid);
					streamDataErrorCount++;
					cs_sleepms(100);
				}
			}
			else
			{
				streamDataErrorCount = 0;
			}
			
			streamConnectErrorCount = 0;
			bytesRead += streamStatus;
			
			if(bytesRead >= cur_dvb_buffer_wait)
			{	
				startOffset = 0;
				if(stream_buf[0] != 0x47 || packetSize == 0) // only search if not starting on ts packet or unknown packet size
				{
					SearchTsPackets(stream_buf, bytesRead, &packetSize, &startOffset);
				}
				if(packetSize == 0)
				{
					bytesRead = 0;
				}
				else
				{
					packetCount = ((bytesRead-startOffset) / packetSize);
					
					ParseTSPackets(data, stream_buf+startOffset, packetCount*packetSize, packetSize);
					
					clientStatus = send(conndata->connfd, stream_buf+startOffset, packetCount*packetSize, 0);
						 
					remainingDataPos = startOffset+(packetCount*packetSize);
					remainingDataLength = bytesRead-remainingDataPos;
					
					if(remainingDataPos < remainingDataLength)
						{ memmove(stream_buf, stream_buf+remainingDataPos, remainingDataLength); }
					else
						{ memcpy(stream_buf, stream_buf+remainingDataPos, remainingDataLength); }
					
					bytesRead = remainingDataLength;
				}
			}
		}
		
		close(streamfd);
	}
	
	NULLFREE(http_buf);
	NULLFREE(stream_buf);
	for(i=0; i<8; i++)
	{
		if(data->key.pvu_csa_ks[i])
			{ free_key_struct(data->key.pvu_csa_ks[i]); }
	}
	NULLFREE(data);

	stream_client_disconnect(conndata);
	return NULL;
}

void *stream_server(void *UNUSED(a))
{
	struct sockaddr_in servaddr, cliaddr;
	socklen_t clilen;
	int32_t connfd, reuse = 1, i;
	int8_t connaccepted;
	emu_stream_client_conn_data *conndata;

	cluster_size = get_internal_parallelism();
	cs_log("INFO: FFDecsa parallel mode = %d", cluster_size);

	if(!emu_stream_server_mutex_init)
	{
		SAFE_MUTEX_INIT(&emu_stream_server_mutex, NULL);
		emu_stream_server_mutex_init = 1;
	}
	
#ifdef WITH_EMU
	SAFE_MUTEX_LOCK(&emu_fixed_key_srvid_mutex);
	for(i=0; i<EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		emu_stream_cur_srvid[i] = NO_SRVID_VALUE;
		stream_server_has_ecm[i] = 0;
	}
	SAFE_MUTEX_UNLOCK(&emu_fixed_key_srvid_mutex);
#endif
	
	for(i=0; i<EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		gconnfd[i] = -1;
	}
	
	glistenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(glistenfd == -1)
	{
		cs_log("ERROR: cannot create stream server socket");
		return NULL;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(emu_stream_relay_port);
	setsockopt(glistenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	
	if(bind(glistenfd,(struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
	{
		cs_log("ERROR: cannot bind to stream server socket");
		close(glistenfd);
		return NULL;
	}
	
	if(listen(glistenfd, 3) == -1)
	{
		cs_log("ERROR: cannot listen to stream server socket");
		close(glistenfd);
		return NULL;
	}
	
	while(!exit_oscam)
	{
		clilen = sizeof(cliaddr);
		connfd = accept(glistenfd,(struct sockaddr *)&cliaddr, &clilen);
		
		if(connfd == -1)
		{
			cs_log("ERROR: accept() failed");
			break;
		}
		
		connaccepted = 0;
		
		if(cs_malloc(&conndata, sizeof(emu_stream_client_conn_data)))
		{		
			SAFE_MUTEX_LOCK(&emu_stream_server_mutex);
			if(gconncount < EMU_STREAM_SERVER_MAX_CONNECTIONS)
			{
				for(i=0; i<EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
				{
					if(gconnfd[i] == -1)
					{
						gconnfd[i] = connfd;
						gconncount++;
						connaccepted = 1;
						
						conndata->connfd = connfd;
						conndata->connid = i;
						
						break;
					}
				}
			}
			SAFE_MUTEX_UNLOCK(&emu_stream_server_mutex);
		}
	
		if(connaccepted)
		{
			int on = 1;
			if(setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
			{
				cs_log("ERROR: stream client %i setsockopt() failed for TCP_NODELAY", conndata->connid);
			}
			
			start_thread("emu stream client", stream_client_handler, (void*)conndata, NULL, 1, 0);
		}
		else
		{
			shutdown(connfd, 2);
			close(connfd);
			cs_log("ERROR: stream server client dropped because of too many connections (%i)", EMU_STREAM_SERVER_MAX_CONNECTIONS);
		}
		
		cs_sleepms(20);
	}
	
	close(glistenfd);
	
	return NULL;
}

#ifdef WITH_EMU
void *stream_key_delayer(void *UNUSED(arg))
{
	int32_t i, j;
	emu_stream_client_key_data* cdata;
	LL_ITER it;
	emu_stream_cw_item *item;
	struct timeb t_now;
	
	while(!exit_oscam)
	{
		cs_ftime(&t_now);
		
		for(i=0; i<EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
		{
			it = ll_iter_create(ll_emu_stream_delayed_keys[i]);
			while((item = ll_iter_next(&it)))
			{
				if(comp_timeb(&t_now, &item->write_time) < 0)
				{
					break;
				}
				
				SAFE_MUTEX_LOCK(&emu_fixed_key_data_mutex[i]);
				
				cdata = &emu_fixed_key_data[i];
				
				for(j=0; j<8; j++)
				{
					if(item->csa_used)
					{	
						if(cdata->pvu_csa_ks[j] == NULL)
							{ cdata->pvu_csa_ks[j] = get_key_struct(); }
							
						if(item->is_even)
							{ set_even_control_word(cdata->pvu_csa_ks[j], item->cw[j]); }
						else
							{ set_odd_control_word(cdata->pvu_csa_ks[j], item->cw[j]); }
						
						cdata->pvu_csa_used = 1;
					}
					else
					{
						if(item->is_even)
							{ des_set_key(item->cw[j], cdata->pvu_des_ks[j][0]); }
						else
							{ des_set_key(item->cw[j], cdata->pvu_des_ks[j][1]); }
							
						cdata->pvu_csa_used = 0;
					}
				}
				
				SAFE_MUTEX_UNLOCK(&emu_fixed_key_data_mutex[i]);
				
				ll_iter_remove_data(&it);
			}
		}
		
		cs_sleepms(25);
	}
	
	return NULL;
}
#endif

void stop_stream_server(void)
{
	int32_t i;
	
	SAFE_MUTEX_LOCK(&emu_stream_server_mutex);
	for(i=0; i<EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if(gconnfd[i] != -1)
		{
			shutdown(gconnfd[i], 2);
			close(gconnfd[i]);
			gconnfd[i] = -1;
		}
	}
	
	gconncount = 0;
	SAFE_MUTEX_UNLOCK(&emu_stream_server_mutex);
	
	shutdown(glistenfd, 2);
	close(glistenfd);
}
