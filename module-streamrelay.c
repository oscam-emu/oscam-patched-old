#define MODULE_LOG_PREFIX "relay"

#include "globals.h"

#ifdef MODULE_STREAMRELAY

#include <dlfcn.h>
#include "module-streamrelay.h"
#include "oscam-config.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-chk.h"

#define STREAM_UNDEFINED 0x00
#define STREAM_VIDEO     0x01
#define STREAM_AUDIO     0x02
#define STREAM_SUBTITLE  0x03
#define STREAM_TELETEXT  0x04

extern int32_t exit_oscam;

typedef struct
{
	int32_t connfd;
	int32_t connid;
} stream_client_conn_data;

char stream_source_host[256];
char *stream_source_auth = NULL;
uint32_t cluster_size = 50;
bool has_dvbcsa_ecm = 0, is_dvbcsa_static = 0;

static uint8_t stream_server_mutex_init = 0;
static pthread_mutex_t stream_server_mutex;
static int32_t glistenfd, gconncount = 0, gconnfd[STREAM_SERVER_MAX_CONNECTIONS];

static pthread_mutex_t fixed_key_srvid_mutex;
static uint16_t stream_cur_srvid[STREAM_SERVER_MAX_CONNECTIONS];
static stream_client_key_data key_data[STREAM_SERVER_MAX_CONNECTIONS];

#ifdef MODULE_RADEGAST
static int32_t gRadegastFd = 0;

static bool connect_to_radegast(void)
{
	struct SOCKADDR cservaddr;

	if (gRadegastFd == 0)
		gRadegastFd = socket(DEFAULT_AF, SOCK_STREAM, 0);

	if (gRadegastFd < 0)
	{
		gRadegastFd = 0;
		return false;
	}

	int32_t flags = fcntl(gRadegastFd, F_GETFL);
	fcntl(gRadegastFd, F_SETFL, flags | O_NONBLOCK);

	bzero(&cservaddr, sizeof(cservaddr));
	SIN_GET_FAMILY(cservaddr) = DEFAULT_AF;
	SIN_GET_PORT(cservaddr) = htons(cfg.rad_port);
	SIN_GET_ADDR(cservaddr) = cfg.rad_srvip;

	if (connect(gRadegastFd, (struct sockaddr *)&cservaddr, sizeof(cservaddr)) == -1)
	{
		return false;
	}

	return true;
}

static void close_radegast_connection(void)
{
	close(gRadegastFd);
	gRadegastFd = 0;
}

static bool send_to_radegast(uint8_t* data, int len)
{
	if (send(gRadegastFd, data, len, 0) < 0)
	{
		cs_log("send_to_radegast: Send failure");
		return false;
	}
	return true;
}

static void radegast_client_ecm(stream_client_data *cdata)
{
	uint16_t section_length = SCT_LEN(cdata->ecm_data);
	uint8_t md5tmp[MD5_DIGEST_LENGTH];
	MD5(cdata->ecm_data, section_length, md5tmp);

	if (!memcmp(cdata->ecm_md5, md5tmp, MD5_DIGEST_LENGTH)) { return; }
	memcpy(cdata->ecm_md5, md5tmp, MD5_DIGEST_LENGTH);

	uint16_t packet_len;
	static uint8_t header_len = 2;
	static uint8_t payload_static_len = 12;

	if (gRadegastFd <= 0)
		{ connect_to_radegast(); }

	packet_len = header_len + payload_static_len + section_length;
	uint8_t outgoing_data[packet_len];
	outgoing_data[0] = 1;
	outgoing_data[1] = payload_static_len + section_length;
	outgoing_data[2] = 10;  // caid
	outgoing_data[3] = 2;
	outgoing_data[4] = cdata->caid >> 8;
	outgoing_data[5] = cdata->caid & 0xFF;
	outgoing_data[6] = 9;   // srvid
	outgoing_data[7] = 4;
	outgoing_data[8] = cdata->srvid & 0xFF;
	outgoing_data[10] = cdata->srvid >> 8;
	outgoing_data[12] = 3;
	outgoing_data[13] = section_length;

	memcpy(outgoing_data + header_len + payload_static_len, cdata->ecm_data, section_length);

	if (!send_to_radegast(outgoing_data, packet_len))
	{
		close_radegast_connection();
		if (connect_to_radegast())
		{
			send_to_radegast(outgoing_data, packet_len);
		}
	}
}

void ParseEcmData(stream_client_data *cdata)
{
	uint8_t *data = cdata->ecm_data;
	uint16_t section_length = SCT_LEN(data);

	if (section_length < 11)
	{
		return;
	}

	radegast_client_ecm(cdata);
}
#endif // MODULE_RADEGAST

static void write_cw(ECM_REQUEST *er, int32_t connid)
{
	const uint8_t ecm = (caid_is_videoguard(er->caid) && (er->ecm[4] != 0 && (er->ecm[2] - er->ecm[4]) == 4)) ? 4 : 0;
	if (memcmp(er->cw, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0)
	{
		if (has_dvbcsa_ecm)
		{
			dvbcsa_bs_key_set(er->cw, key_data[connid].key[EVEN]);
		}
	}

	if (memcmp(er->cw + 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0)
	{
		if (has_dvbcsa_ecm)
		{
			dvbcsa_bs_key_set(er->cw + 8, key_data[connid].key[ODD]);
		}
	}
}

bool stream_write_cw(ECM_REQUEST *er)
{
	int32_t i;
	if (er->rc == E_FOUND)
	{
		bool cw_written = false;
		//SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
		for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
		{
			if (stream_cur_srvid[i] == er->srvid)
			{
				write_cw(er, i);
				cw_written = true;
				// don't return as there might be more connections for the same channel (e.g. recordings)
			}
		}
		//SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);
		return cw_written;
	}
	return true;
}

static void SearchTsPackets(const uint8_t *buf, const uint32_t bufLength, uint16_t *packetSize, uint16_t *startOffset)
{
	uint32_t i;

	for (i = 0; i < bufLength; i++)
	{
		if (buf[i] == 0x47)
		{
			// if three packets align, probably safe to assume correct size
			if ((buf[i + 188] == 0x47) & (buf[i + 376] == 0x47))
			{
				(*packetSize) = 188;
				(*startOffset) = i;
				return;
			}
			else if ((buf[i + 204] == 0x47) & (buf[i + 408] == 0x47))
			{
				(*packetSize) = 204;
				(*startOffset) = i;
				return;
			}
			else if ((buf[i + 208] == 0x47) & (buf[i + 416] == 0x47))
			{
				(*packetSize) = 208;
				(*startOffset) = i;
				return;
			}
		}
	}

	(*packetSize) = 0;
	(*startOffset) = 0;
}

typedef void (*ts_data_callback)(stream_client_data *cdata);

static void ParseTsData(const uint8_t table_id, const uint8_t table_mask, const uint8_t min_table_length, int8_t *flag,
						uint8_t *data, const uint16_t data_length, uint16_t *data_pos, const int8_t payloadStart,
						const uint8_t *buf, const int32_t len, ts_data_callback func, stream_client_data *cdata)
{
	int32_t i;
	uint16_t offset = 0;
	bool found_start = 0;

	if (len < 1)
	{
		return;
	}

	if (*flag == 0 && !payloadStart)
	{
		return;
	}

	if (*flag == 0)
	{
		*data_pos = 0;
		offset = 1 + buf[0];
	}
	else if (payloadStart)
	{
		offset = 1;
	}

	if ((len - offset) < 1)
	{
		return;
	}

	const int32_t free_data_length = (data_length - *data_pos);
	const int32_t copySize = (len - offset) > free_data_length ? free_data_length : (len - offset);

	memcpy(data + *data_pos, buf + offset, copySize);
	*data_pos += copySize;

	for (i = 0; i < *data_pos; i++)
	{
		if ((data[i] & table_mask) == table_id)
		{
			if (i != 0)
			{
				if (*data_pos - i > i)
				{
					memmove(data, &data[i], *data_pos - i);
				}
				else
				{
					memcpy(data, &data[i], *data_pos - i);
				}

				*data_pos -= i;
			}
			found_start = 1;
			break;
		}
	}

	const uint16_t section_length = SCT_LEN(data);

	if (!found_start || (section_length > data_length) || (section_length < min_table_length))
	{
		*flag = 0;
		return;
	}

	if ((*data_pos < section_length) || (*data_pos < 3))
	{
		*flag = 2;
		return;
	}

	func(cdata);

	found_start = 0;
	for (i = section_length; i < *data_pos; i++)
	{
		if ((data[i] & table_mask) == table_id)
		{
			if (*data_pos - i > i)
			{
				memmove(data, &data[i], *data_pos - i);
			}
			else
			{
				memcpy(data, &data[i], *data_pos - i);
			}

			*data_pos -= i;
			found_start = 1;
			break;
		}
	}

	if (!found_start || (data_length < *data_pos + copySize + 1))
	{
		*data_pos = 0;
	}

	*flag = 1;
}

static void ParsePatData(stream_client_data *cdata)
{
	int32_t i;
	uint16_t srvid;
#ifdef __BISS__
	cdata->STREAMpidcount = 0;
#endif
	for (i = 8; i + 7 < SCT_LEN(cdata->pat_data); i += 4)
	{
		srvid = b2i(2, cdata->pat_data + i);
		if (srvid == 0)
		{
			continue;
		}

		if (cdata->srvid == srvid)
		{
			cdata->pmt_pid = b2i(2, cdata->pat_data + i + 2) & 0x1FFF;
			cs_log_dbg(D_READER, "Stream client %i found pmt pid: 0x%04X (%i)",
						cdata->connid, cdata->pmt_pid, cdata->pmt_pid);
			break;
		}
	}
}

static void ParseDescriptors(const uint8_t *buffer, const uint16_t info_length, uint8_t *type)
{
	uint32_t i;
	uint8_t j, descriptor_length = 0;

	if (info_length < 1)
	{
		return;
	}

	for (i = 0; i + 1 < info_length; i += descriptor_length + 2)
	{
		descriptor_length = buffer[i + 1];
		switch (buffer[i]) // descriptor tag
		{
			case 0x05: // Registration descriptor
			{
				// "HDMV" format identifier is removed
				// Cam does not need to know about Blu-ray
				const char format_identifiers_audio[10][5] =
				{
					"AC-3", "BSSD", "dmat", "DRA1", "DTS1",
					"DTS2", "DTS3", "EAC3", "mlpa", "Opus",
				};
				for (j = 0; j < 10; j++)
				{
					if (memcmp(buffer + i + 2, format_identifiers_audio[j], 4) == 0)
					{
						*type = STREAM_AUDIO;
						break;
					}
				}
				break;
			}
			//case 0x09: // CA descriptor
			//{
			//	break;
			//}
			case 0x46: // VBI teletext descriptor (DVB)
			case 0x56: // teletext descriptor (DVB)
			{
				*type = STREAM_TELETEXT;
				break;
			}
			case 0x59: // subtitling descriptor (DVB)
			{
				*type = STREAM_SUBTITLE;
				break;
			}
			case 0x6A: // AC-3 descriptor (DVB)
			case 0x7A: // enhanced AC-3 descriptor (DVB)
			case 0x7B: // DTS descriptor (DVB)
			case 0x7C: // AAC descriptor (DVB)
			case 0x81: // AC-3 descriptor (ATSC)
			case 0xCC: // Enhanced AC-3 descriptor (ATSC)
			{
				*type = STREAM_AUDIO;
				break;
			}
			case 0x7F: // extension descriptor (DVB)
			{
				switch(buffer[i + 2]) // extension descriptor tag
				{
					case 0x0E: // DTS-HD descriptor (DVB)
					case 0x0F: // DTS Neural descriptor (DVB)
					case 0x15: // AC-4 descriptor (DVB)
						*type = STREAM_AUDIO;
						break;

					case 0x20: // TTML subtitling descriptor (DVB)
						*type = STREAM_SUBTITLE;
						break;

					default:
						*type = STREAM_UNDEFINED;
						break;
				}
				break;
			}
			default:
				break;
		}
	}
}

static void stream_parse_pmt_ca_descriptor(const uint8_t *data, const int32_t data_pos, const int32_t offset, const uint16_t info_length, stream_client_data *cdata)
{
	if (cdata->ecm_pid)
	{
		return;
	}

	// parse program descriptors (we are looking only for CA descriptor here)
	int32_t i;
	uint16_t caid;
	uint8_t descriptor_tag, descriptor_length = 0;

	for (i = offset; i + 1 < offset + info_length; i += descriptor_length + 2)
	{
		descriptor_tag = data[i + data_pos];
		descriptor_length = data[i + 1 + data_pos];
		if (descriptor_length < 1)
		{
			break;
		}

		if (i + 1 + descriptor_length >= offset + info_length)
		{
			break;
		}

		if (descriptor_tag == 0x09 && descriptor_length >= 4)
		{
			caid = b2i(2, data + i + 2 + data_pos);
			if (chk_ctab_ex(caid, &cfg.stream_relay_ctab))
			{
				if (cdata->caid == NO_CAID_VALUE)
				{
					cdata->caid = caid;
				}

				if (cdata->caid != caid)
				{
					continue;
				}
				cdata->ecm_pid = b2i(2, data + i + 4 + data_pos) & 0x1FFF;
				cs_log_dbg(D_READER, "Stream client %i found ecm pid: 0x%04X (%i)",
							cdata->connid, cdata->ecm_pid, cdata->ecm_pid);	
			}	
		}
	}
}

static void ParsePmtData(stream_client_data *cdata)
{
	int32_t i;
	uint16_t program_info_length = 0, es_info_length = 0, elementary_pid;
	const uint16_t section_length = SCT_LEN(cdata->pmt_data);
	uint8_t offset = 0;

	cdata->ecm_pid = 0;
	cdata->pcr_pid = b2i(2, cdata->pmt_data + 8) & 0x1FFF;

	if (cdata->pcr_pid != 0x1FFF)
	{
		cs_log_dbg(D_READER, "Stream client %i found pcr pid: 0x%04X (%i)",
					cdata->connid, cdata->pcr_pid, cdata->pcr_pid);
	}
	program_info_length = b2i(2, cdata->pmt_data + 10) & 0xFFF;
	if (!program_info_length)
	{
		offset = 5;
		program_info_length = (b2i(2, cdata->pmt_data + 10 + offset) & 0xFFF);
	}
	if (12 + offset + program_info_length >= section_length) { return; }
	stream_parse_pmt_ca_descriptor(cdata->pmt_data, 0, 12 + offset, program_info_length, cdata);

	offset = offset == 5 ? 0 : program_info_length;
	for (i = 12 + offset; i + 4 <  section_length; i += 5 + es_info_length)
	{
		elementary_pid = b2i(2, cdata->pmt_data + i + 1) & 0x1FFF;
		es_info_length = b2i(2, cdata->pmt_data + i + 3) & 0xFFF;
		switch (cdata->pmt_data[i]) // stream type
		{
			case 0x01:
			case 0x02:
			case 0x10:
			case 0x1B:
			case 0x20:
			case 0x24:
			case 0x25:
			case 0x42:
			case 0xD1:
			case 0xEA:
			{
				cs_log_dbg(D_READER, "Stream client %i found video pid: 0x%04X (%i)",
							cdata->connid, elementary_pid, elementary_pid);
				stream_parse_pmt_ca_descriptor(cdata->pmt_data, i, 5, es_info_length, cdata);
				break;
			}
			case 0x03:
			case 0x04:
			case 0x0F:
			case 0x11:
			case 0x1C:
			case 0x2D:
			case 0x2E:
			case 0x81:
			{
				cs_log_dbg(D_READER, "Stream client %i found audio pid: 0x%04X (%i)",
							cdata->connid, elementary_pid, elementary_pid);
				break;
			}
			case 0x06:
			//case 0x81: // some ATSC AC-3 streams do not contain the AC-3 descriptor!
			case 0x87:
			{
				uint8_t type = STREAM_UNDEFINED;
				ParseDescriptors(cdata->pmt_data + i + 5, es_info_length, &type);
				if (type == STREAM_AUDIO)
				{
					cs_log_dbg(D_READER, "Stream client %i found audio pid: 0x%04X (%i)",
								cdata->connid, elementary_pid, elementary_pid);
				}
				else if (type == STREAM_TELETEXT)
				{
					cs_log_dbg(D_READER, "Stream client %i found teletext pid: 0x%04X (%i)",
								cdata->connid, elementary_pid, elementary_pid);
				}
				break;
			}
		}
#ifdef __BISS__
		cdata->STREAMpids[cdata->STREAMpidcount] = elementary_pid;
		cdata->STREAMpidcount++;
#endif
	}
}

static void ParseTsPackets(stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
{
	uint8_t payloadStart;
	uint16_t pid, offset;
	uint32_t i, tsHeader;

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
		pid = (tsHeader & 0x1FFF00) >> 8;
		payloadStart = (tsHeader & 0x400000) >> 22;

		if (tsHeader & 0x20)
		{
			offset = 4 + stream_buf[i + 4] + 1;
		}
		else
		{
			offset = 4;
		}

		if (packetSize - offset < 1)
		{
			continue;
		}

		if (pid == 0x0000 && data->have_pat_data != 1) // Search the PAT for the PMT pid
		{
			ParseTsData(0x00, 0xFF, 16, &data->have_pat_data, data->pat_data, sizeof(data->pat_data),
						&data->pat_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParsePatData, data);
			continue;
		}

		if (pid == data->pmt_pid && data->have_pmt_data != 1) // Search the PMT for PCR, ECM, Video and Audio pids
		{
			ParseTsData(0x02, 0xFF, 21, &data->have_pmt_data, data->pmt_data, sizeof(data->pmt_data),
						&data->pmt_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParsePmtData, data);
			continue;
		}

		// We have bot PAT and PMT data - No need to search the rest of the packets
		if (data->have_pat_data == 1 && data->have_pmt_data == 1)
		{
			break;
		}
	}
}

static void decrypt(struct dvbcsa_bs_batch_s *tsbbatch, uint16_t fill[2], const uint8_t oddeven, const int32_t connid)
{
	if (fill[oddeven] > 0)
	{
#if 0
		uint16_t i;
		for(i = fill[oddeven]; i <= cluster_size; i++)
		{
			tsbbatch[i].data = NULL;
			tsbbatch[i].len = 0;
		}
#else
		tsbbatch[fill[oddeven]].data = NULL;
#endif
		//cs_log_dbg(D_READER, "dvbcsa (%s), batch=%d", oddeven == ODD ? "odd" : "even", fill[oddeven]);

		fill[oddeven] = 0;

		dvbcsa_bs_decrypt(key_data[connid].key[oddeven], tsbbatch, 184);
	}
}
#define decrypt(a) decrypt(tsbbatch, fill, a, data->connid)

static void DescrambleTsPackets(stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize, struct dvbcsa_bs_batch_s *tsbbatch)
{
	uint32_t i, tsHeader;
	uint16_t offset, fill[2] = {0,0};
	uint8_t oddeven = 0;
#ifdef MODULE_RADEGAST
	uint16_t pid;
	uint8_t payloadStart;
#endif

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
#ifdef MODULE_RADEGAST
		pid = (tsHeader & 0x1FFF00) >> 8;
		payloadStart = (tsHeader & 0x400000) >> 22;
#endif
		offset = (tsHeader & 0x20) ? 4 + stream_buf[i + 4] + 1 : 4;
		if (packetSize - offset < 1)
		{
			continue;
		}
#ifdef MODULE_RADEGAST
#ifdef __BISS__
		if(data->ecm_pid == 0x1FFF && caid_is_biss_fixed(data->caid))
		{
			uint32_t j, n; 
			uint16_t ecm_len = 7;
			data->ecm_data[0] = 0x80; // to pass the cache check it must be 0x80 or 0x81
			data->ecm_data[1] = 0x00;
			data->ecm_data[2] = 0x04;
			i2b_buf(2, data->srvid, data->ecm_data + 3);
			i2b_buf(2, data->pmt_pid, data->ecm_data + 5);
			for(j = 0, n = 7; j < data->STREAMpidcount; j++, n += 2)
			{
				i2b_buf(2, data->STREAMpids[j], data->ecm_data + n);
				data->ecm_data[2] += 2;
				ecm_len += 2;
			}
			data->ens &= 0x0FFFFFFF; // clear top 4 bits (in case of DVB-T/C or garbage), prepare for flagging
			data->ens |= 0xA0000000; // flag to emu: this is the namespace, not a pid
			i2b_buf(2, data->tsid, data->ecm_data + ecm_len);     // place tsid after the last stream pid
			i2b_buf(2, data->onid, data->ecm_data + ecm_len + 2); // place onid right after tsid
			i2b_buf(4, data->ens, data->ecm_data + ecm_len + 4);  // place namespace at the end of the ecm
			data->ecm_data[2] += 8;
			ParseEcmData(data);
		} else
#endif // __BISS__
		if (data->ecm_pid && pid == data->ecm_pid) // Process the ECM data
		{
			// set to null pid
			stream_buf[i + 1] |= 0x1F;
			stream_buf[i + 2] = 0xFF;
			ParseTsData(0x80, 0xFE, 3, &data->have_ecm_data, data->ecm_data, sizeof(data->ecm_data),
						&data->ecm_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParseEcmData, data);
			continue;
		}
#endif // MODULE_RADEGAST
		if ((tsHeader & 0xC0) == 0)
		{
			continue;
		}

		stream_buf[i + 3] &= 0x3f; // consider it decrypted now
		oddeven = (tsHeader & 0xC0) == 0xC0 ? ODD: EVEN;
		decrypt(oddeven == ODD ? EVEN : ODD);
		tsbbatch[fill[oddeven]].data = &stream_buf[i + offset];
		tsbbatch[fill[oddeven]].len = packetSize - offset;
		fill[oddeven]++;

		if (fill[oddeven] > cluster_size - 1)
		{
			decrypt(oddeven);
		}
	}

	decrypt(oddeven);
}

static int32_t connect_to_stream(char *http_buf, int32_t http_buf_len, char *stream_path)
{
	struct SOCKADDR cservaddr;
	IN_ADDR_T in_addr;

	int32_t streamfd = socket(DEFAULT_AF, SOCK_STREAM, 0);
	if (streamfd == -1) { return -1; }

	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if (setsockopt(streamfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv))
	{
		cs_log("ERROR: setsockopt() failed for SO_RCVTIMEO");
		return -1;
	}

	bzero(&cservaddr, sizeof(cservaddr));
	SIN_GET_FAMILY(cservaddr) = DEFAULT_AF;
	SIN_GET_PORT(cservaddr) = htons(cfg.stream_source_port);
	cs_resolve(stream_source_host, &in_addr, NULL, NULL);
	SIN_GET_ADDR(cservaddr) = in_addr;

	if (connect(streamfd, (struct sockaddr *)&cservaddr, sizeof(cservaddr)) == -1)
	{
		cs_log("WARNING: Connect to stream source port %d failed", cfg.stream_source_port);
		return -1;
	}

	if (stream_source_auth)
	{
		snprintf(http_buf, http_buf_len, "GET %s HTTP/1.1\nHost: %s:%u\n"
				"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0\n"
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
				"Accept-Language: en-US\n"
				"Authorization: Basic %s\n"
				"Connection: keep-alive\n\n", stream_path, stream_source_host, cfg.stream_source_port, stream_source_auth);
	}
	else
	{
		snprintf(http_buf, http_buf_len, "GET %s HTTP/1.1\nHost: %s:%u\n"
				"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0\n"
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
				"Accept-Language: en-US\n"
				"Connection: keep-alive\n\n", stream_path, stream_source_host, cfg.stream_source_port);
	}

	if (send(streamfd, http_buf, cs_strlen(http_buf), 0) == -1) { return -1; }
	return streamfd;
}

static void stream_client_disconnect(stream_client_conn_data *conndata)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
	stream_cur_srvid[conndata->connid] = NO_SRVID_VALUE;
	SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);

	SAFE_MUTEX_LOCK(&stream_server_mutex);
	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if (gconnfd[i] == conndata->connfd)
		{
			gconnfd[i] = -1;
			gconncount--;
		}
	}
	SAFE_MUTEX_UNLOCK(&stream_server_mutex);

	shutdown(conndata->connfd, 2);
	close(conndata->connfd);

	cs_log("Stream client %i disconnected",conndata->connid);

	NULLFREE(conndata);
}

static void *stream_client_handler(void *arg)
{
	stream_client_conn_data *conndata = (stream_client_conn_data *)arg;
	stream_client_data *data;

	char *http_buf, stream_path[255], stream_path_copy[255];
	char *saveptr, *token, http_version[4];

	int8_t streamConnectErrorCount = 0, streamDataErrorCount = 0;
	int32_t bytesRead = 0, http_status_code = 0;
	int32_t i, clientStatus, streamStatus, streamfd;

	uint8_t *stream_buf;
	uint16_t packetCount = 0, packetSize = 0, startOffset = 0;
	uint32_t remainingDataPos, remainingDataLength, tmp_pids[4];
	uint8_t descrambling = 0;

	const int32_t cur_dvb_buffer_size = DVB_BUFFER_SIZE_CSA;
	const int32_t cur_dvb_buffer_wait = DVB_BUFFER_WAIT_CSA;

	struct dvbcsa_bs_batch_s *tsbbatch;

	cs_log("Stream client %i connected", conndata->connid);

	if (!cs_malloc(&http_buf, 1024))
	{
		stream_client_disconnect(conndata);
		return NULL;
	}

	if (!cs_malloc(&stream_buf, DVB_BUFFER_SIZE))
	{
		NULLFREE(http_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}

	if (!cs_malloc(&data, sizeof(stream_client_data)))
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}

	clientStatus = recv(conndata->connfd, http_buf, 1024, 0);
	if (clientStatus < 1)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	http_buf[1023] = '\0';
	if (sscanf(http_buf, "GET %254s ", stream_path) < 1)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	cs_strncpy(stream_path_copy, stream_path, sizeof(stream_path));

	token = strtok_r(stream_path_copy, ":", &saveptr); // token 0
	for (i = 1; token != NULL && i < 7; i++) // tokens 1 to 6
	{
		token = strtok_r(NULL, ":", &saveptr);
		if (token == NULL)
		{
			break;
		}

		if (i >= 3) // We olny need token 3 (srvid), 4 (tsid), 5 (onid) and 6 (ens)
		{
			if (sscanf(token, "%x", &tmp_pids[i - 3]) != 1)
			{
				tmp_pids[i - 3] = 0;
			}
		}
	}

	data->srvid = tmp_pids[0] & 0xFFFF;
	data->tsid = tmp_pids[1] & 0xFFFF;
	data->onid = tmp_pids[2] & 0xFFFF;
	data->ens = tmp_pids[3];

	if (data->srvid == 0) // We didn't get a srvid - Exit
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	key_data[conndata->connid].key[ODD]  = dvbcsa_bs_key_alloc();
	key_data[conndata->connid].key[EVEN] = dvbcsa_bs_key_alloc();

	if (!cs_malloc(&tsbbatch, (cluster_size + 1) * sizeof(struct dvbcsa_bs_batch_s)))
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
	stream_cur_srvid[conndata->connid] = data->srvid;
	SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);

	cs_log("Stream client %i request %s", conndata->connid, stream_path);

	cs_log_dbg(D_READER, "Stream client %i received srvid: %04X tsid: %04X onid: %04X ens: %08X",
				conndata->connid, data->srvid, data->tsid, data->onid, data->ens);

	snprintf(http_buf, 1024, "HTTP/1.0 200 OK\nConnection: Close\nContent-Type: video/mpeg\nServer: stream_enigma2\n\n");
	clientStatus = send(conndata->connfd, http_buf, cs_strlen(http_buf), 0);

	data->connid = conndata->connid;
	data->caid = NO_CAID_VALUE;
	data->have_pat_data = 0;
	data->have_pmt_data = 0;
	data->have_cat_data = 0;
	data->have_ecm_data = 0;
	data->have_emm_data = 0;

	while (!exit_oscam && clientStatus != -1 && streamConnectErrorCount < 3
			&& streamDataErrorCount < 15)
	{
		streamfd = connect_to_stream(http_buf, 1024, stream_path);
		if (streamfd == -1)
		{
			cs_log("WARNING: stream client %i cannot connect to stream source", conndata->connid);
			streamConnectErrorCount++;
			cs_sleepms(500);
			continue;
		}
		streamStatus = 0;
		bytesRead = 0;
		while (!exit_oscam && clientStatus != -1 && streamStatus != -1
#if 0
				&& streamConnectErrorCount < 3 && streamDataErrorCount < 15)
#else
				&& (streamConnectErrorCount < 3 || streamDataErrorCount < 15))
#endif
		{
			streamStatus = recv(streamfd, stream_buf + bytesRead, cur_dvb_buffer_size - bytesRead, MSG_WAITALL);
			if (streamStatus == 0) // socket closed
			{
				cs_log("WARNING: stream client %i - stream source closed connection", conndata->connid);
				streamConnectErrorCount++;
				cs_sleepms(100);
				break;
			}
			if (streamStatus < 0) // error
			{
				if ((errno == EWOULDBLOCK) | (errno == EAGAIN))
				{
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
			if (streamStatus < cur_dvb_buffer_size - bytesRead) // probably just received header but no stream
			{
				if (!bytesRead && streamStatus > 13 &&
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

			if (bytesRead >= cur_dvb_buffer_wait)
			{
				startOffset = 0;

				// only search if not starting on ts packet or unknown packet size
				if (stream_buf[0] != 0x47 || packetSize == 0)
				{
					SearchTsPackets(stream_buf, bytesRead, &packetSize, &startOffset);
				}

				if (packetSize == 0)
				{
					bytesRead = 0;
				}
				else
				{
					packetCount = ((bytesRead - startOffset) / packetSize);

					// We have both PAT and PMT data - We can start descrambling
					if (data->have_pat_data == 1 && data->have_pmt_data == 1)
					{
						if (chk_ctab_ex(data->caid, &cfg.stream_relay_ctab) && (data->caid != 0xA101 || data->caid == NO_CAID_VALUE))
						{
								DescrambleTsPackets(data, stream_buf + startOffset, packetCount * packetSize, packetSize, tsbbatch);
								if (!descrambling && cfg.stream_relay_buffer_time) {
									cs_sleepms(cfg.stream_relay_buffer_time);
									descrambling = 1;
								}
						}
						else
						{
							cs_log_dbg(D_READER, "Stream client %i caid %04X not enabled in stream relay config",
										conndata->connid, data->caid);
						}
					}
					else // Search PAT and PMT packets for service information
					{
						ParseTsPackets(data, stream_buf + startOffset, packetCount * packetSize, packetSize);
					}

					clientStatus = send(conndata->connfd, stream_buf + startOffset, packetCount * packetSize, 0);

					remainingDataPos = startOffset + (packetCount * packetSize);
					remainingDataLength = bytesRead - remainingDataPos;

					if (remainingDataPos < remainingDataLength)
					{
						memmove(stream_buf, stream_buf + remainingDataPos, remainingDataLength);
					}
					else
					{
						memcpy(stream_buf, stream_buf + remainingDataPos, remainingDataLength);
					}

					bytesRead = remainingDataLength;
				}
			}
		}

		close(streamfd);
	}

	NULLFREE(http_buf);
	NULLFREE(stream_buf);

	dvbcsa_bs_key_free(key_data[conndata->connid].key[ODD]);
	dvbcsa_bs_key_free(key_data[conndata->connid].key[EVEN]);
	NULLFREE(tsbbatch);

	NULLFREE(data);

	stream_client_disconnect(conndata);
	return NULL;
}

void *stream_server(void *UNUSED(a))
{
#ifdef IPV6SUPPORT
	struct sockaddr_in6 servaddr, cliaddr;
#else
	struct sockaddr_in servaddr, cliaddr;
#endif
	socklen_t clilen;
	int32_t connfd, reuse = 1, i;
	int8_t connaccepted;
	stream_client_conn_data *conndata;

	cluster_size = dvbcsa_bs_batch_size();

	if(strcmp(LIBDVBCSA_LIB, "libdvbcsa.a"))
	{
		has_dvbcsa_ecm = (dlsym(RTLD_DEFAULT, "dvbcsa_bs_key_set_ecm"));
	}
	else
	{
		has_dvbcsa_ecm = DVBCSA_ECM_HEADER;
		is_dvbcsa_static = 1;
	}

	cs_log("INFO: %s %s dvbcsa parallel mode = %d (relay buffer time: %d ms)", (!has_dvbcsa_ecm) ? "(wrong)" : "(ecm)", (!is_dvbcsa_static) ? "dynamic" : "static", cluster_size, cfg.stream_relay_buffer_time);

	if (!stream_server_mutex_init)
	{
		SAFE_MUTEX_INIT(&stream_server_mutex, NULL);
		stream_server_mutex_init = 1;
	}

	SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		stream_cur_srvid[i] = NO_SRVID_VALUE;
	}
	SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);

	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		gconnfd[i] = -1;
	}
#ifdef IPV6SUPPORT
	glistenfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (glistenfd == -1)
	{
		cs_log("ERROR: cannot create stream server socket");
		return NULL;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_addr = in6addr_any;
	servaddr.sin6_port = htons(cfg.stream_relay_port);
#else
	glistenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (glistenfd == -1)
	{
		cs_log("ERROR: cannot create stream server socket");
		return NULL;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(cfg.stream_relay_port);
#endif
	setsockopt(glistenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if (bind(glistenfd,(struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
	{
		cs_log("ERROR: cannot bind to stream server socket");
		close(glistenfd);
		return NULL;
	}

	if (listen(glistenfd, 3) == -1)
	{
		cs_log("ERROR: cannot listen to stream server socket");
		close(glistenfd);
		return NULL;
	}

	while (!exit_oscam)
	{
		clilen = sizeof(cliaddr);
		connfd = accept(glistenfd,(struct sockaddr *)&cliaddr, &clilen);

		if (connfd == -1)
		{
			cs_log("ERROR: accept() failed");
			break;
		}

		connaccepted = 0;

#ifdef MODULE_RADEGAST
		if(cfg.stream_client_source_host)
		{
#ifdef IPV6SUPPORT
			// Read ip of client who wants to play the stream
			unsigned char *ip = (unsigned char *)&cliaddr.sin6_addr;
			cs_log("Stream Client ip is: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x, will fetch stream there\n", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);

			// Store ip of client in stream_source_host variable
			snprintf(stream_source_host, sizeof(stream_source_host), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
#else
			// Read ip of client who wants to play the stream
			unsigned char *ip = (unsigned char *)&cliaddr.sin_addr.s_addr;
			cs_log("Stream Client ip is: %d.%d.%d.%d, will fetch stream there\n", ip[0], ip[1], ip[2], ip[3]);

			// Store ip of client in stream_source_host variable
			snprintf(stream_source_host, sizeof(stream_source_host), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
#endif
		}
#endif

		if (cs_malloc(&conndata, sizeof(stream_client_conn_data)))
		{
			SAFE_MUTEX_LOCK(&stream_server_mutex);
			if (gconncount < STREAM_SERVER_MAX_CONNECTIONS)
			{
				for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
				{
					if (gconnfd[i] == -1)
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
			SAFE_MUTEX_UNLOCK(&stream_server_mutex);
		}

		if (connaccepted)
		{
			int on = 1;
			if (setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
			{
				cs_log("ERROR: stream client %i setsockopt() failed for TCP_NODELAY", conndata->connid);
			}

			start_thread("stream client", stream_client_handler, (void*)conndata, NULL, 1, 0);
		}
		else
		{
			shutdown(connfd, 2);
			close(connfd);
			cs_log("ERROR: stream server client dropped because of too many connections (%i)", STREAM_SERVER_MAX_CONNECTIONS);
		}

		cs_sleepms(20);
	}

	close(glistenfd);

	return NULL;
}

void init_stream_server(void)
{
	char authtmp[128];

	if (cfg.stream_relay_enabled)
	{

		cs_strncpy(stream_source_host, cfg.stream_source_host, sizeof(stream_source_host));

		if (cfg.stream_source_auth_user && cfg.stream_source_auth_password)
		{
			snprintf(authtmp, sizeof(authtmp), "%s:%s", cfg.stream_source_auth_user, cfg.stream_source_auth_password);
			b64encode(authtmp, cs_strlen(authtmp), &stream_source_auth);
		}

		start_thread("stream_server", stream_server, NULL, NULL, 1, 1);
		cs_log("Stream Relay server initialized");
	}
}

void stop_stream_server(void)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&stream_server_mutex);
	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if (gconnfd[i] != -1)
		{
			shutdown(gconnfd[i], 2);
			close(gconnfd[i]);
			gconnfd[i] = -1;
		}
	}

	gconncount = 0;
	SAFE_MUTEX_UNLOCK(&stream_server_mutex);

#ifdef MODULE_RADEGAST
	close_radegast_connection();
#endif

	shutdown(glistenfd, 2);
	close(glistenfd);
}

#endif // MODULE_STREAMRELAY
