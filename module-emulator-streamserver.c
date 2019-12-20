#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "ffdecsa/ffdecsa.h"
#include "module-emulator-osemu.h"
#include "module-emulator-streamserver.h"
#include "module-emulator-powervu.h"
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

pthread_mutex_t emu_fixed_key_srvid_mutex;
uint16_t emu_stream_cur_srvid[EMU_STREAM_SERVER_MAX_CONNECTIONS];
int8_t stream_server_has_ecm[EMU_STREAM_SERVER_MAX_CONNECTIONS];

pthread_mutex_t emu_fixed_key_data_mutex[EMU_STREAM_SERVER_MAX_CONNECTIONS];
emu_stream_client_key_data emu_fixed_key_data[EMU_STREAM_SERVER_MAX_CONNECTIONS];
LLIST *ll_emu_stream_delayed_keys[EMU_STREAM_SERVER_MAX_CONNECTIONS];

static void SearchTsPackets(uint8_t *buf, uint32_t bufLength, uint16_t *packetSize, uint16_t *startOffset)
{
	uint32_t i;

	(*packetSize) = 0;
	(*startOffset) = 0;

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
}

typedef void (*ts_data_callback)(emu_stream_client_data *cdata);

static void ParseTsData(uint8_t table_id, uint8_t table_mask, uint8_t min_table_length, int8_t *flag,
						uint8_t *data, uint16_t data_length, uint16_t *data_pos, int8_t payloadStart,
						uint8_t *buf, int32_t len, ts_data_callback func, emu_stream_client_data *cdata)
{
	int8_t found_start = 0;
	int32_t free_data_length, copySize, i;
	uint16_t section_length, offset = 0;

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

	if (len - offset < 1)
	{
		return;
	}

	free_data_length = data_length - *data_pos;
	copySize = (len - offset) > free_data_length ? free_data_length : (len - offset);

	memcpy(data + (*data_pos), buf + offset, copySize);
	(*data_pos) += copySize;

	found_start = 0;
	for (i = 0; i < *data_pos; i++)
	{
		if ((data[i] & table_mask) == table_id)
		{
			if (i != 0)
			{
				if ((*data_pos) - i > i)
				{
					memmove(data, &data[i], (*data_pos) - i);
				}
				else
				{
					memcpy(data, &data[i], (*data_pos) - i);
				}

				*data_pos -= i;
			}
			found_start = 1;
			break;
		}
	}

	if (!found_start)
	{
		*flag = 0;
		return;
	}

	*flag = 2;

	if (*data_pos < 3)
	{
		return;
	}

	section_length = SCT_LEN(data);

	if (section_length > data_length || section_length < min_table_length)
	{
		*flag = 0;
		return;
	}

	if ((*data_pos) < section_length)
	{
		return;
	}

	func(cdata);

	found_start = 0;
	for (i = section_length; i < *data_pos; i++)
	{
		if ((data[i] & table_mask) == table_id)
		{
			if ((*data_pos) - i > i)
			{
				memmove(data, &data[i], (*data_pos) - i);
			}
			else
			{
				memcpy(data, &data[i], (*data_pos) - i);
			}

			*data_pos -= i;
			found_start = 1;
			break;
		}
	}

	if (!found_start)
	{
		*data_pos = 0;
	}

	*flag = 1;
}

static void ParsePatData(emu_stream_client_data *cdata)
{
	int32_t i;
	uint8_t *data = cdata->pat_data;
	uint16_t srvid, section_length = SCT_LEN(data);

	for (i = 8; i + 7 < section_length; i += 4)
	{
		srvid = b2i(2, data + i);
		if (srvid == 0)
		{
			continue;
		}

		if (cdata->srvid == srvid)
		{
			cdata->pmt_pid = b2i(2, data + i + 2) & 0x1FFF;
			cs_log_dbg(D_READER, "Stream client %i found pmt pid: 0x%04X (%i)",
						cdata->connid, cdata->pmt_pid, cdata->pmt_pid);
			break;
		}
	}
}

static int8_t stream_client_get_caid(emu_stream_client_data *cdata)
{
	uint32_t tmp1 = (cdata->srvid << 16) | cdata->pmt_pid;
	uint8_t tmp2[2];

	if (emu_find_key('A', tmp1, 0, "FAKE", tmp2, 2, 0, 0, 0, NULL))
	{
		cdata->caid = b2i(2, tmp2);
		return 1;
	}
	return 0;
}

static void ParseDescriptors(uint8_t *buffer, uint16_t info_length, uint8_t *type)
{
	uint8_t descriptor_tag = buffer[0], descriptor_length = 0;
	uint32_t j, k;

	if (info_length < 1)
	{
		return;
	}

	for (j = 0; j + 1 < info_length; j += descriptor_length + 2)
	{
		descriptor_tag = buffer[j];
		descriptor_length = buffer[j + 1];

		switch (descriptor_tag)
		{
			case 0x05: // Registration descriptor
			{
				// "HDMV" format identifier is removed
				// OSCam does not need to know about Blu-ray
				const char format_identifiers_audio[10][5] =
				{
					"AC-3", "BSSD", "dmat", "DRA1", "DTS1",
					"DTS2", "DTS3", "EAC3", "mlpa", "Opus",
				};

				for (k = 0; k < 10; k++)
				{
					if (memcmp(buffer + j + 2, format_identifiers_audio[k], 4) == 0)
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
				uint8_t extension_descriptor_tag = buffer[j + 2];

				switch (extension_descriptor_tag)
				{
					case 0x0E: // DTS-HD descriptor (DVB)
					case 0x0F: // DTS Neural descriptor (DVB)
					case 0x15: // AC-4 descriptor (DVB)
					case 0x21: // DTS-UHD descriptor (DVB)
						*type = STREAM_AUDIO;
						break;
				}
				break;
			}
		}
	}
}

static void ParsePmtData(emu_stream_client_data *cdata)
{
	int32_t i;
	uint8_t *data = cdata->pmt_data;
	uint8_t descriptor_tag = 0, descriptor_length = 0, stream_type;
	uint16_t program_info_length = 0, es_info_length = 0, elementary_pid, caid;
	uint16_t section_length = SCT_LEN(data);

	cdata->pcr_pid = b2i(2, data + 8) & 0x1FFF;
	if (cdata->pcr_pid != 0x1FFF)
	{
		cs_log_dbg(D_READER, "Stream client %i found pcr pid: 0x%04X (%i)",
					cdata->connid, cdata->pcr_pid, cdata->pcr_pid);
	}

	program_info_length = b2i(2, data + 10) & 0xFFF;

	if (12 + program_info_length >= section_length)
	{
		return;
	}

	// parse program descriptors (we are looking only for CA descriptor here)
	for (i = 12; i + 1 < 12 + program_info_length; i += descriptor_length + 2)
	{
		descriptor_tag = data[i];
		descriptor_length = data[i + 1];

		if (descriptor_length < 1)
		{
			break;
		}

		if (i + 1 + descriptor_length >= 12 + program_info_length)
		{
			break;
		}

		if (descriptor_tag == 0x09 && descriptor_length >= 4)
		{
			caid = b2i(2, data + i + 2);

			if (caid_is_powervu(caid) || caid == 0xA101) // add all supported caids here
			{
				if (cdata->caid == NO_CAID_VALUE)
				{
					cdata->caid = caid;
				}
				cdata->ecm_pid = b2i(2, data + i + 4) & 0x1FFF;
				cs_log_dbg(D_READER, "Stream client %i found ecm pid: 0x%04X (%i)",
							cdata->connid, cdata->ecm_pid, cdata->ecm_pid);
				break;
			}
		}
	}

	for (i = 12 + program_info_length; i + 4 < section_length; i += 5 + es_info_length)
	{
		stream_type = data[i];
		elementary_pid = b2i(2, data + i + 1) & 0x1FFF;
		es_info_length = b2i(2, data + i + 3) & 0xFFF;

		switch (stream_type)
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
				cdata->video_pid = elementary_pid;
				cs_log_dbg(D_READER, "Stream client %i found video pid: 0x%04X (%i)",
							cdata->connid, elementary_pid, elementary_pid);
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
				if (cdata->audio_pid_count >= EMU_STREAM_MAX_AUDIO_SUB_TRACKS)
				{
					continue;
				}

				cdata->audio_pids[cdata->audio_pid_count] = elementary_pid;
				cdata->audio_pid_count++;
				cs_log_dbg(D_READER, "Stream client %i found audio pid: 0x%04X (%i)",
							cdata->connid, elementary_pid, elementary_pid);
				break;
			}

			case 0x06:
			//case 0x81: // some ATSC AC-3 streams do not contain the AC-3 descriptor!
			case 0x87:
			{
				uint8_t type = STREAM_UNDEFINED;
				ParseDescriptors(data + i + 5, es_info_length, &type);

				if (type == STREAM_AUDIO)
				{
					if (cdata->audio_pid_count >= EMU_STREAM_MAX_AUDIO_SUB_TRACKS)
					{
						continue;
					}

					cdata->audio_pids[cdata->audio_pid_count] = elementary_pid;
					cdata->audio_pid_count++;
					cs_log_dbg(D_READER, "Stream client %i found audio pid: 0x%04X (%i)",
								cdata->connid, elementary_pid, elementary_pid);
				}
				else if (type == STREAM_TELETEXT)
				{
					cdata->teletext_pid = elementary_pid;
					cs_log_dbg(D_READER, "Stream client %i found teletext pid: 0x%04X (%i)",
								cdata->connid, elementary_pid, elementary_pid);
				}
				break;
			}
		}
	}

	// If we haven't found a CAID for this service,
	// search the keyDB for a fake one
	if (cdata->caid == NO_CAID_VALUE && stream_client_get_caid(cdata) == 1)
	{
		cs_log_dbg(D_READER, "Stream client %i found fake caid: 0x%04X (%i)",
					cdata->connid, cdata->caid, cdata->caid);
	}
}

static void ParseCatData(emu_stream_client_data *cdata)
{
	uint8_t *data = cdata->cat_data;
	uint32_t i;

	for (i = 8; i < (b2i(2, data + 1) & 0xFFF) - 1; i += data[i + 1] + 2)
	{
		if (data[i] != 0x09)
		{
			continue;
		}

		uint16_t caid = b2i(2, data + i + 2);

		if (caid_is_powervu(caid)) // add all supported caids here
		{
			if (cdata->caid == NO_CAID_VALUE)
			{
				cdata->caid = caid;
			}
			cdata->emm_pid = b2i(2, data + i + 4) & 0x1FFF;;
			cs_log_dbg(D_READER, "Stream client %i found emm pid: 0x%04X (%i)",
						cdata->connid, cdata->emm_pid, cdata->emm_pid);
			break;
		}
	}
}

static void ParseEmmData(emu_stream_client_data *cdata)
{
	uint32_t keysAdded = 0;

	emu_process_emm(NULL, cdata->caid, cdata->emm_data, &keysAdded);

	if (keysAdded)
	{
		//refresh_entitlements(rdr);
		cs_log("Stream client %i found %i keys", cdata->connid, keysAdded);
	}
}

static void ParseEcmData(emu_stream_client_data *cdata)
{
	uint8_t *data = cdata->ecm_data;
	uint8_t dcw[16];
	uint16_t section_length = SCT_LEN(data);

	if (section_length < 11)
	{
		return;
	}

	if (caid_is_powervu(cdata->caid))
	{
		if (data[11] > cdata->ecm_nb || (cdata->ecm_nb == 255 && data[11] == 0) || ((cdata->ecm_nb - data[11]) > 5))
		{
			cdata->ecm_nb = data[11];
			powervu_ecm(data, dcw, NULL, cdata->srvid, cdata->caid, cdata->tsid, cdata->onid, cdata->ens, &cdata->key);
		}
	}
	//else if () // All other caids
	//{
		//emu_process_ecm();
	//}
}

static void ParseTsPackets(emu_stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
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

static void DescrambleTsPacketsPowervu(emu_stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
{
	int8_t oddKeyUsed;

	uint8_t scramblingControl, payloadStart, oddeven;
	uint8_t *pdata, *packetClusterV[256];
	uint8_t *packetClusterA[EMU_STREAM_MAX_AUDIO_SUB_TRACKS][64]; // separate cluster arrays for video and each audio track
	uint16_t pid, offset;
	uint32_t i, j, k, tsHeader;
	uint32_t scrambled_packets = 0, scrambled_packetsA[EMU_STREAM_MAX_AUDIO_SUB_TRACKS] = { 0 };
	uint32_t *deskey;
	uint32_t cs = 0; // video cluster start
	uint32_t ce = 1; // video cluster end
	uint32_t csa[EMU_STREAM_MAX_AUDIO_SUB_TRACKS] = { 0 }; // cluster index for audio tracks

	void *csakeyA[EMU_STREAM_MAX_AUDIO_SUB_TRACKS] = { 0 };
	void *csakeyV = 0;
	emu_stream_client_key_data *keydata;

	packetClusterV[0] = NULL;

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
		pid = (tsHeader & 0x1FFF00) >> 8;
		scramblingControl = tsHeader & 0xC0;
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

		if (emu_stream_emm_enabled && pid == 0x0001 && data->have_cat_data != 1) // Search the CAT for EMM pids
		{
			// set to null pid
			stream_buf[i + 1] |= 0x1F;
			stream_buf[i + 2] = 0xFF;

			ParseTsData(0x01, 0xFF, 8, &data->have_cat_data, data->cat_data, sizeof(data->cat_data),
						&data->cat_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParseCatData, data);
			continue;
		}

		if (emu_stream_emm_enabled && data->emm_pid && pid == data->emm_pid) // Process the EMM data
		{
			// set to null pid
			stream_buf[i + 1] |= 0x1F;
			stream_buf[i + 2] = 0xFF;

			ParseTsData(0x80, 0xF0, 3, &data->have_emm_data, data->emm_data, sizeof(data->emm_data),
						&data->emm_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParseEmmData, data);
			continue;
		}

		if (data->ecm_pid && pid == data->ecm_pid) // Process the ECM data
		{
			stream_server_has_ecm[data->connid] = 1;

			// set to null pid
			stream_buf[i + 1] |= 0x1F;
			stream_buf[i + 2] = 0xFF;

			ParseTsData(0x80, 0xFE, 3, &data->have_ecm_data, data->ecm_data, sizeof(data->ecm_data),
						&data->ecm_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParseEcmData, data);
			continue;
		}

		if (scramblingControl == 0)
		{
			continue;
		}

		if (!(stream_buf[i + 3] & 0x10))
		{
			stream_buf[i + 3] &= 0x3F;
			continue;
		}

		oddKeyUsed = scramblingControl == 0xC0 ? 1 : 0;

		if (!stream_server_has_ecm[data->connid])
		{
			keydata = &emu_fixed_key_data[data->connid];
			SAFE_MUTEX_LOCK(&emu_fixed_key_data_mutex[data->connid]);
			data->key.pvu_csa_used = keydata->pvu_csa_used;
		}
		else
		{
			keydata = &data->key;
		}

		if (keydata->pvu_csa_used)
		{
			oddeven = scramblingControl; // for detecting odd/even switch

			if (pid == data->video_pid) // start with video pid, since it is most dominant
			{
				csakeyV = keydata->pvu_csa_ks[PVU_CW_VID];

				if (csakeyV != NULL)
				{
					cs = 0;
					ce = 1;
					packetClusterV[cs] = stream_buf + i; // set first cluster start
					packetClusterV[ce] = stream_buf + i + packetSize - 1;
					scrambled_packets = 1;

					// Now iterate through the rest of the packets and create clusters for batch decryption
					for (j = i + packetSize; j < bufLength; j += packetSize)
					{
						tsHeader = b2i(4, stream_buf + j);
						pid = (tsHeader & 0x1FFF00) >> 8;

						if (pid == data->video_pid)
						{
							if (oddeven != (tsHeader & 0xC0)) // changed key so stop adding clusters
							{
								break;
							}

							if (cs > ce) // First video packet for each cluster
							{
								packetClusterV[cs] = stream_buf + j;
								ce = cs + 1;
							}

							scrambled_packets++;
						}
						else
						{
							if (cs < ce) // First non-video packet - need to set end of video cluster
							{
								packetClusterV[ce] = stream_buf + j - 1;
								cs = ce + 1;
							}

							if ((tsHeader & 0xC0) == 0)
							{
								continue;
							}

							if (oddeven != (tsHeader & 0xC0)) // changed key so stop adding clusters
							{
								j = bufLength; // to break out of outer loop also
								break;
							}

							// Check for audio tracks and create single packet clusters
							for (k = 0; k < data->audio_pid_count; k++)
							{
								if (pid == data->audio_pids[k])
								{
									packetClusterA[k][csa[k]] = stream_buf + j;
									csa[k]++;
									packetClusterA[k][csa[k]] = stream_buf + j + packetSize - 1;
									csa[k]++;
									scrambled_packetsA[k]++;
								}
							}
						}
					}

					if (cs > ce) // last packet was not a video packet, so set null for end of all clusters
					{
						packetClusterV[cs] = NULL;
					}
					else
					{
						// last packet was a video packet, so set end of cluster to end of last packet
						if (scrambled_packets > 1)
						{
							packetClusterV[ce] = stream_buf + j - 1;
						}

						packetClusterV[ce + 1] = NULL; // add null to end of cluster list
					}

					while (j >= cluster_size)
					{
						j = decrypt_packets(csakeyV, packetClusterV);
					}

					for (k = 0; k < data->audio_pid_count; k++)
					{
						// if audio track has scrambled packets, set null to mark end and decrypt
						if (scrambled_packetsA[k])
						{
							csakeyA[k] = keydata->pvu_csa_ks[PVU_CW_A1 + k];
							packetClusterA[k][csa[k]] = NULL;
							decrypt_packets(csakeyA[k], packetClusterA[k]);
							csa[k] = 0;
							scrambled_packetsA[k] = 0;
						}
					}
				}
			}
			else
			{
				for (j = 0; j < data->audio_pid_count; j++)
				{
					if (pid == data->audio_pids[j])
					{
						csakeyA[0] = keydata->pvu_csa_ks[PVU_CW_A1 + j];
					}
				}

				if (csakeyA[0] != NULL)
				{
					packetClusterA[0][0] = stream_buf + i;
					packetClusterA[0][1] = stream_buf + i + packetSize - 1;
					packetClusterA[0][2] = NULL;
					decrypt_packets(csakeyA[0], packetClusterA[0]);
				}
			}
		}
		else
		{
			deskey = NULL;

			if (pid == data->video_pid)
			{
				deskey = keydata->pvu_des_ks[PVU_CW_VID][oddKeyUsed];
			}
			else
			{
				for (j = 0; j < data->audio_pid_count; j++)
				{
					if (pid == data->audio_pids[j])
					{
						deskey = keydata->pvu_des_ks[PVU_CW_A1 + j][oddKeyUsed];
					}
				}
			}

			if (deskey == NULL)
			{
				deskey = keydata->pvu_des_ks[PVU_CW_HSD][oddKeyUsed];
			}

			for (j = offset; j + 7 < 188; j += 8)
			{
				pdata = stream_buf + i + j;
				des(pdata, deskey, 0);
			}

			stream_buf[i + 3] &= 0x3F;
		}

		if (!stream_server_has_ecm[data->connid])
		{
			SAFE_MUTEX_UNLOCK(&emu_fixed_key_data_mutex[data->connid]);
		}
	}
}

static void DescrambleTsPacketsRosscrypt1(emu_stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
{
	int8_t is_av_pid;
	int32_t j;

	uint8_t scramblingControl;
	uint16_t pid, offset;
	uint32_t i, tsHeader;

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
		pid = (tsHeader & 0x1FFF00) >> 8;
		scramblingControl = tsHeader & 0xC0;

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

		if (scramblingControl == 0)
		{
			continue;
		}

		if (!(stream_buf[i + 3] & 0x10))
		{
			stream_buf[i + 3] &= 0x3F;
			continue;
		}

		is_av_pid = 0;

		if (pid == data->video_pid)
		{
			is_av_pid = 1;
		}
		else
		{
			for (j = 0; j < data->audio_pid_count; j++)
			{
				if (pid == data->audio_pids[j])
				{
					is_av_pid = 1;
					break;
				}
			}
		}

		if (is_av_pid)
		{
			static uint8_t dyn_key[184];
			static uint8_t last_packet[184];

			// Reset key on channel change
			if (data->reset_key_data == 1)
			{
				memset(dyn_key, 0x00, 184);
				memset(last_packet, 0x00, 184);
				data->reset_key_data = 0;
			}

			if (memcmp(last_packet, stream_buf + i + 4, 184) == 0)
			{
				if (memcmp(dyn_key, stream_buf + i + 4, 184) != 0)
				{
					memcpy(dyn_key, stream_buf + i + 4, 184);
				}
			}
			else
			{
				memcpy(last_packet, stream_buf + i + 4, 184);
			}

			for (j = 0; j < 184; j++)
			{
				stream_buf[i + 4 + j] ^= dyn_key[j];
			}

			stream_buf[i + 3] &= 0x3F;
		}
	}
}

static void DescrambleTsPacketsCompel(emu_stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
{
	int8_t is_pes_pid; // any PES pid
	int32_t j;
	const int8_t limit = 4;

	uint8_t scramblingControl;
	uint16_t pid, offset;
	uint32_t i, tsHeader;

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
		pid = (tsHeader & 0x1FFF00) >> 8;
		scramblingControl = tsHeader & 0xC0;

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

		if (scramblingControl == 0)
		{
			continue;
		}

		if (!(stream_buf[i + 3] & 0x10))
		{
			stream_buf[i + 3] &= 0x3F;
			continue;
		}

		is_pes_pid = 0;

		if (pid == data->video_pid)
		{
			is_pes_pid = 1;
		}
		else if (pid == data->teletext_pid)
		{
			is_pes_pid = 1;
		}
		else
		{
			for (j = 0; j < data->audio_pid_count; j++)
			{
				if (pid == data->audio_pids[j])
				{
					is_pes_pid = 1;
					break;
				}
			}
		}

		if (is_pes_pid)
		{
			static uint8_t dyn_key[184];
			static uint8_t found_key_bytes[184];
			static uint8_t found_key_bytes_count = 8;
			static uint8_t lastScramblingControl = 0xFF;

			int8_t matches00 = 0;
			int8_t matchesFF = 0;
			int8_t last00_was_good = 0;
			int8_t lastFF_was_good = 0;

			// Reset key when scrambling control changes from odd to even
			// and vice versa (every ~53 seconds) or when we change channel
			if (lastScramblingControl != scramblingControl)
			{
				memset(dyn_key, 0x00, 184);
				memset(found_key_bytes, 0, 184);
				found_key_bytes_count = 8;
				lastScramblingControl = scramblingControl;

				//cs_log_dbg(D_READER, "resetting key data (scrambling control: %02X)", scramblingControl);
			}

			for (j = 8; j < 184; j++)
			{
				if (found_key_bytes_count == 184)
				{
					break;
				}

				if (stream_buf[i + 4 + j] == 0x00)
				{
					last00_was_good = 1;
					matches00++;

					if (matches00 > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x00;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else if (stream_buf[i + 4 + j] == 0x3F)
				{
					last00_was_good = 1;
					matches00++;

					if (matches00 > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x3F;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else
				{
					if (last00_was_good == 1)
					{
						last00_was_good = 0;
						matches00--;
					}
					else
					{
						matches00 -= 2;
					}

					if (matches00 < 0)
					{
						matches00 = 0;
					}
				}

				if (stream_buf[i + 4 + j] == 0xC0)
				{
					lastFF_was_good = 1;
					matchesFF++;

					if (matchesFF > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x3F;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else if (stream_buf[i + 4 + j] == 0xFF)
				{
					lastFF_was_good = 1;
					matchesFF++;

					if (matchesFF > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x00;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else
				{
					if (lastFF_was_good == 1)
					{
						lastFF_was_good = 0;
						matchesFF--;
					}
					else
					{
						matchesFF -= 2;
					}

					if (matchesFF < 0)
					{
						matchesFF = 0;
					}
				}
			}

			for (j = 183; j >= 8; j--)
			{
				if (found_key_bytes_count == 184)
				{
					break;
				}

				if (stream_buf[i + 4 + j] == 0x00)
				{
					last00_was_good = 1;
					matches00++;

					if (matches00 > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x00;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else if (stream_buf[i + 4 + j] == 0x3F)
				{
					last00_was_good = 1;
					matches00++;

					if (matches00 > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x3F;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else
				{
					if (last00_was_good == 1)
					{
						last00_was_good = 0;
						matches00--;
					}
					else
					{
						matches00 -= 2;
					}

					if (matches00 < 0)
					{
						matches00 = 0;
					}
				}

				if (stream_buf[i + 4 + j] == 0xC0)
				{
					lastFF_was_good = 1;
					matchesFF++;

					if (matchesFF > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x3F;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else if (stream_buf[i + 4 + j] == 0xFF)
				{
					lastFF_was_good = 1;
					matchesFF++;

					if (matchesFF > limit && found_key_bytes[j] == 0)
					{
						dyn_key[j] = 0x00;
						found_key_bytes[j] = 1;
						found_key_bytes_count++;
					}
				}
				else
				{
					if (lastFF_was_good == 1)
					{
						lastFF_was_good = 0;
						matchesFF--;
					}
					else
					{
						matchesFF -= 2;
					}

					if (matchesFF < 0)
					{
						matchesFF = 0;
					}
				}
			}

			for (j = 8; j < 184; j++)
			{
				stream_buf[i + 4 + j] ^= dyn_key[j];
			}
		}

		stream_buf[i + 3] &= 0x3F; // Clear scrambling bits
	}
}

static int32_t connect_to_stream(char *http_buf, int32_t http_buf_len, char *stream_path)
{
	struct sockaddr_in cservaddr;
	IN_ADDR_T in_addr;

	int32_t streamfd = socket(AF_INET, SOCK_STREAM, 0);
	if (streamfd == -1)
	{
		return -1;
	}

	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if (setsockopt(streamfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv))
	{
		cs_log("ERROR: setsockopt() failed for SO_RCVTIMEO");
		return -1;
	}

	bzero(&cservaddr, sizeof(cservaddr));
	cservaddr.sin_family = AF_INET;
	cs_resolve(emu_stream_source_host, &in_addr, NULL, NULL);
	SIN_GET_ADDR(cservaddr) = in_addr;
	cservaddr.sin_port = htons(emu_stream_source_port);

	if (connect(streamfd, (struct sockaddr *)&cservaddr, sizeof(cservaddr)) == -1)
	{
		return -1;
	}

	if (emu_stream_source_auth)
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

	if (send(streamfd, http_buf, strlen(http_buf), 0) == -1)
	{
		return -1;
	}

	return streamfd;
}

static void stream_client_disconnect(emu_stream_client_conn_data *conndata)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&emu_fixed_key_srvid_mutex);
	emu_stream_cur_srvid[conndata->connid] = NO_SRVID_VALUE;
	stream_server_has_ecm[conndata->connid] = 0;
	SAFE_MUTEX_UNLOCK(&emu_fixed_key_srvid_mutex);

	SAFE_MUTEX_LOCK(&emu_stream_server_mutex);
	for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if (gconnfd[i] == conndata->connfd)
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
	emu_stream_client_conn_data *conndata = (emu_stream_client_conn_data *)arg;
	emu_stream_client_data *data;

	char *http_buf, stream_path[255], stream_path_copy[255];
	char *saveptr, *token, http_version[4];

	int8_t streamConnectErrorCount = 0, streamDataErrorCount = 0;
	int32_t bytesRead = 0, http_status_code = 0;
	int32_t clientStatus, streamStatus, streamfd;
	int32_t cur_dvb_buffer_size, cur_dvb_buffer_wait, i;

	uint8_t *stream_buf;
	uint16_t packetCount = 0, packetSize = 0, startOffset = 0;
	uint32_t remainingDataPos, remainingDataLength, tmp_pids[4];

	cs_log("Stream client %i connected", conndata->connid);

	if (!cs_malloc(&http_buf, 1024))
	{
		stream_client_disconnect(conndata);
		return NULL;
	}

	if (!cs_malloc(&stream_buf, EMU_DVB_BUFFER_SIZE))
	{
		NULLFREE(http_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}

	if (!cs_malloc(&data, sizeof(emu_stream_client_data)))
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

	SAFE_MUTEX_LOCK(&emu_fixed_key_srvid_mutex);
	emu_stream_cur_srvid[conndata->connid] = data->srvid;
	stream_server_has_ecm[conndata->connid] = 0;
	SAFE_MUTEX_UNLOCK(&emu_fixed_key_srvid_mutex);

	cs_log("Stream client %i request %s", conndata->connid, stream_path);

	cs_log_dbg(D_READER, "Stream client %i received srvid: %04X tsid: %04X onid: %04X ens: %08X",
				conndata->connid, data->srvid, data->tsid, data->onid, data->ens);

	snprintf(http_buf, 1024, "HTTP/1.0 200 OK\nConnection: Close\nContent-Type: video/mpeg\nServer: stream_enigma2\n\n");
	clientStatus = send(conndata->connfd, http_buf, strlen(http_buf), 0);

	data->connid = conndata->connid;
	data->caid = NO_CAID_VALUE;
	data->have_pat_data = 0;
	data->have_pmt_data = 0;
	data->have_cat_data = 0;
	data->have_ecm_data = 0;
	data->have_emm_data = 0;
	data->reset_key_data = 1;

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
				&& streamConnectErrorCount < 3 && streamDataErrorCount < 15)
		{
			if (data->key.pvu_csa_used)
			{
				cur_dvb_buffer_size = EMU_DVB_BUFFER_SIZE_CSA;
				cur_dvb_buffer_wait = EMU_DVB_BUFFER_WAIT_CSA;
			}
			else
			{
				cur_dvb_buffer_size = EMU_DVB_BUFFER_SIZE_DES;
				cur_dvb_buffer_wait = EMU_DVB_BUFFER_WAIT_DES;
			}

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
						if (chk_ctab_ex(data->caid, &cfg.emu_stream_relay_ctab))
						{
							if (caid_is_powervu(data->caid))
							{
								DescrambleTsPacketsPowervu(data, stream_buf + startOffset, packetCount * packetSize, packetSize);
							}
							else if (data->caid == 0xA101) // Rosscrypt1
							{
								DescrambleTsPacketsRosscrypt1(data, stream_buf + startOffset, packetCount * packetSize, packetSize);
							}
							else if (data->caid == NO_CAID_VALUE) // Compel
							{
								DescrambleTsPacketsCompel(data, stream_buf + startOffset, packetCount * packetSize, packetSize);
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

	for (i = 0; i < 8; i++)
	{
		if (data->key.pvu_csa_ks[i])
		{
			free_key_struct(data->key.pvu_csa_ks[i]);
		}
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

	if (!emu_stream_server_mutex_init)
	{
		SAFE_MUTEX_INIT(&emu_stream_server_mutex, NULL);
		emu_stream_server_mutex_init = 1;
	}

	SAFE_MUTEX_LOCK(&emu_fixed_key_srvid_mutex);
	for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		emu_stream_cur_srvid[i] = NO_SRVID_VALUE;
		stream_server_has_ecm[i] = 0;
	}
	SAFE_MUTEX_UNLOCK(&emu_fixed_key_srvid_mutex);

	for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		gconnfd[i] = -1;
	}

	glistenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (glistenfd == -1)
	{
		cs_log("ERROR: cannot create stream server socket");
		return NULL;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(emu_stream_relay_port);
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

		if (cs_malloc(&conndata, sizeof(emu_stream_client_conn_data)))
		{
			SAFE_MUTEX_LOCK(&emu_stream_server_mutex);
			if (gconncount < EMU_STREAM_SERVER_MAX_CONNECTIONS)
			{
				for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
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
			SAFE_MUTEX_UNLOCK(&emu_stream_server_mutex);
		}

		if (connaccepted)
		{
			int on = 1;
			if (setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
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

void *stream_key_delayer(void *UNUSED(arg))
{
	int32_t i, j;
	emu_stream_client_key_data *cdata;
	LL_ITER it;
	emu_stream_cw_item *item;
	struct timeb t_now;

	while (!exit_oscam)
	{
		cs_ftime(&t_now);

		for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
		{
			it = ll_iter_create(ll_emu_stream_delayed_keys[i]);

			while ((item = ll_iter_next(&it)))
			{
				if (comp_timeb(&t_now, &item->write_time) < 0)
				{
					break;
				}

				SAFE_MUTEX_LOCK(&emu_fixed_key_data_mutex[i]);

				cdata = &emu_fixed_key_data[i];

				for (j = 0; j < 8; j++)
				{
					if (item->csa_used)
					{
						if (cdata->pvu_csa_ks[j] == NULL)
						{
							cdata->pvu_csa_ks[j] = get_key_struct();
						}

						if (item->is_even)
						{
							set_even_control_word(cdata->pvu_csa_ks[j], item->cw[j]);
						}
						else
						{
							set_odd_control_word(cdata->pvu_csa_ks[j], item->cw[j]);
						}

						cdata->pvu_csa_used = 1;
					}
					else
					{
						if (item->is_even)
						{
							des_set_key(item->cw[j], cdata->pvu_des_ks[j][0]);
						}
						else
						{
							des_set_key(item->cw[j], cdata->pvu_des_ks[j][1]);
						}

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

void stop_stream_server(void)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&emu_stream_server_mutex);
	for (i = 0; i < EMU_STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if (gconnfd[i] != -1)
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

#endif // WITH_EMU
