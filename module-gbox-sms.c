#define MODULE_LOG_PREFIX "gbox/sms"

#include "globals.h"

#ifdef MODULE_GBOX
#include "module-gbox.h"
#include "module-gbox-sms.h"
#include "oscam-string.h"
#include "oscam-files.h"
#include "oscam-string.h"
#include "oscam-client.h"
#include "oscam-time.h"
#include "oscam-lock.h"

static int32_t poll_gsms_data (uint16_t *boxid, uint8_t *num, char *text)
{
	char *fext= FILE_GSMS_TXT; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "r");
	if(!fhandle)
		{
		//cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return -2;
		}
	uint32_t length1;
	uint8_t length;
	char buffer[140];
	char *tail;
	memset(buffer, 0, sizeof(buffer));
	fseek (fhandle,0L,SEEK_END);
	length1 = ftell(fhandle);
	fseek (fhandle,0L,SEEK_SET);
	if (length1 < 13)
		{
		cs_log("min msg char in %s = 6, actual = %d",fname, length1-7);
		fclose(fhandle);
		unlink(fname);
		return -1;
		}
	if(fgets(buffer,140,fhandle) != NULL)
		{	
		*boxid = strtol (buffer, &tail, 16);
		*num = atoi (tail);
		}
	fclose(fhandle);
	unlink(fname);
	if (length1 > (127+7))
		{
		length = 127+7;
		}
	else
		{
		length = length1;
		}
	cs_log_dbg(D_READER, "total msg length taken from %s = %d, limitted to %d",fname, length1, length);
	strncpy(text, &(buffer[7]),length-7);
	return 0;
}
static void write_gsms_to_osd_file(struct s_client *cli, unsigned char *gsms)
{
	char *fext= FILE_OSD_MSG; 
	char *fname = get_gbox_tmp_fname(fext); 
	if (file_exists(fname))
	{
	char gsms_buf[150];
	uint8_t i;
	// allow only alphanumerical characters in osd gsms due to safety reasons
	for (i=0; i< strlen((char*)gsms); i++)
	if (!isalnum(gsms[i]) && gsms[i] != ' ')
		{ gsms[i] = '_'; }
	
	memset(gsms_buf, 0, sizeof(gsms_buf));
	snprintf(gsms_buf, sizeof(gsms_buf), "%s %s:%s %s", fname, username(cli), cli->reader->device, gsms);
	cs_log_dbg(D_READER, "found OSD 'driver' %s - write gsms to OSD", fname);
	char *cmd = gsms_buf;
		FILE *p;
		if ((p = popen(cmd, "w")) == NULL)
		{
		cs_log("Error %s",fname);
		return;
		}
			pclose(p);
	}
	return;
}

void write_gsms_ack (struct s_client *cli)
{
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	struct gbox_peer *peer = cli->gbox;
	char *fext= FILE_GSMS_ACK; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "a+");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	fprintf(fhandle, "Peer %04X (%s) confirmed receipt of GSMS on %s",peer->gbox.id, cli->reader->device, tsbuf);
	fclose(fhandle);
	return;
}

static void write_gsms_nack (struct s_client *cl, uint8_t inf)
{
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	struct gbox_peer *peer = cl->gbox;
	char *fext= FILE_GSMS_NACK; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "a+");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	if(inf)
	{
	fprintf(fhandle, "INFO: GSMS to all: Peer %04X (%s) was OFFLINE %s",peer->gbox.id, cl->reader->device,tsbuf);
	}
	else
	{
	fprintf(fhandle, "WARNING: Private GSMS to Peer %04X (%s) failed - was OFFLINE %s",peer->gbox.id, cl->reader->device,tsbuf);
	}
	fclose(fhandle);
	return;
}

void write_gsms_msg (struct s_client *cli, uchar *gsms, uint16_t type, uint16_t UNUSED(msglen))
{
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	struct gbox_peer *peer = cli->gbox;
	struct s_reader *rdr = cli->reader;
	char *fext= FILE_GSMS_MSG; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "a+");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	if(type == 0x30)
		{
		fprintf(fhandle, "Normal message received from %04X %s on %s%s\n\n",peer->gbox.id, cli->reader->device, tsbuf, gsms);
		snprintf(rdr->last_gsms, sizeof(rdr->last_gsms), "%s %s", gsms, tsbuf); //added for easy handling of gsms by webif
		}
	else if(type == 0x31)
		{
		fprintf(fhandle, "OSD message received from %04X %s on %s%s\n\n",peer->gbox.id, cli->reader->device, tsbuf, gsms);
		write_gsms_to_osd_file(cli, gsms);
		snprintf(rdr->last_gsms, sizeof(rdr->last_gsms), "%s %s", gsms, tsbuf); //added for easy handling of gsms by webif
		}
	else 
		{fprintf(fhandle, "Corrupted message received from %04X %s on %s%s\n\n",peer->gbox.id, cli->reader->device, tsbuf, gsms);}
		fclose(fhandle);
	return;
}

void gsms_unavail(void)
{
	cs_log("INFO: GSMS feature disabled by conf");
}

static void gbox_send_gsms2peer(struct s_client *cl, char *gsms, uint8_t msg_type, int8_t gsms_len)
{
	uchar outbuf[150];
	struct gbox_peer *peer = cl->gbox;
	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();
	struct s_reader *rdr = cl->reader;

	gbox_message_header(outbuf, MSG_GSMS, peer->gbox.password, local_gbox_pw);
	outbuf[10] = (peer->gbox.id >> 8) & 0xff;
	outbuf[11] = peer->gbox.id & 0xff;
	outbuf[12] = (local_gbox_id >> 8) & 0xff;
	outbuf[13] = local_gbox_id & 0xff;
	outbuf[14] = msg_type;
	outbuf[15] = gsms_len;
	memcpy(&outbuf[16], gsms,gsms_len);
	outbuf[16 + gsms_len] = 0;
	cs_log("<-[gbx] send GSMS to %s:%d id: %04X", rdr->device, rdr->r_port, peer->gbox.id);
	gbox_send(cl, outbuf, gsms_len + 17);
	return;
}
int gbox_direct_send_gsms(uint16_t boxid, uint8_t num, char *gsms)
{
	uint8_t msg_type = 0, gsms_len = 0;
	int peer_found=0;
	char text[GBOX_MAX_MSG_TXT+1];
	
	memset(text, 0, sizeof(text));
	if(cfg.gsms_dis)
	{
		gsms_unavail();
		return 0;
	}
	gsms_len = strlen(gsms);
	if(gsms_len<6)
	{
		cs_log("GBOX: message to send to peer is too short 6 chars expected and %d received texte[%s]", gsms_len, gsms);
	}
	else if(gsms_len>GBOX_MAX_MSG_TXT)
	{
		gsms_len=GBOX_MAX_MSG_TXT;
		cs_log("GBOX message is too long so it will be truncated to max. [%d].", GBOX_MAX_MSG_TXT);
	}
	cs_strncpy(text,gsms,gsms_len+1);

	switch(num)
	{
		case 0: {msg_type = 0x30; break;}
		case 1: {msg_type = 0x31; break;}
	//	case 2: {gsms_prot = 2;	msg_type = 0x30; break;}
	//	case 3: {gsms_prot = 2;	msg_type = 0x31; break;}
		default:{cs_log("ERROR unknown gsms protocol"); return 0;}
	}
	cs_log_dbg(D_READER,"init gsms_length=%d  msg_type=%02X ",gsms_len, msg_type);
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);
	for (cl = first_client; cl; cl = cl->next)
	{
		peer_found=0;
		if(cl->gbox && cl->typ == 'p')
		{
			struct gbox_peer *peer = cl->gbox;
			if (peer->online && boxid == 0xFFFF) //send gsms to all peers online
			{
				gbox_send_gsms2peer(cl, text, msg_type, gsms_len);
				peer_found=1;
			}
			if (!peer->online && boxid == 0xFFFF)
			{
				cs_log("GBOX Info: peer %04X is OFFLINE",peer->gbox.id); 
				write_gsms_nack( cl, 1); 
			}
			if (peer->online && boxid == peer->gbox.id)
			{
				gbox_send_gsms2peer(cl, text, msg_type, gsms_len);
				peer_found=1; 
			}
			if (!peer->online && boxid == peer->gbox.id)
			{
				cs_log("GBOX WARNING: send GSMS failed - peer %04X is OFFLINE",peer->gbox.id);
				write_gsms_nack( cl, 0);  
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	return peer_found;
}

void gbox_get_online_peers(void)
{
	int n = 0, i;
	struct s_client *cl;

	for(i = 0; i < GBOX_MAX_DEST_PEERS; i++)
	{
		cfg.gbox_dest_peers[i]='\0';
	}
	cfg.gbox_dest_peers_num=0;
	cs_readlock(__func__, &clientlist_lock);
	for (cl = first_client; cl; cl = cl->next)
	{
		if((cl->gbox && cl->typ == 'p') && (n<GBOX_MAX_DEST_PEERS))
		{
			struct gbox_peer *peer = cl->gbox;
			if (peer->online) //peer is online
			{
				cfg.gbox_dest_peers[n++] = (peer->gbox.id);
			}
		}
	}
		cs_readunlock(__func__, &clientlist_lock);
	cfg.gbox_dest_peers_num = n;
	return;
}

void gbox_init_send_gsms(void)
{
	uint16_t boxid = 0;
	uint8_t num = 0;
	uint8_t msg_type = 0;
	int32_t poll_result = 0;
	char text[150];
	memset(text, 0, sizeof(text));
	char *fext= FILE_GSMS_TXT; 
	char *fname = get_gbox_tmp_fname(fext); 
	if(cfg.gsms_dis)
	{
	unlink(fname);
	gsms_unavail();
	return;
	}
	poll_result = poll_gsms_data( &boxid, &num, text);
	if(poll_result)
	{
	if(poll_result != -2) 
		{ cs_log("ERROR polling file %s", fname); }
	return;
	}
	int8_t gsms_len = strlen(text);
	cs_log_dbg(D_READER,"got from %s: box_ID = %04X  num = %d  gsms_length = %d  txt = %s",fname, boxid, num, gsms_len, text);

	switch(num)
	{
	case 0: {msg_type = 0x30; break;}
	case 1: {msg_type = 0x31; break;}
//	case 2: {gsms_prot = 2;	msg_type = 0x30; break;}
//	case 3: {gsms_prot = 2;	msg_type = 0x31; break;}
	default:{cs_log("ERROR unknown gsms protocol"); return;}
	}
	cs_log_dbg(D_READER,"init gsms to boxid= %04X  length= %d  msg_type= %02X ",boxid, gsms_len, msg_type);

	uint8_t id_valid = 0;
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);
	for (cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p')
		{
			struct gbox_peer *peer = cl->gbox;
			
			if (peer->online && boxid == 0xFFFF) //send gsms to all peers online
			{
			gbox_send_gsms2peer(cl, text, msg_type, gsms_len);
			id_valid = 1; 
			}
			if (!peer->online && boxid == 0xFFFF)
			{
			cs_log("Info: peer %04X is OFFLINE",peer->gbox.id); 
			write_gsms_nack( cl, 1);
			id_valid = 1;  
			}
			if (peer->online && boxid == peer->gbox.id)
			{
			gbox_send_gsms2peer(cl, text, msg_type, gsms_len); 
			id_valid = 1; 
			}
			if (!peer->online && boxid == peer->gbox.id)
			{
			cs_log("WARNING: send GSMS failed - peer %04X is OFFLINE",peer->gbox.id);
			write_gsms_nack( cl, 0);
			id_valid = 1; 
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	if (!id_valid)
			{
			cs_log("WARNING: send GSMS failed - peer_id unknown");
			}
	return;
}

void gbox_send_gsms_ack(struct s_client *cli)
{
	uchar outbuf[20];
	struct gbox_peer *peer = cli->gbox;
	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();
	struct s_reader *rdr = cli->reader;

		if (peer->online)
		{
		gbox_message_header(outbuf, MSG_GSMS_ACK, peer->gbox.password, local_gbox_pw);
		outbuf[10] = 0;
		outbuf[11] = 0;
		outbuf[12] = (local_gbox_id >> 8) & 0xff;
		outbuf[13] = local_gbox_id & 0xff;
		outbuf[14] = 0x1;
		outbuf[15] = 0;
		cs_log_dbg(D_READER,"<-[gbx] send GSMS_ACK to %s:%d id: %04X",rdr->device, rdr->r_port, peer->gbox.id);
		gbox_send(cli, outbuf, 16);
		}
}

static pthread_t sms_sender_thread;
static int32_t sms_sender_active = 0;
static pthread_cond_t sleep_cond;
static pthread_mutex_t sleep_cond_mutex;
static pthread_mutex_t sms_mutex;

static void sms_mutex_init(void)
{
	static int8_t mutex_init = 0;
	
	if(!mutex_init)
	{
		SAFE_MUTEX_INIT(&sms_mutex, NULL);
		cs_pthread_cond_init(__func__, &sleep_cond_mutex, &sleep_cond);
		mutex_init = 1;
	}	
}

static void sms_sender(void)
{
 	char *fext= FILE_GSMS_TXT;
	char *fname = get_gbox_tmp_fname(fext);
			
	while(sms_sender_active)
	{
    	if (file_exists(fname))
        {
			gbox_init_send_gsms();
        } 		
		
		sleepms_on_cond(__func__, &sleep_cond_mutex, &sleep_cond, 1000);
	}
	pthread_exit(NULL);
}

void start_sms_sender(void)
{
	int32_t is_active;
	
	sms_mutex_init();
	
	SAFE_MUTEX_LOCK(&sms_mutex);
	is_active = sms_sender_active;
	if(!sms_sender_active)
	{
		sms_sender_active = 1;
	}
	
	if(is_active || cfg.gsms_dis)
	{
		SAFE_MUTEX_UNLOCK(&sms_mutex);
		return;	
	}
	
	int32_t ret = start_thread("sms sender", (void *)&sms_sender, NULL, &sms_sender_thread, 0, 1);
	if(ret)
	{
		sms_sender_active = 0;
	}
	
	SAFE_MUTEX_UNLOCK(&sms_mutex);
}

void stop_sms_sender(void)
{
	sms_mutex_init();
	
	SAFE_MUTEX_LOCK(&sms_mutex);
	
	if(sms_sender_active)
	{
		sms_sender_active = 0;
		SAFE_COND_SIGNAL(&sleep_cond);
		SAFE_THREAD_JOIN(sms_sender_thread, NULL);
	}
	
	SAFE_MUTEX_UNLOCK(&sms_mutex);
}


#endif
