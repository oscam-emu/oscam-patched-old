#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "ffdecsa/ffdecsa.h"
#include "module-emulator-icam.h"
#include "module-emulator-streamserver.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"

#ifdef MODULE_RADEGAST
static int32_t gRadegastFd = 0;
static uint8_t gLast_ecm_paket[EMU_STREAM_SERVER_MAX_CONNECTIONS][8];
#endif

#ifdef MODULE_RADEGAST

static bool connect_to_radegast(void)
{
	struct sockaddr_in cservaddr;

	if (gRadegastFd == 0)
	{
		gRadegastFd = socket(AF_INET, SOCK_STREAM, 0);
	}

	if (gRadegastFd < 0)
	{
		gRadegastFd = 0;
		return false;
	}

	int32_t flags = fcntl(gRadegastFd, F_GETFL);
	fcntl(gRadegastFd, F_SETFL, flags | O_NONBLOCK);

	bzero(&cservaddr, sizeof(cservaddr));
	cservaddr.sin_family = AF_INET;
	SIN_GET_ADDR(cservaddr) = cfg.rad_srvip;
	cservaddr.sin_port = htons(cfg.rad_port);

	connect(gRadegastFd,(struct sockaddr *)&cservaddr, sizeof(cservaddr));
	return true;
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

void icam_close_radegast_connection(void)
{
	close(gRadegastFd);
	gRadegastFd = 0;
}

void icam_reset(int32_t connid)
{
	memset(gLast_ecm_paket[connid], 0, 8);
}

void icam_ecm(emu_stream_client_data *cdata)
{
	uint16_t section_length = SCT_LEN(cdata->ecm_data);
	uint16_t packet_len;
	static uint8_t header_len = 2;
	static uint8_t payload_static_len = 12;

	if (memcmp(gLast_ecm_paket[cdata->connid], cdata->ecm_data, 8) != 0)
	{
		memcpy(gLast_ecm_paket[cdata->connid], cdata->ecm_data, 8);

		if (gRadegastFd <= 0)
		{
			connect_to_radegast();
		}

		packet_len = header_len + payload_static_len + section_length;
		uint8_t outgoing_data[packet_len];
		outgoing_data[0] = 1;
		outgoing_data[1] = payload_static_len + section_length;
		outgoing_data[2] = 10; // caid
		outgoing_data[3] = 2;
		outgoing_data[4] = cdata->caid >> 8;
		outgoing_data[5] = cdata->caid & 0xFF;
		outgoing_data[6] = 9; // srvid
		outgoing_data[7] = 4;
		outgoing_data[8] = cdata->srvid & 0xFF;
		outgoing_data[10] = cdata->srvid >> 8;
		outgoing_data[12] = 3;
		outgoing_data[13] = section_length;

		memcpy(outgoing_data + header_len + payload_static_len, cdata->ecm_data, section_length);

		if (!send_to_radegast(outgoing_data, packet_len))
		{
			icam_close_radegast_connection();

			if (connect_to_radegast())
			{
				send_to_radegast(outgoing_data, packet_len);
			}
		}
	}
}

#endif // MODULE_RADEGAST

void icam_write_cw(ECM_REQUEST *er, int32_t connid)
{
	SAFE_MUTEX_LOCK(&emu_fixed_key_data_mutex[connid]);

	if (emu_fixed_key_data[connid].icam_csa_ks == NULL)
	{
		emu_fixed_key_data[connid].icam_csa_ks = get_key_struct();
	}

	bool icam = (er->ecm[2] - er->ecm[4]) == 4;

	if (er->ecm[0] == 0x80)
	{
		if (icam)
		{
			set_even_control_word_ecm(emu_fixed_key_data[connid].icam_csa_ks, er->cw, er->ecm[0x15]);
		}
		else
		{
			set_even_control_word(emu_fixed_key_data[connid].icam_csa_ks, er->cw);
		}
	}
	else if (icam)
	{
		set_odd_control_word_ecm(emu_fixed_key_data[connid].icam_csa_ks, er->cw + 8, er->ecm[0x15]);
	}
	else
	{
		set_odd_control_word(emu_fixed_key_data[connid].icam_csa_ks, er->cw + 8);
	}

	emu_fixed_key_data[connid].icam_csa_used = 1;

	SAFE_MUTEX_UNLOCK(&emu_fixed_key_data_mutex[connid]);
}

#endif // WITH_EMU
