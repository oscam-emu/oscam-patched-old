#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "oscam-conf-chk.h"
#include "oscam-config.h"
#include "oscam-reader.h"
#include "oscam-string.h"

/*
 * Readers in OSCam consist of 2 basic parts.
 * The hardware or the device part. This is where physical smart cards are inserted
 * and made available to OSCam.
 * The software or the emulation part. This is where the actual card reading is done,
 * including ecm and emm processing (i.e emulation of the various cryptosystems).
 * In the Emu reader, the device part has no meaning, but we have to create it in
 * order to be compatible with OSCam's reader structure.
*/

/*
 * Create the Emu "emulation" part. This is of type s_cardsystem.
 * Similar structures are found in the main sources folder (files reader-xxxxxx.c)
 * for every cryptosystem supported by OSCam.
 * Here we read keys from our virtual card (aka the SoftCam.Key file) and we inform
 * OSCam about them. This is done with the emu_card_info() function. Keep in mind
 * that Emu holds all its keys to separate structures for faster access.
 * In addition, ECM and EMM requests are processed here, with the emu_do_ecm() and
 * emu_do_emm() functions.
*/

#define CS_OK    1
#define CS_ERROR 0

static int32_t emu_do_ecm(struct s_reader *UNUSED(rdr), const ECM_REQUEST *UNUSED(er), struct s_ecm_answer *UNUSED(ea)) { return CS_ERROR; }
static int32_t emu_do_emm(struct s_reader *UNUSED(rdr), EMM_PACKET *UNUSED(emm)) { return CS_ERROR; }
static int32_t emu_card_info(struct s_reader *UNUSED(rdr)) { return CS_ERROR; }
//static int32_t emu_card_init(struct s_reader *UNUSED(rdr), struct s_ATR *UNUSED(atr)) { return CS_ERROR; }
static int32_t emu_get_emm_type(struct emm_packet_t *UNUSED(ep), struct s_reader *UNUSED(rdr)) { return CS_ERROR; }

FILTER *get_emu_prids_for_caid(struct s_reader *rdr, uint16_t caid)
{
	int32_t i;

	for (i = 0; i < rdr->emu_auproviders.nfilts; i++)
	{
		if (caid == rdr->emu_auproviders.filts[i].caid)
		{
			return &rdr->emu_auproviders.filts[i];
		}
	}

	return NULL;
}

static int32_t emu_get_emm_filter(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **UNUSED(emm_filters), unsigned int *UNUSED(filter_count)) { return CS_ERROR; }
static int32_t emu_get_emm_filter_adv(struct s_reader *UNUSED(rdr), struct s_csystem_emm_filter **UNUSED(emm_filters), unsigned int *UNUSED(filter_count), uint16_t UNUSED(caid), uint32_t UNUSED(provid), uint16_t UNUSED(srvid)) { return CS_ERROR; }

const struct s_cardsystem reader_emu =
{
	.desc = "emu",
	.caids = (uint16_t[]){ 0x05, 0x06, 0x09, 0x0D, 0x0E, 0x10, 0x18, 0x26, 0x4A, 0 },
	.do_ecm = emu_do_ecm,
	.do_emm = emu_do_emm,
	.card_info = emu_card_info,
	//.card_init = emu_card_init, // apparently this is not needed at all
	.get_emm_type = emu_get_emm_type,
	.get_emm_filter = emu_get_emm_filter, // needed to pass checks
	.get_emm_filter_adv = emu_get_emm_filter_adv,
};

/*
 * Create the Emu virtual "device" part. This is of type s_cardreader.
 * Similar structures are found in the csctapi (Card System Card Terminal API)
 * folder for every IFD (InterFace Device), aka smart card reader.
 * Since we have no hardware to initialize, we start our Stream Relay server
 * with the emu_reader_init() function.
 * At Emu shutdown, we remove keys from memory with the emu_close() function.
*/

#define CR_OK    0
#define CR_ERROR 1

static int32_t emu_reader_init(struct s_reader *UNUSED(reader)) { return CR_OK; }
static int32_t emu_close(struct s_reader *UNUSED(reader)) { return CR_OK; }
static int32_t emu_get_status(struct s_reader *UNUSED(reader), int32_t *in) { *in = 1; return CR_OK; }
static int32_t emu_activate(struct s_reader *UNUSED(reader), struct s_ATR *UNUSED(atr)) { return CR_OK; }
static int32_t emu_transmit(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer), uint32_t UNUSED(size), uint32_t UNUSED(expectedlen), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t emu_receive(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer), uint32_t UNUSED(size), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t emu_write_settings(struct s_reader *UNUSED(reader), struct s_cardreader_settings *UNUSED(s)) { return CR_OK; }
static int32_t emu_card_write(struct s_reader *UNUSED(pcsc_reader), const uint8_t *UNUSED(buf), uint8_t *UNUSED(cta_res), uint16_t *UNUSED(cta_lr), int32_t UNUSED(l)) { return CR_OK; }
static int32_t emu_set_protocol(struct s_reader *UNUSED(rdr), uint8_t *UNUSED(params), uint32_t *UNUSED(length), uint32_t UNUSED(len_request)) { return CR_OK; }

const struct s_cardreader cardreader_emu =
{
	.desc                   = "emu",
	.typ                    = R_EMU,
	.skip_extra_atr_parsing = 1,
	.reader_init            = emu_reader_init,
	.get_status             = emu_get_status,
	.activate               = emu_activate,
	.transmit               = emu_transmit,
	.receive                = emu_receive,
	.close                  = emu_close,
	.write_settings         = emu_write_settings,
	.card_write             = emu_card_write,
	.set_protocol           = emu_set_protocol,
};

#endif // WITH_EMU
