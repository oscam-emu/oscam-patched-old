#include "../globals.h"

#ifdef CARDREADER_PCSC

#include "atr.h"
#include "../oscam-string.h"

#if defined(__CYGWIN__)
#define __reserved
#define __nullnullterminated
#include <specstrings.h>
#include <WinSCard.h>
#endif

#if !defined(__CYGWIN__)
#if !defined(__APPLE__)
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <PCSC/reader.h>
#endif
#endif

#if defined(__APPLE__)
#include "pcsclite.h"
#include "winscard.h"
#include "wintypes.h"
#include "reader.h"
#endif

#ifndef ERR_INVALID
#define ERR_INVALID -1
#endif

#if defined(__CYGWIN__)
#undef OK
#undef ERROR
#undef LOBYTE
#undef HIBYTE
#endif

#define OK 0
#define ERROR 1

struct pcsc_data
{
	bool         pcsc_has_card;
	char         pcsc_name[128];
	SCARDCONTEXT hContext;
	SCARDHANDLE  hCard;
	DWORD        dwActiveProtocol;
};

static int32_t pcsc_init(struct s_reader *pcsc_reader)
{
	ULONG rv;
	DWORD dwReaders = 0;
	LPSTR mszReaders = NULL;
	char *ptr, **readers = NULL;
	char *device = pcsc_reader->device;
	int32_t nbReaders;
	int32_t reader_nb;

	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC establish context for PCSC pcsc_reader %s", device);
	SCARDCONTEXT hContext;
	memset(&hContext, 0, sizeof(hContext));
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if(rv == SCARD_S_SUCCESS)
	{
		if(!cs_malloc(&pcsc_reader->crdr_data, sizeof(struct pcsc_data)))
			{ return ERROR; }
		struct pcsc_data *crdr_data = pcsc_reader->crdr_data;
		crdr_data->hContext = hContext;

		// here we need to list the pcsc readers and get the name from there,
		// the pcsc_reader->device should contain the pcsc_reader number
		// and after the actual device name is copied in crdr_data->pcsc_name .
		rv = SCardListReaders(crdr_data->hContext, NULL, NULL, &dwReaders);
		if(rv != SCARD_S_SUCCESS)
		{
			rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC failed listing readers [1] : (%lx)", (unsigned long)rv);
			return ERROR;
		}
		if(!cs_malloc(&mszReaders, dwReaders))
			{ return ERROR; }
		rv = SCardListReaders(crdr_data->hContext, NULL, mszReaders, &dwReaders);
		if(rv != SCARD_S_SUCCESS)
		{
			rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC failed listing readers [2]: (%lx)", (unsigned long)rv);
			NULLFREE(mszReaders);
			return ERROR;
		}
		/* Extract readers from the null separated string and get the total
		 * number of readers
		 */
		nbReaders = 0;
		ptr = mszReaders;
		while(*ptr != '\0')
		{
			ptr += cs_strlen(ptr) + 1;
			nbReaders++;
		}

		if(nbReaders == 0)
		{
			rdr_log(pcsc_reader, "PCSC : no pcsc_reader found");
			NULLFREE(mszReaders);
			return ERROR;
		}

		if(!cs_malloc(&readers, nbReaders * sizeof(char *)))
		{
			NULLFREE(mszReaders);
			return ERROR;
		}

		char* device_line;
		char* device_first;
		char* device_second;

		device_line = strdup((const char *)&pcsc_reader->device);
		device_first = strsep(&device_line, ":");
		device_second = strsep(&device_line, ":");
		reader_nb = atoi(device_first);

		/* fill the readers table */
		nbReaders = 0;
		ptr = mszReaders;
		while(*ptr != '\0')
		{
			rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC pcsc_reader %d: %s", nbReaders, ptr);
			readers[nbReaders] = ptr;
			if ((reader_nb == -1) && (device_second != NULL) && strstr(ptr,device_second)){
				reader_nb = nbReaders;
			}
			ptr += cs_strlen(ptr) + 1;
			nbReaders++;
		}

		if(reader_nb < 0 || reader_nb >= nbReaders)
		{
			rdr_log(pcsc_reader, "Wrong pcsc_reader index: %d", reader_nb);
			NULLFREE(mszReaders);
			NULLFREE(readers);
			NULLFREE(device_line);
			return ERROR;
		}

		if (readers)
		{
		snprintf(crdr_data->pcsc_name, sizeof(crdr_data->pcsc_name), "%s", readers[reader_nb]);
		NULLFREE(readers);
		}
		NULLFREE(mszReaders);
		NULLFREE(device_line);
	}
	else
	{
		rdr_log(pcsc_reader, "PCSC failed establish context (%lx)", (unsigned long)rv);
		return ERROR;
	}
	return OK;
}

static int32_t pcsc_do_api(struct s_reader *pcsc_reader, const uint8_t *buf, uint8_t *cta_res, uint16_t *cta_lr, int32_t l)
{
	LONG rv;
	DWORD dwSendLength, dwRecvLength;

	*cta_lr = 0;
	if(!l)
	{
		rdr_log(pcsc_reader, "ERROR: Data length to be send to the pcsc_reader is %d", l);
		return ERROR;
	}

	char tmp[l * 3];
	dwRecvLength = CTA_RES_LEN;

	struct pcsc_data *crdr_data = pcsc_reader->crdr_data;
	if(crdr_data->dwActiveProtocol == SCARD_PROTOCOL_T0)
	{
		//  explanantion as to why we do the test on buf[4] :
		// Issuing a command without exchanging data :
		//To issue a command to the card that does not involve the exchange of data (either sent or received), the send and receive buffers must be formatted as follows.
		//The pbSendBuffer buffer must contain the CLA, INS, P1, and P2 values for the T=0 operation. The P3 value is not sent. (This is to differentiate the header from the case where 256 bytes are expected to be returned.)
		//The cbSendLength parameter must be set to four, the size of the T=0 header information (CLA, INS, P1, and P2).
		//The pbRecvBuffer will receive the SW1 and SW2 status codes from the operation.
		//The pcbRecvLength should be at least two and will be set to two upon return.
		if(buf[4])
			{ dwSendLength = l; }
		else
			{ dwSendLength = l - 1; }
		rdr_log_dbg(pcsc_reader, D_DEVICE, "sending %lu bytes to PCSC : %s", (unsigned long)dwSendLength, cs_hexdump(1, buf, l, tmp, sizeof(tmp)));
		rv = SCardTransmit(crdr_data->hCard, SCARD_PCI_T0, (LPCBYTE) buf, dwSendLength, NULL, (LPBYTE) cta_res, (LPDWORD) &dwRecvLength);
		*cta_lr = dwRecvLength;
	}
	else  if(crdr_data->dwActiveProtocol == SCARD_PROTOCOL_T1)
	{
		dwSendLength = l;
		rdr_log_dbg(pcsc_reader, D_DEVICE, "sending %lu bytes to PCSC : %s", (unsigned long)dwSendLength, cs_hexdump(1, buf, l, tmp, sizeof(tmp)));
		rv = SCardTransmit(crdr_data->hCard, SCARD_PCI_T1, (LPCBYTE) buf, dwSendLength, NULL, (LPBYTE) cta_res, (LPDWORD) &dwRecvLength);
		*cta_lr = dwRecvLength;
	}
	else
	{
		rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC invalid protocol (T=%lu)", (unsigned long)crdr_data->dwActiveProtocol);
		return ERROR;
	}

	rdr_log_dbg(pcsc_reader, D_DEVICE, "received %d bytes from PCSC with rv=%lx : %s", *cta_lr, (unsigned long)rv, cs_hexdump(1, cta_res, *cta_lr, tmp, sizeof(tmp)));

	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC doapi (%lx ) (T=%d), %d", (unsigned long)rv, (crdr_data->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1), *cta_lr);

	if(rv  == SCARD_S_SUCCESS)
	{
		return OK;
	}
	else
	{
		return ERROR;
	}

}

static int32_t pcsc_activate_card(struct s_reader *pcsc_reader, uint8_t *atr, uint16_t *atr_size)
{
	struct pcsc_data *crdr_data = pcsc_reader->crdr_data;
	LONG rv;
	DWORD dwState, dwAtrLen, dwReaderLen;
	unsigned char pbAtr[ATR_MAX_SIZE];
	char tmp[sizeof(pbAtr) * 3 + 1];

	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC initializing card in (%s)", crdr_data->pcsc_name);
	dwAtrLen = sizeof(pbAtr);
	dwReaderLen = 0;

	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC resetting card in (%s) with handle %ld", crdr_data->pcsc_name, (long)(crdr_data->hCard));
	rv = SCardReconnect(crdr_data->hCard, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,  SCARD_RESET_CARD, &crdr_data->dwActiveProtocol);

	if(rv != SCARD_S_SUCCESS)
	{
		rdr_log_dbg(pcsc_reader, D_DEVICE, "ERROR: PCSC failed to reset card (%lx)", (unsigned long)rv);
		return ERROR;
	}

	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC resetting done on card in (%s)", crdr_data->pcsc_name);
	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC Protocol (T=%d)", (crdr_data->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));

	rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC getting ATR for card in (%s)", crdr_data->pcsc_name);
	rv = SCardStatus(crdr_data->hCard, NULL, &dwReaderLen, &dwState, &crdr_data->dwActiveProtocol, pbAtr, &dwAtrLen);
	if(rv == SCARD_S_SUCCESS)
	{
		rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC Protocol (T=%d)", (crdr_data->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
		memcpy(atr, pbAtr, dwAtrLen);
		*atr_size = dwAtrLen;

		rdr_log(pcsc_reader, "ATR: %s", cs_hexdump(1, (uint8_t *)pbAtr, dwAtrLen, tmp, sizeof(tmp)));
		memcpy(pcsc_reader->card_atr, pbAtr, dwAtrLen);
		pcsc_reader->card_atr_length = dwAtrLen;
		return OK;
	}
	else
	{
		rdr_log_dbg(pcsc_reader, D_DEVICE, "ERROR: PCSC failed to get ATR for card (%lx)", (unsigned long)rv);
	}

	return ERROR;
}

static int32_t pcsc_activate(struct s_reader *reader, struct s_ATR *atr)
{
	unsigned char atrarr[ATR_MAX_SIZE];
	uint16_t atr_size = 0;
	if(pcsc_activate_card(reader, atrarr, &atr_size) == OK)
	{
		if(ATR_InitFromArray(atr, atrarr, atr_size) != ERROR)  // ATR is OK or softfail malformed
			{ return OK; }
		else
			{ return ERROR; }
	}
	else
		{ return ERROR; }
}

static int32_t pcsc_check_card_inserted(struct s_reader *pcsc_reader)
{
	struct pcsc_data *crdr_data = pcsc_reader->crdr_data;
	DWORD dwState, dwAtrLen, dwReaderLen;
	unsigned char pbAtr[64];
	SCARDHANDLE rv;

	dwAtrLen = sizeof(pbAtr);
	rv = 0;
	dwState = 0;
	dwReaderLen = 0;

	// Do we have a card ?
	if(!crdr_data->pcsc_has_card && !crdr_data->hCard)
	{
		// try connecting to the card
		rv = SCardConnect(crdr_data->hContext, crdr_data->pcsc_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &crdr_data->hCard, &crdr_data->dwActiveProtocol);
		if(rv == (SCARDHANDLE)SCARD_E_NO_SMARTCARD)
		{
			// no card in pcsc_reader
			crdr_data->pcsc_has_card = 0;
			if(crdr_data->hCard)
			{
				SCardDisconnect(crdr_data->hCard, SCARD_RESET_CARD);
				crdr_data->hCard = 0;
			}
			// rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC card in %s removed / absent [dwstate=%lx rv=(%lx)]", crdr_data->pcsc_name, dwState, (unsigned long)rv );
			return OK;
		}
		else if(rv == (SCARDHANDLE)SCARD_W_UNRESPONSIVE_CARD)
		{
			// there is a problem with the card in the pcsc_reader
			crdr_data->pcsc_has_card = 0;
			crdr_data->hCard = 0;
			rdr_log(pcsc_reader, "PCSC card in %s is unresponsive. Eject and re-insert please.", crdr_data->pcsc_name);
			return ERROR;
		}
		else if(rv == SCARD_S_SUCCESS)
		{
			// we have a card
			crdr_data->pcsc_has_card = 1;
			rdr_log(pcsc_reader, "PCSC was opened with handle: %ld", (long)crdr_data->hCard);
		}
		else
		{
			// if we get here we have a bigger problem -> display status and debug
			// rdr_log_dbg(pcsc_reader, D_DEVICE, "PCSC pcsc_reader %s status [dwstate=%lx rv=(%lx)]", crdr_data->pcsc_name, dwState, (unsigned long)rv );
			return ERROR;
		}

	}

	// if we get there the card is ready, check its status
	rv = SCardStatus(crdr_data->hCard, NULL, &dwReaderLen, &dwState, &crdr_data->dwActiveProtocol, pbAtr, &dwAtrLen);

	if(rv == SCARD_S_SUCCESS && (dwState & (SCARD_PRESENT | SCARD_NEGOTIABLE | SCARD_POWERED)))
	{
		return OK;
	}
	else
	{
		SCardDisconnect(crdr_data->hCard, SCARD_RESET_CARD);
		crdr_data->hCard = 0;
		crdr_data->pcsc_has_card = 0;
	}

	return ERROR;
}

static int32_t pcsc_get_status(struct s_reader *reader, int32_t *in)
{
	struct pcsc_data *crdr_data = reader->crdr_data;
	int32_t ret = pcsc_check_card_inserted(reader);
	*in = crdr_data->pcsc_has_card;
	return ret;
}

static int32_t pcsc_close(struct s_reader *pcsc_reader)
{
	struct pcsc_data *crdr_data = pcsc_reader->crdr_data;
	rdr_log_dbg(pcsc_reader, D_IFD, "PCSC : Closing device %s", pcsc_reader->device);
	SCardDisconnect(crdr_data->hCard, SCARD_LEAVE_CARD);
	SCardReleaseContext(crdr_data->hContext);
	return OK;
}

const struct s_cardreader cardreader_pcsc =
{
	.desc                    = "pcsc",
	.typ                     = R_PCSC,
	.skip_extra_atr_parsing  = 1,
	.skip_t1_command_retries = 1,
	.skip_setting_ifsc       = 1,
	.reader_init             = pcsc_init,
	.get_status              = pcsc_get_status,
	.activate                = pcsc_activate,
	.card_write              = pcsc_do_api,
	.close                   = pcsc_close,
};

#endif
