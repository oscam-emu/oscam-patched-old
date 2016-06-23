/*
        ifd_drecas.c
        This module provides IFD handling functions for DreCas reader.
*/

#include "../globals.h"
#include "../oscam-string.h"

#ifdef CARDREADER_DRECAS
#include "../oscam-time.h"
#include "icc_async.h"
#include "ifd_drecas.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1

int32_t DreCas_Init(struct s_reader *reader)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	if(crdr_ops->flush) { IO_Serial_Flush(reader); }

	rdr_log_dbg(reader, D_IFD, "Initializing reader type=%d", reader->typ);

	/* Default serial port settings */
	if(reader->atr[0] == 0)
	{
		if(IO_Serial_SetParams(reader, DEFAULT_BAUDRATE, 8, PARITY_NONE, 1, NULL, NULL)) { return ERROR; }
		if(crdr_ops->flush) { IO_Serial_Flush(reader); }
	}
	return OK;
}

int32_t DreCas_GetStatus(struct s_reader *UNUSED(reader), int32_t *UNUSED(status))
{
	return OK;
}

int32_t DreCas_Reset(struct s_reader *reader, ATR *atr)
{
	rdr_log_dbg(reader, D_IFD, "Resetting card");
	rdr_log_dbg(reader, D_IFD, "DreCas_Reset");
	int32_t ret;
	uint8_t buf[ATR_MAX_SIZE];
	uint8_t reset_cmd[5] = { 0xDB ,0x03 ,0x00 ,0xC1 ,0xC1 };
	
	if(IO_Serial_SetParams(reader, DEFAULT_BAUDRATE, 8, PARITY_NONE, 2, NULL, NULL)) { return ERROR; }
	
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;


	if(crdr_ops->flush) { IO_Serial_Flush(reader); }

	ret = ERROR;

	IO_Serial_Ioctl_Lock(reader, 1);
		
	/* Module soft reset */

	IO_Serial_Write(reader, 0, 0, (uint32_t)sizeof(reset_cmd), reset_cmd);
	cs_sleepms(50);
		
	IO_Serial_Ioctl_Lock(reader, 0);

	int32_t n = 0;

	while(n < ATR_MAX_SIZE && !IO_Serial_Read(reader, 50, ATR_TIMEOUT, 1, buf + n))
		{ n++; }
	
	if(ATR_InitFromArray(atr, buf, n) != ERROR)
		{ ret = OK; }

	return ret;
}

int32_t DreCas_Close(struct s_reader *reader)
{
	rdr_log_dbg(reader, D_IFD, "Closing DreCas device %s", reader->device);
	IO_Serial_Close(reader);
	return OK;
}

static int32_t mouse_init(struct s_reader *reader)
{
	const struct s_cardreader *crdr_ops = reader->crdr;
	if (!crdr_ops) return ERROR;

	reader->handle = open(reader->device,  O_RDWR | O_NOCTTY | O_NONBLOCK);
	if(reader->handle < 0)
	{
		rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)",
				reader->device, errno, strerror(errno));
		return ERROR;
	}
	if(DreCas_Init(reader))
	{
		rdr_log(reader, "ERROR: DreCas_Init returns error");
		DreCas_Close(reader);
		return ERROR;
	}
	return OK;
}

static int32_t DreCas_SetParity(struct s_reader *reader, unsigned char UNUSED(parity))
{
	return IO_Serial_SetParity(reader, PARITY_NONE);
}

const struct s_cardreader cardreader_drecas =
{
	.desc          = "drecas",
	.typ           = R_DRECAS,
	.flush         = 1,
	.read_written  = 0,
	.need_inverse  = 0,
	.reader_init   = mouse_init,
	.get_status    = DreCas_GetStatus,
	.activate      = DreCas_Reset,
	.transmit      = IO_Serial_Transmit,
	.receive       = IO_Serial_Receive,
	.close         = DreCas_Close,
	.set_parity    = DreCas_SetParity,
	.set_baudrate  = IO_Serial_SetBaudrate,
};

#endif

