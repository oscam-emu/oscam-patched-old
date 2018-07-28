/*
    icc_async.h
    Asynchronous integrated circuit cards handling functions

    This file is part of the Unix driver for Towitoko smartcard readers
    Copyright (C) 2000 2001 Carlos Prados <cprados@yahoo.com>

    This version is modified by doz21 to work in a special manner ;)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _ICC_ASYNC_
#define _ICC_ASYNC_

#include "atr.h"

/*
 * Exported types definition
 */

/* Initialization and Deactivation */
int32_t ICC_Async_Activate(struct s_reader *reader, ATR *newatr, uint16_t deprecated);
int32_t ICC_Async_Close(struct s_reader *reader);
int32_t ICC_Async_Device_Init(struct s_reader *reader);
int32_t ICC_Async_Init_Locks(void);

/* Attributes */
int32_t ICC_Async_GetTimings(struct s_reader *reader, uint32_t wait_etu);
int32_t ICC_Async_GetStatus(struct s_reader *reader, int32_t *has_card);

/* Operations */
int32_t ICC_Async_CardWrite(struct s_reader *reader, unsigned char *cmd, uint16_t lc, unsigned char *rsp, uint16_t *lr, uint8_t block_nad);
int32_t ICC_Async_Transmit(struct s_reader *reader, uint32_t size, uint32_t expectedlen, unsigned char *buffer, uint32_t delay, uint32_t timeout);
int32_t ICC_Async_Receive(struct s_reader *reader, uint32_t size, unsigned char *buffer, uint32_t delay, uint32_t timeout);

void ICC_Async_DisplayMsg(struct s_reader *, char *msg);
int32_t ICC_Async_Reset(struct s_reader *, struct s_ATR *, int32_t (*rdr_activate_card)(struct s_reader *, struct s_ATR *, uint16_t deprecated), int32_t (*rdr_get_cardsystem)(struct s_reader *, struct s_ATR *));

#ifdef READER_NAGRA_MERLIN
uint32_t calc_ccitt32(uint8_t *buf, uint8_t count);
uint32_t cas7_seq;
void calculate_cas7_cmd(struct s_reader *reader, uint8_t *cmdin,uint8_t cmdlen,uint8_t *cmdout);
void do_cas7_cmd(struct s_reader *reader,unsigned char *cta_res, uint16_t *p_cta_lr,uint8_t *data,uint8_t inlen,uint8_t resplen);
#endif

#endif /* _ICC_ASYNC_ */


