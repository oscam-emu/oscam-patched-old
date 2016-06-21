/*
 * Header file for DreCas reader.
 */
#ifndef _CSCTAPI_IFD_DRECAS_H_
#define _CSCTAPI_IFD_DRECAS_H_

int32_t DreCas_Init(struct s_reader *reader);
int32_t DreCas_GetStatus(struct s_reader *reader, int32_t *status);
int32_t DreCas_Reset(struct s_reader *reader, ATR *atr);
int32_t DreCas_Close(struct s_reader *reader);
int32_t DreCas_FastReset(struct s_reader *reader, int32_t delay);

#endif

