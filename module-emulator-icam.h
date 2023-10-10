#ifndef MODULE_EMULATOR_ICAM_H
#define MODULE_EMULATOR_ICAM_H

#ifdef WITH_EMU

#include "module-emulator-streamserver.h"

bool caid_is_icam(uint16_t caid);
void icam_write_cw(ECM_REQUEST *er, int32_t connid);

#ifdef MODULE_RADEGAST
void icam_ecm(emu_stream_client_data *cdata);
bool icam_connect_to_radegast(void);
void icam_close_radegast_connection(void);
void icam_reset(int32_t connid);
bool icam_send_to_radegast(uint8_t* data, int len);
#endif // MODULE_RADEGAST

#endif // WITH_EMU

#endif // MODULE_EMULATOR_ICAM_H
