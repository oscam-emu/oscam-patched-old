#ifndef MODULE_EMULATOR_ICAM_H
#define MODULE_EMULATOR_ICAM_H

#ifdef WITH_EMU

#include "module-emulator-streamserver.h"

#ifdef MODULE_RADEGAST
void icam_close_radegast_connection(void);
void icam_reset(int32_t connid);
void icam_ecm(emu_stream_client_data *cdata);
#endif // MODULE_RADEGAST

void icam_write_cw(ECM_REQUEST *er, int32_t connid);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_ICAM_H
