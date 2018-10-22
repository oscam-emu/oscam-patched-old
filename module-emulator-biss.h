#ifndef MODULE_EMULATOR_BISS_H
#define MODULE_EMULATOR_BISS_H

#ifdef WITH_EMU

int8_t BissECM(struct s_reader *rdr, const uint8_t *ecm, int16_t ecmDataLen, uint8_t *dw, uint16_t srvid, uint16_t ecmpid);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_BISS_H
