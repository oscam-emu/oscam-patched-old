#ifndef MODULE_EMULATOR_BISS_H
#define MODULE_EMULATOR_BISS_H

#ifdef WITH_EMU

int8_t BissEcm(struct s_reader *rdr, uint16_t caid, const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_BISS_H
