#ifndef MODULE_EMULATOR_IRDETO_H
#define MODULE_EMULATOR_IRDETO_H

#ifdef WITH_EMU

int8_t irdeto2_ecm(uint16_t caid, uint8_t *oecm, uint8_t *dw);
int8_t irdeto2_emm(uint16_t caid, uint8_t *oemm, uint32_t *keysAdded);

// hexserial must be of type "uint8_t hexserial[3]"
// returns 0 on error, 1 on success
int8_t irdeto2_get_hexserial(uint16_t caid, uint8_t *hexserial);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_IRDETO_H
