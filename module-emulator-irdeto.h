#ifndef MODULE_EMULATOR_IRDETO_H
#define MODULE_EMULATOR_IRDETO_H

#ifdef WITH_EMU

int8_t Irdeto2ECM(uint16_t caid, uint8_t *oecm, uint8_t *dw);
int8_t Irdeto2EMM(uint16_t caid, uint8_t *oemm, uint32_t *keysAdded);

// hexserial must be of type "uint8_t hexserial[3]"
// returns 0 on error, 1 on success
int8_t GetIrdeto2Hexserial(uint16_t caid, uint8_t* hexserial);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_IRDETO_H
