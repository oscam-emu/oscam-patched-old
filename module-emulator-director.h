#ifndef MODULE_EMULATOR_DIRECTOR_H
#define MODULE_EMULATOR_DIRECTOR_H

#ifdef WITH_EMU

int8_t director_ecm(uint8_t *ecm, uint8_t *dw);
int8_t director_emm(uint8_t *emm, uint32_t *keysAdded);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_DIRECTOR_H
