#ifndef MODULE_EMULATOR_VIACCESS_H
#define MODULE_EMULATOR_VIACCESS_H

#ifdef WITH_EMU

int8_t viaccess_ecm(uint8_t *ecm, uint8_t *dw);
int8_t viaccess_emm(uint8_t *emm, uint32_t *keysAdded);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_VIACCESS_H
