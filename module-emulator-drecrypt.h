#ifndef MODULE_EMULATOR_DRECRYPT_H
#define MODULE_EMULATOR_DRECRYPT_H

#ifdef WITH_EMU

int8_t Drecrypt2ECM(uint32_t provId, uint8_t *ecm, uint8_t *dw);
int8_t Drecrypt2EMM(struct s_reader *rdr, uint32_t provId, uint8_t *emm, uint32_t *keysAdded);

// hexserials must be of type "uint8_t hexserials[length]"
// returns 0 on error, 1 on success
int8_t GetDrecryptHexserials(uint16_t caid, uint32_t provid, uint8_t *hexserials, int32_t length, int32_t* count);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_DRECRYPT_H
