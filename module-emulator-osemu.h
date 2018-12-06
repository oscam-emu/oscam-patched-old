#ifndef MODULE_EMULATOR_H_
#define MODULE_EMULATOR_H_

#ifdef WITH_EMU

#define EMU_MAX_CHAR_KEYNAME 12
#define EMU_KEY_FILENAME "SoftCam.Key"
#define EMU_KEY_FILENAME_MAX_LEN 31
#define EMU_MAX_ECM_LEN MAX_ECM_SIZE
#define EMU_MAX_EMM_LEN MAX_EMM_SIZE

/*
 * Error codes for ProccessECM and ProccessEMM functions
 *  0 - OK
 *  1 - ECM / EMM not supported
 *  2 - ECM / EMM key not found
 *  3 - Nano80 error
 *  4 - Corrupt data
 *  5 - CW not found
 *  6 - CW / ECM / EMM checksum error
 *  7 - Out of memory
 *  8 - ICG error
 *  9 - Wrong provider
 * 10 - ECM key rejected
*/

#define EMU_OK             0
#define EMU_NOT_SUPPORTED  1
#define EMU_KEY_NOT_FOUND  2
#define EMU_NANO_80_ERROR  3
#define EMU_CORRUPT_DATA   4
#define EMU_CW_NOT_FOUND   5
#define EMU_CHECKSUM_ERROR 6
#define EMU_OUT_OF_MEMORY  7
#define EMU_ICG_ERROR      8
#define EMU_WRONG_PROVID   9
#define EMU_KEY_REJECTED  10

typedef struct KeyData KeyData;

struct KeyData
{
	char identifier;
	uint32_t provider;
	char keyName[EMU_MAX_CHAR_KEYNAME];
	uint8_t *key;
	uint32_t keyLength;
	KeyData *nextKey;
};

typedef struct
{
	KeyData *EmuKeys;
	uint32_t keyCount;
	uint32_t keyMax;
} KeyDataContainer;

extern KeyDataContainer CwKeys;
extern KeyDataContainer ViKeys;
extern KeyDataContainer NagraKeys;
extern KeyDataContainer IrdetoKeys;
extern KeyDataContainer NDSKeys;
extern KeyDataContainer BissKeys;
extern KeyDataContainer PowervuKeys;
extern KeyDataContainer DreKeys;
extern KeyDataContainer TandbergKeys;
extern uint8_t viasat_const[];
extern char *emu_keyfile_path;
extern pthread_mutex_t emu_key_data_mutex;

void set_emu_keyfile_path(const char *path);
void clear_emu_keydata(void);
uint8_t read_emu_keyfile(struct s_reader *rdr, const char *path);

#if !defined(__APPLE__) && !defined(__ANDROID__)
void read_emu_keymemory(struct s_reader *rdr);
#endif

void read_emu_eebin(const char *path, const char *name);
void read_emu_deskey(uint8_t *dreOverKey, uint8_t len);

extern uint16_t GetEcmLen(const uint8_t *ecm);
int8_t isValidDCW(uint8_t *dw);
int8_t CharToBin(uint8_t *out, const char *in, uint32_t inLen);
void Date2Str(char *dateStr, uint8_t len, int8_t offset, uint8_t format);
KeyDataContainer *GetKeyContainer(char identifier);

int8_t ProcessECM(struct s_reader *rdr, int16_t ecmDataLen, uint16_t caid, uint32_t provider,
				const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid, EXTENDED_CW* cw_ex);

int8_t ProcessEMM(struct s_reader *rdr, uint16_t caid, uint32_t provider, const uint8_t *emm,
				uint32_t *keysAdded);

int8_t FindKey(char identifier, uint32_t provider, uint32_t providerIgnoreMask, char *keyName,
				uint8_t *key, uint32_t maxKeyLength, uint8_t isCriticalKey, uint32_t keyRef,
				uint8_t matchLength, uint32_t *getProvider);

int8_t SetKey(char identifier, uint32_t provider, char *keyName, uint8_t *orgKey, uint32_t keyLength,
				uint8_t writeKey, char *comment, struct s_reader *rdr);

int8_t UpdateKey(char identifier, uint32_t provider, char *keyName, uint8_t *key, uint32_t keyLength,
				uint8_t writeKey, char *comment);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_H_
