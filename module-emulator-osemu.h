#ifndef MODULE_EMULATOR_OSEMU_H_
#define MODULE_EMULATOR_OSEMU_H_

#ifdef WITH_EMU

// Version info
#define EMU_VERSION 798

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
 *  3 - ECM key rejected
 *  4 - Corrupt data
 *  5 - CW not found
 *  6 - CW / ECM / EMM checksum error
 *  7 - Out of memory
*/

#define EMU_OK             0
#define EMU_NOT_SUPPORTED  1
#define EMU_KEY_NOT_FOUND  2
#define EMU_KEY_REJECTED   3
#define EMU_CORRUPT_DATA   4
#define EMU_CW_NOT_FOUND   5
#define EMU_CHECKSUM_ERROR 6
#define EMU_OUT_OF_MEMORY  7

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
extern KeyDataContainer BissSWs;      // 'F' identifier - BISS1 and BISS2 mode 1/E session words
extern KeyDataContainer Biss2Keys;    // 'G' identifier - BISS2 mode CA session keys (ECM keys)
extern KeyDataContainer PowervuKeys;
extern KeyDataContainer TandbergKeys;
extern KeyDataContainer StreamKeys;
extern uint8_t viasat_const[];
extern char *emu_keyfile_path;
extern pthread_mutex_t emu_key_data_mutex;

void emu_set_keyfile_path(const char *path);
void emu_clear_keydata(void);
uint8_t emu_read_keyfile(struct s_reader *rdr, const char *path);
void emu_read_keymemory(struct s_reader *rdr);

int8_t is_valid_dcw(uint8_t *dw);
int8_t char_to_bin(uint8_t *out, const char *in, uint32_t inLen);
void date_to_str(char *dateStr, uint8_t len, int8_t offset, uint8_t format);

KeyDataContainer *emu_get_key_container(char identifier);

int8_t emu_process_ecm(struct s_reader *rdr, const ECM_REQUEST *er, uint8_t *cw, EXTENDED_CW* cw_ex);

int8_t emu_process_emm(struct s_reader *rdr, uint16_t caid, const uint8_t *emm, uint32_t *keysAdded);

int8_t emu_find_key(char identifier, uint32_t provider, uint32_t providerIgnoreMask, char *keyName,
					uint8_t *key, uint32_t maxKeyLength, uint8_t isCriticalKey, uint32_t keyRef,
					uint8_t matchLength, uint32_t *getProvider);

int8_t emu_set_key(char identifier, uint32_t provider, char *keyName, uint8_t *orgKey, uint32_t keyLength,
					uint8_t writeKey, char *comment, struct s_reader *rdr);

int8_t emu_update_key(char identifier, uint32_t provider, char *keyName, uint8_t *key, uint32_t keyLength,
						uint8_t writeKey, char *comment);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_H_
