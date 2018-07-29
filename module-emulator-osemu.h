#include "globals.h"
#include "module-emulator-stream.h"

#ifndef EMULATOR_H_
#define EMULATOR_H_

#define EMU_MAX_CHAR_KEYNAME 12
#define EMU_KEY_FILENAME "SoftCam.Key"
#define EMU_KEY_FILENAME_MAX_LEN 31
#define EMU_MAX_ECM_LEN MAX_ECM_SIZE
#define EMU_MAX_EMM_LEN MAX_EMM_SIZE

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

uint32_t GetOSemuVersion(void);

void set_emu_keyfile_path(const char *path);
void clear_emu_keydata(void);
uint8_t read_emu_keyfile(struct s_reader *rdr, const char *path);

#if !defined(__APPLE__) && !defined(__ANDROID__)
void read_emu_keymemory(struct s_reader *rdr);
#endif

void read_emu_eebin(const char *path, const char *name);
void read_emu_deskey(uint8_t *dreOverKey, uint8_t len);

int32_t CharToBin(uint8_t *out, const char *in, uint32_t inLen);

/* Error codes
0  OK
1  ECM not supported
2  Key not found
3  Nano80 problem
4  Corrupt data
5  CW not found
6  CW checksum error
7  Out of memory
8  ECM checksum error
9  ICG error
*/
#ifdef WITH_EMU
int8_t ProcessECM(struct s_reader *rdr, int16_t ecmDataLen, uint16_t caid, uint32_t provider,
				  const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid, EXTENDED_CW* cw_ex);
#else
int8_t ProcessECM(struct s_reader *rdr, int16_t ecmDataLen, uint16_t caid, uint32_t provider,
				  const uint8_t *ecm, uint8_t *dw, uint16_t srvid, uint16_t ecmpid);
#endif

const char* GetProcessECMErrorReason(int8_t result);

/* Error codes
0  OK
1  EMM not supported
2  Key not found
3  Nano80 problem
4  Corrupt data
5
6  Checksum error
7  Out of memory
*/
int8_t ProcessEMM(struct s_reader *rdr, uint16_t caid, uint32_t provider, const uint8_t *emm, uint32_t *keysAdded);

const char* GetProcessEMMErrorReason(int8_t result);

// hexserial must be of type "uint8_t hexserial[3]"
// returns 0 on error, 1 on success
int32_t GetIrdeto2Hexserial(uint16_t caid, uint8_t* hexserial);

// hexserials must be of type "uint8_t hexserials[length][4]"
// if srvid == 0xFFFF all serials are returned (no srvid filtering)
// returns 0 on error, 1 on success
int32_t GetPowervuHexserials(uint16_t srvid, uint8_t hexserials[][4], int32_t length, int32_t* count);

// hexserials must be of type "uint8_t hexserials[length]"
// returns 0 on error, 1 on success
int32_t GetDrecryptHexserials(uint16_t caid, uint32_t provid, uint8_t *hexserials, int32_t length, int32_t* count);

#define PVU_CW_VID 0    // VIDeo
#define PVU_CW_HSD 1    // High Speed Data
#define PVU_CW_A1  2    // Audio 1
#define PVU_CW_A2  3    // Audio 2
#define PVU_CW_A3  4    // Audio 3
#define PVU_CW_A4  5    // Audio 4
#define PVU_CW_UTL 6    // UTiLity
#define PVU_CW_VBI 7    // Vertical Blanking Interval

#ifdef WITH_EMU
int8_t PowervuECM(uint8_t *ecm, uint8_t *dw, uint16_t srvid, emu_stream_client_key_data *cdata, EXTENDED_CW* cw_ex);
#else
int8_t PowervuECM(uint8_t *ecm, uint8_t *dw, emu_stream_client_key_data *cdata);
#endif

#ifdef WITH_EMU
int32_t FindKey(char identifier, uint32_t provider, uint32_t providerIgnoreMask, char *keyName, uint8_t *key,
				uint32_t maxKeyLength, uint8_t isCriticalKey, uint32_t keyRef, uint8_t matchLength, uint32_t *getProvider);
#endif

#endif
