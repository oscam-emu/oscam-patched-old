#ifndef OSCAM_STRING_H_
#define OSCAM_STRING_H_

bool cs_malloc(void *result, size_t size) MUST_CHECK_RESULT;
bool cs_realloc(void *result, size_t size) MUST_CHECK_RESULT;
char *cs_strdup(const char *str);

void cs_strncpy(char *destination, const char *source, size_t num);
char *strtolower(char *txt);
char *strtoupper(char *txt);
char *trim(char *txt);
char *trim2(char *txt);
char *remove_white_chars(char *txt);
bool streq(const char *s1, const char *s2);

char *cs_hexdump(int32_t m, const uint8_t *buf, int32_t n, char *target, int32_t len);
int32_t gethexval(char c);
int32_t cs_atob(uint8_t *buf, char *asc, int32_t n);
uint32_t cs_atoi(char *asc, int32_t l, int32_t val_on_err);
int32_t byte_atob(char *asc);
int32_t word_atob(char *asc);
int32_t dyn_word_atob(char *asc);
int32_t key_atob_l(char *asc, uint8_t *bin, int32_t l);
uint32_t b2i(int32_t n, const uint8_t *b);
uint64_t b2ll(int32_t n, const uint8_t *b);
uint8_t *i2b_buf(int32_t n, uint32_t i, uint8_t *b);
uint8_t *ull2b_buf(uint64_t i, uint8_t *b);
uint32_t a2i(char *asc, int32_t bytes);
int32_t boundary(int32_t exp, int32_t n);
int32_t array_has_nonzero_byte(uint8_t *value, int32_t length);

void get_random_bytes_init(void);
void get_random_bytes(uint8_t *dst, uint32_t dst_len);

uint32_t crc32(uint32_t crc, const uint8_t *buf, uint32_t len);
uint16_t ccitt_crc(uint8_t *data, size_t length, uint16_t seed, uint16_t final);
uint32_t ccitt32_crc(uint8_t *data, size_t len);
uint32_t jhash(const char *key, size_t len);

char to_hex(char code);
void char_to_hex(const uint8_t *p_array, uint32_t p_array_len, uint8_t *result);

#define BASE64_LENGTH(inlen) ((((inlen) + 2) / 3) * 4)
void base64_encode(const char *in, size_t inlen, char *out, size_t outlen);
size_t b64encode(const char *in, size_t inlen, char **out);

void b64prepare(void);
int32_t b64decode(uint8_t *result);

#ifdef READ_SDT_CHARSETS
size_t ISO6937toUTF8(const uint8_t **inbuf, size_t *inbytesleft, uint8_t **outbuf, size_t *outbytesleft);
size_t ISO8859toUTF8(int8_t iso_table_number, const uint8_t **inbuf, size_t *inbytesleft, uint8_t **outbuf, size_t *outbytesleft);
#endif
size_t UnicodetoUTF8(const uint8_t **inbuf, size_t *inbytesleft, uint8_t **outbuf, size_t *outbytesleft);
#endif
