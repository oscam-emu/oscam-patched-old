#ifndef MODULE_NEWCAMD_DES_H_
#define MODULE_NEWCAMD_DES_H_

#define DES_HASH            8

#define DES_ECM_CRYPT       0
#define DES_ECM_HASH        DES_HASH

	int nc_des_encrypt(uint8_t *buffer, int len, uint8_t *deskey);
	int nc_des_decrypt(uint8_t *buffer, int len, uint8_t *deskey);
	uint8_t *nc_des_login_key_get(uint8_t *key1, uint8_t *key2, int len, uint8_t *des16);

	void nc_des(unsigned char key[], unsigned char mode, unsigned char data[]);

#endif
