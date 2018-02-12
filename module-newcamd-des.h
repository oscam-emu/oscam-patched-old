#ifndef MODULE_NEWCAMD_DES_H_
#define MODULE_NEWCAMD_DES_H_

#define DES_HASH            8

#define DES_ECM_CRYPT       0
#define DES_ECM_HASH        DES_HASH

	int nc_des_encrypt(unsigned char *buffer, int len, unsigned char *deskey);
	int nc_des_decrypt(unsigned char *buffer, int len, unsigned char *deskey);
	unsigned char *nc_des_login_key_get(unsigned char *key1, unsigned char *key2, int len, unsigned char *des16);

	void nc_des(unsigned char key[], unsigned char mode, unsigned char data[]);

#endif
