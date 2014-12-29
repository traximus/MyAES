#ifndef __IGD_AES__
#define __IGD_AES__
#include "aes.h"

extern unsigned char *igd_aes_encrypt(const unsigned char *in, int in_len,
	int *out_len, const unsigned char *key, int key_len);
extern unsigned char *igd_aes_decrypt(const unsigned char *in, int in_len,
	const unsigned char *key, int key_len);

#endif /* __IGD_AES__ */
