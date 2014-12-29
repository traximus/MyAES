#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "igd_aes.h"
#include "md5.h"

#define IGD_DEBUG_CRYPTO_SHA1_AES 0
#define IGD_BUF_LEN 1024
#define IGD_MD5_LEN 33
#define IGD_MD5DIGEST_LEN 16

#if 0
#define AES_DEBUG(fmt, args...) do{console_printf("%s=>%s=>line %d : "fmt, __FILE__, __FUNCTION__, __LINE__, ##args);}while(0)
#else
#define AES_DEBUG(fmt, args...) do{}while(0)
#endif




int igd_bin2str(void *bin, int size, char *out, int out_len)
{
    int i, len;
    unsigned char *b = bin;
    
    if (!b) {
        return -1;
    }
    for (i=0, len = 0; i<size && len <= out_len-
         3; i++) {
        len += snprintf(out+len, out_len-len,"%02X", b[i]);
    }
    out[len] = 0;
    
    return 0;
}




// out_len == in_len
unsigned char *igd_aes_decrypt(const unsigned char *in, int in_len,
	const unsigned char *key, int key_len)
{
	aes_decrypt_ctx de_ctx[1];
	unsigned char *pout, md5[16] = {0};
	char md5_str[33] = {0};
	int decode_len;
	
	if (!in || !in_len || !key || !key_len) {
		AES_DEBUG("in %p, in_len %d, key %p, key_len %d. check it !!! \n",
			in, in_len, key, key_len);
		return NULL;
	}
	get_md5_numbers(key, md5, key_len);
	igd_bin2str(md5, sizeof(md5), md5_str, sizeof(md5_str));
	AES_DEBUG("aes_key %s, md5 %s\n", key, md5_str);		
	pout = (unsigned char *)calloc(1, in_len);
	if (!pout) {
		AES_DEBUG("calloc failed(size %d).\n", in_len);
		return NULL;
	}	
	aes_decrypt_key256(md5_str, de_ctx);
	aes_ecb_decrypt(in, pout, in_len, de_ctx);
	
	return pout;
}

unsigned char * igd_aes_encrypt(const unsigned char *in, int in_len, int *out_len,
	const unsigned char *key, int key_len)
{
	unsigned long i_encry = 0, i_padding = 0, new_len = 0;
	unsigned char *pbuf, *pout, md5[16] = {0};
	char md5_str[33] = {0};
	aes_encrypt_ctx en_ctx[1];

	if (!in || !in_len || !out_len || !key || !key_len) {
		AES_DEBUG("in %p, in_len %d, out_len %p, key %p, key_len %d. check it !!! \n",
			in, in_len, out_len, key, key_len);
		return NULL;
	}
	get_md5_numbers(key, md5, key_len);
	igd_bin2str(md5, sizeof(md5), md5_str, sizeof(md5_str));
	AES_DEBUG("aes_key %s, md5 %s\n", key, md5_str);	
	i_encry = in_len/AES_BLOCK_SIZE+1;
	i_padding = AES_BLOCK_SIZE-in_len%AES_BLOCK_SIZE;
	new_len = in_len+i_padding;
	
	pbuf = (unsigned char *)calloc(1, new_len);
	if (!pbuf) {
		AES_DEBUG("calloc failed(size %d).\n", new_len);
		return NULL;
	}
	pout = (unsigned char *)calloc(1, new_len);
	if (!pout) {
		AES_DEBUG("calloc failed(size %d).\n", new_len);
		return NULL;
	}
	memcpy(pbuf, in, in_len);
	memset(pbuf+in_len, i_padding, i_padding);
	aes_encrypt_key256(md5_str, en_ctx);
	aes_ecb_encrypt(pbuf, pout, new_len, en_ctx);
	*out_len = new_len;
	free(pbuf);
	
	return pout;
}

