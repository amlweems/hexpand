#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "byteorder.h"

unsigned int strntoul(const char* str, int length, int base) {
	char buf[length+1];
	memcpy(buf, str, length);
	buf[length] = '\0';
	return strtoul(buf, NULL, base);
}

char* sha1_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	int length_modulo = mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length%length_modulo;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	unsigned char data[length+padding+length_bytes];
	memset(data, 'A', length+padding+length_bytes);
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);

	unsigned char* h_data = (unsigned char *)((SHA512_CTX *)mdctx->md_data)->h;
	int h_data_size = (mdctx->digest->md_size);
	int sha_switch = length_modulo/16;
	int i = 0, j = 0;
	while (i < h_data_size) {
		for (j = 0; j < sha_switch; j++) {
			h_data[i+j] = strntoul(signature+2*(i+sha_switch-1-j), 2, 16);
		}
		i+=sha_switch;
	}

	char* output = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	output[0] = '8';
	output[1] = '0';
	for (i = 1; i < 2*(padding+length_bytes); i++) output[i] = '0';
	if (length_modulo == 128) sprintf(output+2*padding, "%032llx", htole64(8*length));
	else sprintf(output+2*padding, "%016llx", htole64(8*length));
	output[2*(padding+length_bytes)] = 0;

	return output;
}

char* md5_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	int length_modulo = mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length&0x3f;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	unsigned char data[length+padding+length_bytes];
	memset(data, 'A', length+padding+length_bytes);
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);
	((MD5_CTX *)mdctx->md_data)->A = htonl(strntoul(signature, 8, 16));
	((MD5_CTX *)mdctx->md_data)->B = htonl(strntoul(signature+8, 8, 16));
	((MD5_CTX *)mdctx->md_data)->C = htonl(strntoul(signature+16, 8, 16));
	((MD5_CTX *)mdctx->md_data)->D = htonl(strntoul(signature+24, 8, 16));

	int i;
	char* output = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	output[0] = '8';
	output[1] = '0';
	for (i = 1; i < 2*(padding+length_bytes); i++) output[i] = '0';
	sprintf(output+2*padding, "%016llx", htobe64(8*length));
	output[2*(padding+length_bytes)] = 0;
	return output;
}

void *extend_get_funcbyname(const char* str) {
	if (strcmp(str, "md5") == 0) {
		return &md5_extend;
	} else if (strcmp(str, "sha1") == 0) {
		return &sha1_extend;
	} else if (strcmp(str, "sha256") == 0) {
		return &sha1_extend;
	} else if (strcmp(str, "sha512") == 0) {
		return &sha1_extend;
	} else {
		return NULL;
	}
}

int hash_extend(const EVP_MD *md,
				char* (*extend_function)(EVP_MD_CTX *m, char* s, int l),
				char *signature,
				char *message,
				int length,
				unsigned char* digest,
				char** output) {
	EVP_MD_CTX *mdctx;
	unsigned int block_size;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	*output = (*extend_function)(mdctx, signature, length);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, digest, &block_size);
	EVP_MD_CTX_destroy(mdctx);
	return block_size;
}
