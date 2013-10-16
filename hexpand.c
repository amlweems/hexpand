#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

void help(void) {
	fprintf(stderr, "Usage:\n"
		"\thexpand -t type -s signature -l length -m message\n\n"
		"Options:\n"
		"\t-t\tthe hash algorithm for expansion (md5, sha1, sha256, or sha512\n"
		"\t-s\tthe result of the original hash function\n"
		"\t-l\tthe length of the original message"
		"\t-m\tthe message to be appended\n");
	exit(EXIT_FAILURE);
}

unsigned int strntoul(const char* str, int length, int base) {
	char buf[length+1];
	memcpy(buf, str, length);
	buf[length] = '\0';
	return strtoul(buf, NULL, base);
}

void sha1_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	int length_modulo = mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length&0x3f;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	unsigned char data[length+padding+length_bytes];
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
}

void md5_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	int length_modulo = mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length&0x3f;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	unsigned char data[length+padding+length_bytes];
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);
	((MD5_CTX *)mdctx->md_data)->A = htonl(strntoul(signature, 8, 16));
	((MD5_CTX *)mdctx->md_data)->B = htonl(strntoul(signature+8, 8, 16));
	((MD5_CTX *)mdctx->md_data)->C = htonl(strntoul(signature+16, 8, 16));
	((MD5_CTX *)mdctx->md_data)->D = htonl(strntoul(signature+24, 8, 16));
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
				unsigned char* digest) {
	EVP_MD_CTX *mdctx;
	unsigned int block_size;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	(*extend_function)(mdctx, signature, length);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, digest, &block_size);
	EVP_MD_CTX_destroy(mdctx);
	return block_size;
}

int main(int argc, char *argv[]) {
	char *signature = NULL;
	char *message = NULL;
	int length, c;
	const EVP_MD *type = NULL;
	void *func = NULL;

	OpenSSL_add_all_digests();

	opterr = 0;
	while ((c = getopt(argc, argv, "l:m:s:t:")) != -1) {
		switch (c) {
			case 'l':
				length = atoi(optarg);
				break;
			case 'm':
				message = optarg;
				break;
			case 's':
				signature = optarg;
				break;
			case 't':
				type = EVP_get_digestbyname(optarg);
				func = extend_get_funcbyname(optarg);
				if (!type || !func) {
					fprintf(stderr, "%s is not a supported hash format\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			default:
				help();
		}
	}

	if (message == NULL || signature == NULL) {
		help();
	}

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int block_size;

	block_size = hash_extend(type, func, signature, message, length, md_value);

	printf("\nSignature:\t");
	for(c = 0; c < block_size; c++)
		printf("%02x", md_value[c]);
	printf("\n");

	exit(EXIT_SUCCESS);
}
