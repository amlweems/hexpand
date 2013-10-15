#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
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

long strntol(const char* str, int length, int base) {
	char buf[length+1];
	memcpy(buf, str, length);
	buf[length] = '\0';
	return strtol(buf, NULL, base);
}

int hash_extend(const EVP_MD *md, char *signature, char *message, int length, unsigned char* digest) {
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	unsigned int block_size = mdctx->digest->block_size;
	unsigned int padding = block_size*((length+block_size-1)/block_size) - length;
	unsigned char data[length+padding];
	EVP_DigestUpdate(mdctx, data, length+padding);
	((MD5_CTX *)mdctx->md_data)->A = htonl(strntol(signature, 8, 16));
	((MD5_CTX *)mdctx->md_data)->B = htonl(strntol(signature+8, 8, 16));
	((MD5_CTX *)mdctx->md_data)->C = htonl(strntol(signature+16, 8, 16));
	((MD5_CTX *)mdctx->md_data)->D = htonl(strntol(signature+24, 8, 16));
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, digest, &block_size);
	EVP_MD_CTX_destroy(mdctx);
	return block_size;
}

int main(int argc, char *argv[]) {
	char *signature = NULL;
	char *message = NULL;
	int length;
	const EVP_MD *type = NULL;
	int c;

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
				if (!type) {
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
	length = hash_extend(type, signature, message, length, md_value);
	for(c = 0; c < length; c++)
		printf("%02x", md_value[c]);
	printf("\n");

	exit(EXIT_SUCCESS);
}
