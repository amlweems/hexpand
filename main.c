#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "hexpand.h"

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
	unsigned char* output;
	unsigned int block_size;
	block_size = hash_extend(type, func, signature, message, length, md_value, &output);
	printf("Append (hex):\t%s", output);
	for(c = 0; c < strlen(message); c++)
		printf("%02x", message[c]);

	printf("\nSignature:\t");
	for(c = 0; c < block_size; c++)
		printf("%02x", md_value[c]);
	printf("\n");

	free(output);
	exit(EXIT_SUCCESS);
}
