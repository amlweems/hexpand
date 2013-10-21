#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <openssl/evp.h>
#include "hexpand.h"

void help(void) {
	fprintf(stderr, "Usage:\n"
		"\thexpand -t type -s signature -l length -m message\n"
		"\thexpand --test\n\n"
		"Options:\n"
		"\t-t --type\tthe hash algorithm for expansion (md5, sha1, sha256, or sha512\n"
		"\t-s --sig\tthe result of the original hash function\n"
		"\t-l --length\tthe length of the original message\n"
		"\t-m --message\tthe message to be appended\n"
		"\t--test\t\truns a set of test cases\n");
	exit(EXIT_FAILURE);
}

void test(void) {
	int success = 0;
	// test cases go here
	
	if (success) {
		printf("All tests passed!\n");
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}

static int test_flag = 0;

int main(int argc, char *argv[]) {
	char *signature = NULL;
	char *message = NULL;
	int length, c;
	const EVP_MD *type = NULL;
	void *func = NULL;

	OpenSSL_add_all_digests();

	static struct option long_options[] = {
		{"test",    no_argument,       &test_flag, 1},
		{"type",    required_argument, 0, 't'},
		{"sig",     required_argument, 0, 's'},
		{"length",  required_argument, 0, 'l'},
		{"message", required_argument, 0, 'm'},
		{0, 0, 0, 0}
	};
	int optind = 0;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "l:m:s:t:", long_options, &optind)) != -1) {
		switch (c) {
			case 0:
				break;
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

	if (test_flag) {
		test();
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
