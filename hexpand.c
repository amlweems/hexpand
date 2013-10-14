#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void help(void) {
	fprintf(stderr, "Usage:\n"
		"\thexpand -t type -h hash -m message\n\n"
		"Options:\n"
		"\t-t\tthe hash algorithm for expansion (md5, sha1, sha256, or sha512\n"
		"\t-h\tthe message digest to be expanded\n"
		"\t-m\tthe message to be appended\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	char *hash = NULL;
	char *message = NULL;
	int type = -1;
	int index;
	int c;

	opterr = 0;

	while ((c = getopt(argc, argv, "h:m:t:")) != -1) {
		switch (c) {
			case 'h':
				hash = optarg;
				break;
			case 'm':
				message = optarg;
				break;
			case 't':
				if (strcmp(optarg, "md5") == 0) {
					type = 0;
				} else if (strcmp(optarg, "sha1") == 0) {
					type = 1;
				} else if (strcmp(optarg, "sha256") == 0) {
					type = 2;
				} else if (strcmp(optarg, "sha512") == 0) {
					type = 3;
				} else {
					fprintf(stderr, "%s is not a supported hash format\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			default:
				help();
		}
	}

	if (type == -1 || message == NULL || hash == NULL) {
		help();
	}

    printf("%s %s %d\n", message, hash, type);
	exit(EXIT_SUCCESS);
}
