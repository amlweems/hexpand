
#ifndef __HEXPAND_H__
#define __HEXPAND_H__

unsigned int strntoul(const char* str, int length, int base);

char* sha1_extend(EVP_MD_CTX *mdctx, char* signature, int length);

char* md5_extend(EVP_MD_CTX *mdctx, char* signature, int length);

void *extend_get_funcbyname(const char* str);

int hash_extend(const EVP_MD *md,
				char* (*extend_function)(EVP_MD_CTX *m, char* s, int l),
				char *signature,
				char *message,
				int length,
				unsigned char* digest,
				unsigned char** output);

#endif // __HEXPAND_H__
