//
//  KeyExchangeCBridge.c
//  RemoteID
//
//  Created by Leonardo Verissimo on 12/12/18.
//  Copyright © 2018 Certisign. All rights reserved.
//

#include "KeyExchangeCBridge.h"

#include <string.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#define SALT_LENGTH 32

static const char* const HEX_P = "C199D1410687CAB5048657995C7490864871385EBA37027E6B9441E02E54ACD276CEC267619BB2E0330535EF6704064117C00D37043D14E1EBC0A5F03E719A7BF2916CC6A4D27370AC5697A5F30561414A179C7FBF95D3D720C534E1C6440128416C25C75917F1A413E4EEF48AE5A392A5FF705D733D0189F658C774D9C10E89A0C879795078ABAACEBE6F76712897A9EA8B91C5005C11242ACD57CBA465760B801C4A71509B76CC3010CFCC11FEC90899A019087AB760630E96C23810B2B80E4402A6D49591F31B2FE70F46F85F9CF4C439E3D83B621C5FF49A47ADC011EE6F721C6711ADE8A9930DF69F705D63C1FB346A52BE6B17169B7AD47B5DFD2F1F63";
static const char* const HEX_G = "02";

static const unsigned char SALT[] = { 0xb5, 0x26, 0x8c, 0x16, 0x55, 0x5c, 0x1c, 0xa6,
	0x64, 0x6a, 0xa5, 0x86, 0x71, 0x59, 0xb8, 0x2c,
	0x63, 0x22, 0xb7, 0xe2, 0xe3, 0xc9, 0x23, 0x98,
	0xb7, 0xf8, 0x1a, 0x79, 0x9e, 0x3e, 0xea, 0xd6 };

void generateKeyExchangeKeys(char * bufferPrivateKey, int lengthPrivate,
	char * bufferPublicKey, int lengthPublic) {

	// AVISO! Os valores de P e G devem ser os mesmos da versão em Java!
	DH* dhParams = DH_new();

	BIGNUM * p = NULL;
	BN_hex2bn(&p, HEX_P);
	BIGNUM * g = NULL;
	BN_hex2bn(&g, HEX_G);

	DH_set0_pqg(dhParams, p, NULL, g);

	EVP_PKEY * params = EVP_PKEY_new();
	EVP_PKEY_set1_DH(params, dhParams);
	DH_free(dhParams);

	EVP_PKEY_CTX * kctx = EVP_PKEY_CTX_new(params, NULL);

	EVP_PKEY * dhKey = NULL;

	EVP_PKEY_keygen_init(kctx);
	EVP_PKEY_keygen(kctx, &dhKey);

	// Copiando a chave privada
	BIO * bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, dhKey, NULL, NULL, 0, NULL, NULL);

	int length = BIO_read(bio, bufferPrivateKey, lengthPrivate);
	bufferPrivateKey[length] = '\0';

	printf("Length of private key: %lu\n", strlen(bufferPrivateKey));

	BIO_free(bio);

	// Copiando a chave pública
	bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, dhKey);

	length = BIO_read(bio, bufferPublicKey, lengthPublic);
	bufferPublicKey[length] = '\0';

	printf("Length of public key: %lu\n", strlen(bufferPublicKey));

	BIO_free(bio);

	// Liberando memória
	EVP_PKEY_free(dhKey);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
}

unsigned char * combineOtherPublicKey(int* ptrSecretSize,
	const char * otherPublicKey,
	const char * myPrivateKey,
	const char * myPublicKey) {

	BIO *bio = BIO_new(BIO_s_mem());
	BIO_puts(bio, otherPublicKey);
	EVP_PKEY *evpOtherPub = NULL;
	PEM_read_bio_PUBKEY(bio, &evpOtherPub, NULL, NULL);

	BIO_free(bio);
	bio = BIO_new(BIO_s_mem());
	BIO_puts(bio, myPrivateKey);
	EVP_PKEY *evpOurPriv = NULL;
	PEM_read_bio_PrivateKey(bio, &evpOurPriv, NULL, NULL);

	BIO_free(bio);

	DH* dhOtherPub = EVP_PKEY_get1_DH(evpOtherPub);
	DH* dhOurPriv = EVP_PKEY_get1_DH(evpOurPriv);

	const BIGNUM* otherPubKey = NULL;
	DH_get0_key(dhOtherPub, &otherPubKey, NULL);
	*ptrSecretSize = DH_size(dhOurPriv);
	unsigned char *secret = (unsigned char *) malloc(*ptrSecretSize);
	DH_compute_key(secret, otherPubKey, dhOurPriv);

	DH_free(dhOurPriv);
	DH_free(dhOtherPub);
	EVP_PKEY_free(evpOurPriv);
	EVP_PKEY_free(evpOtherPub);

	return secret;
}

unsigned char * shrinkKey(int * ptrSmallKeySize,
	const unsigned char * largeKey,
	int largeKeySize) {

	EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (EVP_PKEY_derive_init(context) <= 0) {
		// erro
	}
	const EVP_MD* md = EVP_sha1();
	if (EVP_PKEY_CTX_set_hkdf_md(context, md) <= 0) {
		// erro
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(context, SALT, sizeof(SALT)) <= 0) {
		// erro
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(context, largeKey, largeKeySize) <= 0) {
		// erro
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(context, "", 0) <= 0) {
		// erro
	}

	size_t smallKeyLength = EVP_MD_size(md);
	unsigned char * smallKey = (unsigned char *) malloc(smallKeyLength);

	if (EVP_PKEY_derive(context, smallKey, &smallKeyLength) <= 0) {
		// erro
	}

	*ptrSmallKeySize = (int)smallKeyLength;

	return smallKey;
}

unsigned char * hmacSha1(int * ptrDigestSize,
	const unsigned char * data, int dataLength,
	const unsigned char * secret, int secretLength) {

	unsigned int resultLength = EVP_MD_size(EVP_sha1());
	//unsigned char * result = malloc(resultLength);
	//In c++ you should cast the return of malloc
	unsigned char * result = (unsigned char *) malloc(resultLength);

	HMAC(EVP_sha1(),
		secret, secretLength,
		data, dataLength,
		result, &resultLength);

	*ptrDigestSize = resultLength;
	return result;
}
