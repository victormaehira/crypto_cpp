//
//  KeyExchangeCBridge.h
//  RemoteID
//
//  Created by Leonardo Verissimo on 12/12/18.
//  Copyright © 2018 Certisign. All rights reserved.
//

#ifndef KeyExchangeCBridge_h
#define KeyExchangeCBridge_h

#include <stdio.h>

void generateKeyExchangeKeys(char * bufferPrivateKey, int lengthPrivate,
	char * bufferPublicKey, int lengthPublic);

unsigned char * combineOtherPublicKey(int * ptrSecretSize,
	const char * otherPublicKey,
	const char * myPrivateKey,
	const char * myPublicKey);

unsigned char * shrinkKey(int * ptrSmallKeySize,
	const unsigned char * largeKey,
	int largeKeySize);

unsigned char * hmacSha1(int * ptrDigestSize,
	const unsigned char * data, int dataLength,
	const unsigned char * secret, int secretLength);

#endif /* KeyExchangeCBridge_h */