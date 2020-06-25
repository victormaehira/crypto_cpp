// Your First C++ Program

#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <iomanip> 
#include "KeyExchangeCBridge.h"

void findAndReplaceAll(std::string & data, std::string toSearch, std::string replaceStr)
{
	// Get the first occurrence
	size_t pos = data.find(toSearch);
	// Repeat till end is reached
	while (pos != std::string::npos)
	{
		// Replace this occurrence of Sub String
		data.replace(pos, toSearch.size(), replaceStr);
		// Get the next occurrence from the current position
		pos = data.find(toSearch, pos + replaceStr.size());
	}
}

int main() {

	char bufferPrivateKey[2048];
	char bufferPublicKey[2048];
	generateKeyExchangeKeys(bufferPrivateKey, 2048, bufferPublicKey, 2048);

	std::string s(bufferPublicKey);

	std::cout << "s = " << s << "\n";

	findAndReplaceAll(s, "-----BEGIN PUBLIC KEY-----", "");
	findAndReplaceAll(s, "\n", "");
	findAndReplaceAll(s, "-----END PUBLIC KEY-----", "");

	std::cout << "s = " << s << "\n";

	std::string otherKey = "MIICKDCCARsGCSqGSIb3DQEDATCCAQwCggEBAMGZ0UEGh8q1BIZXmVx0kIZIcTheujcCfmuUQeAuVKzSds7CZ2GbsuAzBTXvZwQGQRfADTcEPRTh68Cl8D5xmnvykWzGpNJzcKxWl6XzBWFBShecf7+V09cgxTThxkQBKEFsJcdZF/GkE+Tu9Irlo5Kl/3Bdcz0BifZYx3TZwQ6JoMh5eVB4q6rOvm92cSiXqeqLkcUAXBEkKs1Xy6RldguAHEpxUJt2zDAQz8wR/skImaAZCHq3YGMOlsI4ELK4DkQCptSVkfMbL+cPRvhfnPTEOePYO2IcX/SaR63AEe5vchxnEa3oqZMN9p9wXWPB+zRqUr5rFxabetR7Xf0vH2MCAQICAgQAA4IBBQACggEAftnPqdaAdgD4bgUiZbUfoCso9ztSj/m8NF5fU1E/pSToKu/sLlwp08iQacRre7sXBnokmGbFBH9ejlPAslrydOxHPinelLq4dY9uFnGfJZN9gACAiNjs/cdtRfTTKrVtpYpzmkVsajCN+nWOKg1WeMMmMFA9/4FVGcl23uuF+EzZeWx1N34sGLJOfPLUEOYjUBVtHQbVJ46xO/sJp/+TkO51gTAucZ9+RTrsPJD1SCImlnitMCrGtkLuxLPU0WolQrCUL9R7jNr6kZq/cICEIPNniVzyxxJ4PiHVARcCVw27AYKWh3ia9E3Ou1Lydsmc6Ini7seFCdQ8v63lZn7nKw==";

	std::string otherPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" + otherKey + "\n-----END PUBLIC KEY-----\n";

	std::cout << "otherPublicKeyPEM = " << otherPublicKeyPEM << "\n";
	
	char * otherPublicKeyAsCPointer = new char[otherPublicKeyPEM.length() + 1];

	strcpy_s(otherPublicKeyAsCPointer, otherPublicKeyPEM.length() + 1, otherPublicKeyPEM.c_str());

	int largeKeySize;
	unsigned char * largeSecretKey = combineOtherPublicKey(&largeKeySize, otherPublicKeyAsCPointer, bufferPrivateKey, bufferPublicKey);

	std::cout << "largeKeySize = " << largeKeySize << "\n";

	int smallKeySize;
	unsigned char * smallSecretKey = shrinkKey(&smallKeySize, largeSecretKey, largeKeySize);

	std::cout << "smallKeySize = " << smallKeySize << "\n";

	//getCurrentCounterAndUsedTime
	//unsigned char data[8] = { 0, 0, 0, 0, 0, 41, 33, -71 };

	//teste do getCurrentCounterAndUsedTime
	std::time_t current = std::time(nullptr);
	uint64_t timer = (uint64_t)(floor(current / 30));

	// Little Endian Shift
	unsigned char data[8];
	data[0] = (unsigned char)(timer >> 56);
	data[1] = (unsigned char)(timer >> 48);
	data[2] = (unsigned char)(timer >> 40);
	data[3] = (unsigned char)(timer >> 32);
	data[4] = (unsigned char)(timer >> 24);
	data[5] = (unsigned char)(timer >> 16);
	data[6] = (unsigned char)(timer >> 8);
	data[7] = (unsigned char)(timer);

	int ptrDigestSize;
	unsigned char * hash = hmacSha1(&ptrDigestSize, data, 8, smallSecretKey, smallKeySize);

	std::cout << "ptrDigestSize = " << ptrDigestSize << "\n";

	int offset = hash[strlen((char*)hash) - 1] & 0xf;
	int value = (int)(((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset + 1] & 0xff)) << 16) |
		((int(hash[offset + 2] & 0xff)) << 8) |
		(int(hash[offset + 3]) & 0xff));
	int len = 6;
	int mod = value % int(pow(10, len));
	std::cout << std::setfill('0') << std::setw(6) << mod << std::endl;
	 
	std::cout << "std::to_string(mod) = " << std::to_string(mod) << std::endl;

	return 0;
}

