// Your First C++ Program

#include <iostream>
#include <string>
#include <cstring>
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
	//var largeKeySize : Int32 = 0
		//let largeSecretKey : UnsafeMutablePointer<UInt8> =
		//combineOtherPublicKey(&largeKeySize, otherPublicKeyAsCPointer, privateKeyPEM, publicKeyPEM);
	char * otherPublicKeyAsCPointer = new char[otherPublicKeyPEM.length() + 1];

	strcpy_s(otherPublicKeyAsCPointer, otherPublicKeyPEM.length() + 1, otherPublicKeyPEM.c_str());

	int largeKeySize;
	unsigned char * largeSecretKey = combineOtherPublicKey(&largeKeySize, otherPublicKeyAsCPointer, bufferPrivateKey, bufferPublicKey);

	std::cout << "largeKeySize = " << largeKeySize << "\n";

	int smallKeySize;
	unsigned char * smallSecretKey = shrinkKey(&smallKeySize, largeSecretKey, largeKeySize);

	std::cout << "smallKeySize = " << smallKeySize << "\n";

	//getCurrentCounterAndUsedTime
	unsigned char data[8] = { 0, 0, 0, 0, 0, 41, 33, -71 };

	int ptrDigestSize;
	unsigned char * hash = hmacSha1(&ptrDigestSize, data, 8, smallSecretKey, smallKeySize);

	std::cout << "ptrDigestSize = " << ptrDigestSize << "\n";

	return 0;
}

