// Your First C++ Program

#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <iomanip> 
#include <chrono>
#include "KeyExchangeCBridge.h"

int main() {

	int smallKeySize = 20;
	//unsigned char * smallSecretKey;

	std::cout << "smallKeySize = " << smallKeySize << "\n";

	//toFile(smallSecretKey, smallKeySize);
	unsigned char * smallSecretKey = fromFile();

	toFileAgainPraFazerODiff(smallSecretKey, 20);

	printf("%s\n", smallSecretKey);
	//toFileAgainPraFazerODiff(smallSecretKey, smallKeySize);

	//getCurrentCounterAndUsedTime
	//unsigned char data[8] = { 0, 0, 0, 0, 0, 41, 33, -71 };
	//unsigned char data[8] = { 0, 0, 0, 0, 0, 41, 48, 7 };

	using namespace std::chrono; // just to shorten the namespacing

	std::chrono::milliseconds now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
	std::chrono::milliseconds inicio(1512151500000);
	std::chrono::milliseconds millisecondsSinceBeginning = now - inicio;
	std::chrono::milliseconds millisecondsToStepBy(30 * 1000);

	uint64_t timer = (uint64_t)(floor(millisecondsSinceBeginning / millisecondsToStepBy));
	std::cout << std::chrono::milliseconds(now).count() << "\n";
	std::cout << std::chrono::milliseconds(millisecondsSinceBeginning).count() << "\n";

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

	//printf("%s", hash);
	//std::string hashString(reinterpret_cast<char*>(hash));
	//std::string hashString(reinterpret_cast<char const*>(hash), ptrDigestSize);
	//std::cout << "hashString = " << hashString << "\n";

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

