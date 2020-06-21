// code copy pasted from here https://www.cryptopp.com/w/images/b/bd/AES-CBC-Filter.zip
// crypto.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "aes.h"
#include <Windows.h>

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"
#include "ETokenKeys.h"

int main(int argc, char* argv[])
{
	ETokenKeys etokens;
	std::string chave = etokens.gerarChaves();
	std::cout << "chave = " << chave << "\n";
	return 0;
}