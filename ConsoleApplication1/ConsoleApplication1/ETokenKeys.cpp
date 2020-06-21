#include "pch.h"
#include "ETokenKeys.h"
#include <iostream>
#include <string>

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "dh.h"
using CryptoPP::DH;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "base64.h"
using CryptoPP::Base64Encoder;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

ETokenKeys::ETokenKeys()
{
}


ETokenKeys::~ETokenKeys()
{
}

std::string ETokenKeys::gerarChaves()
{

	//"C199D1410687CAB5048657995C7490864871385EBA37027E6B9441E02E54ACD276CEC267619BB2E0330535EF6704064117C00D37043D14E1EBC0A5F03E719A7BF2916CC6A4D27370AC5697A5F30561414A179C7FBF95D3D720C534E1C6440128416C25C75917F1A413E4EEF48AE5A392A5FF705D733D0189F658C774D9C10E89A0C879795078ABAACEBE6F76712897A9EA8B91C5005C11242ACD57CBA465760B801C4A71509B76CC3010CFCC11FEC90899A019087AB760630E96C23810B2B80E4402A6D49591F31B2FE70F46F85F9CF4C439E3D83B621C5FF49A47ADC011EE6F721C6711ADE8A9930DF69F705D63C1FB346A52BE6B17169B7AD47B5DFD2F1F63"
	//Integer p(1);
	
	AutoSeededRandomPool rnd;

	try
	{
		// RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
		// http://tools.ietf.org/html/rfc5114#section-2.1
		Integer p("0xC199D1410687CAB5048657995C7490864871385EBA37027E6B9441E02E54ACD276CEC267619BB2E0330535EF6704064117C00D37043D14E1EBC0A5F03E719A7BF2916CC6A4D27370AC5697A5F30561414A179C7FBF95D3D720C534E1C6440128416C25C75917F1A413E4EEF48AE5A392A5FF705D733D0189F658C774D9C10E89A0C879795078ABAACEBE6F76712897A9EA8B91C5005C11242ACD57CBA465760B801C4A71509B76CC3010CFCC11FEC90899A019087AB760630E96C23810B2B80E4402A6D49591F31B2FE70F46F85F9CF4C439E3D83B621C5FF49A47ADC011EE6F721C6711ADE8A9930DF69F705D63C1FB346A52BE6B17169B7AD47B5DFD2F1F63");

		Integer g("0x02");

		//Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

		// Schnorr Group primes are of the form p = rq + 1, p and q prime. They
		// provide a subgroup order. In the case of 1024-bit MODP Group, the
		// security level is 80 bits (based on the 160-bit prime order subgroup).		

		// For a compare/contrast of using the maximum security level, see
		// dh-gen.zip. Also see http://www.cryptopp.com/wiki/Diffie-Hellman
		// and http://www.cryptopp.com/wiki/Security_level .

		DH dh;
		//dh.AccessGroupParameters().Initialize(p, q, g);
		dh.AccessGroupParameters().Initialize(p, g);

		SecByteBlock privKey(dh.PrivateKeyLength());
		SecByteBlock pubKey(dh.PublicKeyLength());
		dh.GenerateKeyPair(rnd, privKey, pubKey);
	

		//new
		Integer k1(privKey, privKey.size()); 
		Integer k2(pubKey, pubKey.size());
		cout << "Private key:\n";
		cout << std::hex << k1 << endl;
		cout << "Public key:\n";
		cout << std::hex << k2;
		
		
		string chave;
		Base64Encoder b(new StringSink(chave));
		b.Put(pubKey.data(), pubKey.size());
		b.MessageEnd();
		cout << "chave = " << chave;
		
		//cout << "  Public key pubA: " << pubKey.begin() << endl;
		cout << "\nTeste";
		/*
		if (!dh.GetGroupParameters().ValidateGroup(rnd, 3))
			throw runtime_error("Failed to validate prime and generator");

		size_t count = 0;

		p = dh.GetGroupParameters().GetModulus();
		count = p.BitCount();
		cout << "P (" << std::dec << count << "): " << std::hex << p << endl;

		q = dh.GetGroupParameters().GetSubgroupOrder();
		count = q.BitCount();
		cout << "Subgroup order (" << std::dec << count << "): " << std::hex << q << endl;

		g = dh.GetGroupParameters().GetGenerator();
		count = g.BitCount();
		cout << "G (" << std::dec << count << "): " << std::hex << g << endl;

		// http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
		Integer v = ModularExponentiation(g, q, p);
		if (v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");
			*/
	}

	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return "Erro";
	}

	catch (const std::exception& e)
	{
		cerr << e.what() << endl;
		return "Erro";
	}

	return "teste";
}

