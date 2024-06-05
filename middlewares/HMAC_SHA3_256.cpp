#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/sha3.h"
using CryptoPP::SHA3_256;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;
#ifdef _WIN32
	#include <windows.h>
	#endif
	#include <cstdlib>
	#include <locale>
	#include <cctype>
// Hàm XOR với pad
SecByteBlock xorWithpad(const unsigned char pad, const SecByteBlock key) {
    SecByteBlock keyP = key;
    // Thực hiện phép XOR giữa từng byte của khóa với giá trị pad
    for (size_t i = 0; i < key.size(); ++i) {
        keyP[i] ^= pad;
    }
    return keyP;
}
// Hàm HMAC-SHA3-256
void HMAC_SHA3_256(const byte* key_content, size_t key_length, const byte* input_content, size_t input_length, char* output_hexmac, size_t output_size) {
    // Chuyển key sang SecByteBlock
    SecByteBlock key(key_content, key_length);

    SecByteBlock mac(SHA3_256::DIGESTSIZE);
    const unsigned char ipad = 0x36;
    const unsigned char opad = 0x5c;
    SecByteBlock k_ipad = xorWithpad(ipad, key);
    SecByteBlock k_opad = xorWithpad(opad, key);

    // Hash (k xor ipad) với nội dung file
    HMAC<SHA3_256> i_hmac(k_ipad, k_ipad.size());
    i_hmac.Update(input_content, input_length);
    i_hmac.Final(mac);

    // Hash (k xor opad) với (i_mac)
    HMAC<SHA3_256> hmac(k_opad, k_opad.size());
    hmac.Update(mac, mac.size());
    hmac.Final(mac);

    // Chuyển kết quả sang dạng hex
    HexEncoder encoder;
    encoder.Attach(new ArraySink(reinterpret_cast<byte*>(output_hexmac), output_size));
    encoder.Put(mac, mac.size());
    encoder.MessageEnd();
}