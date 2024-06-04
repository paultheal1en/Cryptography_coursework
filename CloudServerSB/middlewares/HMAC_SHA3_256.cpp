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
//- Add setting for export dll or .so (Windows, Linux)
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
void HMAC_SHA3_256(const char* key_content, const char* input_content, char* output_hexmac, size_t output_size) {
    // Chuyển key sang SecByteBlock
    SecByteBlock key(reinterpret_cast<const byte*>(key_content), strlen(key_content));

    string mac, i_mac;
    const unsigned char ipad = 0x36;
    const unsigned char opad = 0x5c;
    SecByteBlock k_ipad = xorWithpad(ipad, key);
    SecByteBlock k_opad = xorWithpad(opad, key);

    string file_content(input_content);

    // Hash (k xor ipad) với nội dung file
    HMAC<SHA3_256> i_hmac(k_ipad, k_ipad.size());
    StringSource(file_content, true, 
        new HashFilter(i_hmac,
            new StringSink(i_mac)
        ) 
    );

    // Hash (k xor opad) với (i_mac)
    HMAC<SHA3_256> hmac(k_opad, k_opad.size());
    StringSource(i_mac, true, 
        new HashFilter(hmac,
            new StringSink(mac)
        ) 
    );

    // Chuyển kết quả sang dạng hex
    string hexmac;
    StringSource(mac, true, new HexEncoder(new StringSink(hexmac)));

    // Sao chép kết quả hex vào output_hexmac
    strncpy(output_hexmac, hexmac.c_str(), output_size);
}
int main() {
    const char* key = "thisisakey";
    const char* input = "this is some input text";
    char output[65]; // 64 ký tự hex + 1 ký tự null
    HMAC_SHA3_256(key, input, output, sizeof(output));
    cout << "HMAC-SHA3-256: " << output << endl;
    return 0;
}
