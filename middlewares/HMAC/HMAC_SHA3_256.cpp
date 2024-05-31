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
// Hàm tạo key
void GenerateAndSaveKey(const char* filename) {
    // Tạo khóa ngẫu nhiên
    AutoSeededRandomPool prng;
    SecByteBlock key(64);
    prng.GenerateBlock(key, key.size());

    // Chuyển khóa sang dạng hex để lưu vào tệp
    string hexKey;
    ArraySource(key, key.size(), true, new HexEncoder(new StringSink(hexKey)));

    // Lưu khóa vào tệp
    try {
        FileSink file(filename);
        file.Put(reinterpret_cast<const byte*>(hexKey.data()), hexKey.size());
    }
    catch(const CryptoPP::Exception& e) {
        cerr << "Error writing key file: " << e.what() << endl;
        exit(1);
    }
}
// Hàm HMAC-SHA3-256
void HMAC_SHA3_256(const char* keyFile, const char* input_filename, const char* output_filename) {
    // Đọc khóa từ tệp
    string key_content;
    try {
        FileSource(keyFile, true, new StringSink(key_content));
    }
    catch(const CryptoPP::Exception& e) {
        cerr << "Error reading key file: " << e.what() << endl;
        exit(1);
    }

    // Chuyển key sang SecByteBlock
    SecByteBlock key(reinterpret_cast<const byte*>(key_content.data()), key_content.size());

    string mac, i_mac;
    const unsigned char ipad = 0x36;
    const unsigned char opad = 0x5c;
    // XOR lần lượt key với ipad và opad
    SecByteBlock k_ipad = xorWithpad(ipad, key);
    SecByteBlock k_opad = xorWithpad(opad, key);

    // Đọc nội dung từ file đầu vào
    string file_content;
    try {
        FileSource(input_filename, true, new StringSink(file_content));
    }
    catch(const CryptoPP::Exception& e) {
        cerr << "Error reading input file: " << e.what() << endl;
        exit(1);
    }

    // Hash (k xor ipad) với nội dung file
    try {
        HMAC<SHA3_256> i_hmac(k_ipad, k_ipad.size());
        StringSource(file_content, true, 
            new HashFilter(i_hmac,
                new StringSink(i_mac)
            ) // HashFilter      
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    // Hash (k xor opad) với (i_mac) kết quả ở trên 
    try {
        HMAC<SHA3_256> hmac(k_opad, k_opad.size());
        StringSource(i_mac, true, 
            new HashFilter(hmac,
                new StringSink(mac)
            ) // HashFilter      
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    // Chuyển kết quả sang dạng hex
    string hexmac;
    StringSource(mac, true, new HexEncoder(new StringSink(hexmac)));

    // Ghi kết quả vào file đầu ra
    try {
        FileSink file(output_filename);
        file.Put(reinterpret_cast<const byte*>(hexmac.data()), hexmac.size());
    }
    catch(const CryptoPP::Exception& e) {
        cerr << "Error writing output file: " << e.what() << endl;
        exit(1);
    }
}

int main(int argc, char** argv) {
    #ifdef _linux_
    std::locale::global(std::locale("C.utf8"));
    #endif
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    if (argc < 2) {
        cerr << "Usage: \n"
             << argv[0] << " HMAC_SHA3_256 <key_File> <input_File> <output_File>\n"
             << argv[0] << " GenerateAndSaveKey <key_File>\n";
        return -1;
    }
    string option = argv[1];
    if (option == "HMAC_SHA3_256") {
        // Kiểm tra số lượng đối số
        if (argc != 5) {
            cerr << "Usage: " << argv[0] << " HMAC_SHA3_256 <key_File> <input_File> <output_File>\n";
            return -1;
        }
        const char* keyFile = argv[2];
        const char* input_filename = argv[3];
        const char* output_filename = argv[4];
        HMAC_SHA3_256(keyFile, input_filename, output_filename);
        cout << "HMAC-SHA3-256 calculation completed and written to " << output_filename << endl;
    } else if (option == "GenerateAndSaveKey") {
        // Kiểm tra số lượng đối số
        if (argc != 3) {
            cerr << "Usage: " << argv[0] << " GenerateAndSaveKey <key_File>\n";
            return -1;
        }
        const char* keyFile = argv[2];
        GenerateAndSaveKey(keyFile);
        cout << "Random key generated and saved to " << keyFile << endl;
    } else {
        cerr << "Invalid option: " << option << endl;
        return -1;
    }
    return 0;
}
