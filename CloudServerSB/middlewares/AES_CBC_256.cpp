#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

extern "C" {

void Enc(const char* key, const char* iv, const char* plaintext, size_t plaintext_len, char* ciphertext, size_t* ciphertext_len) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption((const CryptoPP::byte*)key, CryptoPP::AES::DEFAULT_KEYLENGTH, (const CryptoPP::byte*)iv);

    CryptoPP::ArraySink csink((CryptoPP::byte*)ciphertext, *ciphertext_len);
    CryptoPP::StringSource((const CryptoPP::byte*)plaintext, plaintext_len, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::Redirector(csink)
        )
    );

    *ciphertext_len = csink.TotalPutLength();
}

void Dec(const char* key, const char* iv, const char* ciphertext, size_t ciphertext_len, char* plaintext, size_t* plaintext_len) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption((const CryptoPP::byte*)key, CryptoPP::AES::DEFAULT_KEYLENGTH, (const CryptoPP::byte*)iv);

    CryptoPP::ArraySink psink((CryptoPP::byte*)plaintext, *plaintext_len);
    CryptoPP::StringSource((const CryptoPP::byte*)ciphertext, ciphertext_len, true,
        new CryptoPP::StreamTransformationFilter(decryption,
            new CryptoPP::Redirector(psink)
        )
    );

    *plaintext_len = psink.TotalPutLength();
}
}
