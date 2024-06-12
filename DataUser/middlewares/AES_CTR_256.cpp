#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#ifndef AES_H
#define AES_H

#ifdef BUILD_DLL
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif

extern "C" {
    EXPORT void Enc(const char* key, const char* iv, const char* plaintext, size_t plaintext_len, char* ciphertext, size_t* ciphertext_len);
    EXPORT void Dec(const char* key, const char* iv, const char* ciphertext, size_t ciphertext_len, char* plaintext, size_t* plaintext_len);
}

#endif

void Enc(const char* key, const char* iv, const char* plaintext, size_t plaintext_len, char* ciphertext, size_t* ciphertext_len) {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption encryption((const CryptoPP::byte*)key, CryptoPP::AES::DEFAULT_KEYLENGTH, (const CryptoPP::byte*)iv);

    CryptoPP::ArraySink csink((CryptoPP::byte*)ciphertext, *ciphertext_len);
    CryptoPP::StringSource ss((const CryptoPP::byte*)plaintext, plaintext_len, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::Redirector(csink)
        )
    );

    *ciphertext_len = csink.TotalPutLength();
}

void Dec(const char* key, const char* iv, const char* ciphertext, size_t ciphertext_len, char* plaintext, size_t* plaintext_len) {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption decryption((const CryptoPP::byte*)key, CryptoPP::AES::DEFAULT_KEYLENGTH, (const CryptoPP::byte*)iv);

    CryptoPP::ArraySink psink((CryptoPP::byte*)plaintext, *plaintext_len);
    CryptoPP::StringSource ss((const CryptoPP::byte*)ciphertext, ciphertext_len, true,
        new CryptoPP::StreamTransformationFilter(decryption,
            new CryptoPP::Redirector(psink)
        )
    );

    *plaintext_len = psink.TotalPutLength();
}
