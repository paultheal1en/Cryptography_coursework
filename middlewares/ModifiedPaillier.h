#ifndef Modified_Paillier_DEFINED
#define Modified_Paillier_DEFINED

#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/osrng.h" // For random number generation
#include "cryptopp/dh.h"
#include "cryptopp/osrng.h"
#include "cryptopp/modarith.h" 
#include <iostream>
#include "Conversion.h" // bytes_to_int || int_to_bytes
using CryptoPP::Integer;
using CryptoPP::ModularExponentiation;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::ModularArithmetic;
// Pk + PrK

struct PublicKey {
    Integer n;
    Integer g;
    Integer h;
};

struct PrivateKey {
    Integer skp;
};

struct Ciphertext {
    Integer c1;
    Integer c2;
};
// mã hóa m sử dụng khóa PK(n,g,h)
Ciphertext E(const PublicKey& pk, const Integer& m) {
    AutoSeededRandomPool prng;
    Integer n2 = pk.n * pk.n;
    Integer r = Integer(prng, 0, pk.n - 1); // tạo random r từ 0 đến n-1 
    Integer c1 = ((1 + m * pk.n) % n2); //c1 = t_mod(1 + m * pk['n'], n2) 
    c1 = ((c1 * ModularExponentiation(pk.h, r, n2)) % n2);//c1 = t_mod(c1 * powmod(pk['h'], r, n2), n2)
    Integer c2 = ModularExponentiation(pk.g, r, n2);//c2 = powmod(pk['g'], r, n2)
    return {c1, c2}; 
}
//giống cái trên nhưng mã hóa -m 
Ciphertext oppoE(const PublicKey& pk, const Integer& m) {
    AutoSeededRandomPool prng;
    Integer n2 = pk.n * pk.n;
    Integer r = Integer(prng, 0, pk.n - 1);
    Integer c1 = ((1 - m * pk.n) % n2);//c1 = t_mod(1 - m * pk['n'], n2)
    c1 = ((c1 * ModularExponentiation(pk.h, r, n2)) % n2);//c1 = t_mod(c1 * powmod(pk['h'], r, n2), n2)
    Integer c2 = ModularExponentiation(pk.g, r, n2);//c2 = powmod(pk['g'], r, n2)
    return {c1, c2}; 
}
//giải mã 
Integer DE(const PublicKey& pk, const Integer& skp, const Ciphertext& c) {
        // Tính n^2
        Integer n2 = pk.n.Squared();
        // Cấu hình arithmetic modulator cho n^2
        ModularArithmetic ma(n2);
        // Tính g^skp mod n^2
        Integer gskp = ma.Exponentiate(c.c2, skp);
        // Tính c1 * g^(-skp) mod n^2
        Integer c1 = ma.Multiply(c.c1, ma.MultiplicativeInverse(gskp));
        return c1;
    }
Ciphertext DEp1(const PublicKey& pk, const Integer& skp, const Ciphertext& c) {
    // Tính n^2
    Integer n2 = pk.n.Squared();
    // Cấu hình arithmetic modulator cho n^2
    ModularArithmetic ma(n2);
    // Tính g^skp mod n^2
    Integer gskp = ma.Exponentiate(c.c2, skp); 
    // Tính c1 * g^(-skp) mod n^2
    Integer c1 = ma.Multiply(c.c1, ma.MultiplicativeInverse(gskp));
    // Tính (c1 - 1) / n
    c1 = (c1 - 1) / pk.n;

    return {c1, c.c2}; // Trả về c1 là phần đầu tiên của giá trị sau khi giải mã từ ciphertext và c2 là phần thứ hai của ciphertext ban đầu
}

Integer DEp2(const PublicKey& pk, const Integer& skp, const Ciphertext& c) {
    // Tính n^2
    Integer n2 = pk.n.Squared();
    // Cấu hình arithmetic modulator cho n^2
    ModularArithmetic ma(n2);
    // Tính g^skp mod n^2
    Integer gskp = ma.Exponentiate(c.c2, skp);
    // Tính c1 * g^(-skp) mod n^2
    Integer c1 = ma.Multiply(c.c1, ma.MultiplicativeInverse(gskp));
    return c1;
}

Ciphertext mul(const PublicKey& pk, const Ciphertext& E1, const Ciphertext& E2) {
    Integer n2 = pk.n.Squared();
    ModularArithmetic ma(n2);

    // Thực hiện phép nhân trên cả hai phần của bản mã
    Integer newC1 = ma.Multiply(E1.c1, E2.c1);
    Integer newC2 = ma.Multiply(E1.c2, E2.c2);

    return {newC1, newC2};
}

#endif //ModifiedPaillier_DEFINED