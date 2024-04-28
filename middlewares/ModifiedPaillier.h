#include <openssl/bn.h>
#include <openssl/rand.h>
#include <iostream>
#include <utility>

struct PaillierPublicKey {
    BIGNUM* n;
    BIGNUM* g;
    BIGNUM* h;
};

struct PaillierPrivateKey {
    BIGNUM* skp;
};

struct PaillierEncrypted {
    BIGNUM* c1;
    BIGNUM* c2;
};

PaillierEncrypted E(const PaillierPublicKey& pk, const BIGNUM* m) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n2 = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* c1 = BN_new();
    BIGNUM* c2 = BN_new();

    // Tính n^2
    BN_sqr(n2, pk.n, ctx);

    // Chọn r ngẫu nhiên từ Z_n
    BN_rand_range(r, pk.n);

    // Tính c1 = (1 + m * n) % n^2
    BIGNUM* m_n = BN_new(); 
    BIGNUM* one = BN_new(); 
    BN_one(one);
    BN_mod_mul(m_n, m, pk.n, n2, ctx);
    BN_add(c1, one, m_n);
    BN_mod(c1, c1, n2, ctx);

    // Tính c1 = c1 * h^r % n^2
    BIGNUM* h_r = BN_new();
    BN_mod_exp(h_r, pk.h, r, n2, ctx);
    BN_mod_mul(c1, c1, h_r, n2, ctx);

    // Tính c2 = g^r % n^2
    BN_mod_exp(c2, pk.g, r, n2, ctx);

    // Dọn dẹp
    BN_free(m_n);
    BN_free(one);
    BN_free(h_r);
    BN_CTX_free(ctx);

    PaillierEncrypted result = {c1, c2};
    return result;
}

PaillierEncrypted  oppoE(const PaillierPublicKey& pk, const BIGNUM* m) {
    BN_CTX* ctx = BN_CTX_new();  // Tạo một new context cho toán số học Big Num.
    PaillierEncrypted  em;         // Khởi tạo cấu trúc chứa thông điệp đã mã hóa.

    // Tạo các biến Big Num cần thiết.
    BIGNUM* n2 = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* neg_m = BN_new();
    BIGNUM* one_plus_neg_m_mul_n = BN_new();
    
    // Tính n2 = pk.n * pk.n.
    BN_sqr(n2, pk.n, ctx);
    
    // Tính m = -m (chuyển m sang dạng âm).
    BN_copy(neg_m, m);
    BN_set_negative(neg_m, 1);

    // Chọn một số r ngẫu nhiên trong khoảng [0, pk.n - 1].
    BN_rand_range(r, pk.n);

    // Tính c1 và c2.
    em.c1 = BN_new();
    em.c2 = BN_new();

    // Tính one_plus_neg_m_mul_n = 1 - m * n (vì m đã mang dấu âm).
    BN_mul(one_plus_neg_m_mul_n, neg_m, pk.n, ctx);
    BN_add(one_plus_neg_m_mul_n, one_plus_neg_m_mul_n, BN_value_one());

    // Tính em.c1 = (1 - m * n) * (pk.h ^ r) mod n^2.
    BN_mod_exp(em.c1, pk.h, r, n2, ctx);
    BN_mod_mul(em.c1, em.c1, one_plus_neg_m_mul_n, n2, ctx);

    // Tính em.c2 = (pk.g ^ r) mod n^2.
    BN_mod_exp(em.c2, pk.g, r, n2, ctx);

    // Giải phóng các biến không cần thiết.
    BN_free(n2);
    BN_free(r);
    BN_free(neg_m);
    BN_free(one_plus_neg_m_mul_n);
    BN_CTX_free(ctx);

    return em; // Trả về cấu trúc chứa thông điệp đã mã hóa.
}

BIGNUM* DE(const PaillierPublicKey& pk, const PaillierPrivateKey& sk, const PaillierEncrypted& c) {
    BN_CTX* ctx = BN_CTX_new(); // Tạo một new context cho toán số học Big Num.

    BIGNUM* n2 = BN_new();
    BN_sqr(n2, pk.n, ctx); // Tính n2 = pk.n^2.

    BIGNUM* mu = BN_new();
    // Tính mu = c.c2^sk.skp mod n2.
    BN_mod_exp(mu, c.c2, sk.skp, n2, ctx);

    BIGNUM* l = BN_new();
    // Tính l = ((c.c1 * mu^-1) - 1) / pk.n.
    BIGNUM* mu_inv = BN_mod_inverse(NULL, mu, n2, ctx); // Tính mu^-1 mod n2.
    BN_mul(l, c.c1, mu_inv, ctx); // Tính c.c1 * mu^-1.
    BN_mod(l, l, n2, ctx); // Tính (c.c1 * mu^-1) mod n2.
    BN_sub(l, l, BN_value_one()); // Tính ((c.c1 * mu^-1) mod n2) - 1.
    BN_div(l, NULL, l, pk.n, ctx); // Tính (((c.c1 * mu^-1) mod n2) - 1) / pk.n.

    // Giải phóng các biến và bộ nhớ không cần thiết.
    BN_free(mu);
    BN_free(mu_inv);
    BN_free(n2);
    BN_CTX_free(ctx);

    return l; // Trả về thông điệp giải mã.
}

PaillierEncrypted DEp1(const PaillierPublicKey& pk, const BIGNUM *skp, const PaillierEncrypted& c) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n2 = BN_new();
    BIGNUM *gskp = BN_new();
    BIGNUM *c1 = BN_new();
    BIGNUM *c2 = BN_new();
    BIGNUM *temp = BN_new();

    // Calculate n^2
    BN_mul(n2, pk.n, pk.n, ctx);

    // gskp = c2^skp % (n^2)
    BN_mod_exp(gskp, c.c2, skp, n2, ctx);

    // c1 = (c1 * gskp^-1) % n^2
    BN_mod_inverse(temp, gskp, n2, ctx);
    BN_mod_mul(c1, c.c1, temp, n2, ctx);
    BN_mod(c1, c1, n2, ctx);

    // Clean up
    BN_CTX_free(ctx);
    BN_free(n2);
    BN_free(gskp);
    BN_free(temp);

    // Create and return the PaillierEncrypted structure
    PaillierEncrypted result = {c1, c2};
    return result;
}

BIGNUM* DEp2(const PaillierPublicKey& pk, const PaillierPrivateKey& sk, const PaillierEncrypted& c) {
    BN_CTX* ctx = BN_CTX_new(); // Tạo một new context cho toán số học Big Num.

    BIGNUM* n2 = BN_new();
    BN_sqr(n2, pk.n, ctx); // Tính n2 = pk.n^2.

    BIGNUM* mu = BN_new();
    // Tính mu = c.c2^sk.skp mod n2.
    BN_mod_exp(mu, c.c2, sk.skp, n2, ctx);

    BIGNUM* l = BN_new();
    // Tính l = ((c.c1 * mu^-1) - 1) / pk.n.
    BIGNUM* mu_inv = BN_mod_inverse(NULL, mu, n2, ctx); // Tính mu^-1 mod n2.
    BN_mul(l, c.c1, mu_inv, ctx); // Tính c.c1 * mu^-1.
    BN_mod(l, l, n2, ctx); // Tính (c.c1 * mu^-1) mod n2.
    BN_sub(l, l, BN_value_one()); // Tính ((c.c1 * mu^-1) mod n2) - 1.
    BN_div(l, NULL, l, pk.n, ctx); // Tính (((c.c1 * mu^-1) mod n2) - 1) / pk.n.

    // Giải phóng các biến và bộ nhớ không cần thiết.
    BN_free(mu);
    BN_free(mu_inv);
    BN_free(n2);
    BN_CTX_free(ctx);

    return l; // Trả về thông điệp giải mã.
}

PaillierEncrypted mul(const PaillierPublicKey& pk, const PaillierEncrypted& E1, const PaillierEncrypted& E2) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n2 = BN_new();
    BIGNUM *c1 = BN_new();
    BIGNUM *c2 = BN_new();

    // Calculate n^2
    BN_mul(n2, pk.n, pk.n, ctx);

    // c1 = (E1.c1 * E2.c1) % n^2
    BN_mod_mul(c1, E1.c1, E2.c1, n2, ctx);

    // c2 = (E1.c2 * E2.c2) % n^2
    BN_mod_mul(c2, E1.c2, E2.c2, n2, ctx);

    // Clean up
    BN_CTX_free(ctx);
    BN_free(n2);

    // Create and return the PaillierEncrypted structure
    PaillierEncrypted result = {c1, c2};
    return result;
}
