// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "BigNumUtils.h"
#include "Utils.h"

using namespace std;

num_t::num_t() {
    val = BN_new();
    ASSERT(val != nullptr, "Failed creating BN for new num_t.")
}

num_t::num_t(const BIGNUM* bn) {
    val = BN_dup(bn);
    ASSERT(val != nullptr, "Failed creating BN for new num_t.")
}

num_t::num_t(const num_t& y) {
    val = (y.val == nullptr) ? BN_new() : BN_dup(y.val);
    ASSERT(val != nullptr, "Failed creating BN for new num_t.")
}

num_t::num_t(num_t&& y) {
    ASSERT(y.val != nullptr, "Tried moving NULL BN from num_t in constructor")
    this->val = y.val;
    y.val = nullptr;
}

num_t::num_t(const int in) {
    BIGNUM* v = BN_new();
    ASSERT(v != nullptr, "Failed creating BN for new num_t.")
    string in_str = to_string(in);
    int ret = BN_dec2bn(&v, in_str.c_str());
    ASSERT(ret != 0, "Failed converting decimal to BN for new num_t.")
    val = v;
}

num_t::num_t(const uint64_t& in) {
    BIGNUM* v = BN_new();
    ASSERT(v != nullptr, "Failed creating BN for new num_t.")
    string in_str = to_string(in);
    int ret = BN_dec2bn(&v, in_str.c_str());
    ASSERT(ret != 0, "Failed converting decimal to BN for new num_t.")
    val = v;
}

num_t::~num_t() {
    if (val != nullptr) {
        BN_clear_free(val);
        val = nullptr;
    }
}

num_t& num_t::operator=(const num_t& in) {
    BIGNUM* copy = BN_dup(in.val);
    ASSERT(copy != nullptr, "Failed creating BN copy for num_t assignment.")
    BIGNUM* old = this->val;
    this->val = copy;
    if (old != nullptr) {
        BN_clear_free(old);
    }
    return *this;
}

num_t& num_t::operator=(num_t&& in) {
    ASSERT(in.val != nullptr, "Tried moving NULL BN from num_t in assignment")
    BIGNUM* old = this->val;
    this->val = in.val;
    in.val = nullptr;
    if (old != nullptr) {
        BN_clear_free(old);
    }
    return *this;
}

bool num_t::operator<(const num_t& b) const { return BN_cmp(val, b.val) == -1; }

bool num_t::operator<=(const num_t& b) const { return BN_cmp(val, b.val) <= 0; }

bool num_t::operator>(const num_t& b) const { return BN_cmp(val, b.val) == 1; }

bool num_t::operator>=(const num_t& b) const { return BN_cmp(val, b.val) >= 0; }

bool num_t::operator==(const num_t& b) const { return BN_cmp(val, b.val) == 0; }

bool num_t::operator!=(const num_t& b) const { return BN_cmp(val, b.val) != 0; }

num_t num_t::operator+(const num_t& y) const {
    BIGNUM* z = BN_new();
    ASSERT(z != nullptr, "Failed creating BN for adding num_t.")
    int ret = BN_add(z, val, y.val);
    ASSERT(ret == 1, "Failed adding BNs for num_t addition.")
    num_t result = num_t(z);
    BN_clear_free(z);
    return result;
}

num_t num_t::operator-(const num_t& y) const {
    BIGNUM* z = BN_new();
    ASSERT(z != nullptr, "Failed creating BN for subtracting num_t.")
    int ret = BN_sub(z, val, y.val);
    ASSERT(ret == 1, "Failed subtracting BNs for num_t subtraction.")
    num_t result = num_t(z);
    BN_clear_free(z);
    return result;
}

num_t num_t::operator*(const num_t& y) const {
    BIGNUM* z = BN_new();
    ASSERT(z != nullptr, "Failed creating BN for multiplying num_t.")
    BN_CTX* ctx = BN_CTX_new();
    ASSERT(ctx != nullptr, "Failed creating BN ctx for multiplying num_t.")
    int ret = BN_mul(z, val, y.val, ctx);
    ASSERT(ret == 1, "Failed multiplying BNs for num_t multiplication.")
    BN_CTX_free(ctx);
    num_t result = num_t(z);
    BN_clear_free(z);
    return result;
}

num_t num_t::operator/(const num_t& y) const {
    BIGNUM* z = BN_new();
    ASSERT(z != nullptr, "Failed creating BN for dividing num_t.")
    BN_CTX* ctx = BN_CTX_new();
    ASSERT(ctx != nullptr, "Failed creating BN ctx for dividing num_t.")
    int ret = BN_div(z, nullptr, val, y.val, ctx);
    ASSERT(ret == 1, "Failed dividing BNs for num_t division.");
    BN_CTX_free(ctx);
    num_t result = num_t(z);
    BN_clear_free(z);
    return result;
}

num_t num_t::operator%(const num_t& y) const {
    BIGNUM* z = BN_new();
    ASSERT(z != nullptr, "Failed creating BN for mod'ing num_t.")
    BN_CTX* ctx = BN_CTX_new();
    ASSERT(ctx != nullptr, "Failed creating BN ctx for mod'ing num_t.")
    int ret = BN_mod(z, val, y.val, ctx);
    ASSERT(ret == 1, "Failing mod'ing BNs for num_t modulo.")
    BN_CTX_free(ctx);
    num_t result = num_t(z);
    BN_clear_free(z);
    return result;
}

num_t num_t::div(const num_t& y, num_t* rem) {
    BIGNUM* res_val = BN_new();
    ASSERT(res_val != nullptr, "Failed creating BN for num_t division.")
    BIGNUM* res_rem = BN_new();
    ASSERT(res_rem != nullptr, "Failed creating BN for num_t division remainder.")
    BN_CTX* ctx = BN_CTX_new();
    ASSERT(ctx != nullptr, "Failed creating BN ctx for dividing num_t.")
    int ret = BN_div(res_val, res_rem, val, y.val, ctx);
    ASSERT(ret == 1, "Failing dividing BNs in num_t::div.")
    BN_CTX_free(ctx);
    num_t result = num_t(res_val);
    if (rem != nullptr) {
        *rem = num_t(res_rem);
    }
    BN_clear_free(res_val);
    BN_clear_free(res_rem);
    return result;
}

int pad_bn_val(const BIGNUM* bn, BIGNUM* padded_bn) {
    unsigned char to[32];
    if (BN_bn2binpad(bn, to, 32) <= 0) {
        print_message("failed to pad");
        return -1;
    }

    BN_bin2bn(to, 32, padded_bn);
    return 0;
}
