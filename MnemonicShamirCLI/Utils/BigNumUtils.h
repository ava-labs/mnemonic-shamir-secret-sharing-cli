// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "Utils.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <vector>

// A BIGNUM* wrapper for ease of mathematic operations with large integers.
struct num_t {
public:
    num_t();
    num_t(const num_t& y);
    num_t(num_t&& y);
    explicit num_t(const BIGNUM* bn);
    num_t(const int in);
    num_t(const uint64_t& in);

    virtual ~num_t();

    // Copy and Move Assignment (=)
    num_t& operator=(const num_t& in);
    num_t& operator=(num_t&& in);

    // Comparators
    bool operator<(const num_t& b) const;
    bool operator<=(const num_t& b) const;
    bool operator>(const num_t& b) const;
    bool operator>=(const num_t& b) const;
    bool operator==(const num_t& b) const;
    bool operator!=(const num_t& b) const;

    // Basic Arithmetic
    num_t operator+(const num_t& y) const;
    num_t operator-(const num_t& y) const;
    num_t operator*(const num_t& y) const;
    num_t operator/(const num_t& y) const;
    num_t operator%(const num_t& y) const;
    num_t div(const num_t& y, num_t* rem);

    // Return the raw BN pointer. May be modified by the caller.
    inline BIGNUM* get_bignum_val() const { return val; }

    // Return the managed pointer and cease managing it.
    inline BIGNUM* release() {
        BIGNUM* tmp = val;
        val = nullptr;
        return tmp;
    }

    inline void reset(BIGNUM* new_val) {
        BIGNUM* old_val = this->val;
        this->val = new_val;
        if (old_val != nullptr) {
            BN_clear_free(old_val);
        }
    }

private:
    BIGNUM* val;
};

int pad_bn_val(const BIGNUM* bn, BIGNUM* padded_bn);
