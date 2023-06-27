// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "BigNumUtils.h"
#include "Utils.h"
#include <openssl/sha.h>
#include <string>
#include <unordered_map>
#include <vector>

#define SECRET_SHARES_NUM_MIN 2
#define SECRET_SHARES_NUM_MAX 20
#define SECRET_SHARE_Y_BITS 256
#define SECRET_SHARE_LENGTH 78

// Struct that represents an individual secret share in its base form. Each share
// has a version, and x and y values that are used in lagrange interpolation to
// recompute the master secret. The x value of shares are deterministically derived
// for a given warden, making it possible to recompute an individual wardens secret
// share given a threshold of the other secret shares. The y-value is the true secret, which
// is a cryptographically hard random integer between 0 and the 13th Mersenne prime (2 ^ 521 - 1).
struct SecretShare {
    // Default constructor.
    SecretShare() :
        x(0),
        y(BN_new()){ ASSERT(y != nullptr, "Failed creating y-value for new SecretShare instance.") }

        // Constructor with values.
        SecretShare(const size_t p_x, const BIGNUM* p_y) :
        x(p_x) {
        y = BN_dup(p_y);
        ASSERT(y != nullptr, "Failed creating y-value for new SecretShare instance.")
    }

    // Copy Constructor.
    SecretShare(const SecretShare& in) : x(in.x) {
        y = BN_dup(in.y);
        ASSERT(y != nullptr, "Failed creating y-value for new SecretShare instance.")
    }

    // Assignment Operator.
    SecretShare& operator=(const SecretShare& in) {
        x = in.x;
        BIGNUM* copy = BN_dup(in.y);
        ASSERT(copy != nullptr, "Failed creating y-value copy for SecretShare assignment.")
        BIGNUM* old = y;
        y = copy;
        if (old != nullptr) {
            BN_clear_free(old);
        }
        return *this;
    }

    // Destructor
    virtual ~SecretShare() {
        if (y != nullptr) {
            BN_clear_free(y);
            y = nullptr;
        }
    }

    // Get Methods:
    inline size_t get_x() const { return x; }
    inline BIGNUM* get_y() const { return y; }

    // Member variables.
private:
    size_t x;
    BIGNUM* y;
};

// Generates cryptographically hard secret shares for the desired total number of shares and threshold.
// Creates a new BIGNUM that is stored in result_master_secret,
// and sets serialized_shares with the resulting secret shares. Does not store the results in memory.
// It is the callers responsibility to use the results properly.
int split_secret(const BIGNUM* master_secret, const uint32_t t, const uint32_t n, std::vector<SecretShare>* shares);

// Takes atleast a threshold of secret shares generated by generate_master_secret and recomputes the master secret value
// using Lagrange interpolation. All salts and keys can then be deterministically computed from the secret.
int regenerate_secret(const std::vector<SecretShare>& secret_shares, const uint32_t threshold, BIGNUM** result);

// Generates the cryptographically hard secret by creating a new BIGNUM and storing it in result_master_secret.
// Does not store the result in a file.
int create_secret(BIGNUM** result_master_secret);
