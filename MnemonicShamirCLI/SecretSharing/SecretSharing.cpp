// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "SecretSharing.h"
#include "Hashing.h"
#include "Utils.h"
#include <memory>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

using namespace std;

// Because we use a 257 bit prime in generating secret shares, some secret shares
// end up being 257 bits and some are 256 bits or fewer. We regenerate shares
// up to MAX_ITERATIONS number of times until all shares are 256 bits or fewer
#define MAX_ITERATIONS 500000

// rnd_top is the upper limit for a random number.
// The generated random number is multiplied to the prime modulus to ahieve an extended modulus.
// Careful not to exceed the maximum value that a size_t can hold
static size_t rnd_top = 65536;

static BIGNUM* prime = nullptr;

// Generates a random value in the range (0, max_rnd) exclusive on both limits.
void generate_non_zero_random_bn(num_t& result, const BIGNUM* max_rnd) {
    num_t rnd_num;
    do {
        BN_zero(rnd_num.get_bignum_val());
        if (BN_rand_range(rnd_num.get_bignum_val(), max_rnd) != 1) {
            print_message("Error generating a random BN in generate_non_zero_random_bn.");
            return;
        }
    } while (BN_is_zero(rnd_num.get_bignum_val()));

    result = rnd_num;
}

void initialize_prime_number() {
    // The value below is a 257bit prime generated with BN_generate_prime_ex().
    // Add one to the length for null terminating character.
    char prime_string[SECRET_SHARE_LENGTH + 1] = "18711042233916165673175729240372539406"
                                                 "7928975545356095774785896842956550853219";
    // the prime is 78 characters long
    ASSERT(BN_dec2bn(&prime, prime_string) == 78, "Failed setting prime.")
}

// Evaluates the polynomial defined by coefficients at y(x). Say that n is the size
// of coefficients, then the polynomial is of the form:
// y = coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 ... + coefficients[n-1]*x^(n-1)
// Returns a new BIGNUM that must be free'd by the caller when no longer needed.
int evaluate_polynomial(const vector<num_t>& coefficients, const size_t x, num_t& result) {
    if (prime == nullptr) {
        initialize_prime_number();
    }

    BN_CTX* ctx = BN_CTX_new();
    ASSERT(ctx != nullptr, "Failed creating new BN context in evaluate_polynomial.")

    num_t bnx(x);
    num_t accum;

    BN_zero(accum.get_bignum_val());

    // Generate an extended modulus using a random coefficient
    // Calculations will be done modulo this extended prime ext_prime1
    num_t rnd_coeff_top(rnd_top);

    num_t rnd_coeff1;
    generate_non_zero_random_bn(rnd_coeff1, rnd_coeff_top.get_bignum_val());

    num_t ext_prime1;
    if (BN_mul(ext_prime1.get_bignum_val(), rnd_coeff1.get_bignum_val(), prime, ctx) != 1) {
        print_message("Error executing BN_mul in evaluate_polynomial.");
        BN_CTX_free(ctx);
        return -1;
    }

    for (auto it = coefficients.rbegin(); it != coefficients.rend(); it++) {
        num_t temp_a;
        if (BN_mul(temp_a.get_bignum_val(), accum.get_bignum_val(), bnx.get_bignum_val(), ctx) != 1) {
            print_message("Failed multiplying values in in evaluate_polynomial");
            BN_CTX_free(ctx);
            return -1;
        }
        num_t temp_b;

        if (BN_add(temp_b.get_bignum_val(), temp_a.get_bignum_val(), it->get_bignum_val()) != 1) {
            print_message("Failed adding values in in evaluate_polynomial");
            BN_CTX_free(ctx);
            return -1;
        }
        if (BN_nnmod(accum.get_bignum_val(), temp_b.get_bignum_val(), prime, ctx) != 1) {
            print_message("Failed nnmod'ing values in in evaluate_polynomial");
            BN_CTX_free(ctx);
            return -1;
        }
    }
    result = accum;
    BN_CTX_free(ctx);
    return 0;
}

// Function that checks that the BN elements of the vector are different in value
// returns true if they are different
// returns false if there are at least two elements equal in value
bool check_unique_values(const vector<num_t>& x_s) {
    int are_unique = true;
    // To check if all the x_s are different, first I make a copy of x_s and sort them using the equivalent comparator
    // of < for BN
    vector<num_t> x_s_copy;
    // make a copy of x_s
    for (auto elem : x_s) {
        x_s_copy.emplace_back(elem);
    }
    // sort the values of x_s_copy using the equivalent comparator of < for BN
    sort(x_s_copy.begin(), x_s_copy.end(), [](num_t first, num_t second) {
        if (BN_cmp(first.get_bignum_val(), second.get_bignum_val()) == -1) {
            return 1;
        } else {
            return 0;
        }
    });
    // Since the vector of x_s_copy is sorted, compare subsequent values in pairs searching for equality
    // If two are equal, exit
    if (x_s_copy.size() > 1)
        for (size_t i = 0; i < x_s_copy.size() - 1; i++) {
            if (BN_cmp(x_s_copy[i].get_bignum_val(), x_s_copy[i + 1].get_bignum_val()) == 0) {
                are_unique = false;
                break;
            }
        }

    return are_unique;
}

int product_of_inputs(const vector<num_t>& inputs, num_t& result) {
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        print_message("Failed creating new BN context in product_of_inputs.");
        return -1;
    }
    num_t res;
    BN_one(res.get_bignum_val());
    for (uint32_t i = 0; i < inputs.size(); i++) {
        num_t temp_result;
        if (BN_mul(temp_result.get_bignum_val(), res.get_bignum_val(), inputs[i].get_bignum_val(), ctx) != 1) {
            print_message("Failed to calculate product of inputs.");
            BN_CTX_free(ctx);
            return -1;
        }
        res = temp_result;
    }
    BN_CTX_free(ctx);
    result = res;
    return 0;
}

int div_mod(BIGNUM* num, BIGNUM* den, num_t& result) {
    if (prime == nullptr) {
        print_message("Need to initialize prime before calling div_mod.");
        return -1;
    }
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        print_message("Failed creating new BN context in div_mod.");
        return -1;
    }
    num_t res;
    num_t inv;
    if (BN_mod_inverse(inv.get_bignum_val(), den, prime, ctx) == nullptr) {
        print_message("BN_mod_inverse failed in div_mod.");
        BN_CTX_free(ctx);
        return -1;
    }
    if (BN_mul(res.get_bignum_val(), num, inv.get_bignum_val(), ctx) != 1) {
        print_message("Multiplication failed in div_mod.");
        BN_CTX_free(ctx);
        return -1;
    }
    BN_CTX_free(ctx);
    result = res;
    return 0;
}

int lagrange_interpolate(const size_t x, const vector<num_t>& x_s, const vector<num_t>& y_s, BIGNUM** result) {
    if (prime == nullptr) {
        initialize_prime_number();
    }

    if (!check_unique_values(x_s)) {
        print_message(
            "Invalid lagrange interpolate inputs. At least two values are the same or error creating a BN. (li-1)");
        return -1;
    }

    // At this point all x_s values are unique.
    if (x_s.size() != y_s.size()) {
        print_message("Invalid lagrange interpolate input (li-2)");
        return -1;
    }

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return -1;
    }
    num_t bnx(x);

    // Generate an extended modulus using a random coefficient
    // Calculations will be done modulo this extended prime ext_prime1
    num_t rnd_coeff_top(rnd_top);

    num_t rnd_coeff1;
    generate_non_zero_random_bn(rnd_coeff1, rnd_coeff_top.get_bignum_val());

    num_t ext_prime1;
    if (BN_mul(ext_prime1.get_bignum_val(), rnd_coeff1.get_bignum_val(), prime, ctx) != 1) {
        print_message("Error executing BN_mul in evaluate_polynomial.");
        BN_CTX_free(ctx);
        return -1;
    }

    vector<num_t> nums;
    vector<num_t> dens;

    for (uint32_t i = 0; i < x_s.size(); i++) {
        num_t cur = x_s[i];
        vector<num_t> num_components;
        vector<num_t> denom_components;
        for (uint32_t j = 0; j < x_s.size(); j++) {
            if (i == j) {
                continue;
            }
            num_t n;
            num_t d;
            if (BN_sub(n.get_bignum_val(), bnx.get_bignum_val(), x_s[j].get_bignum_val()) != 1 ||
                BN_sub(d.get_bignum_val(), cur.get_bignum_val(), x_s[j].get_bignum_val()) != 1) {
                BN_CTX_free(ctx);
                return -1;
            }
            num_components.emplace_back(std::move(n));
            denom_components.emplace_back(std::move(d));
        }
        num_t num_component;
        if (product_of_inputs(num_components, num_component)) {
            print_message("Error calling product_of_inputs for BN");
            BN_CTX_free(ctx);
            return -1;
        }
        num_t denom_component;
        if (product_of_inputs(denom_components, denom_component)) {
            print_message("Error calling product_of_inputs for BN");
            BN_CTX_free(ctx);
            return -1;
        }
        nums.emplace_back(std::move(num_component));
        dens.emplace_back(std::move(denom_component));
    }

    num_t den;
    if (product_of_inputs(dens, den)) {
        print_message("Error calling product_of_inputs for BN");
        BN_CTX_free(ctx);
        return -1;
    }
    num_t num;
    BN_zero(num.get_bignum_val());
    for (uint32_t i = 0; i < y_s.size(); i++) {
        num_t temp_a;
        if (BN_mul(temp_a.get_bignum_val(), nums[i].get_bignum_val(), den.get_bignum_val(), ctx) != 1) {
            BN_CTX_free(ctx);
            return -1;
        }
        num_t temp_b;
        if (BN_mul(temp_b.get_bignum_val(), temp_a.get_bignum_val(), y_s[i].get_bignum_val(), ctx) != 1) {
            BN_CTX_free(ctx);
            return -1;
        }
        num_t temp_c;
        if (BN_nnmod(temp_c.get_bignum_val(), temp_b.get_bignum_val(), prime, ctx) != 1) {
            BN_CTX_free(ctx);
            return -1;
        }
        num_t new_num;
        if (div_mod(temp_c.get_bignum_val(), dens[i].get_bignum_val(), new_num)) {
            print_message("Error calling div_mod for BN");
            BN_CTX_free(ctx);
            return -1;
        }
        num_t temp_d;
        if (BN_add(temp_d.get_bignum_val(), num.get_bignum_val(), new_num.get_bignum_val()) != 1) {
            BN_CTX_free(ctx);
            return -1;
        }
        num = temp_d;
    }

    num_t temp_a;
    if (div_mod(num.get_bignum_val(), den.get_bignum_val(), temp_a)) {
        print_message("Error calling div_mod for BN");
        BN_CTX_free(ctx);
        return -1;
    }
    num_t temp_b;
    if (BN_add(temp_b.get_bignum_val(), temp_a.get_bignum_val(), prime) != 1) {
        BN_CTX_free(ctx);
        return -1;
    }
    num_t res;
    if (BN_nnmod(res.get_bignum_val(), temp_b.get_bignum_val(), prime, ctx) != 1) {
        BN_CTX_free(ctx);
        return -1;
    }

    BN_CTX_free(ctx);

    *result = res.release();
    return 0;
}

// Generates the cryptographically hard secret by creating a new BIGNUM and storing it in result_master_secret.
// Does not store the result in a file.
int create_secret(BIGNUM** result_master_secret) {
    if (prime == nullptr) {
        initialize_prime_number();
    }

    // Generate the secret.
    // iterate until generated secret is <= 256 bits
    for (uint32_t j = 0; j < MAX_ITERATIONS; j++) {
        num_t sec;
        if (BN_rand_range(sec.get_bignum_val(), prime) != 1) {
            print_message("Failed generating random BN when creating secret shares.");
            return -1;
        }

        // skip secrets that are too large
        if (BN_num_bits(sec.get_bignum_val()) > SECRET_SHARE_Y_BITS) {
            continue;
        }

        // Set the result value.
        *result_master_secret = sec.release();
        return 0;
    }

    print_message("Failed to generate a master secret in %d iterations", MAX_ITERATIONS);
    return -1;
}

// Takes master secret, a threshold t, and a total number of shares n, and splits master secret
// into n shares, where t shares are sufficient to recover the original secret.
// Final result is stored in shares vector.
int split_secret(const BIGNUM* master_secret, const uint32_t t, const uint32_t n, std::vector<SecretShare>* shares) {
    if (t > n || t < 2) {
        print_message("ERROR: Invalid Shamir secret sharing parameters. Threshold must be between 2 and %d.", n);
        return -1;
    }

    if (prime == nullptr) {
        initialize_prime_number();
    }

    // Iterate until all n shares are <= 256 bits.
    // Because we use a 257 bit prime, the shares we generate are <= 257 bits in size,
    // so shares that are 257 bits don't translate neatly into BIP-39 mnemonics that must be 256 bits.
    // Iterating until all generated shares were <= 256 bits is the preferred solution for this use case.
    // Other alternatives included having secret shares > 256 bits and generating mnemonic phrases > 24 words to store
    // extra information or selecting particular X values, s.t. corresponding Y values were <= 256 bits.
    for (uint32_t j = 0; j < MAX_ITERATIONS; j++) {
        std::vector<SecretShare> generated_shares;
        // Generate t random BIGNUMS, the first of which is the master secret
        vector<num_t> coefficients;
        coefficients.emplace_back(master_secret);
        for (uint32_t i = 1; i < t; i++) {
            num_t coef;
            if (BN_rand_range(coef.get_bignum_val(), prime) != 1) {
                return -1;
            }
            coefficients.emplace_back(std::move(coef));
        }

        // Generate the secret shares
        int num_smaller = 0;
        for (uint32_t i = 0; i < n; i++) {
            size_t x_val = i + 1;

            num_t y_val;
            if (evaluate_polynomial(coefficients, x_val, y_val)) {
                print_message("ERROR: Error calling evaluate_polynomial when creating master secret.");
                return -1;
            }

            SecretShare share(x_val, y_val.get_bignum_val());
            if (BN_num_bits(y_val.get_bignum_val()) <= 256) {
                num_smaller += 1;
            }

            generated_shares.push_back(share);
        }
        // all n shares are <= 256 bits, these are the final shares
        if (num_smaller == n) {
            *shares = generated_shares;
            return 0;
        }
    }

    print_message("Failed to generate secret shares after %d iterations.", MAX_ITERATIONS);
    return -1;
}

// Takes at least a threshold of secret shares generated by generate_master_secret and recomputes the master secret
// value using Lagrange interpolation. All keys can then be deterministically computed from the secret.
int regenerate_secret(const vector<SecretShare>& secret_shares, const uint32_t threshold, BIGNUM** result) {
    if (prime == nullptr) {
        initialize_prime_number();
    }

    if (threshold <= 0) {
        print_message("ERROR: Threshold was not greater than 0 in regenerate_secret.");
        return -1;
    }

    if (secret_shares.size() < threshold) {
        print_message("ERROR: Insufficient number of valid secret shares provided to regenerate_secret.");
        return -1;
    }

    // Only use the exact threshold of shares in lagrange interpolation.
    vector<SecretShare> shares_to_use(secret_shares.begin(), secret_shares.begin() + threshold);

    // Check that all of the x values are distinct and that all of the shares have the same version.
    unordered_set<size_t> x_vals;
    for (const SecretShare& s : shares_to_use) {
        if (x_vals.count(s.get_x()) != 0) {
            print_message("ERROR: Secret shares were not distinct when regenerating master secret.");
            return -1;
        }
        x_vals.insert(s.get_x());
    }

    // Create proper vector inputs for lagrange_interpolate
    vector<num_t> x_s;
    vector<num_t> y_s;
    for (const auto& share : shares_to_use) {
        x_s.emplace_back(share.get_x());
        y_s.emplace_back(share.get_y());
    }

    if (lagrange_interpolate(0, x_s, y_s, result) != 0) {
        print_message("ERROR: Lagrange interpolation failed. Master secret not regenerated.");
        return -1;
    }

    // Regenerated secret is too large and cannot be converted into a mnemonic
    // This likely means that provided secret shares are not valid
    int secret_size = BN_num_bits(*result);
    if (secret_size > SECRET_SHARE_Y_BITS) {
        print_message("ERROR: Regenerated master secret is too large. Expected %d bits, got %d bits.",
                      SECRET_SHARE_Y_BITS,
                      secret_size);
        print_message("This is likely because the shares provided are not valid.");
        print_message("RECOVERED SECRET: %s", BN_bn2hex(*result));
        return -1;
    }

    return 0;
}
