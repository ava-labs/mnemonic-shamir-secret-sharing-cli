// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "MnemonicShamirSecretSharing.h"

using namespace std;

int mnemonic_split(const Mnemonics<std::string>& mnemonic,
                   const int k,
                   const int n,
                   std::map<size_t, std::vector<std::string>>* mnemonics) {

    if (!validate_mnemonic(mnemonic)) {
        print_message("Invalid mnemonic.");
        return -1;
    }

    // Convert mnemonic into 256 bit secret
    BIGNUM* bn = nullptr;
    if (derive_key_from_mnemonic(mnemonic, &bn) != 0) {
        print_message("Invalid seed phrase.");
        if (bn != nullptr) {
            BN_clear_free(bn);
        }
        return -1;
    }

    // turns over management of bn pointer to num_t, RAII wrapper for BIGNUM
    num_t user_key;
    user_key.reset(bn);

    // Split above secret into n shares with k recovery threshold
    std::vector<SecretShare> shares;
    int success = split_secret(user_key.get_bignum_val(), k, n, &shares);
    if (success != 0) {
        print_message("Failed to split generated 256 bit secret into shares.");
        return -1;
    }

    // Convert each secret share into a 24 word mnemonic
    for (SecretShare share : shares) {
        Mnemonics<std::string> mnemonic_vec;
        generate_mnemonic(share.get_y(), &mnemonic_vec);
        mnemonics->insert(std::make_pair(share.get_x(), mnemonic_vec.get()));
    }

    return 0;
}

int mnemonic_recover(const std::map<size_t, std::vector<std::string>>& mnemonics,
                     const int k,
                     Mnemonics<std::string>* recovered_mnemonic) {
    std::vector<SecretShare> recovered_shares;
    for (auto& it : mnemonics) {
        BIGNUM* y_val = nullptr;
        if (derive_key_from_mnemonic(it.second, &y_val) != 0) {
            print_message("Failed to derive key from mnemonic %lu.", it.first);
            if (y_val != nullptr) {
                BN_clear_free(y_val);
            }
            return -1;
        }
        SecretShare share(it.first, y_val);
        recovered_shares.push_back(share);
        BN_clear_free(y_val);
    }

    // recover master secret from secret shares
    BIGNUM* bn = nullptr;
    if (regenerate_secret(recovered_shares, k, &bn) != 0) {
        print_message("Failed to recover the 256 bit original secret");
        if (bn != nullptr) {
            BN_clear_free(bn);
        }
        return -1;
    }

    // turns over management of bn pointer to num_t, RAII wrapper for BIGNUM
    num_t recovered_key;
    recovered_key.reset(bn);

    // generate mnemonic phrase from recovered master secret
    generate_mnemonic(recovered_key.get_bignum_val(), recovered_mnemonic);
    if (recovered_mnemonic->empty()) {
        print_message("Failed to generate a mnemonic phrase from reconstructed 256 bit secret");
        return -1;
    }

    return 0;
}

int mnemonic_generate(Mnemonics<std::string>& mnemonic) {

    // Generate a new secret
    BIGNUM* bn = nullptr;
    if (create_secret(&bn) != 0) {
        print_message("Failed to generate a new 256 bit secret.");
        if (bn != nullptr) {
            BN_clear_free(bn);
        }
        return -1;
    }

    // turns over management of bn pointer to num_t, RAII wrapper for BIGNUM
    num_t new_secret;
    new_secret.reset(bn);

    // Convert the new secret to a mnemonic
    generate_mnemonic(new_secret.get_bignum_val(), &mnemonic);

    return 0;
}
