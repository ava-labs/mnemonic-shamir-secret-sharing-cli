// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "SecretSharing.h"
#include <gtest/gtest.h>
#include <openssl/bn.h>

TEST(SplitRecoverMasterSecret, ValidCases) {
    for (int total = SECRET_SHARES_NUM_MIN; total <= SECRET_SHARES_NUM_MAX; total++) {
        for (int quorum = SECRET_SHARES_NUM_MIN; quorum <= total; quorum++) {
            print_message("Testing valid cases, total %d shares, recovery threshold %d shares...", total, quorum);
            // Generate random secret key
            BIGNUM* key = nullptr;
            int res = create_secret(&key);
            ASSERT_EQ(0, res);

            // Split into secret shares
            std::vector<SecretShare> shares;
            int split_success = split_secret(key, quorum, total, &shares);
            ASSERT_EQ(0, split_success);

            // Recover master secret
            std::unordered_set<int> share_indexes;
            generate_rand_indexes(0, total - 1, quorum, &share_indexes); // get random secret share indexes

            std::vector<SecretShare> recovered_shares;
            for (auto i : share_indexes) {
                recovered_shares.push_back(shares.at(i));
            }

            BIGNUM* recovered_key = nullptr;
            int recover_success = regenerate_secret(recovered_shares, quorum, &recovered_key);
            ASSERT_EQ(0, recover_success);
            ASSERT_EQ(0, BN_cmp(key, recovered_key));

            BN_clear_free(key);
            BN_clear_free(recovered_key);
            print_message("Success.");
        }
    }
}

TEST(SplitRecoverMasterSecret, InvalidCases) {
    for (int total = SECRET_SHARES_NUM_MIN; total <= SECRET_SHARES_NUM_MAX; total++) {
        // for invalid cases, test just one threshold per total number of shares
        int quorum = rand() % (total - SECRET_SHARES_NUM_MIN + 1) + SECRET_SHARES_NUM_MIN;

        print_message("Testing invalid cases, total %d shares, recovery threshold %d shares...", total, quorum);

        // Generate random secret key
        BIGNUM* key = nullptr;
        int res = create_secret(&key);
        ASSERT_EQ(0, res);

        // Split into secret shares
        std::vector<SecretShare> shares;
        int split_success = split_secret(key, quorum, total, &shares);
        ASSERT_EQ(0, split_success);

        // Recover master secret
        std::unordered_set<int> share_indexes;
        generate_rand_indexes(0, total - 1, quorum, &share_indexes); // get random secret share indexes

        std::vector<SecretShare> recovered_shares;
        for (auto i : share_indexes) {
            recovered_shares.push_back(shares.at(i));
        }

        // Modify one of the shares to invalidate the secret shares set

        // Generate a pseudo-random 256 bit BIGNUM
        BIGNUM* invalid_y = BN_new();
        BN_pseudo_rand(invalid_y, SECRET_SHARE_Y_BITS, -1, 0);

        // Replace the first share with the newly generated share
        SecretShare invalid_share(recovered_shares[0].get_x(), invalid_y);
        recovered_shares[0] = invalid_share;

        BIGNUM* recovered_key = nullptr;
        int recover_success = regenerate_secret(recovered_shares, quorum, &recovered_key);
        // Should either fail regenerating a secret or the regenerated secret is incorrect
        EXPECT_TRUE(recover_success == -1 || BN_cmp(key, recovered_key) != 0);

        BN_clear_free(key);
        BN_clear_free(recovered_key);
        print_message("Success.");
    }
}
