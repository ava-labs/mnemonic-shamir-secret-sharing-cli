// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "MnemonicShamirSecretSharing.h"
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

TEST(EndToEndTests, GenerateRecoverValidMnemonics) {
    for (int total = SECRET_SHARES_NUM_MIN; total <= SECRET_SHARES_NUM_MAX; total++) {
        for (int quorum = SECRET_SHARES_NUM_MIN; quorum <= total; quorum++) {
            print_message("End-to-end testing total %d shares, recovery threshold %d shares...", total, quorum);

            // Generate random mnemonic
            Mnemonics<std::string> mnemonic;
            int generate_success = mnemonic_generate(mnemonic);
            ASSERT_EQ(0, generate_success);

            // Split into secret shares
            std::map<size_t, std::vector<std::string>> mnemonics;
            int split_success = mnemonic_split(mnemonic, quorum, total, &mnemonics);
            ASSERT_EQ(0, split_success);

            // Recover mnemonic

            // Pick random shares from set of generated shares
            std::unordered_set<int> share_indexes;
            generate_rand_indexes(1, total, quorum, &share_indexes); // get random secret share indexes

            std::map<size_t, std::vector<std::string>> recovered_shares;
            for (auto i : share_indexes) {
                recovered_shares[i] = mnemonics[i];
            }

            // Recover mnemonic from picked shares
            Mnemonics<std::string> recovered_mnemonic;
            int recover_success = mnemonic_recover(recovered_shares, quorum, &recovered_mnemonic);
            ASSERT_EQ(0, recover_success);

            // Assert
            ASSERT_EQ(mnemonic, recovered_mnemonic);
            print_message("Success.");
        }
    }
}

TEST(InputTests, GenerateRecoverInvalidMnemonics) {
    for (int total = SECRET_SHARES_NUM_MIN; total <= SECRET_SHARES_NUM_MAX; total++) {
        // for invalid cases, test just one threshold per total number of shares
        int quorum = rand() % (total - SECRET_SHARES_NUM_MIN + 1) + SECRET_SHARES_NUM_MIN;
        print_message("End-to-end testing, invalid cases, total %d shares, recovery threshold %d shares...",
                      total,
                      quorum);

        // Generate random mnemonic
        Mnemonics<std::string> mnemonic;
        int generate_success = mnemonic_generate(mnemonic);
        ASSERT_EQ(0, generate_success);

        // Split into secret shares
        std::map<size_t, std::vector<std::string>> mnemonics;
        int split_success = mnemonic_split(mnemonic, quorum, total, &mnemonics);
        ASSERT_EQ(0, split_success);

        // Recover mnemonic

        // Pick random shares from set of generated shares
        std::unordered_set<int> share_indexes;
        generate_rand_indexes(1, total, quorum, &share_indexes); // get random secret share indexes

        std::map<size_t, std::vector<std::string>> recovered_shares;
        for (auto i : share_indexes) {
            recovered_shares[i] = mnemonics[i];
        }

        // Replace one of the shares with random mnemonic
        Mnemonics<std::string> random_mnemonic;
        mnemonic_generate(random_mnemonic);
        recovered_shares[0] = random_mnemonic.get();

        // Recover mnemonic from picked shares
        Mnemonics<std::string> recovered_mnemonic;
        int recover_success = mnemonic_recover(recovered_shares, quorum, &recovered_mnemonic);
        // Should either fail regenerating a secret or the regenerated secret is incorrect
        EXPECT_TRUE(recover_success == -1 || mnemonic != recovered_mnemonic);

        // Assert
        print_message("Success.");
    }
    // }
}
