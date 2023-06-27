// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "MnemonicShamirSecretSharing.h"
#include <getopt.h>
#include <unistd.h>

using namespace std;

const static string help_message("\nMnemonic Shamir's Secret Sharing Tool Usage:\n"
                                 "\nOPTIONS:\n"
                                 "-total n : total number of shares, 2 <= n <= 20\n"
                                 "-quorum k : number of shares required to regenerate the key, 2 <= k <= n\n"
                                 "-word <short/long> : input the mnemonic words in abbreviated or complete form\n"
                                 "-mode <word/phrase> : input the mnemonic words word-by-word or by phrase\n"
                                 "\nCOMMANDS:\n"
                                 "split : splits provided mnemonic into shares\n"
                                 "recover : recovers a mnemonic from provided shares\n"
                                 "generate : generates a new random mnemonic\n"
                                 "\nUSAGE:\n"
                                 "./mnemonic-sss split -quorum k -total n\n"
                                 "./mnemonic-sss split -quorum k -total n -word long\n"
                                 "./mnemonic-sss split -quorum k -total n -mode phrase\n"
                                 "./mnemonic-sss split -quorum k -total n -word long -mode phrase\n"
                                 "./mnemonic-sss recover -quorum k\n"
                                 "./mnemonic-sss recover -quorum k -word long\n"
                                 "./mnemonic-sss recover -quorum k -mode phrase\n"
                                 "./mnemonic-sss recover -quorum k -word long -mode phrase\n"
                                 "./mnemonic-sss generate");

bool validate_arguments(const char* function, const int k, const int n) {
    if (function == SPLIT) {
        if (n >= SECRET_SHARES_NUM_MIN && n <= SECRET_SHARES_NUM_MAX && k >= SECRET_SHARES_NUM_MIN && k <= n) {
            return true;
        }
    } else if (function == RECOVER) {
        if (k >= SECRET_SHARES_NUM_MIN && k <= SECRET_SHARES_NUM_MAX) {
            return true;
        }
    }
    return false;
}

int split(const Mnemonics<std::string>& master_mnemonic, int k, int n) {
    if (!validate_mnemonic(master_mnemonic)) {
        print_message("Invalid mnemonic.");
        return -1;
    }

    std::map<size_t, std::vector<std::string>> mnemonics;
    if (mnemonic_split(master_mnemonic, k, n, &mnemonics) != 0) {
        for (auto& it : mnemonics) {
            secure_mem_clear_mnemonic<std::string>(it.second);
        }
        return -1;
    }

    // Verify that the all the combinations of the shares can regenerate the master secret
    // The elements of the vector v indicate if the corresponding indices will be considered in the test
    std::vector<bool> v(n, false);
    std::fill(v.end() - k, v.end(), true);

    int num_tests = 0;
    int num_total_combinations = num_combinations(n, k);
    float percentage_test = 0.0;
    int previous_percentage = 0;

    print_message("\nTesting all combinations of shares...");
    do {
        num_tests++;
        percentage_test = static_cast<float>(num_tests) * 10 / num_total_combinations;
        if (previous_percentage != static_cast<int>(percentage_test)) {
            previous_percentage = static_cast<int>(percentage_test);
            print_message("Tested %d%%", previous_percentage * 10);
        }

        std::map<size_t, std::vector<std::string>> mnemonics_to_recover;

        // Create the combination of mnemonics to test
        for (int i = 0; i < n; ++i) {
            if (v[i]) {
                mnemonics_to_recover[i + 1] = mnemonics[i + 1];
            }
        }

        // regenerate the master secret from the shares
        Mnemonics<std::string> recovered_mnemonic_vec;
        if (mnemonic_recover(mnemonics_to_recover, k, &recovered_mnemonic_vec) != 0) {
            print_message("Regeneration failed!\n");
            // In case of error, clear the memory before exiting
            for (auto& it : mnemonics_to_recover) {
                secure_mem_clear_mnemonic<std::string>(it.second);
            }
            for (auto& it : mnemonics) {
                secure_mem_clear_mnemonic<std::string>(it.second);
            }
            return -1;
        }

        // securely clear the mnemonics of the temporary map
        for (auto& it : mnemonics_to_recover) {
            secure_mem_clear_mnemonic<std::string>(it.second);
        }

        // compare if the regenerated secret is equal to the original secret
        if (!mnemonics_are_equal(recovered_mnemonic_vec, master_mnemonic)) {
            print_message("Regeneration failed!\n");
            // In case of error, clear the memory before exiting
            for (auto& it : mnemonics) {
                secure_mem_clear_mnemonic<std::string>(it.second);
            }
            return -1;
        }

    } while (std::next_permutation(v.begin(), v.end()));

    print_message("Tested %d combinations.", num_tests);
    print_message("Tested all combinations of %d shares out of %d.", k, n);

    // Print shares to screen
    print_message("\nRecord and store these %d shares along with their corresponding share numbers in a safe place.", n);
    print_message("You will need %d shares to recover the original mnemonic phrase.\n", k);
    for (auto& it : mnemonics) {
        print_message("%lu: %s", it.first, mnemonic_to_string(it.second).c_str());
    }

    // Cleanup

    // Zeroize generated secret share mnemonics
    // Secret share values are cleaned up in SecretShare destructor
    for (auto& it : mnemonics) {
        secure_mem_clear_mnemonic<std::string>(it.second);
    }

    return 0;
}

int recover(const std::map<size_t, std::vector<std::string>>& mnemonics, const int k) {
    // generate mnemonic phrase from recovered master secret
    Mnemonics<std::string> recovered_mnemonic_vec;
    if (mnemonic_recover(mnemonics, k, &recovered_mnemonic_vec) != 0) {
        return -1;
    }

    print_message("\nRecovered mnemonic phrase is:\n%s", mnemonic_to_string(recovered_mnemonic_vec.get()).c_str());

    return 0;
}

int generate() {
    Mnemonics<std::string> mnemonic;
    if (mnemonic_generate(mnemonic) != 0) {
        // In case of error, clear the memory before exiting
        return -1;
    }

    print_message("\nGenerated mnemonic:\n\n%s", mnemonic_to_string(mnemonic.get()).c_str());

    return 0;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        print_message("Invalid arguments. Must provide function  \"%s\", \"%s\", or \"%s\".", SPLIT, RECOVER, GENERATE);
        print_message("%s", help_message.c_str());
        return -1;
    }

    string function_name(argv[1]);
    if (function_name != SPLIT && function_name != RECOVER && function_name != GENERATE) {
        print_message("Invalid function argument. Must provide function \"%s\", \"%s\", or \"%s\".",
                      SPLIT,
                      RECOVER,
                      GENERATE);
        print_message("%s", help_message.c_str());
        return -1;
    }

    // options passed to the executable
    static struct option long_options[] = { { QUORUM, required_argument, nullptr, 'q' }, // -quorum
                                            { TOTAL, required_argument, nullptr, 't' },  // - total
                                            { WORD, required_argument, nullptr, 'w' },   // -word
                                            { MODE, required_argument, nullptr, 'm' },   // -mode
                                            { nullptr, 0, nullptr, 0 } };

    // parse command options -quorum and -total and their values
    int option = 0;
    int quorum = 0;
    int total = 0;
    bool abbreviated_word = true;
    bool input_mode_by_word = true;

    // getopt_long_only parses command options, where each found option character/string
    //  is assigned to "option". When there are no more option strings left,
    // getopt_long_only returns -1
    while ((option = getopt_long_only(argc, argv, "q:t:", long_options, nullptr)) != -1) {
        switch (option) {
        case 'q':
            quorum = atoi(optarg);
            break;
        case 't':
            total = atoi(optarg);
            break;
        case 'w':
            if (strcmp(optarg, "short") == 0) {
                abbreviated_word = true;
            } else if (strcmp(optarg, "long") == 0) {
                abbreviated_word = false;
            } else {
                print_message("%s", help_message.c_str());
                return -1;
            }
            break;
        case 'm':
            if (strcmp(optarg, "word") == 0) {
                input_mode_by_word = true;
            } else if (strcmp(optarg, "phrase") == 0) {
                input_mode_by_word = false;
            } else {
                print_message("%s", help_message.c_str());
                return -1;
            }
            break;
        default:
            print_message("%s", help_message.c_str());
            return -1;
        }
    }

    // Split mnemonic into secret shares
    if (function_name == SPLIT) {
        if (!validate_arguments(SPLIT, quorum, total)) {
            print_message("Invalid \"%s\" arguments. Must provide \"-quorum k -total n\".", SPLIT);
            print_message("%s", help_message.c_str());
            return -1;
        }

        Mnemonics<std::string> mnemonic;

        // when invoking input_mnemonics_list the quorum is set to 0 to avoid printing the number of shares and the quorum
        input_mnemonics_list(0, 0, &mnemonic, abbreviated_word, input_mode_by_word);

        if (split(mnemonic, quorum, total) != 0) {
            print_message("Failed to split provided mnemonic into secret shares.");
        }
    }

    // Recover A mnemonic from provided secret shares
    // That is, will recover some mnemonic, accuracy depends on user providing correct shares (y value)
    // and their corresponding share numbers (x value)
    else if (function_name == RECOVER) {
        if (!validate_arguments(RECOVER, quorum, 0)) {
            print_message("Invalid \"%s\" arguments. Must provide \"-quorum k -total n\".", RECOVER);
            print_message("%s", help_message.c_str());
            return -1;
        }

        std::map<size_t, std::vector<std::string>> mnemonics;
        print_message("\nPlease enter your secret share mnemonic phrases, a share number followed by 24 word phrase:");

        int i = 0;
        std::set<int> share_idx_set;
        while (i < quorum) {
            bool share_num_already_in_set = true;
            int share_num;
            do {
                print_message("\nPlease enter share number (share %d of %d):", i + 1, quorum);
                std::string share_num_input;
                std::getline(std::cin, share_num_input);
                share_num = atoi(share_num_input.c_str()); // share_num has to be between 1 and 20, atoi is sufficient
                                                           // for this conversion
                if (share_num < 1 || share_num > SECRET_SHARES_NUM_MAX) {
                    print_message("Invalid share number: %d. Share number has to be between 1 and %d.",
                                  share_num,
                                  SECRET_SHARES_NUM_MAX);
                    continue;
                }
                auto it = std::find(share_idx_set.begin(), share_idx_set.end(), share_num);
                if (it == share_idx_set.end()) {
                    share_idx_set.insert(share_num);
                    share_num_already_in_set = false;
                } else {
                    print_message("Share number %d has already been entered. Use a different share number.", share_num);
                }
            } while (share_num_already_in_set);

            Mnemonics<std::string> mnemonic;
            input_mnemonics_list(i + 1, quorum, &mnemonic, abbreviated_word, input_mode_by_word);
            mnemonics[share_num] = mnemonic.get();
            i++;
        }
        if (recover(mnemonics, quorum) != 0) {
            print_message("Failed to recover original mnemonic.");
        }
        // Cleanup
        // Zeroize mnemonics before exiting
        for (auto& it : mnemonics) {
            secure_mem_clear_mnemonic<std::string>(it.second);
        }
    }

    // We check whether the function_name is one of SPLIT, RECOVE, or GENERATE above
    // before parsing options input. We check if function_name is SPLIT or RECOVER
    // in two previous if statements, so the only way to land here is if
    // the function_name is GENERATE.
    else {
        if (generate() != 0) {
            print_message("Failed to generate a new mnemonic.");
            return -1;
        }
    }
}
