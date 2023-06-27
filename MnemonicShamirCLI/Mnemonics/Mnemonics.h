// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#ifndef MNEMONICS_H_
#define MNEMONICS_H_

#include "MnemonicsStruct.h"
#include "Utils.h"
#include <openssl/bn.h>
#include <string>
#include <vector>

#define MNEMONIC_ENTROPY_SIZE 32
#define MNEMONIC_BYTE_SIZE 33
#define MNEMONIC_WORD_COUNT 24
#define MNEMONIC_WORD_DELIMITER " " // delimiter is a single white space

inline int is_big_endian() {
    int i = 1;
    return !*((char*) &i);
}

void initialize_mnemonic_word_map();
void initialize_mnemonic_word_map_abbreviated();
void input_mnemonics_list(const int share_num,
                          const int quorum,
                          Mnemonics<std::string>* mnemonics_list,
                          const bool is_abbreviated = true,
                          const bool word_by_word = true);
bool validate_mnemonic(const Mnemonics<std::string>& mnemonic);
void generate_mnemonic(const BIGNUM* entropy, Mnemonics<std::string>* result);
int derive_key_from_mnemonic(const Mnemonics<std::string>& mnemonic, BIGNUM** result);
std::string mnemonic_to_string(const std::vector<std::string>& mnemonic);

#endif // MNEMONICS_H_