// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#ifndef UTILS_H_
#define UTILS_H_

#include "Mnemonics.h"
#include "assert.h"
#include <bits/stdc++.h>
#include <cstdarg>
#include <cstring>
#include <functional>
#include <iostream>
#include <list>
#include <openssl/bn.h>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <typeindex>
#include <typeinfo>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

// print log for debugging
void print_message(const char* fmt, ...);
std::string trim(const std::string& str);
std::string tolowercase(const std::string& str);
void split_string(std::string str_input, std::string delimiter, Mnemonics<std::string>* result);
void generate_rand_indexes(int min, int max, const int target_num_elements, std::unordered_set<int>* result);
bool mnemonics_are_equal(const Mnemonics<std::string>& mnemonics1, const Mnemonics<std::string>& mnemonics2);
unsigned num_combinations(unsigned n, unsigned k);

// securely clears each of the strings of the mnemonic
template <typename T> void secure_mem_clear_mnemonic(std::vector<T>& mnemonic) {
    for (T& st : mnemonic) {
        OPENSSL_cleanse(&st[0], st.size());
    }
}

#define ASSERT(cond, msg)                                                                                              \
    if (!(cond)) {                                                                                                     \
        print_message("ASSERTION FAILED.");                                                                            \
        print_message("File: %s", __FILE__);                                                                           \
        print_message("MESSAGE: %s", msg);                                                                             \
        print_message("Exiting...");                                                                                   \
        abort();                                                                                                       \
    }

#endif // UTILS_H_