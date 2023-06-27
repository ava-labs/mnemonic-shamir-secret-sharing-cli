// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "Utils.h"
#include <algorithm>
#include <cmath>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>

#define DEFAULT_LOG_BUFF_SIZE 10000

using namespace std;

// print log for debugging
void print_message(const char* fmt, ...) {
    char buf[DEFAULT_LOG_BUFF_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, DEFAULT_LOG_BUFF_SIZE, fmt, ap);
    va_end(ap);
    std::cout << buf << std::endl;
    fflush(stdout);
}

// Removes leading and trailing spaces
std::string trim(const std::string& str) {
    std::string whitespace = " \t";
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos) {
        return "";
    }
    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;
    return str.substr(strBegin, strRange);
}

// Normalizes the case to lowercase
std::string tolowercase(const std::string& str) {
    std::string result = str;
    std::transform(str.begin(), str.end(), result.begin(), [](unsigned char c) { return std::tolower(c); });
    return result;
}

// Splits provided string str on specified delimiter. Stores resulting parsed strings in result.
// If str does not contain the specified delimiter, returns a vector with single element that
// is the original string str.
void split_string(std::string str_input, std::string delimiter, Mnemonics<std::string>* result) {
    size_t pos = 0;
    std::string token;

    std::string str = trim(str_input);

    while ((pos = str.find(delimiter)) != std::string::npos) {
        token = str.substr(0, pos);
        // std::cout << token << std::endl;
        token = trim(token);
        if (token != "") {
            result->push_back(token);
        }
        str.erase(0, pos + delimiter.length());
    }
    result->push_back(str);

    // Cleanup
    OPENSSL_cleanse(&str[0], str.size());
    OPENSSL_cleanse(&str_input[0], str_input.size());
    return;
}

// Generates set of <target_num_elements> random indexes in range
// E.g. given a set of 10 secret shares with recovery threshold 4, may generate a set {9, 2, 1, 5}
void generate_rand_indexes(int min, int max, int target_num_elements, std::unordered_set<int>* result) {
    int num_elements = 0;
    while (num_elements < target_num_elements) {
        int elem = rand() % (max - min + 1) + min;
        if (result->find(elem) == result->end()) {
            result->emplace(elem);
            num_elements++;
        }
    }
}

// Compare two mnemonics phrases and tests if they are equal
bool mnemonics_are_equal(const Mnemonics<std::string>& mnemonics1, const Mnemonics<std::string>& mnemonics2) {

    if (mnemonics1.size() != mnemonics2.size()) {
        return false;
    }
    for (size_t i = 0; i < mnemonics1.size(); i++) {
        if (mnemonics1[i].compare(mnemonics2[i]) != 0) {
            return false;
        }
    }
    return true;
}

// Calculates the number of combinations nCk
unsigned num_combinations(unsigned n, unsigned k) {
    if (k > n) {
        return 0;
    }
    if (k == 0 || k == n) {
        return 1;
    }
    double binom = 1 / ((n + 1) * std::beta(n - k + 1, k + 1));
    return static_cast<unsigned>(binom);
}
