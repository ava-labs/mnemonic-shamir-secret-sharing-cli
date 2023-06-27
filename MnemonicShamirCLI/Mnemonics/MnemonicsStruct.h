// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#ifndef MNEMONICSSTRUCT_H_
#define MNEMONICSSTRUCT_H_

#include <iostream>
#include <openssl/bn.h>
#include <vector>

template <typename T> struct Mnemonics {
    std::vector<T> mnemonic;
    Mnemonics(){};
    Mnemonics(const std::vector<T>& str) { mnemonic = str; };
    std::vector<T>& get() { return mnemonic; }
    void push_back(const T& st) { mnemonic.push_back(st); };
    void clear() {
        for (auto& w : mnemonic) {
            OPENSSL_cleanse(&w[0], w.size());
        }
        mnemonic.clear();
    };
    typename std::vector<T>::iterator begin() { return mnemonic.begin(); }
    typename std::vector<T>::iterator end() { return mnemonic.end(); }
    size_t size() const { return mnemonic.size(); }
    bool empty() { return mnemonic.empty(); }
    bool operator==(const Mnemonics& a) const {
        if (a.mnemonic.size() != mnemonic.size()) {
            return false;
        }
        for (int i = 0; i < mnemonic.size(); i++) {
            if (a.mnemonic[i] != mnemonic[i]) {
                return false;
            }
        }
        return true;
    }
    bool operator!=(const Mnemonics& a) const { return !(*this == a); }
    T& operator[](const size_t i) { return mnemonic[i]; }
    const T& operator[](const size_t i) const { return mnemonic[i]; }
    virtual ~Mnemonics() {
        for (auto& w : mnemonic) {
            OPENSSL_cleanse(&w[0], w.size());
        }
    };
    friend std::ostream& operator<<(std::ostream& out, const Mnemonics& a) {
        for (auto& w : a.mnemonic) {
            out << w << " ";
        }
        return out;
    }
};

#endif // MNEMONICSSTRUCT_H_