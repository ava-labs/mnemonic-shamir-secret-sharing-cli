// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "Constants.h"
#include "Mnemonics.h"
#include "MnemonicsStruct.h"
#include "SecretSharing.h"
#include "Utils.h"
#include <map>
#include <string>
#include <vector>

int mnemonic_split(const Mnemonics<std::string>& mnemonic,
                   const int k,
                   const int n,
                   std::map<size_t, std::vector<std::string>>* mnemonics);
int mnemonic_recover(const std::map<size_t, std::vector<std::string>>& mnemonics,
                     const int k,
                     Mnemonics<std::string>* recovered_mnemonic);
int mnemonic_generate(Mnemonics<std::string>& mnemonic);
