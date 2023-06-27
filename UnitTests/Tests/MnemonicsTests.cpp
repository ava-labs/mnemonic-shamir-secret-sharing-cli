// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "Mnemonics.h"
#include <gtest/gtest.h>
#include <string>
#include <unordered_map>
#include <vector>

TEST(ValidateMnemonic, ValidMnemonics) {
    // Arrange
    std::vector<std::vector<std::string>> valid_mnemonics = {
        { "mention", "inch",    "detect",  "coil",     "portion", "boss",   "hip",   "rent",
          "another", "weather", "length",  "replace",  "vibrant", "coffee", "clean", "climb",
          "globe",   "tourist", "fitness", "cupboard", "finger",  "easily", "oval",  "garlic" },
        { "repair", "gallery",  "miss",   "decorate", "alone",  "hen",    "alert", "special",
          "often",  "burst",    "castle", "only",     "middle", "hidden", "hunt",  "more",
          "hunt",   "original", "save",   "theme",    "tissue", "lava",   "slush", "hole" },
        { "wash",    "dove",    "olive",   "skate",  "phrase", "noodle", "news",    "ride",
          "element", "stand",   "desk",    "manage", "goat",   "spell",  "neutral", "woman",
          "trial",   "involve", "holiday", "weird",  "earn",   "travel", "team",    "napkin" },
        { "glove",  "abstract", "donor",  "profit", "can",     "patrol", "obey",     "you",
          "album",  "work",     "grab",   "gentle", "popular", "fish",   "crater",   "nasty",
          "cattle", "noble",    "finish", "join",   "client",  "excess", "frequent", "very" },
    };

    // Act and Assert
    for (const std::vector<std::string>& mnemonic : valid_mnemonics) {
        bool res = validate_mnemonic(mnemonic);
        ASSERT_TRUE(res);
    }
}

TEST(ValidateMnemonic, InvalidMnemonics) {
    // Arrange
    // first has too few words
    // second has too many words
    // third has a word not in the word list
    std::vector<std::vector<std::string>> valid_mnemonics = {
        { "mention", "inch",    "detect",  "coil",     "portion", "boss",   "hip",   "rent",
          "another", "weather", "length",  "replace",  "vibrant", "coffee", "clean", "climb",
          "globe",   "tourist", "fitness", "cupboard", "finger",  "easily", "oval" },
        { "wash",    "dove",  "olive",  "skate",  "phrase", "noodle",  "news",  "ride",  "element",
          "stand",   "desk",  "manage", "goat",   "spell",  "neutral", "woman", "trial", "involve",
          "holiday", "weird", "earn",   "travel", "team",   "napkin",  "hidden" },
        { "repair", "gallery",  "miss",   "decorate", "alone",  "hen",    "alert", "special",
          "often",  "burst",    "castle", "only",     "middle", "hidden", "hunt",  "more",
          "hunt",   "original", "save",   "theme",    "tissue", "lava",   "slush", "hippo" },
    };

    // Act and Assert
    for (const std::vector<std::string>& mnemonic : valid_mnemonics) {
        bool res = validate_mnemonic(mnemonic);
        ASSERT_FALSE(res);
    }
}

TEST(GenerateMnemonic, Seeds) {
    // Arrange

    Mnemonics<std::string> c1({ "leisure", "zero",    "town",   "need",    "misery", "still", "hundred", "top",
                                "brass",   "solar",   "engine", "bargain", "solve",  "table", "cover",   "radio",
                                "dry",     "fragile", "hello",  "loyal",   "snack",  "alone", "drip",    "trouble" });
    Mnemonics<std::string> c2({ "raw",   "cool",    "turtle",  "someone", "pupil", "devote",   "wheel",    "mammal",
                                "into",  "bracket", "romance", "dwarf",   "entry", "describe", "rubber",   "welcome",
                                "coast", "flock",   "stone",   "inmate",  "ride",  "drastic",  "remember", "suggest" });
    Mnemonics<std::string> c3({ "negative", "start",   "crew",  "under",  "ridge", "riot",  "trick",  "goat",
                                "prize",    "width",   "town",  "lyrics", "order", "scrub", "narrow", "gym",
                                "blossom",  "improve", "night", "invite", "ski",   "sail",  "degree", "believe" });
    Mnemonics<std::string> c4({ "vendor",  "process", "old",     "gloom",   "jelly", "enlist",  "amount", "gather",
                                "already", "random",  "sample",  "finish",  "print", "slim",    "crouch", "rhythm",
                                "egg",     "excess",  "student", "enforce", "spy",   "coconut", "bubble", "rug" });

    std::unordered_map<std::string, Mnemonics<std::string>> cases;
    cases["7FBFF79949E8DBAB9BCF271B39CD29895CEFB9CC658643AB8DAB424CD00DD0CF"] = c1;
    cases["B285FBABE78ADE79BE843575C35AEE2254BA772F37CA2CCB2B593A2B9684AD6E"] = c2;
    cases["93FA94CD766B99747A1B20AB5F5B9942B9C383A4C340180E42563B0CA57C4E70"] = c3;
    cases["F235726831B77C95820303073636FC2B8AAD978D0DC646C9D35DA51D3459C755"] = c4;

    // Act and Assert
    for (const auto& kvp : cases) {
        BIGNUM* entropy = nullptr;
        int res = BN_hex2bn(&entropy, kvp.first.c_str());
        // BN_hex2bn returns 0 on error
        ASSERT_NE(0, res);

        Mnemonics<std::string> mnemonic_vec;
        generate_mnemonic(entropy, &mnemonic_vec);
        ASSERT_EQ(mnemonic_vec, kvp.second);

        BN_clear_free(entropy);
    }
}

TEST(DeriveKeyFromMnemonic, Mnemonics) {
    // Arrange
    std::unordered_map<std::string, std::string> cases = {
        { "enable sing drop leopard deny glow caught season mosquito toss exit belt pony reject junior proud simple force hurt quality dry federal police bicycle",
          "4959290DC023AAC7891E11901CB53F8A7A7F69DE4D66C90B61BF57943AA8E9E8" },
        { "occur sight creek hair kitchen calm ginger wisdom patrol pulse swift harbor art miss genre wonder property napkin puppy regular pride initial unveil cattle",
          "98D904CCB427B0411887E2A135B36F3480CD1B9847E8AC725EB85A6AA8E7FB99" },
        { "flight fat found mad brown gallery scatter february salad survey echo vehicle traffic entire typical betray agree identify myself bulk indoor season join throw",
          "58EA6D70C2D1D0BE301AA2BE5B5517F8FE6C973AF8AB050E12490F0731845E0F" },
    };

    // Act and Assert
    for (const auto& kvp : cases) {
        Mnemonics<std::string> mnemonic;
        split_string(kvp.first, std::string(MNEMONIC_WORD_DELIMITER), &mnemonic);

        BIGNUM* derived_key = nullptr;
        int res = derive_key_from_mnemonic(mnemonic, &derived_key);

        ASSERT_EQ(0, res);
        EXPECT_STREQ(kvp.second.c_str(), BN_bn2hex(derived_key));

        BN_clear_free(derived_key);
    }
}
