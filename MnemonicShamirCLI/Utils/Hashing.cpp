// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include "Hashing.h"

void sha256(const unsigned char* plaintext, const uint32_t plaintext_size, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, plaintext_size);
    SHA256_Final(hash, &sha256);
}
