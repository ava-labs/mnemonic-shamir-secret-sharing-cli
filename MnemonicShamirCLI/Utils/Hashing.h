// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

#include <openssl/sha.h>

void sha256(const unsigned char* plaintext, const uint32_t plaintext_size, unsigned char hash[SHA256_DIGEST_LENGTH]);
