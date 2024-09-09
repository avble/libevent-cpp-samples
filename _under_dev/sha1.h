#pragma once
/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include "stdint.h"

#include <string>
#include <vector>

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]);

void SHA1Init(SHA1_CTX * context);

void SHA1Update(SHA1_CTX * context, const unsigned char * data, uint32_t len);

void SHA1Final(unsigned char digest[20], SHA1_CTX * context);

void SHA1(char * hash_out, const char * str, int len);

std::vector<char> SHA1_CPP(const std::string & data);

char * base64_encode(const unsigned char * data, size_t input_length, size_t * output_length);
std::string base64_encode_cpp(const std::vector<char> & data);

void DumpHex(const void * data, size_t size);
