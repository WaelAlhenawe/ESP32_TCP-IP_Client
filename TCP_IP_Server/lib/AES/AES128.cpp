/* --COPYRIGHT--,BSD 
 * Copyright (c) 2011, Texas Instruments Incorporated
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * *  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * *  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * *  Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * --/COPYRIGHT--*/
/*
 * AES128.cpp
 *
 *  Created on: Nov 3, 2011
 *      Author: Eric Peeters
 *
 *  Description: Implementation of the AES-128 as defined by the FIPS PUB 197: 
 *  the official AES standard
 */

#include <AES128.h>
#include <Arduino.h>

#if (AES_BLOCK_SIZE > 15) || (AES_BLOCK_SIZE < 1)
#error AES_BLOCK_SIZE should be greater than 0 and lesser than 16.
#elif (AES_KEY_SIZE != 16) || (AES_CIPHER_SIZE != 16)
#error AES_KEY_SIZE and AES_CIPHER_SIZE should be 16.
#endif

static uint8_t aes_key[16];

// Foreward sbox
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// Inverse sbox
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// Round constant
const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// Multiply by 2 in the galois field
static uint8_t galois_mul2(uint8_t value)
{
    int8_t temp;
    temp = (int8_t)value;
    temp = temp >> 7;
    temp = temp & 0x1b;
    return ((value << 1) ^ temp);
}

// Generate, set and return the key
const uint8_t *aes128_init_key(uint8_t *key)
{
    if (key == NULL)
    {
        randomSeed(micros());
        for (uint8_t i = 0; i < AES_KEY_SIZE; i++)
        {
            aes_key[i] = random(0xFF);
        }
    }
    else
    {
        memcpy(aes_key, key, AES_KEY_SIZE);
    }

    return (const uint8_t *)aes_key;
}

// AES-128 encryption function
bool aes128_encrypt(uint8_t *data, uint8_t data_size, uint8_t *cipher)
{
    if ((data_size < 1) || (data_size > AES_BLOCK_SIZE))
    {
        return false;
    }

    uint8_t key[AES_KEY_SIZE] = {};
    memcpy(key, aes_key, AES_KEY_SIZE);
    uint8_t padding = AES_CIPHER_SIZE - data_size;

    if (data == cipher)
    {
        memmove(cipher + padding, cipher, data_size);
    }
    else
    {
        memcpy(cipher + padding, data, data_size);
    }

    randomSeed(micros());
    cipher[0] = (padding << 4U) | random(0x0F);
    for (uint8_t i = 1; i < padding; i++)
    {
        cipher[i] = random(0xFF);
    }

    uint8_t buf1, buf2, buf3, buf4, round, i;

    for (round = 0; round < 10; round++)
    {
        key[0] = sbox[key[13]] ^ key[0] ^ rcon[round];
        key[1] = sbox[key[14]] ^ key[1];
        key[2] = sbox[key[15]] ^ key[2];
        key[3] = sbox[key[12]] ^ key[3];
        for (i = 4; i < 16; i++)
        {
            key[i] = key[i] ^ key[i - 4];
        }
    }

    for (i = 0; i < 16; i++)
    {
        cipher[i] = cipher[i] ^ key[i];
    }

    for (round = 0; round < 10; round++)
    {
        for (i = 15; i > 3; --i)
        {
            key[i] = key[i] ^ key[i - 4];
        }
        key[0] = sbox[key[13]] ^ key[0] ^ rcon[9 - round];
        key[1] = sbox[key[14]] ^ key[1];
        key[2] = sbox[key[15]] ^ key[2];
        key[3] = sbox[key[12]] ^ key[3];

        if (round > 0)
        {
            for (i = 0; i < 4; i++)
            {
                buf4 = (i << 2);
                buf1 = galois_mul2(galois_mul2(cipher[buf4] ^ cipher[buf4 + 2]));
                buf2 = galois_mul2(galois_mul2(cipher[buf4 + 1] ^ cipher[buf4 + 3]));
                cipher[buf4] ^= buf1;
                cipher[buf4 + 1] ^= buf2;
                cipher[buf4 + 2] ^= buf1;
                cipher[buf4 + 3] ^= buf2;
                buf1 = cipher[buf4] ^ cipher[buf4 + 1] ^ cipher[buf4 + 2] ^ cipher[buf4 + 3];
                buf2 = cipher[buf4];
                buf3 = cipher[buf4] ^ cipher[buf4 + 1];
                buf3 = galois_mul2(buf3);
                cipher[buf4] = cipher[buf4] ^ buf3 ^ buf1;
                buf3 = cipher[buf4 + 1] ^ cipher[buf4 + 2];
                buf3 = galois_mul2(buf3);
                cipher[buf4 + 1] = cipher[buf4 + 1] ^ buf3 ^ buf1;
                buf3 = cipher[buf4 + 2] ^ cipher[buf4 + 3];
                buf3 = galois_mul2(buf3);
                cipher[buf4 + 2] = cipher[buf4 + 2] ^ buf3 ^ buf1;
                buf3 = cipher[buf4 + 3] ^ buf2;
                buf3 = galois_mul2(buf3);
                cipher[buf4 + 3] = cipher[buf4 + 3] ^ buf3 ^ buf1;
            }
        }

        buf1 = cipher[13];
        cipher[13] = cipher[9];
        cipher[9] = cipher[5];
        cipher[5] = cipher[1];
        cipher[1] = buf1;
        buf1 = cipher[10];
        buf2 = cipher[14];
        cipher[10] = cipher[2];
        cipher[14] = cipher[6];
        cipher[2] = buf1;
        cipher[6] = buf2;
        buf1 = cipher[3];
        cipher[3] = cipher[7];
        cipher[7] = cipher[11];
        cipher[11] = cipher[15];
        cipher[15] = buf1;
        for (i = 0; i < 16; i++)
        {
            cipher[i] = rsbox[cipher[i]] ^ key[i];
        }
    }

    return true;
}

// AES-128 decryption function
uint8_t aes128_decrypt(uint8_t *cipher, uint8_t *data)
{
    uint8_t length = 0;
    uint8_t key[AES_KEY_SIZE] = {};
    memcpy(key, aes_key, AES_KEY_SIZE);

    uint8_t buf1, buf2, buf3, buf4, round, i;

    for (round = 0; round < 10; round++)
    {
        for (i = 0; i < 16; i++)
        {
            cipher[i] = sbox[cipher[i] ^ key[i]];
        }

        buf1 = cipher[1];
        cipher[1] = cipher[5];
        cipher[5] = cipher[9];
        cipher[9] = cipher[13];
        cipher[13] = buf1;

        buf1 = cipher[2];
        buf2 = cipher[6];
        cipher[2] = cipher[10];
        cipher[6] = cipher[14];
        cipher[10] = buf1;
        cipher[14] = buf2;

        buf1 = cipher[15];
        cipher[15] = cipher[11];
        cipher[11] = cipher[7];
        cipher[7] = cipher[3];
        cipher[3] = buf1;

        if (round < 9)
        {
            for (i = 0; i < 4; i++)
            {
                buf4 = (i << 2);
                buf1 = cipher[buf4] ^ cipher[buf4 + 1] ^ cipher[buf4 + 2] ^ cipher[buf4 + 3];
                buf2 = cipher[buf4];
                buf3 = cipher[buf4] ^ cipher[buf4 + 1];
                buf3 = galois_mul2(buf3);
                cipher[buf4] = cipher[buf4] ^ buf3 ^ buf1;
                buf3 = cipher[buf4 + 1] ^ cipher[buf4 + 2];
                buf3 = galois_mul2(buf3);
                cipher[buf4 + 1] = cipher[buf4 + 1] ^ buf3 ^ buf1;
                buf3 = cipher[buf4 + 2] ^ cipher[buf4 + 3];
                buf3 = galois_mul2(buf3);
                cipher[buf4 + 2] = cipher[buf4 + 2] ^ buf3 ^ buf1;
                buf3 = cipher[buf4 + 3] ^ buf2;
                buf3 = galois_mul2(buf3);
                cipher[buf4 + 3] = cipher[buf4 + 3] ^ buf3 ^ buf1;
            }
        }

        key[0] = sbox[key[13]] ^ key[0] ^ rcon[round];
        key[1] = sbox[key[14]] ^ key[1];
        key[2] = sbox[key[15]] ^ key[2];
        key[3] = sbox[key[12]] ^ key[3];
        for (i = 4; i < 16; i++)
        {
            key[i] = key[i] ^ key[i - 4];
        }
    }

    for (i = 0; i < 16; i++)
    {
        cipher[i] = cipher[i] ^ key[i];
    }

    uint8_t padding = (cipher[0] >> 4);
    length = AES_CIPHER_SIZE - padding;
    memcpy(data, cipher + padding, length);

    return length;
}