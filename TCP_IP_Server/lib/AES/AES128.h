/**
 * @file AES128.h
 * @author Faroch Mehri (faroch.mehri@ya.se)
 * @brief A library based on https://www.ti.com/tool/AES-128 to encrypt/decrypt messages using AES-128
 * @version 0.1
 * @date 2020-07-12
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef AES128_H
#define AES128_H

#include <stdint.h>

#define AES_KEY_SIZE (16U)
#define AES_BLOCK_SIZE (15U)
#define AES_CIPHER_SIZE (16U)

/**
 * @brief Initialize the AES-128 key (16 bytes)
 * 
 * @param key The AES-128 key(16 bytes). If key is NULL, a random AES128 key is generated.
 * @return const uint8_t* A pointer to a const which points to the current AES-128 key (16 bytes)
 */
const uint8_t *aes128_init_key(uint8_t key[AES_KEY_SIZE]);

/**
 * @brief This function is used to encrypt data usign AES-128
 * 
 * @param data The data which is supposed to be encrypted.
 * @param data_size Size of the data. It should be at most AES_BLOCK_SIZE bytes.
 * @param cipher The encrypted data, 16 bytes length.
 * @return bool true if the encryption is successful, otherwise false.
 */
bool aes128_encrypt(uint8_t *data, uint8_t data_size, uint8_t cipher[AES_CIPHER_SIZE]);

/**
 * @brief This function is used to decrypt a cipher which is encrypted usign AES-128
 * 
 * @param cipher The encrypted cipher, 16 bytes length.
 * @param data A buffer of at least AES_BLOCK_SIZE bytes for the decrypted data.
 * @return uint8_t Size of the decrypted data.
 */
uint8_t aes128_decrypt(uint8_t cipher[AES_CIPHER_SIZE], uint8_t data[AES_BLOCK_SIZE]);

#endif /* AES128_H */
