/**
 * @file SHA1.h
 * @author Faroch Mehri (faroch.mehri@ya.se)
 * @brief A library based on https://github.com/mr-glt/Arduino-SHA-1-Hash.git to hash messages usign SHA-1
 * @version 0.1
 * @date 2020-07-12
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

#define HASH_SIZE (20U)

/**
 * @brief This function calculates the hash value of data using SHA-1
 * 
 * @param data A pointer to the data
 * @param data_size Size of the data in bytes
 * @param hash The array of the hash. The size of this array should be 20
 */
void sha1(uint8_t *data, uint32_t data_size, uint8_t hash[HASH_SIZE]);

#endif /* SHA1_H */
