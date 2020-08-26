#ifndef SERVER_H
#define SERVER_H


#include <WiFi.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <stdbool.h>
#include <RSA.h>
#include <SHA1.h>
#include <AES128.h>



#define PORT (12345U)
#define BUFFER_SIZE (128U)
#define HASH_SIZE (20U)
#define SESSION_PERIOD (60000U)
#define AUTH_MES_SIZE (84U)
#define REQ_MES_SIZE (36U)
#define SESSION_ID_SIZE (3U)

enum sending_types
{
    LED_ON = 1,
    LED_OFF,
    LED_STATUS,
    TEMPERATURE,
    END_SESSION,
    ERROR
};

enum receiving_types
{
    REQUEST_DONE = 0,
    NOT_RESEIVED,
    NOT_AUTH,
    SESSION_END,
};

typedef struct
{
    uint8_t the_secret[HASH_SIZE] = {};
    uint8_t session_Id[SESSION_ID_SIZE] = {};
    uint8_t request[AES_BLOCK_SIZE - SESSION_ID_SIZE] = {};
} message_info;

typedef struct
{
    uint8_t session_Id[SESSION_ID_SIZE] = {};
    uint32_t end_session;
} session_t;


static uint8_t auth_hash_key[HASH_SIZE] = {
    0x6E, 0x31, 0x2B, 0x1F, 0xAC, 0x84, 0xB7, 0x9C, 0x56, 0x3F,
    0x3E, 0xE8, 0x98, 0x29, 0xC0, 0x0C, 0xEC, 0xB3, 0xEE, 0xBD};
static uint8_t public_key[RSA_SIZE] = {
    0xC3, 0xA5, 0x4E, 0x87, 0xAD, 0xC6, 0xA4, 0x02, 0x11, 0x0B, 0xF2, 0x75, 0xE3, 0xB6, 0x6D, 0xE6,
    0x55, 0xA0, 0x17, 0x60, 0x16, 0xC2, 0x12, 0x58, 0xA9, 0xC6, 0xF5, 0x91, 0xCD, 0xB7, 0xA7, 0xA9};
static uint8_t private_key[RSA_SIZE] = {
    0x56, 0x29, 0x30, 0xE2, 0x73, 0xD7, 0x6D, 0x57, 0x33, 0xA6, 0xAD, 0x4A, 0xD9, 0xD3, 0xF7, 0xA5,
    0x98, 0xF3, 0xFA, 0x07, 0x64, 0x7D, 0xE5, 0xE4, 0x4B, 0x13, 0x5C, 0x90, 0x38, 0xF4, 0x3B, 0x59};
static uint8_t public_key_client[RSA_SIZE] = {
    0xDB, 0x44, 0xDD, 0xA4, 0xB7, 0xAB, 0x9D, 0x86, 0x2B, 0xBD, 0xC1, 0xFD, 0x67, 0xC9, 0x0B, 0xAF,
    0x05, 0x76, 0x3E, 0x4E, 0xD3, 0xD1, 0xDF, 0x9B, 0x7A, 0x75, 0x6E, 0x4C, 0x5F, 0x63, 0x63, 0x75};

/**
 * @brief Print data in hex
 * 
 * @param data data which is suppose to be print in Hex
 * @param size  size of the data
 */
void print_data(const uint8_t *data, uint8_t size);

/**
 * @brief Print data in hex
 * 
 * @param message_details data which is suppose to be print in Hex
 * @param mes_len  size of the data
 * @param message
 * @return 
 */
message_info message_decrypting(message_info message_details, uint8_t mes_len, uint8_t *message);

/**
 * @brief Print data in hex
 * 
 * @param message_details data which is suppose to be print in Hex
 * @param mes_len  size of the data
 * @param message
 * @return 
 */
bool check_hash(uint8_t mes_len, uint8_t *the_whole_message);

uint8_t build_response(uint8_t mes_len, uint8_t *data, uint8_t data_size, uint8_t *buffer);

session_t session_creater();

void providing_aes_session(session_t session, uint8_t *buffer);

bool session_check(session_t ses);

uint8_t check_mes_len(uint8_t *mes);

void join_message(receiving_types type, uint8_t *message, uint8_t *buffer);

void renew_session(uint32_t session_end_time);

uint8_t handler_request(uint32_t * session_end_time, uint8_t mes_len, sending_types request, uint8_t * buffer);

#endif /* SERVER_H */
