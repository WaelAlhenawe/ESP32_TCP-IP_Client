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
 * @param data data which is suppose to be print in Hex
 * @param size  size of the data
 */
void print_data(const uint8_t *data, uint8_t size);

/**
 * @brief Message decryption based on RSA(authentication) and AES(requesting)
 * @param mes_len  length of the received message from client
 * @param message  message is the received buffer
 * @return it will return a struct of type message_info. If the decryption is based on RSA it will fill 
 * (the_secret)memeber of the struct, and it fill (session_id and request) members of the struct if its 
 * the decryption is based on AES 
 */
message_info message_decrypting(uint8_t mes_len, uint8_t *message);

/**
 * @brief checking the received hash and hash which is calculated for encrypted data are same
 * @param mes_len  length of the received message from client
 * @param the_whole_message is the received buffer
 * @return  boolen value 
 */
bool check_hash(uint8_t mes_len, uint8_t *the_whole_message);


/**
 * @brief Build the response message to the client
 * @param mes_len  length of the received message from client
 * @param data which is supposed to be encrypted
 * @param data_size size of the data
 * @param buffer  in which encrypted data and hash value are stored.
 * @return  uint8_t which is size of the encrypted data and hash size(the whole message)
 */
uint8_t build_response(uint8_t mes_len, uint8_t *data, uint8_t data_size, uint8_t *buffer);

/**
 * @brief creating Session id and Session end time for the session and stored in a struct sesstion_t
 * @return Struct session_t
 */
session_t session_creater();

/**
 * @brief Generating the AES key and copy it with the session id to the buffer
 * @param session Struct session_t
 * @param buffer  which is suppose to be store AES key and session id  
 */
void providing_aes_session(session_t session, uint8_t *buffer);

/**
 * @brief checking whether the session exceeds one minute or not.
 * @param ses as struct holding current session id and end session time
 * @return boolean value 
 */
bool session_check(session_t ses);

/**
 * @brief This function is used to check the message length of the received buffer from client
 * @param mes which is holding the received buffer.
 * @return uint8_t length of the received buffer.
 */
uint8_t check_mes_len(uint8_t *mes);

/**
 * @brief This function is used to Joined the parts to make a Message before encryption.
 * @param type as a enum receiving_types  which is supposed to be send to client as a response
 * @param message which holding original message 
 * @param buffer which holding both receiving_types and original message.
 */
void join_message(receiving_types type, uint8_t *message, uint8_t *buffer);

/**
 * @brief This function is used to renew the current session time if session time does not exceeds one minute.
 * @param session_end_time is end_session (struct session_t )
 */
void renew_session(uint32_t session_end_time);

/**
 * @brief This function is used to handle the client request and return tx counter of the sending buffer.
 * @param session_end_time is end session time
 * @param mes_len   length of the received message(buffer) from client
 * @param request (enum sending_types) 
 * @param buffer which will holds the  encrypted data and hash value.
 * @return uint8_t tx_counter of the buffer
 */
uint8_t handler_request(uint32_t * session_end_time, uint8_t mes_len, sending_types request, uint8_t * buffer);

#endif /* SERVER_H */
