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
