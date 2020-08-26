#ifndef CLIENT_H
#define CLIENT_H

#include <WiFi.h>
#include <Arduino.h>
#include <esp32-hal.h>
#include <IPAddress.h>
#include <WiFiClient.h>
#include <RSA.h>
#include <SHA1.h>
#include <AES128.h>

#define SERVER "192.168.1.69"

#define PORT (12345U)

#define HASH_SIZE (20U)
#define BUFFER_SIZE (128U)
#define SESSION_ID_SIZE (3U)
#define SESSION_PERIOD (60000U)
#define AUTH_MES_SIZE (84U)
#define RSA_MES_SIZE (52U)
#define REQUEST_MES_SIZE (36U)

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

struct response_info
{
  uint8_t session_Id[SESSION_ID_SIZE] = {};
  uint8_t message[AES_BLOCK_SIZE - 1];
  receiving_types type;
};

void print_data(const uint8_t *data, uint8_t size);

char services_menu();

response_info message_parsing(response_info old_decrypted_details, uint8_t mes_len, uint8_t *message);

bool check_hash(uint8_t mes_len, uint8_t *the_whole_message);

void build_request(const uint8_t *session_id, sending_types request, char *buffer);

void authorization(uint8_t * buffer);

uint8_t check_mes_len(uint8_t *mes);




#endif /* SERVER_H */
