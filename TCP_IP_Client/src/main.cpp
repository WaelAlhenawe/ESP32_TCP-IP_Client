#include <WiFi.h>
#include <Arduino.h>
#include <esp32-hal.h>
#include <IPAddress.h>
#include <WiFiClient.h>

#include <RSA.h>
#include <SHA1.h>
#include <AES128.h>

#define SSID "YA-LOCAL"
#define PASSWORD "utbildning2020"

// #define SSID "Telia-ED8AC9"
// #define PASSWORD "05162D814F"

#define SERVER "192.168.0.116"

#define PORT (12345U)

#define HASH_SIZE (20U)
#define BUFFER_SIZE (128U)
#define SESSION_ID_SIZE (3U)
#define SESSION_PERIOD (60000U)
#define AES_MES_SIZE (52U)
#define RES_MES_SIZE (36U)
#define NUMBER_OF_ATTEMPT (3U)

// The keys are generated by https://csfieldguide.org.nz/en/interactives/rsa-key-generator/

static uint8_t client_public_key[RSA_SIZE] = {
    0xDB, 0x44, 0xDD, 0xA4, 0xB7, 0xAB, 0x9D, 0x86, 0x2B, 0xBD, 0xC1, 0xFD, 0x67, 0xC9, 0x0B, 0xAF,
    0x05, 0x76, 0x3E, 0x4E, 0xD3, 0xD1, 0xDF, 0x9B, 0x7A, 0x75, 0x6E, 0x4C, 0x5F, 0x63, 0x63, 0x75};
static uint8_t client_private_key[RSA_SIZE] = {
    0x5B, 0xF4, 0x39, 0x6F, 0x46, 0x87, 0x75, 0xFC, 0x3A, 0x83, 0xCD, 0xC2, 0xD3, 0xAF, 0x80, 0x72,
    0x12, 0x98, 0x99, 0x0E, 0x0F, 0x43, 0xA2, 0x7B, 0x47, 0xB1, 0x3C, 0x23, 0xC9, 0x99, 0x64, 0x81};
static uint8_t public_key_server[RSA_SIZE] = {
    0xC3, 0xA5, 0x4E, 0x87, 0xAD, 0xC6, 0xA4, 0x02, 0x11, 0x0B, 0xF2, 0x75, 0xE3, 0xB6, 0x6D, 0xE6,
    0x55, 0xA0, 0x17, 0x60, 0x16, 0xC2, 0x12, 0x58, 0xA9, 0xC6, 0xF5, 0x91, 0xCD, 0xB7, 0xA7, 0xA9};

static bool authorized = false;

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

//static uint8_t client_public_key[RSA_SIZE] ={};
//static uint8_t client_private_key[RSA_SIZE] ={};
static WiFiClient client;
static uint8_t tx_counter = 0U;
static char tx_buffer[BUFFER_SIZE] = {};
static response_info message_details = {};
char menu_choice = ' ';
uint8_t rx_buffer[BUFFER_SIZE] = {};
uint8_t auth_key[RSA_BLOCK_SIZE] = "kp2-5v8/B?E(H+VmY3wA";
// const uint8_t *key = {};

// To print data in hex
static void print_data(const uint8_t *data, uint8_t size)
{
  for (uint8_t i = 0; i < size; i++)
  {
    Serial.printf("%02X ", data[i]);
  }
  Serial.println();
}

static char services_menu()
{
  bool menu_apper = true, ok = true, get_it = false;
  char chr = '0';

  while (ok)
  {
    while (menu_apper)
    {
      menu_apper = false;
      get_it = false;

      Serial.println("------------------------------");
      Serial.println("Please Choose Type Of Service.");
      Serial.println("------------------------------");
      Serial.println("(0) For Authentication.");
      Serial.println("(1) For Set Light ON.");
      Serial.println("(2) For Set Light OFF.");
      Serial.println("(3) For Get Light Status.");
      Serial.println("(4) For Get Server Temperature.");
      Serial.println("(5) For End Session.");
      Serial.print("Your Choice: ");
    }

    while (!get_it)
    {
      if (Serial.available())
      {
        chr = Serial.read();

        Serial.println(chr);

        if (chr == '0' || chr == '1' || chr == '2' || chr == '3' || chr == '4' || chr == '5')
        {
          get_it = true;
          ok = false;
        }
        else
        {
          Serial.println("PLEASE ENTER RIGHT CHOICE");
          get_it = true;
          menu_apper = true;
        }
      }
    }
  }
  return chr;
}

static response_info message_parsing(response_info old_decrypted_details, uint8_t mes_len, uint8_t *message)
{
#ifdef DEVELOPMENT
  Serial.println("I AM ON MESSAGE PARSING: ");
  Serial.printf("\nMes_Len is: %d\n", mes_len);
  Serial.print("The Whole Message is: ");
  print_data(message, mes_len);

#endif
  response_info decrypted_details = old_decrypted_details;
  uint8_t decrypting_size, *decrypted_data;

  if (mes_len == AES_MES_SIZE)
  {
    uint8_t temp_aes_key[AES_KEY_SIZE]={};
    decrypting_size = RSA_BLOCK_SIZE;
    decrypted_data = (uint8_t *)malloc(decrypting_size);
    rsa_private_decrypt(message, client_public_key, client_private_key, decrypted_data);
    memcpy(decrypted_details.session_Id, decrypted_data, SESSION_ID_SIZE);
    memcpy(temp_aes_key, &*decrypted_data + SESSION_ID_SIZE, AES_KEY_SIZE);
    aes128_init_key(temp_aes_key);
#ifdef DEVELOPMENT
    Serial.print("Session ID is: ");
    print_data(decrypted_details.session_Id, SESSION_ID_SIZE);
    Serial.print("AES key is: ");
    print_data(temp_aes_key, AES_KEY_SIZE);
#endif
    free(decrypted_data);
  }
  if (mes_len == RES_MES_SIZE)
  {
    decrypting_size = AES_BLOCK_SIZE;
    decrypted_data = (uint8_t *)malloc(decrypting_size);
    aes128_decrypt(message, decrypted_data);
    decrypted_details.type = (receiving_types)decrypted_data[0];
    memcpy(decrypted_details.message, &*decrypted_data + 1, AES_BLOCK_SIZE);

#ifdef DEVELOPMENT
    Serial.printf("\nResponse type is: %d\n", (int)decrypted_details.type);
    Serial.printf("\nResponse Message is: %s\n", decrypted_details.message);
#endif
    free(decrypted_data);
  }
  return decrypted_details;
}

static bool check_hash(uint8_t mes_len, uint8_t *the_whole_message)
{
#ifdef DEVELOPMENT
    Serial.println("\n//.........................I AM IN HASH CHECK.........................//\n");
#endif

    uint8_t the_mes[mes_len - HASH_SIZE], res_hash[HASH_SIZE], temp_hash[HASH_SIZE];

    memcpy(the_mes, the_whole_message, mes_len - HASH_SIZE);

    memcpy(res_hash, &*the_whole_message + (mes_len - HASH_SIZE), HASH_SIZE);

    sha1(the_mes, mes_len - HASH_SIZE, temp_hash);
#ifdef DEVELOPMENT
    Serial.print("Received Hash is:   ");
    print_data(res_hash, HASH_SIZE);
    Serial.print("Calculated Hash is: ");
    print_data(temp_hash, HASH_SIZE);
#endif
    if (!memcmp(temp_hash, res_hash, HASH_SIZE))
    {
        return true;
        ;
    }
    else
    {
        return false;
    }
}

static void build_request(const uint8_t *session_id, sending_types request, char *buffer)
{
  uint8_t hash[HASH_SIZE] = {};
  Serial.println("I AM ON BUILD : ");
  uint8_t *full_mes, *encrypted_mes;
  full_mes = (uint8_t *)malloc(SESSION_ID_SIZE + 1);
  encrypted_mes = (uint8_t *)malloc(AES_CIPHER_SIZE);
  Serial.printf("ID is:");
  print_data(session_id, SESSION_ID_SIZE);
  memcpy_P(full_mes, session_id, SESSION_ID_SIZE);
  full_mes[SESSION_ID_SIZE] = request;

  aes128_encrypt(full_mes, SESSION_ID_SIZE + 1, encrypted_mes);
  Serial.printf("Encrypted Mes is:");
  print_data(encrypted_mes, AES_CIPHER_SIZE);
  sha1(encrypted_mes, AES_CIPHER_SIZE, hash);

#ifdef DEVELOPMENT
  Serial.print("Hash builded is: ");
  print_data(hash, sizeof(hash));
#endif

  memcpy(buffer, encrypted_mes, AES_CIPHER_SIZE);
  memcpy(&*buffer + AES_CIPHER_SIZE, hash, HASH_SIZE);
  free(full_mes);
  free(encrypted_mes);
}

static void authorization()
{
  uint8_t auth_hash[HASH_SIZE] = {};
  sha1(auth_key, RSA_BLOCK_SIZE, auth_hash);
  Serial.print("First hash is: ");
  print_data((uint8_t *)auth_hash, HASH_SIZE);

  uint8_t sign_auth[RSA_SIZE] = {};
  rsa_private_encrypt(auth_hash, HASH_SIZE, client_public_key, client_private_key, sign_auth);
  Serial.println("Sign  is: ");
  print_data(sign_auth, RSA_SIZE);
  uint8_t sign_first_part[RSA_BLOCK_SIZE] = {};
  uint8_t sign_second_part[RSA_SIZE - RSA_BLOCK_SIZE] = {};

  for (uint8_t i = 0; i < RSA_BLOCK_SIZE; i++)
  {
    sign_first_part[i] = sign_auth[i];
  }
  for (uint8_t i = RSA_BLOCK_SIZE; i < RSA_SIZE; i++)
  {
    sign_second_part[i - RSA_BLOCK_SIZE] = sign_auth[i];
  }

  Serial.println("Second part is: ");
  print_data(sign_second_part, RSA_SIZE - RSA_BLOCK_SIZE);
  uint8_t en_sign_first_part[RSA_SIZE] = {};
  uint8_t en_sign_second_part[RSA_SIZE] = {};

  rsa_public_encrypt(sign_first_part, RSA_BLOCK_SIZE, public_key_server, en_sign_first_part);
  rsa_public_encrypt(sign_second_part, RSA_SIZE - RSA_BLOCK_SIZE, public_key_server, en_sign_second_part);

  for (tx_counter = 0; tx_counter < RSA_SIZE; tx_counter++)
  {
    tx_buffer[tx_counter] = en_sign_first_part[tx_counter];
  }

  for (; tx_counter < (RSA_SIZE * 2); tx_counter++)
  {
    tx_buffer[tx_counter] = en_sign_second_part[tx_counter - RSA_SIZE];
  }

  uint8_t auth_hash_hash[HASH_SIZE] = {};
  sha1((uint8_t *)tx_buffer, (RSA_SIZE * 2), auth_hash_hash);
  for (tx_counter = tx_counter; tx_counter < (RSA_SIZE * 2) + HASH_SIZE; tx_counter++)
  {
    tx_buffer[tx_counter] = auth_hash_hash[tx_counter - (RSA_SIZE * 2)];
  }
  Serial.print("The whole message is: ");
  print_data((uint8_t *)tx_buffer, tx_counter);
}

static uint8_t check_mes_len(uint8_t *mes)
{
#ifdef DEVELOPMENT
    Serial.println("\n//...................I AM IN CHECKING MESSAGE LENGHT..................//\n");
#endif
  uint8_t mes_len = 0, counter = 0;

  for (uint8_t i = 0; i < BUFFER_SIZE; i++)
  {
    if (mes[i] == (0x00))
    {
      if (counter < 3)
      {
        if (counter == 0)
        {
          mes_len = i;
        }
        counter++;
      }
      else
      {
        break;
      }
    }
    else
    {
      counter = 0;
    }
  }
#ifdef DEVELOPMENT
    Serial.printf("Message Lenght is: %d\n", (int) mes_len);
#endif
  return mes_len;
}

void setup()
{
  Serial.begin(9600);
  while (!Serial)
  {
    delay(100);
  }
  while (WL_CONNECTED != WiFi.begin(SSID, PASSWORD))
  {
    delay(4000);
    Serial.print(".");
  }

  Serial.print("\nIP Address: ");
  Serial.println(WiFi.localIP());
}

void loop()
{
  if (!authorized)
  {
    while (menu_choice != '0')
    {
      menu_choice = services_menu();
      if (menu_choice != '0')
      {
        Serial.println("You need to be Authorized first.");
      }
    }
    authorization();
  }
  if (authorized)
  {
    Serial.println("I am on REQUEST");
    Serial.println(menu_choice);
    while (menu_choice == '0')
    {
      menu_choice = services_menu();
      if (menu_choice == '0')
      {
        Serial.println("You are already Authorized, Please choose one of the services.");
      }
    }

    build_request(message_details.session_Id, (sending_types)menu_choice, tx_buffer);
    print_data(message_details.session_Id, SESSION_ID_SIZE);
    tx_counter = RES_MES_SIZE;
  }

  client.connect(SERVER, PORT);

  if (client.connected())
  {
    client.write_P(tx_buffer, tx_counter);
    delay(2500);

    if (client.connected())
    {
      client.read((uint8_t *)rx_buffer, (size_t)sizeof(rx_buffer));
      uint8_t mes_len;
      if ((mes_len = check_mes_len(rx_buffer)))
      {
#ifdef DEVELOPMENT
      Serial.print("rx_buffer readed is: ");
      print_data(rx_buffer, mes_len);
#endif
        if (check_hash(mes_len, rx_buffer))
        {
          message_details = message_parsing(message_details, mes_len, rx_buffer);
          if (mes_len == AES_MES_SIZE)
          {
            authorized = true;
          }
          if (mes_len == RES_MES_SIZE)
          {
            switch (message_details.type)
            {
            case (receiving_types(NOT_RESEIVED)):
              Serial.print("The encrypted res massage is: ");
              Serial.println((char *)message_details.message);
              break;

            case (receiving_types(NOT_AUTH)):
              Serial.print("Auth Error: ");
              Serial.println((char *)message_details.message);
              authorized = false;
              break;

            case (receiving_types(SESSION_END)):
              Serial.print("Seesion END: ");
              Serial.println((char *)message_details.message);
              authorized = false;
              break;

            case (receiving_types(REQUEST_DONE)):
              Serial.print("The massage is: ");
              Serial.println((char *)message_details.message);
              break;
            }
          }
        }
        else
        {
        }
      }
      else
      {
        Serial.printf("\nServer Error!!!\nReauthenticate...\n");
        delay(2000);
        authorized = false;
      }
    }
    else
    {
      client.stop();
      client.connect(SERVER, PORT);
    }
  }
  else
  {
    client.stop();
    Serial.print(".");
  }
  tx_counter = 0;
  menu_choice = '0';
  memset(tx_buffer, 0, BUFFER_SIZE);
  memset(rx_buffer, 0, BUFFER_SIZE);
}
