#include <WiFi.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <stdbool.h>
#include <RSA.h>
#include <SHA1.h>
#include <AES128.h>
#include <time.h>

//#define SSID "YA-OPEN"
//#define PASSWORD "utbildning2015"

#define SSID "Telia-ED8AC9"
#define PASSWORD "05162D814F"

#define NUMBER_OF_ATTEMPT (3U)
#define SESSION_ID_SIZE (4U)

#define PORT (12345U)
#define MAX_CLIENTS (8U)
#define BUFFER_SIZE (128U)
#define HASH_SIZE (20U)
#define SESSION_PERIOD (60000)

static uint8_t tx_counter = 0U;
static uint8_t attempt_counter = 0U;

enum client_mes_type
{
    AUTH = 1,
    AES_KEY,
    REQUEST
};

enum server_mes_type
{
    AUTH_OK = 1,
    AES_OK,
    DONE,
    RE_AUTH,
    ERROR,
    RE_DO
};

struct message_info
{
    uint8_t message[RSA_SIZE] = {};
    uint8_t hash_value[HASH_SIZE] = {};
};

struct request_info
{
    uint8_t session_Id[SESSION_ID_SIZE] = {};
    uint8_t request[AES_BLOCK_SIZE] = {};
};

struct session
{
    uint8_t session_Id[SESSION_ID_SIZE] = {};
    //unsigned long long start_session;
    unsigned long long end_session;
};
session client_session;
static void print_data(const uint8_t *data, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}

struct conction_flow
{
    bool _pass = false;
    bool aes_pass = false;
};

static conction_flow status;

//static uint8_t exponent[] ={ 0x00, 0x01, 0x00, 0x01 };
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

const uint8_t *key;

// const uint8_t *key = {};
static WiFiServer server(PORT);
static WiFiClient client_global;
uint8_t hash[HASH_SIZE] = {};
uint8_t auth_key[RSA_BLOCK_SIZE] = "kp2-5v8/B?E(H+VmY3wA";

static request_info request_parsing(uint8_t *message)
{
    Serial.println("I AM ON REQUEST PARSING: ");
    Serial.printf("Recived message lenght is = %d \n", strlen((char *)message));

    request_info temp = {};

    for (uint8_t i = 0; i < SESSION_ID_SIZE; i++)
    {
        temp.session_Id[i] = message[i];
    }
    Serial.println("Session ID is: ");
    print_data(temp.session_Id, sizeof(temp.session_Id));

    for (uint8_t i = SESSION_ID_SIZE; i < SESSION_ID_SIZE + AES_CIPHER_SIZE; i++)
    {
        temp.request[i - SESSION_ID_SIZE] = message[i];
    }
    Serial.println("Reqest is: ");
    print_data(temp.request, sizeof(temp.request));

    return temp;
}


static message_info message_parsing(uint8_t *message)
{
    Serial.println("I AM ON MESSAGE PARSING: ");
    Serial.printf("Recived message lenght is = %d \n", strlen((char *)message));

    message_info temp = {};

    if (strlen((char *)message) == 52)
    {
        for (uint8_t i = 0; i < RSA_SIZE; i++)
        {
            temp.message[i] = message[i];
        }
        Serial.println("Message is: ");
        print_data(temp.message, sizeof(temp.message));

        for (uint8_t i = RSA_SIZE; i < RSA_SIZE + HASH_SIZE; i++)
        {
            temp.hash_value[i - RSA_SIZE] = message[i];
        }
        Serial.println("Hsah is: ");
        print_data(temp.hash_value, sizeof(temp.hash_value));
    }
    if (strlen((char *)message) == 40)
    {
        for (uint8_t i = 0; i < AES_CIPHER_SIZE; i++)
        {
            temp.message[i] = message[i];
        }
        Serial.println("Hash is: ");
        print_data(temp.message, sizeof(temp.message));

        for (uint8_t i = AES_CIPHER_SIZE; i < AES_CIPHER_SIZE + HASH_SIZE; i++)
        {
            temp.hash_value[i - AES_CIPHER_SIZE] = message[i];
        }
        Serial.println("Hsah is: ");
        print_data(temp.hash_value, sizeof(temp.hash_value));
    }
    return temp;
}

static bool check_hash(uint8_t *mes, const uint8_t *hash_res)
{
    Serial.println("I AM ON CHECK HASH: ");

    bool flag = true;
    uint8_t temp_hash[HASH_SIZE] = {};
    sha1(mes, RSA_SIZE, temp_hash);

    Serial.print("New hash is: ");
    print_data(temp_hash, HASH_SIZE);

    Serial.print("Old hash is: ");
    print_data(hash_res, HASH_SIZE);

    for (int i = 0; i < HASH_SIZE; i++)
    {
        if (!(hash_res[i] == temp_hash[i]))
        {
            flag = false;
            break;
        }
    }
    delay(10000);
    return flag;
}

static void build_response(uint8_t *data, uint8_t data_size, uint8_t *buffer)
{
    Serial.println("I AM ON BUILD RESPONSE: ");

    uint8_t hash[HASH_SIZE] = {};

    if (data_size == 20)
    {
        uint8_t encrypted[RSA_SIZE] = {};
        rsa_public_encrypt(data, data_size, public_key_client, encrypted);

        for (tx_counter = 0; tx_counter < RSA_SIZE; tx_counter++)
        {
            buffer[tx_counter] = encrypted[tx_counter];
        }
        // Debug
        Serial.print("Encrypted RSA is: ");
        print_data(encrypted, sizeof(encrypted));

        sha1(encrypted, RSA_SIZE, hash);
        // Debug
        Serial.print("Hash RSA is: ");
        print_data(hash, sizeof(hash));

        for (tx_counter = RSA_SIZE; tx_counter < HASH_SIZE + RSA_SIZE; tx_counter++)
        {
            buffer[tx_counter] = hash[tx_counter - RSA_SIZE];
        }
        buffer[tx_counter] = '\0';
    }
    else
    {
        uint8_t encrypted[AES_CIPHER_SIZE] = {};
        aes128_encrypt(data, data_size, encrypted);

        // Debug
        Serial.print("Encrypt AES is: ");
        print_data(encrypted, sizeof(encrypted));
        for (tx_counter = 0; tx_counter < AES_CIPHER_SIZE; tx_counter++)
        {
            buffer[tx_counter] = encrypted[tx_counter];
        }
        sha1(encrypted, AES_CIPHER_SIZE, hash);

        // Debug
        Serial.print("Hash AES is: ");
        print_data(hash, sizeof(hash));

        for (tx_counter = AES_CIPHER_SIZE; tx_counter < HASH_SIZE + AES_CIPHER_SIZE; tx_counter++)
        {
            buffer[tx_counter] = hash[tx_counter - AES_CIPHER_SIZE];
        }
        buffer[tx_counter] = '\0';
    }
}

static bool check_Auth(const uint8_t *rec_key, const uint8_t *saved_key)
{
    bool flag = true;

    for (uint8_t i = 0; i < RSA_BLOCK_SIZE; i++)
    {
        if (!(saved_key[i] == rec_key[i]))
        {
            flag = false;
            break;
        }
    }
    return flag;
}

static void keys_generater(uint8_t key_holder[], uint8_t key_size)
{
    for (uint8_t i = 0; i < key_size; i++)
    {
        key_holder[i] = random(0xFF);
    }
}

static session session_creater()
{
    session temp;
    keys_generater(temp.session_Id, SESSION_ID_SIZE);
    temp.end_session = millis() + SESSION_PERIOD;
    Serial.printf("\nEnd Session is %llu, In creation \n", temp.end_session);

    return temp;
}

static bool session_check(session ses)
{
    bool flag;
    ;
    if (ses.end_session - millis() <= SESSION_PERIOD)
    {
        flag = true;
    }
    else
    {
        flag = false;
    }
    return flag;
}

void setup()
{

    Serial.begin(9600);
    delay(3000);

    WiFi.begin(SSID, PASSWORD);

    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }

    Serial.print("\nIP Address: ");
    Serial.println(WiFi.localIP());
    pinMode(BUILTIN_LED, OUTPUT);

    server.begin();
}

void loop()
{

    WiFiClient client = server.available();
    if (client)
    {

        if (!client_global.connected())
        {
            client_global = client;
        }
    }

    if (client_global.connected() && client_global.available())
    {
        uint8_t rx_buffer[BUFFER_SIZE] = {};

        client_global.read(rx_buffer, sizeof(rx_buffer));

        uint8_t encrypted_massage_size;
        uint8_t decrypted_massage_size;

        // Error Receiving 1
        if (strlen((char *)rx_buffer))
        {
            message_info message_details;
            request_info request_details;

            Serial.println("Lenght of HASH out Check");
            Serial.println(strlen((char *)message_parsing(rx_buffer).hash_value));

            if (strlen((char *)message_parsing(rx_buffer).hash_value) == HASH_SIZE)
            {
                message_details = message_parsing(rx_buffer);
                Serial.println("Passed Parsing");

                if (strlen((char *)message_parsing(rx_buffer).message) == RSA_SIZE)
                {
                    decrypted_massage_size = RSA_BLOCK_SIZE;
                }
                else
                {
                    decrypted_massage_size = AES_CIPHER_SIZE;
                }

                uint8_t decrypt[decrypted_massage_size] = {};
                if (check_hash(message_details.message, message_details.hash_value))
                {
                    if (encrypted_massage_size == RSA_SIZE)
                    {
                        Serial.print("Will decrypt By RSA:");
                        rsa_public_decrypt(message_details.message, public_key_client, decrypt);
                        if (check_Auth(decrypt, auth_hash_key))
                        {
                            key = aes128_init_key(NULL);
                            Serial.print("AES Key: ");
                            print_data(key, AES_KEY_SIZE);
                            client_session = session_creater();
                            Serial.print("Session ID: ");
                            print_data(client_session.session_Id, SESSION_ID_SIZE);
                            uint8_t temp_message[SESSION_ID_SIZE + AES_KEY_SIZE] = {};
                            strcpy((char *)temp_message, (char *)client_session.session_Id);
                            strcpy((char *)temp_message, (char *)key);

                            build_response(temp_message, sizeof(temp_message), rx_buffer);
                        }
                        else
                        {
                            Serial.println("NOT Auth");
                            build_response((uint8_t *)"NOT Auth", RSA_BLOCK_SIZE, rx_buffer);
                        }
                    }
                    else
                    {
                        Serial.print("Will decrypt By AES:");
                        aes128_decrypt(message_details.message, decrypt);
                        request_details = request_parsing(decrypt);
                        if (check_Auth(client_session.session_Id, request_details.session_Id))
                        {
                            if (session_check(client_session))
                            {
                                Serial.printf("\nEnd Session is %llu, After Check \n", client_session.end_session);
                                client_session.end_session = millis() + SESSION_PERIOD;
                                Serial.printf("\nEnd Session is %llu, After Renew \n", client_session.end_session);
                                switch ((char)request_details.request[0])
                                {
                                case ('1'):
                                    Serial.println("I am in Led ON");
                                    Serial.printf("\nEnd Session is %llu, 1 \n", client_session.end_session);
                                    digitalWrite(BUILTIN_LED, HIGH);
                                    build_response((uint8_t *)"Light ON", sizeof("Light ON"), rx_buffer);
                                    break;

                                case ('2'):

                                    digitalWrite(BUILTIN_LED, LOW);
                                    build_response((uint8_t *)"Light OFF", sizeof("Light OFF"), rx_buffer);
                                    break;

                                case ('3'):
                                    digitalWrite(BUILTIN_LED, HIGH);
                                    build_response((uint8_t *)"Light ON", AES_KEY_SIZE, rx_buffer);
                                    break;

                                case ('4'):
                                {
                                    char temp[6];
                                    float x = temperatureRead();
                                    dtostrf(x, 5, 2, temp);
                                    char messeage[] = "Temperature: ";

                                    build_response((uint8_t *)temp, sizeof(temp), rx_buffer);
                                    strcat(messeage, temp);
                                }
                                break;

                                case ('5'):
                                    digitalWrite(BUILTIN_LED, HIGH);
                                    build_response((uint8_t *)"Light ON", AES_KEY_SIZE, rx_buffer);
                                    break;
                                }
                            }
                        }
                        else
                        {
                            Serial.println("Session End");
                            build_response((uint8_t *)"Session End", AES_KEY_SIZE, rx_buffer);
                        }
                    }
                }
                else
                {
                    Serial.println("Error Receiving3");
                    build_response((uint8_t *)"Error Receiving", AES_KEY_SIZE, rx_buffer);
                }
            }
            else
            {
                Serial.println("Error Receiving2");
                build_response((uint8_t *)"Error Receiving", AES_KEY_SIZE, rx_buffer);
            }
        }
        else
        {
            Serial.println("Error Receiving1");
            build_response((uint8_t *)"Error Receiving", AES_KEY_SIZE, rx_buffer);
        }
        client_global.write((char *)rx_buffer);
        Serial.flush();
    }

}