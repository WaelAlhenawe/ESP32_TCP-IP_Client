#include <WiFi.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <stdbool.h>
#include <RSA.h>
#include <SHA1.h>
#include <AES128.h>

#define SSID "YA-LOCAL"
#define PASSWORD "utbildning2020"

// #define SSID "Telia-ED8AC9"
// #define PASSWORD "05162D814F"

#define PORT (12345U)
#define BUFFER_SIZE (128U)
#define HASH_SIZE (20U)
#define SESSION_PERIOD (60000U)
#define AUTH_MES_SIZE (84U)
#define AUTH_MES_SIZE_NO_HASH (64U)
#define REQ_MES_SIZE (36U)
#define TYPE_MES_SIZE (2U)
#define NUMBER_OF_ATTEMPT (3U)
#define SESSION_ID_SIZE (3U)

enum request_types
{
    LED_ON = 1,
    LED_OFF,
    TEMPERATURE,
    END_SESSION,
    ERROR
};

enum server_response
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

static WiFiServer server(PORT);
static WiFiClient client_global;
uint8_t hash[HASH_SIZE] = {};
static bool authorized = false;
static uint8_t tx_counter = 0U;
session_t client_session;
const uint8_t *key;

static void print_data(const uint8_t *data, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}

static message_info message_decrypting(message_info message_details, uint8_t mes_len, uint8_t *message)
{

#ifdef DEVELOPMENT
    Serial.println("\n//.....................I AM IN MESSAGE DECRYPTING.....................//\n");
#endif
    message_info decrypted_pieces = message_details;
    if (mes_len == AUTH_MES_SIZE)
    {
#ifdef DEVELOPMENT
        Serial.println("I AM ON AUTHENTICATION DECRYPTING: ");
        Serial.println("Will decrypt By RSA:");
#endif
        uint8_t first_part[RSA_SIZE], second_part[RSA_SIZE], decrypt_first_part[RSA_SIZE],
            decrypt_second_part[RSA_SIZE - RSA_BLOCK_SIZE], encrypt_secret[RSA_SIZE], *temp;

        memcpy(first_part, message, RSA_SIZE);
        memcpy(second_part, &*message + RSA_SIZE, RSA_SIZE);

        rsa_private_decrypt(first_part, public_key, private_key, decrypt_first_part);
        rsa_private_decrypt(second_part, public_key, private_key, decrypt_second_part);

        memcpy(encrypt_secret, decrypt_first_part, RSA_BLOCK_SIZE);
        temp = &*encrypt_secret + RSA_BLOCK_SIZE;
        memcpy(temp, decrypt_second_part, RSA_SIZE - RSA_BLOCK_SIZE);

#ifdef DEVELOPMENT
        Serial.print("First Decrypt part is: ");
        print_data(decrypt_first_part, RSA_BLOCK_SIZE);
        Serial.print("Second Decrypt part is: ");
        print_data(decrypt_second_part, RSA_SIZE - RSA_BLOCK_SIZE);
        Serial.print("The Secret is: ");
        print_data(encrypt_secret, RSA_SIZE);
#endif
        rsa_public_decrypt(encrypt_secret, public_key_client, decrypted_pieces.the_secret);
#ifdef DEVELOPMENT
        Serial.print("The Hash of ID is: ");
        print_data(decrypted_pieces.the_secret, HASH_SIZE);
#endif
    }
    if (mes_len == REQ_MES_SIZE)
    {
#ifdef DEVELOPMENT
        Serial.println("I AM ON REQUEST PARSING: ");
        Serial.println("Will decrypt By AES:");
#endif
        uint8_t request[AES_CIPHER_SIZE], decrypt_request[AES_BLOCK_SIZE];

        memcpy(request, message, AES_CIPHER_SIZE);

        aes128_decrypt(request, decrypt_request);
        memcpy(decrypted_pieces.session_Id, decrypt_request, SESSION_ID_SIZE);
        memcpy(decrypted_pieces.request, &*decrypt_request + SESSION_ID_SIZE, AES_BLOCK_SIZE - SESSION_ID_SIZE);
#ifdef DEVELOPMENT
        Serial.println("Session ID is: ");
        print_data(decrypted_pieces.session_Id, SESSION_ID_SIZE);
        Serial.printf("Request type is: %c\n", decrypted_pieces.request[0]);
#endif
    }
    return decrypted_pieces;
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

static uint8_t build_response(uint8_t mes_len, uint8_t *data, uint8_t data_size, uint8_t *buffer)
{
#ifdef DEVELOPMENT
    Serial.println("\n//.......................I AM IN BUILD RESPONSE.......................//\n");
#endif
    uint8_t hash[HASH_SIZE] = {};
    uint8_t encryption_size, *encrypted_data, counter;

    if (mes_len == AUTH_MES_SIZE)
    {
        encryption_size = RSA_SIZE;
        encrypted_data = (uint8_t *)malloc(encryption_size);
        rsa_public_encrypt(data, data_size, public_key_client, encrypted_data);
        counter = (AUTH_MES_SIZE - RSA_SIZE);
    }
    if (mes_len == REQ_MES_SIZE)
    {
        encryption_size = AES_CIPHER_SIZE;
        encrypted_data = (uint8_t *)malloc(encryption_size);
        aes128_encrypt(data, data_size, encrypted_data);
        counter = REQ_MES_SIZE;
    }
    memcpy(buffer, encrypted_data, encryption_size);

#ifdef DEVELOPMENT
    Serial.print("Encryption is: ");
    print_data(encrypted_data, encryption_size);
#endif

    sha1(encrypted_data, encryption_size, hash);

#ifdef DEVELOPMENT
    Serial.print("Hash is: ");
    print_data(hash, sizeof(hash));
#endif
    memcpy(&*buffer + encryption_size, hash, HASH_SIZE);
#ifdef DEVELOPMENT
    Serial.print("rx_buffer inside 2 is: ");
    print_data(buffer, RSA_SIZE + HASH_SIZE);
#endif
    free(encrypted_data);
    return counter;
}

static void Session_Id_generater(uint8_t key_holder[], uint8_t key_size)
{
    for (uint8_t i = 0; i < key_size; i++)
    {
        key_holder[i] = random(0xFF);
    }
}

static session_t session_creater()
{
    session_t temp;
    Session_Id_generater(temp.session_Id, SESSION_ID_SIZE);
    temp.end_session = millis() + SESSION_PERIOD;

#ifdef DEVELOPMENT
    Serial.printf("\nEnd Session is %d, In creation \n", temp.end_session);
#endif

    return temp;
}

static bool session_check(session_t ses)
{
    bool flag;
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
    Serial.printf("Message Lenght is: %d\n",(int) mes_len);
#endif
    return mes_len;
}

static void join_message(server_response type, uint8_t *message, uint8_t *buffer)
{
    buffer[0] = type;
    memcpy(&*buffer + 1, message, strlen((char *)message));
    buffer[strlen((char *)message) + 1] = '\0';

#ifdef DEVELOPMENT
    Serial.print("Joined Message is:");
    print_data(buffer, strlen((char *)message) + 1);
#endif
}

static void renew_session(uint8_t  session_end_time){
#ifdef DEVELOPMENT
                            Serial.printf("\nEnd Session is %d, After Check \n", client_session.end_session);
                            Serial.printf("\nMillis is %lu, After Check \n", millis());

#endif
                            session_end_time = millis() + SESSION_PERIOD;

#ifdef DEVELOPMENT
                            Serial.printf("\nEnd Session is %d, After Renew \n", client_session.end_session);

#endif

}
void setup()
{
    Serial.begin(9600);
    while (!Serial)
    {
        delay(100);
    }

    // WiFi.begin(SSID, PASSWORD);

    // while (WiFi.status() != WL_CONNECTED)
    // {
    //      delay(500);
    //      Serial.print(".");
    // }
    while (WL_CONNECTED != WiFi.status())
    {
        delay(1000);
        WiFi.begin(SSID, PASSWORD);
        Serial.print(".");
    }
    Serial.print("\nIP Address: ");
    Serial.println(WiFi.localIP());
    pinMode(BUILTIN_LED, OUTPUT);
    server.begin();
}

void loop()
{
    uint8_t rx_buffer[BUFFER_SIZE] = {};

    WiFiClient client = server.available();

    if (client)
    {
        client_global = client;
    }

    if (client_global.connected() && client_global.available())
    {
        client_global.read(rx_buffer, BUFFER_SIZE);
        message_info message_details;
        uint8_t mes_len;
        if ((mes_len = check_mes_len(rx_buffer)))
        {
#ifdef DEVELOPMENT
        Serial.print("Read Buffer is : ");
        print_data(rx_buffer, mes_len);
#endif
            if (check_hash(mes_len, rx_buffer))
            {
                message_details = message_decrypting(message_details, mes_len, rx_buffer);
                if (mes_len == AUTH_MES_SIZE)
                {
                    if (!memcmp(message_details.the_secret, auth_hash_key, HASH_SIZE))
                    {
                        key = aes128_init_key(NULL);
                        client_session = session_creater();

#ifdef DEVELOPMENT
                        Serial.print("AES Key: ");
                        print_data(key, AES_KEY_SIZE);
                        Serial.print("Session ID: ");
                        print_data(client_session.session_Id, SESSION_ID_SIZE);
#endif

                        uint8_t temp_message[SESSION_ID_SIZE + AES_KEY_SIZE] = {};
                        memcpy_P(temp_message, client_session.session_Id, SESSION_ID_SIZE);
                        memcpy_P(&*temp_message + SESSION_ID_SIZE, key, AES_KEY_SIZE);

#ifdef DEVELOPMENT
                        Serial.println("Temp Message is: ");
                        print_data(temp_message, SESSION_ID_SIZE + AES_KEY_SIZE);
#endif

                        tx_counter = build_response(mes_len, temp_message, sizeof(temp_message), rx_buffer);
                        authorized = true;
                    }
                    else
                    {
                        Serial.println("NOT Auth");
                        join_message(server_response(NOT_AUTH), (uint8_t *)"NOT Auth", rx_buffer);
                        tx_counter = build_response(mes_len, rx_buffer, sizeof("NOT Auth") + 1, rx_buffer);
                    }
                }
                else if (mes_len == REQ_MES_SIZE)
                {

                    if (!memcmp(client_session.session_Id, message_details.session_Id, SESSION_ID_SIZE))
                    {
                        if (session_check(client_session))
                        {

                            renew_session(client_session.end_session);
                            switch ((char)message_details.request[0])
                            {
                            case ('1'):

#ifdef DEVELOPMENT
                                Serial.println("I am in Led ON");
                                Serial.printf("\nEnd Session is %d, 1 \n", client_session.end_session);
#endif

                                digitalWrite(BUILTIN_LED, HIGH);
                                join_message(server_response(OK), (uint8_t *)"Light ON", rx_buffer);
                                tx_counter = build_response(mes_len, rx_buffer, sizeof("Light ON") + 1, rx_buffer);
                                break;

                            case ('2'):

                                digitalWrite(BUILTIN_LED, LOW);
                                join_message(server_response(OK), (uint8_t *)"Light OFF", rx_buffer);
                                tx_counter = build_response(mes_len, rx_buffer, sizeof("Light OFF") + 1, rx_buffer);
                                break;

                            case ('3'):
                            {
                                char temp[6];
                                float x = temperatureRead();
                                dtostrf(x, 5, 2, temp);
                                join_message(server_response(OK), (uint8_t *)temp, rx_buffer);
                                tx_counter = build_response(mes_len, rx_buffer, sizeof(temp) + 1, rx_buffer);
                            }
                            break;

                            case ('4'):
                                client_session.end_session -= SESSION_PERIOD;
                                join_message(server_response(OK), (uint8_t *)"Session Ended", rx_buffer);
                                tx_counter = build_response(mes_len, rx_buffer, sizeof("Session Ended") + 1, rx_buffer);
                                break;
                            }
                        }
                        else
                        {
                            Serial.println("Session End");
                            join_message(server_response(SESSION_END), (uint8_t *)"Session End", rx_buffer);
                            tx_counter = build_response(mes_len, rx_buffer, sizeof("Session End") + 1, rx_buffer);
                        }
                    }
                }
                else
                {
                    Serial.println("ELSE!!!!!!!!!!!!");
                    // if (mes_len == AUTH_MES_SIZE){
                    // {
                    // }
                    // else if (mes_len == REQ_MES_SIZE)
                    // {
                    // }
                    // else
                    // {
                    //     build_response
                    // }
                }
            }
        }
        else
        {
            Serial.println("Error Receiving2");
            tx_counter = build_response(mes_len, (uint8_t *)server_response(NOT_RESEIVED), sizeof((uint8_t *)server_response(NOT_RESEIVED)), rx_buffer);
        }
#ifdef DEVELOPMENT
        Serial.print("rx_buffer outside is: ");
        print_data((uint8_t *)rx_buffer, BUFFER_SIZE);
#endif
        client_global.write_P((char *)rx_buffer, tx_counter);
        //client_global.write((char *)rx_buffer);
        memset(rx_buffer, 0, BUFFER_SIZE);
    }

    //delay(7000);
}