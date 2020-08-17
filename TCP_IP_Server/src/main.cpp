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
#define SESSION_PERIOD (60)

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

struct req_info
{
    client_mes_type key;
    uint8_t message[RSA_SIZE] = {};
    uint8_t hash_value[HASH_SIZE] = {};
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

//static uint8_t exponent[] ={ 0x00, 0x01, 0x00, 0x01 };
static uint8_t public_key[RSA_SIZE] = {
    0xC3, 0xA5, 0x4E, 0x87, 0xAD, 0xC6, 0xA4, 0x02, 0x11, 0x0B, 0xF2, 0x75, 0xE3, 0xB6, 0x6D, 0xE6,
    0x55, 0xA0, 0x17, 0x60, 0x16, 0xC2, 0x12, 0x58, 0xA9, 0xC6, 0xF5, 0x91, 0xCD, 0xB7, 0xA7, 0xA9};
static uint8_t private_key[RSA_SIZE] = {
    0x56, 0x29, 0x30, 0xE2, 0x73, 0xD7, 0x6D, 0x57, 0x33, 0xA6, 0xAD, 0x4A, 0xD9, 0xD3, 0xF7, 0xA5,
    0x98, 0xF3, 0xFA, 0x07, 0x64, 0x7D, 0xE5, 0xE4, 0x4B, 0x13, 0x5C, 0x90, 0x38, 0xF4, 0x3B, 0x59};
static uint8_t public_key_client[RSA_SIZE] = {
    0xDB, 0x44, 0xDD, 0xA4, 0xB7, 0xAB, 0x9D, 0x86, 0x2B, 0xBD, 0xC1, 0xFD, 0x67, 0xC9, 0x0B, 0xAF,
    0x05, 0x76, 0x3E, 0x4E, 0xD3, 0xD1, 0xDF, 0x9B, 0x7A, 0x75, 0x6E, 0x4C, 0x5F, 0x63, 0x63, 0x75};

const uint8_t *key = {};
static WiFiServer server(PORT);
static WiFiClient client_global;
uint8_t hash[HASH_SIZE] = {};
uint8_t auth_key[RSA_BLOCK_SIZE] = "kp2-5v8/B?E(H+VmY3wA";

static req_info request_parsing(uint8_t *message)
{
    Serial.println("I AM ON REQUEST PARSING: ");

    req_info temp;

    temp.key = (client_mes_type)message[0];
    Serial.print("Client Massage Type is: ");
    Serial.println(message[0]);
    // Debug
    /*Serial.print("The key is : ");
    Serial.println(temp.key);*/
    if (temp.key == client_mes_type(AUTH) || temp.key == client_mes_type(AES_KEY))
    {
        for (int i = 1; i < RSA_SIZE + 1; i++)
        {
            temp.message[i - 1] = message[i];
        }
        // Debug
        Serial.print("Encrypted message RSA: ");
        print_data(temp.message, sizeof(temp.message));

        for (int i = 1 + RSA_SIZE; i < RSA_SIZE + HASH_SIZE + 1; i++)
        {
            temp.hash_value[i - (1 + RSA_SIZE)] = message[i];
        }
        Serial.print("Hash RSA is: ");
        print_data(temp.hash_value, HASH_SIZE);
        // Debug
    }
    else
    {
        for (int i = 1; i < AES_CIPHER_SIZE + 1; i++)
        {
            temp.message[i - 1] = message[i];
        }
        // Debug
        Serial.print("Encrypted message AES: ");
        print_data(temp.message, AES_CIPHER_SIZE);

        for (int i = 1 + AES_CIPHER_SIZE; i < AES_CIPHER_SIZE + HASH_SIZE + 1; i++)
        {
            temp.hash_value[i - (1 + AES_CIPHER_SIZE)] = message[i];
        }
        Serial.print("Hash AES is: ");
        print_data(temp.hash_value, HASH_SIZE);
        // Debug
        /*Serial.print("The hash is : ");
        Serial.println((char*)temp.hash_value);
        Serial.println(" ");
        Serial.println(" ");*/
    }

    return temp;
}
static bool check_hash(uint8_t *mes, const uint8_t *hash_res, uint8_t size)
{
    Serial.println("I AM ON CHECK HASH: ");

    bool flag = true;
    uint8_t temp_hash[HASH_SIZE] = {};
    sha1(mes, size, temp_hash);

    // Debug
    Serial.print("The mesaseg: ");
    print_data(mes, size);

    Serial.print("New hash is: ");
    print_data(temp_hash, HASH_SIZE);

    Serial.print("Old hash is: ");
    print_data(hash_res, HASH_SIZE);

    for (int i = 0; i < HASH_SIZE; i++)
    {
        if (!(hash_res[i] == temp_hash[i]))
        {
            flag = false;

            /*Serial.print((char)hash_res[i]);
            Serial.print(" ");
            Serial.println((char)temp_hash[i]);
            // Debug
            Serial.println(i);
            Serial.println(i -( (strlen((char*)mes) - HASH_SIZE )));
            Serial.println((char)mes[i]);
            Serial.println((char)hash[i -( (strlen((char*)mes) - HASH_SIZE  ))]);
            Serial.println("Hash Code Fail!!!");*/
            break;
        }
    }
    return flag;
}

static uint8_t build_response(const server_mes_type type, uint8_t *data, uint8_t data_size, uint8_t *buffer)
{
    Serial.println("I AM ON BUILD RESPONSE: ");

    uint8_t i = 0;
    buffer[i] = type;
    Serial.print("Server Massage Type is: ");
    Serial.println(buffer[i]);

    uint8_t hash[HASH_SIZE] = {};

    if (type == server_mes_type(AUTH_OK) || type == server_mes_type(AES_OK))
    {
        uint8_t encrypted[RSA_SIZE] = {};
        rsa_public_encrypt(data, data_size, public_key_client, encrypted);

        for (i = 1; i < RSA_SIZE + 1; i++)
        {
            buffer[i] = encrypted[i - 1];
        }
        // Debug
        Serial.print("Encrypted RSA is: ");
        print_data(encrypted, sizeof(encrypted));
        sha1(encrypted, RSA_SIZE, hash);

        // Debug
        Serial.print("Hash RSA is: ");
        print_data(hash, sizeof(hash));

        for (i = 1 + RSA_SIZE; i < HASH_SIZE + (1 + RSA_SIZE); i++)
        {
            buffer[i] = hash[i - (1 + RSA_SIZE)];
        }
        buffer[i] = '\0';
    }
    else
    {
        uint8_t encrypted[AES_CIPHER_SIZE] = {};
        aes128_encrypt(data, data_size, encrypted);

        // Debug
        Serial.print("Encrypt AES is: ");
        print_data(encrypted, sizeof(encrypted));
        for (i = 1; i < AES_CIPHER_SIZE + 1; i++)
        {
            buffer[i] = encrypted[i - 1];
        }
        sha1(encrypted, AES_CIPHER_SIZE, hash);

        // Debug
        Serial.print("Hash AES is: ");
        print_data(hash, sizeof(hash));

        for (i = 1 + AES_CIPHER_SIZE; i < HASH_SIZE + (1 + AES_CIPHER_SIZE); i++)
        {
            buffer[i] = hash[i - (1 + AES_CIPHER_SIZE)];
        }
        buffer[i] = '\0';
    }
    return i;
}

static bool check_Auth(const char *rec_key, const char *saved_key)
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
    //time_t start_t = time(NULL);
    session temp;
    keys_generater(temp.session_Id, SESSION_ID_SIZE);
    // temp.start_session = millis();
    // Serial.printf("\nStart Session is %llu, In creation \n", temp.start_session);

    temp.end_session = (millis()/1000) + SESSION_PERIOD;
    Serial.printf("\nEnd Session is %llu, In creation \n", temp.end_session);

    return temp;
}

static bool session_check(session ses)
{
    bool flag;
    // if (ses.session_Id == session_id)
    // {
        //time_t curent = ;
        //time(&curent);
        //Serial.printf( " dif is = %0.2f", difftime(curent, ses.start_session));
        if (ses.end_session - (millis()/1000) <=  SESSION_PERIOD)
        {
            flag = true;
        }
    // }
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
    // while (!Serial)
    // {
    //     delay(100);
    // }

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

        if (strlen((char *)rx_buffer))
        {
            req_info request_details = request_parsing(rx_buffer);
            uint8_t encrypted_massage_size;
            uint8_t decrypted_massage_size;

            if (request_details.key == client_mes_type(AUTH) || request_details.key == client_mes_type(AES_KEY))
            {
                encrypted_massage_size = RSA_SIZE;
                decrypted_massage_size = RSA_BLOCK_SIZE;
            }
            else
            {
                encrypted_massage_size = AES_KEY_SIZE;
                decrypted_massage_size = AES_CIPHER_SIZE;
            }
            // Debug
            // Serial.print("Encrypted message 2: ");
            // print_data(details.message, sizeof(details.message));
            // Debug
            // Serial.print("The hash is 2: ");
            // print_data(details.hash_value, sizeof(details.hash_value));
            if (request_details.key == client_mes_type(REQUEST))
            {

                Serial.println("The KEY 1: ");
                print_data(key, AES_KEY_SIZE);
            }
            uint8_t decrypt[decrypted_massage_size] = {};
            if (request_details.key == client_mes_type(REQUEST))
            {

                Serial.println("The KEY 1.1: ");
                print_data(key, AES_KEY_SIZE);
            }
            if (check_hash(request_details.message, request_details.hash_value, encrypted_massage_size))
            {
                if (request_details.key == client_mes_type(AUTH) || request_details.key == client_mes_type(AES_KEY))
                {
                    Serial.print("Will decrypt By RSA:");
                    rsa_private_decrypt(request_details.message, public_key, private_key, decrypt);
                }
                else
                {
                    uint8_t temp_encrypted[AES_CIPHER_SIZE] = {};
                    for (uint8_t i = 0; i < AES_CIPHER_SIZE; i++)
                    {
                        temp_encrypted[i] = request_details.message[i];
                    }
                    Serial.println("The KEY 2 : ");
                    print_data(key, AES_KEY_SIZE);
                    Serial.print("Will decrypt By AES:");
                    aes128_decrypt(temp_encrypted, decrypt);
                    if (request_details.key == client_mes_type(REQUEST))
                    {

                        Serial.println("The KEY 1.3: ");
                        print_data(key, AES_KEY_SIZE);
                    }
                }
                print_data(decrypt, sizeof(decrypt));
                Serial.println((char *)decrypt);
                switch (request_details.key)
                {
                case client_mes_type(AUTH):
                    if (check_Auth((char *)auth_key, (char *)decrypt))
                    {
                        tx_counter = build_response(server_mes_type(AUTH_OK), (uint8_t *)"authentication is ok", RSA_BLOCK_SIZE, rx_buffer);
                        attempt_counter = 0U;
                    }
                    /*else {
                        if (attempt_counter < NUMBER_OF_ATTEMPT) {
                            tx_counter = build_response(server_mes_type(RE_DO), (uint8_t *)"authentication fails", RSA_BLOCK_SIZE, rx_buffer);
                            attempt_counter++;
                        }
                        else {
                            if (attempt_counter < NUMBER_OF_ATTEMPT)
                                tx_counter = build_response(server_mes_type(ERROR), (uint8_t *)"authentication fails", RSA_BLOCK_SIZE, rx_buffer);
                        }
                    }*/
                    break;
                case client_mes_type(AES_KEY):
                {
                    /*uint8_t temp_key[AES_KEY_SIZE]={};
                    memcpy(temp_key, decrypt, AES_KEY_SIZE);
                    for (uint8_t i = 0 ; i<AES_KEY_SIZE ; i++){
                        key [i] = temp_key[i];
                    }   */
                    key = aes128_init_key(decrypt);
                    Serial.print("decrypt in AES_KEY is: ");
                    print_data(decrypt, AES_KEY_SIZE);
                    Serial.print("Temp key is: ");
                    print_data(key, AES_KEY_SIZE);
                    // for (uint8_t i = 0 ; i<AES_KEY_SIZE ; i++){
                    //     temp_key [i] = decrypt[i];
                    // }
                    // key = &temp_key[0];
                    Serial.print("key is: ");
                    print_data(key, AES_KEY_SIZE);
                    client_session = session_creater();
                    //Serial.printf("\nID is %s, After renew \n",(char*) client_session.session_Id);
                    Serial.printf("\nEnd Session is %llu, out creation \n", client_session.end_session);

                    tx_counter = build_response(server_mes_type(AES_OK), (uint8_t *)"AES key is ok", RSA_BLOCK_SIZE, rx_buffer);
                    attempt_counter = 0U;
                }
                break;

                case client_mes_type(REQUEST):
                    Serial.println("I am in REQUEST");

                    Serial.println((char)decrypt[0]);
                    Serial.printf("\nEnd Session is %llu, Before Check \n", client_session.end_session);

                    if (session_check(client_session))

                    {

                    Serial.printf("\nEnd Session is %llu, After Check \n", client_session.end_session);

                        //time_t new_start_time;
                       // client_session.start_session = millis();
                        client_session.end_session = (millis()/1000) + SESSION_PERIOD;
                        Serial.printf("\nEnd Session is %llu, After Renew \n", client_session.end_session);

                        switch ((char)decrypt[0])
                        {
                            case ('1'):
                                Serial.println("I am in REQUEST");
                                Serial.printf("\nEnd Session is %llu, 1 \n", client_session.end_session);
                                digitalWrite(BUILTIN_LED, HIGH);
                                tx_counter = build_response(server_mes_type(DONE), (uint8_t *)"Light ON", sizeof("Light ON"), rx_buffer);
                            break;

                            case ('2'):
                                digitalWrite(BUILTIN_LED, LOW);

                                tx_counter = build_response(server_mes_type(DONE), (uint8_t *)"Light OFF", sizeof("Light OFF"), rx_buffer);
                                break;

                            case ('3'):
                                digitalWrite(BUILTIN_LED, HIGH);
                                tx_counter = build_response(server_mes_type(DONE), (uint8_t *)"Light ON", AES_KEY_SIZE, rx_buffer);
                                break;

                            case ('4'):
                            {
                                char temp[6];
                                float x = temperatureRead();
                                dtostrf(x, 5, 2, temp);
                                char messeage[] = "Temperature: ";

                                tx_counter = build_response(server_mes_type(DONE), (uint8_t *)temp, sizeof(temp), rx_buffer);
                                strcat(messeage, temp);
                            }
                            break;

                            case (5):
                                digitalWrite(BUILTIN_LED, HIGH);
                                tx_counter = build_response(server_mes_type(DONE), (uint8_t *)"Light ON", AES_KEY_SIZE, rx_buffer);
                            break;
                        }

                    }
                    else{
                        Serial.printf("\nEnd Session is %llu, and its expierd \n", client_session.end_session);
                        tx_counter = build_response(server_mes_type(RE_AUTH), (uint8_t *)"Session Expire", sizeof("Session Expire"), rx_buffer);

                    }
                    break;
                }
                // Debug
                // Serial.println("Hash Code OK!");

                // Debug
                // Serial.print("The decrypted message is: ");
                // Serial.println((char*)decrypt);
            }
            else
            {
                Serial.println("Hash Code Fail!!!");
            }

            //Serial.printf("led on");
            //digitalWrite(BUILTIN_LED, HIGH);
            // }
            /* for (uint8_t *ptr = rx_buffer; *ptr; ptr++)
             {
                 *ptr = toupper(*ptr);
             }
                 //client_global.write("Light ON \n");
             for (uint8_t i =0; i < strlen((char*)rx_buffer); i++ )
             {
                 //Serial.println("I am here!");
                 Serial.print((char)rx_buffer[i]);
             }
                 Serial.println("");*/
            // Debug

            /*if (rx_buffer[0] == '2')
            {
                digitalWrite(BUILTIN_LED, LOW);
                client_global.write("Light OFF \n");
            }
            if (rx_buffer[0] == '3')
            {
                float x = temperatureRead();
                char temp[6];
                char messeage[] = "Current Temperature in Server is: ";
                dtostrf(x, 5, 2, temp);
                strcat(messeage, temp);
                client_global.write(strcat(messeage, "\n"));

            }*/
            client_global.write((char *)rx_buffer);
        }
    }

    Serial.flush();
}