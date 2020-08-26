#include <WiFi.h>
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <stdbool.h>
#include <RSA.h>
#include <SHA1.h>
#include <AES128.h>

#include <Server.h>


// To print data in Hex
void print_data(const uint8_t *data, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}

// Message decryption handling based on Authentication and Requesting info.
message_info message_decrypting(message_info message_details, uint8_t mes_len, uint8_t *message)
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
        Serial.print("Session ID is: ");
        print_data(decrypted_pieces.session_Id, SESSION_ID_SIZE);
        Serial.printf("Request type is: %c\n", decrypted_pieces.request[0]);
#endif
    }
    return decrypted_pieces;
}

//  checking Hash 
bool check_hash(uint8_t mes_len, uint8_t *the_whole_message)
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

//Function to build response message to the client
uint8_t build_response(uint8_t mes_len, uint8_t *data, uint8_t data_size, uint8_t *buffer)
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
    print_data(hash, HASH_SIZE);
#endif
    memcpy(&*buffer + encryption_size, hash, HASH_SIZE);
#ifdef DEVELOPMENT
    Serial.print("\nThe Whole Message Befor Sending is: \n");
    print_data(buffer, encryption_size + HASH_SIZE);
#endif
    free(encrypted_data);
    return counter;
}


void Session_Id_generater(uint8_t key_holder[], uint8_t key_size)
{
    for (uint8_t i = 0; i < key_size; i++)
    {
        key_holder[i] = random(0xFF);
    }
}

// Session creator
session_t session_creater()
{
#ifdef DEVELOPMENT
    Serial.println("\n//.......................I AM IN SESSION CREATE ......................//\n");
#endif
    session_t temp;
    Session_Id_generater(temp.session_Id, SESSION_ID_SIZE);
    temp.end_session = millis() + SESSION_PERIOD;

#ifdef DEVELOPMENT
    Serial.print("Sesion ID is: ");
    print_data(temp.session_Id, SESSION_ID_SIZE);
    Serial.printf("\nEnd Session is %d Secunds \n", temp.end_session / 1000);
#endif
    return temp;
}
// AES key generator
void providing_aes_session(session_t session, uint8_t *buffer)
{
    const uint8_t *key = aes128_init_key(NULL);
#ifdef DEVELOPMENT
    Serial.print("AES Key: ");
    print_data(key, AES_KEY_SIZE);
#endif
    memcpy_P(buffer, session.session_Id, SESSION_ID_SIZE);
    memcpy_P(&*buffer + SESSION_ID_SIZE, key, AES_KEY_SIZE);
#ifdef DEVELOPMENT
    Serial.println("AES & SESSION ID is: ");
    print_data(buffer, SESSION_ID_SIZE + AES_KEY_SIZE);
#endif
}

// To check session period is still valid
bool session_check(session_t ses)
{
#ifdef DEVELOPMENT
    Serial.println("\n//........................I AM IN SESSION CHECK.......................//\n");
    Serial.printf("Current Time: %lu Secunds\n", millis() / 1000);
    Serial.printf("Session End at: %d\n", ses.end_session / 1000);
#endif
    bool flag;
    if (ses.end_session - millis() <= SESSION_PERIOD)
    {
        flag = true;
#ifdef DEVELOPMENT
        Serial.println("Pass");
#endif
    }
    else
    {
        flag = false;
#ifdef DEVELOPMENT
        Serial.println("Fail");
#endif
    }
    return flag;
}

// checking the received message length
uint8_t check_mes_len(uint8_t *mes)
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
    Serial.printf("Message Lenght is: %d\n", (int)mes_len);
    Serial.print("\nRead Buffer is : ");
    print_data(mes, mes_len);
#endif
    return mes_len;
}

// Joined the parts to make a Message before encryption which send to the client 
void join_message(receiving_types type, uint8_t *message, uint8_t *buffer)
{
    buffer[0] = type;
    memcpy(&*buffer + 1, message, strlen((char *)message));
    buffer[strlen((char *)message) + 1] = '\0';

#ifdef DEVELOPMENT
    Serial.print("Joined Message is:");
    print_data(buffer, strlen((char *)message) + 1);
#endif
}

void renew_session(uint32_t session_end_time)
{
#ifdef DEVELOPMENT
    Serial.println("\n//.......................I AM IN RENEW SESSION........................//\n");
    Serial.printf("Current Time is: %lu Secunds\n", millis() / 1000);
#endif
    session_end_time = millis() + SESSION_PERIOD;
#ifdef DEVELOPMENT
    Serial.printf("End Session After Renew is: %d Secunds\n", session_end_time / 1000);
#endif
}

// This function is handling the clients request 
uint8_t handler_request(uint32_t * session_end_time, uint8_t mes_len, sending_types request, uint8_t * buffer)
{    
    uint8_t tx_counter;
    switch (request)
    {
    case (sending_types(LED_ON)):
        digitalWrite(BUILTIN_LED, HIGH);
        join_message(receiving_types(OK), (uint8_t *)"Light ON", buffer);
        tx_counter = build_response(mes_len, buffer, sizeof("Light ON") + 1, buffer);
        break;

    case (sending_types(LED_OFF)):
        digitalWrite(BUILTIN_LED, LOW);
        join_message(receiving_types(OK), (uint8_t *)"Light OFF", buffer);
        tx_counter = build_response(mes_len, buffer, sizeof("Light OFF") + 1, buffer);
        break;

    case (sending_types(TEMPERATURE)):
    {
        char temp[6];
        float x = temperatureRead();
        dtostrf(x, 5, 2, temp);
        join_message(receiving_types(OK), (uint8_t *)temp, buffer);
        tx_counter = build_response(mes_len, buffer, sizeof(temp) + 1, buffer);
    }
    break;

    case (sending_types(END_SESSION)):
        *session_end_time = millis();
        Serial.printf ("\n The session After Ended is: %d\n", (uint32_t)*session_end_time /1000);
        join_message(receiving_types(OK), (uint8_t *)"Session Ended", buffer);
        tx_counter = build_response(mes_len, buffer, sizeof("Session Ended") + 1, buffer);
        break;

    case (sending_types(LED_STATUS)):
        if(!digitalRead(BUILTIN_LED)){
             join_message(receiving_types(OK), (uint8_t *)"Light OFF", buffer);
            tx_counter = build_response(mes_len, buffer, sizeof("Light OFF") + 1, buffer);
        }
        if(digitalRead(BUILTIN_LED)){
            join_message(receiving_types(OK), (uint8_t *)"Light ON", buffer);
            tx_counter = build_response(mes_len, buffer, sizeof("Light ON") + 1, buffer);
        }
        break;

    case (sending_types(ERROR)):
    {
        break;
    }
    }
    return tx_counter;
}