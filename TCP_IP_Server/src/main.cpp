#include <Server.h>

// #define SSID "YA-LOCAL"
// #define PASSWORD "utbildning2020"

#define SSID "Telia-ED8AC9"
#define PASSWORD "05162D814F"

static uint8_t auth_hash_key[HASH_SIZE] = {
    0x6E, 0x31, 0x2B, 0x1F, 0xAC, 0x84, 0xB7, 0x9C, 0x56, 0x3F,
    0x3E, 0xE8, 0x98, 0x29, 0xC0, 0x0C, 0xEC, 0xB3, 0xEE, 0xBD};

static bool authorized = false;
static uint8_t tx_counter = 0U;
session_t client_session;
static WiFiServer server(PORT);
static WiFiClient client_global;
uint8_t hash[HASH_SIZE] = {};

void setup()
{
    Serial.begin(9600);
    while (!Serial)
    {
        delay(100);
    }

    WiFi.begin(SSID, PASSWORD);

    while (WL_CONNECTED != WiFi.status())
    {
        delay(3000);
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
    //Establish conction the the client
    WiFiClient client = server.available();

    if (client)
    {
        client_global = client;
    }
    // Check if the client is conected and availabile
    if (client_global.connected() && client_global.available())
    {
        // Read the request from the Client
        client_global.read(rx_buffer, BUFFER_SIZE);
        message_info message_details;
        uint8_t mes_len;
        // Checking received message lenght
        if ((mes_len = check_mes_len(rx_buffer)))
        {
            // Checking the hash received
            if (check_hash(mes_len, rx_buffer))
            {
                // Decrypting the received message and parsing it to message_info struct
                message_details = message_decrypting(mes_len, rx_buffer);
                if (mes_len == AUTH_MES_SIZE)
                {
                    // Check the Hashed ID.
                    if (!memcmp(message_details.the_secret, auth_hash_key, HASH_SIZE))
                    {
                        // Create a new Session
                        client_session = session_creater();
                        // Join response parts in one array and put it in the buffer
                        providing_aes_session(client_session, rx_buffer);
                        // Build the response
                        tx_counter = build_response(mes_len, rx_buffer, AES_KEY_SIZE + SESSION_ID_SIZE, rx_buffer);
                        authorized = true;
                    }
                    else
                    {
                        // Build an Error response if the hashed Id didnt matched.
                        Serial.println("NOT Auth");
                        join_message(receiving_types(ERROR), (uint8_t *)"NOT Auth", rx_buffer);
                        tx_counter = build_response(mes_len, rx_buffer, sizeof("NOT Auth") + 1, rx_buffer);
                    }
                }
                else if (mes_len == REQ_MES_SIZE)
                {
                    // Check the Session ID.
                    if (!memcmp(client_session.session_Id, message_details.session_Id, SESSION_ID_SIZE))
                    {
                        // Check the Session availability.
                        if (session_check(client_session))
                        {
                            // Renew the Session if its still availabile after request.
                            renew_session(client_session.end_session);
                            uint32_t *test = &client_session.end_session;
                            tx_counter = handler_request(test, mes_len, sending_types(message_details.request[0] - '0'), rx_buffer);
                        }
                        else
                        {
                            // Build an Error response if the Session is End
                            Serial.println("Session End");
                            join_message(receiving_types(ERROR), (uint8_t *)"Session End", rx_buffer);
                            tx_counter = build_response(mes_len, rx_buffer, sizeof("Session End") + 1, rx_buffer);
                        }
                    }
                }
            }
            else
            {
                // Build an Error response if the Hashed value didnt match.
                join_message(receiving_types(ERROR), (uint8_t *)"ReAuthenticate", rx_buffer);
                tx_counter = build_response(mes_len, rx_buffer, sizeof("ReAuthenticate") + 1, rx_buffer);
            }
        }
        else
        {
            // Build an Error response if the message lenght value didnt match.
            join_message(receiving_types(ERROR), (uint8_t *)"ReAuthenticate", rx_buffer);
            tx_counter = build_response(mes_len, rx_buffer, sizeof("ReAuthenticate") + 1, rx_buffer);
        }
        // Write what has been built before to the client.
        client_global.write_P((char *)rx_buffer, tx_counter);
        memset(rx_buffer, 0, BUFFER_SIZE);
    }
}