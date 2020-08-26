#include <Client.h>

// #define SSID "YA-LOAL"
// #define PASSWORD "utbildnCing2020"

#define SSID "Telia-ED8AC9"
#define PASSWORD "05162D814F"

static WiFiClient client;
static uint8_t tx_counter = 0U;
static char tx_buffer[BUFFER_SIZE] = {};
static response_info message_details = {};
char menu_choice = ' ';
static uint8_t rx_buffer[BUFFER_SIZE] = {};
static bool authorized = false;


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
    authorization((uint8_t *)tx_buffer);
    tx_counter = AUTH_MES_SIZE;
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
    tx_counter = REQUEST_MES_SIZE;
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
          if (mes_len == RSA_MES_SIZE)
          {
            authorized = true;
          }
          if (mes_len == REQUEST_MES_SIZE)
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
