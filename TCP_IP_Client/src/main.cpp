#include <Client.h>

// #define SSID "YA-LOCAL"
// #define PASSWORD "utbildning2020"

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

  //WiFi.begin(SSID, PASSWORD);

  while (WL_CONNECTED != WiFi.status())
  {
    WiFi.begin(SSID, PASSWORD);
    delay(5000);
    Serial.print(".");
  }

  Serial.print("\nIP Address: ");
  Serial.println(WiFi.localIP());
}

void loop()
{
  // if the client is not authorized yet, it will start with authorization by clicking '0' in the menu
  if (!authorized)
  {
    while (menu_choice != '0')
    {
      menu_choice = services_menu(authorized);
      if (menu_choice != '0')
      {
        Serial.println("You need to be Authorized first.");
      }
    }
    //Calling authorization function for authorized and fill the message to the buffer.
    authorization((uint8_t *)tx_buffer);
    // Set the the buffer size that will be send.
    tx_counter = AUTH_MES_SIZE;
  }
  // if the client is authorized, it will ask for the serivce type(Led on, led Off, Led Status, Temprature, End Session)
  if (authorized)
  {
    while (menu_choice == '0')
    {
      menu_choice = services_menu(authorized);
      if (menu_choice == '0')
      {
        Serial.println("You are already Authorized, Please choose one of the services.");
      }
    }
    // Build the request
    build_request(message_details.session_Id, (sending_types)menu_choice, tx_buffer);
    // Set the the buffer size that will be send.
    tx_counter = REQUEST_MES_SIZE;
  }
  // Connect to the Server
  client.connect(SERVER, PORT);

  if (client.connected())
  {
    // Send the message to the Server
    client.write_P(tx_buffer, tx_counter);
    delay(2500);
    // Read the responce from the Server
    client.read((uint8_t *)rx_buffer, (size_t)sizeof(rx_buffer));
    uint8_t mes_len;
    // Checking received message lenght
    if ((mes_len = check_mes_len(rx_buffer)))
    {
#ifdef DEVELOPMENT
      Serial.print("The received message is: ");
      print_data(rx_buffer, mes_len);
#endif
      // Checking the hash received
      if (check_hash(mes_len, rx_buffer))
      {
        // Decrypting the received message and parsing it to response_info struct
        message_details = message_parsing(message_details, mes_len, rx_buffer);
        if (mes_len == RSA_MES_SIZE)
        {
          //Set the authorized boolean to true if mes mes_len == RSA_MES_SIZE(52U) and the Hash code is ok.
          authorized = true;
        }
        if (mes_len == REQUEST_MES_SIZE)
        {
          // Switching based on the response type( REQUEST_DONE or Error)
          switch (message_details.type)
          {
          case (receiving_types(REQUEST_DONE)):
            // Print the server response message
            Serial.printf("\nResponse Message is: %s\n", message_details.message);
            break;

          case (receiving_types(ERROR)):
            // Print Error to the user and set authorized to false in order to reauthenticate.
            Serial.printf("\nResponse Message is: %s\n", message_details.message);
            authorized = false;
            break;
          }
        }
      }
      else
      {
        // Print Error to the user and set authorized to false in order to reauthenticate.
        Serial.printf("\nHash Code Error!!!\nReauthenticate...\n");
        delay(2000);
        authorized = false;
      }
    }
    else
    {
      // Print message to the user and set authorized to false in order to reauthenticate.
      Serial.printf("\nServer Error!!!\nReauthenticate...\n");
      delay(2000);
      authorized = false;
    }
  }
  else
  {
    // Stop the connection and try to establish it again if there is something wrong with it.
    client.stop();
    client.connect(SERVER, PORT);
    Serial.print(".");
  }
  // Set all values to zeros in the end of looping
  tx_counter = 0;
  menu_choice = '0';
  memset(tx_buffer, 0, BUFFER_SIZE);
  memset(rx_buffer, 0, BUFFER_SIZE);
}
