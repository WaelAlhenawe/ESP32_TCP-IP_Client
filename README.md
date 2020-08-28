DATA INTEGRITY AND SECURITY IN COMMUNICATION

Table of contents:

1.	PROPOSITION ………………………………………………………………………………………………………   3
1.1    REQUIREMENT SPECIFICATIONS ………………………………………………………………….  3 
1.2    PROJECT DESCRIPTION………………………………………………………………………………..   3
1.3     DATE INTEGRITY AND SECURITY IN COMMUNICATION ………………………………   3

        1.3.A   RSA CRYPTOGRAPHY ……………………………………………………………….…………   3

        1.3.B    HASHING ……………………………………………………………………….………………….   4

        1.3.C    ADVANCED ENCRYPTION STANDARD AES    ………………………………………    5

        1.3.D   AUTHENTICATION   …………………………………………………………………………….   6

        1.3.E    EXCHANGED DATA  ……………………………………………………………..…………….   6




1. PROPOSITION:
1.1 Requirement Specifications:
•	Two   Esp32.
•	Connecting wires.
•	Monitoring the client side.

1.2 Project Description:
The purpose of this project is to have a communication between two esp32 via TCP/IP protocol.  One act as a client and other as a server. The client shall be able to request information to the server in a safe and secured way. In order to fulfill this, we use the techniques such as RSA, SHA-1, and AES. So that Client can control built in LED of server and also able to read the temperature sensor of esp32 (server) in a secured way.

1.3 Data Integrity and Security in Communication:
1.3.A  RSA Cryptography:
RSA is an Asymmetric encryption technique that uses two different keys as public and private keys to perform the encryption and decryption. (Lake, 2018).

How the pair keys are generated?
This can be done by two ways.
	Generate a  pair key by online:     We use the website to generate the keys (Group, 2020).
	Generate a  pair key by randomly:   
	A pair key [public and private key], one for client and other for server generated through the function which can find in the RSA.h library.                        
                                                                                                                                                                
                                                        									
How the public keys are exchanged?
	Generate two pair keys [public and private key], one for client and other for server.
	Exchange public key between a client and a server
	First Client sends its public key to the server.
	From server side, the server encrypts its public key by received public key of client and sends back   to the client.
	From client side, the client then decrypts the received public key by its private key. So that client and server have exchanged the public keys.
Alternative Way:
Public keys can be hardcoded in both server and client side instead of sending, in such a way to make the task easier.
1.3.B   Hashing:


Why hashing?
The exchanged data can be hashed by using SHA-1 in order to have a safe communication. (Cryptography - Hash Functions & Digital Signatures | inversegravity.net, 2019)
This can be done by,
	The Encrypted data (can be by RSA or AES) shall be hashed by hash function which we can find in the SHA-1 library.
	Through Hashed function , we get a hash value of  constant size ( 160 bits )
	When there is a transaction, hash value also sends together with the encrypted data, so that receiver can check later the received hash value and calculated value of encrypted data are same.
	All the transactions shall be hashed for a safety purpose.

1.3.C   Advanced Encryption Standard – AES:
AES is a symmetric-key algorithm, meaning the same key is used for both encrypting and decrypting the data. (Lake, 2020)
Solution:
How is it generated?
It can be generated randomly by random function for each session of communication after authentication is valid.
How is it exchanged?
Exchanged key is done by RSA cryptography.
From Server side,
	Once the authentication is done, AES key is generated.
	It is then encrypted by RSA public key (Client public key) and send it together with the hash value to the client.  								
From Client side,
	Received hash value is then compared with the calculated hash value of the encrypted data.
	If both hash value are same, then received encrypted data is then decrypted by RSA private key (client private key) and get the AES key.
	Now the both Client and server having the same AES key for further data exchange.

											   
1.3.D    Authentication:
An Authentication is done by RSA cryptography,
	A  big and strong secret ID  signed by RSA private key in the  client side and send it to the server
	Server shall then decrypt the ID by Client public key and later it checks whether the client is authenticated or not. Once it is authenticated, then it starts the session for the communication.
Solution:
From client side,
	Hash value of Client ID is signed by RSA private key (client private key) 
	Now the above signed data is split in to two parts. Each part is encrypted by RSA public key (server public key).
	And then hashed the encrypted data (join two encrypted parts together) through function which can find In SHA-1 library.
	Send the encrypted data (two joined encrypted parts) and hashed value together to the Server.
From Server side,
	Received hash value is then compared with the calculated hash value of the encrypted data.
	If both hash value are same, then received encrypted data is then decrypted first by server private key and then decrypted by (client public key) and get the hash of Client ID.
	This hash is then compared with the hardcoded hash value of the Client ID in the server side.
	If they are same, then it confirms that the authentication is valid.
	If authentication is true, then it generates the AES key and session ID for the communication and sends it to the client by RSA public key and which will be saved in the client side for this specific session ID.  


1.3.E    Exchanged Data:
 The exchanged data is done by AES key with session ID,
 
From Client side,
	Data and session ID  is encrypted together by AES key 
	Send the encrypted data with the hash value to the server.
From Server side,
	Received hash value is then compared with the calculated hash value of the encrypted data.
	If both hash value are same, then received encrypted data is then decrypted by same AES key and get the data and session ID.              							             
	If session period is still valid and session ID is same, then it will handle the request and response to the client. Otherwise Re -Authentication message (if session period exceeds 1 minute) or error message will send back to the client side.
Note: the Server sends the response back to the client by encrypted data (by AES key) with hash value.                                                                                                                                


References:   
•	Group, U., 2020. RSA Key Generator - Computer Science Field Guide. [online] Csfieldguide.org.nz. Available at: <https://csfieldguide.org.nz/en/interactives/rsa-key-generator/> [Accessed 26 August 2020].
•	Lake, J., 2020. What Is AES Encryption (With Examples) And How Does It Work?. [online] Comparitech. Available at: <https://www.comparitech.com/blog/information-security/what-is-aes-encryption/> [Accessed 30 July 2020].
•	Lake, J., 2018. What Is RSA Encryption And How Does It Work? | Comparitech. [online] Comparitech. Available at: <https://www.comparitech.com/blog/information-security/rsa-encryption/> [Accessed 1 August 2020].
•	Maximilian Weber. 2019. Cryptography - Hash Functions & Digital Signatures | Inversegravity.Net. [online] Available at: <https://inversegravity.net/2019/crypto-hash-digital-signature/> [Accessed 2 August 2020].





                                                                                                                                      				                   								                                   
