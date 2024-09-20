#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netdb.h>

using namespace std;

#define BUFFER_SIZE 2048
#define SERVER_PORT 12346
#define SERVER_IP "192.168.0.127"


// Define paths to the private keys and certificates for Alice and Bob
const char* ALICE_CERT_PATH = "alice.crt";
const char* ALICE_KEY_PATH = "alice.pem";

const char* BOB_CERT_PATH = "bob.crt";
const char* BOB_KEY_PATH = "bob.pem";


class Client {

    private:
        string server_name;

    public:
        Client(string server_name) : server_name(server_name) {}

        int setting_up_udp_sock_for_conn() {

            int clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

            if (clientSocket == -1) {
                perror("....Socket creation failed....");
                return -1;
            }

            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(SERVER_PORT);
            serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

            cout << "Connected with IP address: " << inet_ntoa(serverAddr.sin_addr) << endl;

            return clientSocket;

        }

        void dtls_client(int clientSocket) {

            // Initialize OpenSSL library functions
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();
            char send_buffer[BUFFER_SIZE];
            char receive_buffer[BUFFER_SIZE];

            struct sockaddr_in addr;

            // Create SSL context for storing config. info. about the SSL connections
            SSL_CTX* ctx = SSL_CTX_new(DTLSv1_2_client_method()); 


            if (!ctx) {
                perror("....Failed to create SSL context....");
                return;
            }
            
            // Create a SSL object
            SSL* ssl = SSL_new(ctx);

            if (!ssl) {
                perror("....Failed to create SSL object....");
                SSL_CTX_free(ctx);
                return;
            }

            // Load Alice's certificate
            if (SSL_CTX_use_certificate_file(ctx, ALICE_CERT_PATH, SSL_FILETYPE_PEM) <= 0) {
                perror("Failed to load Alice's certificate file");
                SSL_CTX_free(ctx);
                return;
            }

            // Load Alice's private key
            if (SSL_CTX_use_PrivateKey_file(ctx, ALICE_KEY_PATH, SSL_FILETYPE_PEM) <= 0) {
                perror("Failed to load Alice's private key file");
                SSL_CTX_free(ctx);
                return;
            }

            // Connect to server socket
            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(SERVER_PORT);
            socklen_t serverLen = sizeof(serverAddr);

            if (connect(clientSocket, (struct sockaddr*)&serverAddr,serverLen) <  0) {
                perror("....Invalid address/ Address not supported....");
                return;
            }

            // Set the cipher suites for perfect forward secrecy (PFS) at client side
            const char* cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
            if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {
                cerr << "Failed to set cipher list" << endl;
                SSL_CTX_free(ctx);
                return;
            }

            // Exchange application layer control messages
            char msg_from_server[BUFFER_SIZE];
            char msg_to_send[BUFFER_SIZE];
            const char* chat_hello = "chat_hello";
            const char* chat_ok_reply = "chat_ok_reply";

           

            // Send chat_hello message
            if (sendto(clientSocket, chat_hello, strlen(chat_hello), 0, (struct sockaddr*)&serverAddr, serverLen) < 0) {
                cerr << "Error sending message to server..." << endl;
                close(clientSocket);
                return;
            }

            char buffer[BUFFER_SIZE];
            int reply;

            // Wait for chat_ok_reply from server to close application control messages
            reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &serverLen);
// Receive chat_START_SSL_ACK message
            //reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &serverLen);
            

            if (reply < 0) {
                cerr << "Error recieving message from server..." << endl;
                return;
            }
    
            if (reply > 0) {
                msg_from_server[reply] = '\0';
                cout << "Received: " << msg_from_server << endl;

                string msg="";
                for (int i=0;i<reply;i++){
                msg+=buffer[i];
               }
                cout<<msg<<endl;


                if (msg!= "chat_ok_reply" ) {
                    cerr << "Unexpected response from server11" << endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return;
                }
            } 

            // Send chat_START_SSL message
            strcpy(msg_to_send, "chat_START_SSL");
            if (sendto(clientSocket, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr*)&serverAddr, serverLen) < 0) {
                cerr << "Error sending message to server..." << endl;
                close(clientSocket);
                return;
            }

            // Receive chat_START_SSL_ACK message
            reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddr, &serverLen);
            //cout<<buffer<<reply<<endl;
            
            if (reply < 0) {
                cerr << "Error recieving message from server..." << endl;
                return;
            }

            // Load CA certificate and set up verification locations
            if (SSL_CTX_load_verify_locations(ctx, "/usr/local/share/ca-certificates/new_combined.crt", NULL) != 1) {
                perror("Failed to load CA certificate for verification");
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                cout<<":"<<endl;
                return;
            };
            //cout<<clientSocket<<endl;
            SSL_set_fd(ssl,clientSocket);
            // Perform SSL handshake
            int x = SSL_connect(ssl);
            //cout<<ssl<<endl;
            if (SSL_connect(ssl) <= 0) {
                perror("SSL handshake failed");
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                return;
            }
            
            // DTLS v1.2 Handshake Successful
            cout << "....DTLS v1.2 Handshake Successful...." << endl;

            // Now actual messages can be exchanged
            while (true) {

                char msg[BUFFER_SIZE];
                cout << "Send Message: ";
                cin.getline(msg, BUFFER_SIZE);
                SSL_write(ssl, msg, strlen(msg));

                if (strcmp(msg, "chat_close") == 0) {
                    break;
                }

                cout << "Waiting for Server Message..." << endl;
                reply = SSL_read(ssl, msg_from_server, BUFFER_SIZE);
                if (reply > 0) {
                    msg_from_server[reply] = '\0';
                    cout << "Server: " << msg_from_server << endl;
                    if (strcmp(msg_from_server, "chat_close") == 0) {
                        break;
                    }
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
    }
};

class Server {
    public:
        int setup_udp_socket() {
            int serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

            if (serverSocket == -1) {
                perror("Socket creation failed");
                return -1;
            }

            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
            serverAddr.sin_port = htons(SERVER_PORT);

            if (bind(serverSocket, (struct sockaddr*) &serverAddr, sizeof(serverAddr)) < 0) {
                perror("Bind failed");
                close(serverSocket);
                return -1;
            }

            return serverSocket;
        }
        
        static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
        {   
            memcpy(cookie,  "cookie", 6);
            *cookie_len = 6;

            return 1;
        }

        static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
        {
            return 1;
        }

        int dtls_server() {

            // Initialize OpenSSL library functions
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();

        
            // Create SSL context using TLS_server_method() for DTLS compatibility
            SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());

            if (!ctx) {
                perror("Failed to create SSL context");
                return -1;
            }

            // Load Bob's certificate and private key
            if (SSL_CTX_use_certificate_file(ctx, BOB_CERT_PATH, SSL_FILETYPE_PEM) <= 0) {
                perror("Failed to load Bob's certificate file");
                SSL_CTX_free(ctx);
                return -1;
            }

            if (SSL_CTX_use_PrivateKey_file(ctx, BOB_KEY_PATH, SSL_FILETYPE_PEM) <= 0) {
                perror("Failed to load Bob's private key file");
                SSL_CTX_free(ctx);
                return -1;
            }

            SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

            SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
            SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

            // Set the cipher suites for perfect forward secrecy (PFS) at server side
            const char* cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
            if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {
                cerr << "Failed to set cipher list" << endl;
                SSL_CTX_free(ctx);
                return -1;
            }

            while(true){
            
            int serverSocket = setup_udp_socket();  

            if (serverSocket == -1) {
                return 1;
            }


            struct sockaddr_storage clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);

            // Exchange application layer control messages
            char msg_from_client[BUFFER_SIZE];
            char msg_to_send[BUFFER_SIZE];
            string chat_hello = "chat_hello";
            char* chat_ok_reply = "chat_ok_reply";

            SSL* ssl = NULL;

            // Wait for chat_hello message from client
            int len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr*) &clientAddr, &clientAddrLen);
            string msg="";
            for (int i=0;i<10;i++){
                msg+=msg_from_client[i];
            }

            //cout<<msg<<endl;
            if (len > 0) {
                msg_from_client[len] = '\0';
                cout << "Received from Client: " << msg <<" "<< chat_hello<<endl;
                if (msg!="chat_hello") {
                    cerr << "Unexpected message from client" << endl;
                    close(serverSocket);
                    return -1;
                }
            } 
            // Accept the connection and create a new SSL object
            ssl = SSL_new(ctx);

            if (!ssl) {
                perror("Failed to accept connection");
                SSL_CTX_free(ctx);
                close(serverSocket);
                return -1;
            }
        
            // Send chat_ok_reply message
            
            //strcpy(msg_to_send, chat_ok_reply);
            if (sendto(serverSocket,chat_ok_reply, strlen(chat_ok_reply), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) < 0) {
                cerr << "Error communicating with client..." << std::endl;
                close(serverSocket);
                return 1;
            }
            // Exchange SSL control messages

            // Wait for chat_START_SSL message from client
            len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr*) &clientAddr, &clientAddrLen);

            if (len > 0) {
                msg_from_client[len] = '\0';
                cout << "Received from Client: " << msg_from_client << endl;
            msg="";
            for (int i=0;i<len;i++){
                msg+=msg_from_client[i];
                
            }


                if (msg!="chat_START_SSL") {
                    cerr << "Unexpected message from client" << endl;
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    close(serverSocket);
                    return -1;
                }
            } 

            // Send chat_START_SSL_ACK message
            strcpy(msg_to_send, "chat_START_SSL_ACK");
            if (sendto(serverSocket, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) < 0) {
                cerr << "Error communicating with client..." << std::endl;
                close(serverSocket);
                return 1;
                
            }

            BIO* bio = BIO_new_dgram(serverSocket, BIO_NOCLOSE);

            if (!bio) {
                perror("Failed to create UDP BIO");
                SSL_CTX_free(ctx);
                close(serverSocket);
                return -1;
               
            }

            SSL_set_bio(ssl, bio, bio);

            if (DTLSv1_listen(ssl, (BIO_ADDR *)&clientAddr) <= 0) {
                cout<<"Failed to set DTLS listen"<<endl;
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                continue;
            }

            if(SSL_accept(ssl)<=0){
                cout<<"SSL Handshake Failed"<<endl;
                cerr<<SSL_get_error(ssl,SSL_accept(ssl))<<endl;
            }

            // Now actual messages can be exchanged
            while (true) {
                char msg[BUFFER_SIZE];
                cout << "Waiting for Client Message..." << endl;

                //cout << "Client: ";

                // Read message from client using SSL_read
                len = SSL_read(ssl, msg, BUFFER_SIZE);
                if (len > 0) {
                    msg[len] = '\0';
                    cout << "Client: "<< msg << endl;
                    if (strcmp(msg, "chat_close") == 0) {
                        break;
                    }
                } else {
                    perror("Failed to receive message from client");
                    break;
                }

                // Send message to client using SSL_write
                cout << "Send Reply: ";
                cin.getline(msg, BUFFER_SIZE);
                SSL_write(ssl, msg, strlen(msg));

                if (strcmp(msg, "chat_close") == 0) {
                                        cout<<"........."<<endl;

                    break;
                }
            }

            // Cleanup
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(serverSocket);
        
        }

        return 0;
    }   
};


int main(int argc, char* argv[]) {
    
    int opt;
    bool is_client = false;
    bool is_server = false;
    string server_name;

    if (argc!=2){
        cerr << "Usage: secure_chat_app [-c] [-s server_name]" << endl;
    }
    string option =argv[1];
   
    if (option=="-c") {

        Client client(server_name);

        int clientSocket = client.setting_up_udp_sock_for_conn();

        if (clientSocket == -1) {
            return 1;
        }

        client.dtls_client(clientSocket);

        close(clientSocket);
    }
    
    else if (option=="-s"){
        cout<<".................. Server started ................."<<endl;

        Server server;

        server.dtls_server();

    }
    else{
        cout<<"No connection";
    }

    return 0;
    
}
