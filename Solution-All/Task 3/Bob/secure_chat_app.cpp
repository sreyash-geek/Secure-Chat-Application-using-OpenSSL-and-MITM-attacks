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


// All ips names for references
// 172.31.0.3 Bob
// 172.31.0.2 Alice
// 172.31.0.4 Trudy



#define BUFFER_SIZE 2048

// defining server port 
#define SERVER_PORT 12345

// global serverIP, we are also using gethost by name and updating it in main function, it also have global server address variables
char *SERVER_IP = "172.31.0.3";
int serverSocket;
struct sockaddr_in serverAddr;


// Define paths to the private keys and certificates for Alice and Bob and combined certificate of root and intermediate
const char *ALICE_CERT_PATH = "alice.crt";
const char *ALICE_KEY_PATH = "alice_private_key.pem";

const char *BOB_CERT_PATH = "bob.crt";
const char *BOB_KEY_PATH = "bob_private_key.pem";

const char *COMBINED_CERT_PATH = "combined.crt";


// Client class 
class Client
{
private:
    string server_name;

public:
    Client(string server_name) : server_name(server_name) {}

    // client making connection to server
    int setting_up_udp_sock_for_conn()
    {
        int clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (clientSocket == -1)
        {
            perror("....Socket creation failed....");
            return -1;
        }

        // struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(SERVER_PORT);
        serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

        cout << "Connected with IP address: " << inet_ntoa(serverAddr.sin_addr) << endl;

        return clientSocket;
    }

    
    void dtls_client(int clientSocket)
    {

        // Initialize OpenSSL library functions
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        // Create SSL context for storing config. info. about the SSL connections
        SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_client_method());
        SSL_CTX_set_security_level(ctx, 1);
        if (!ctx)
        {
            perror("....Failed to create SSL context....");
            return;
        }

        // Create a SSL object
        SSL *ssl = SSL_new(ctx);

        if (!ssl)
        {
            perror("....Failed to create SSL object....");
            SSL_CTX_free(ctx);
            return;
        }

        // Load Alice's certificate
        if (SSL_CTX_use_certificate_file(ctx, ALICE_CERT_PATH, SSL_FILETYPE_PEM) <= 0)
        {
            perror("Failed to load Alice's certificate file");
            SSL_CTX_free(ctx);
            return;
        }

        // Load Alice's private key
        if (SSL_CTX_use_PrivateKey_file(ctx, ALICE_KEY_PATH, SSL_FILETYPE_PEM) <= 0)
        {
            perror("Failed to load Alice's private key file");
            SSL_CTX_free(ctx);
            return;
        }

        // Connect to server socket
        socklen_t serverLen = sizeof(serverAddr);

        if (connect(clientSocket, (struct sockaddr *)&serverAddr, serverLen) < 0)
        {
            perror("....Invalid address/ Address not supported....");
            SSL_CTX_free(ctx);
            return;
        }

        // Set the cipher suites for perfect forward secrecy (PFS) at client side
        const char *cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
        if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1)
        {
            cerr << "Failed to set cipher list" << endl;
            SSL_CTX_free(ctx);
            return;
        }

        // Exchange application layer control messages
        char msg_from_server[BUFFER_SIZE];
        char msg_to_send[BUFFER_SIZE];
        const char *chat_hello = "chat_hello";
        const char *chat_ok_reply = "chat_ok_reply";

        // Send chat_hello message
        struct timeval timeout;
        timeout.tv_sec = 1; // 1 seconds timeout we can change it according to need.
        timeout.tv_usec = 0;
        if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        {
            std::cerr << "Error setting socket options: " << strerror(errno) << std::endl;
            close(clientSocket);
            return;
        }

        char buffer[BUFFER_SIZE];
        int reply;

        // Reliability Implemeted for chat_hello

        while (true)
        {

            if (sendto(clientSocket, chat_hello, strlen(chat_hello), 0, (struct sockaddr *)&serverAddr, serverLen) < 0)
            {
                cerr << "Error sending message to server..." << endl;
                SSL_CTX_free(ctx);
                return;
            }

            // Wait for chat_ok_reply from server to close application control messages
            reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&serverAddr, &serverLen);

            // Receive chat_START_SSL_ACK message
            if (reply < 0)
            {
                cout << "........Reconnecting........." << endl;
                continue;
            }

            if (reply > 0)
            {
                msg_from_server[reply] = '\0';

                string msg = "";
                for (int i = 0; i < reply; i++)
                {
                    msg += buffer[i];
                }
                // cout<<"===================================================="<<endl;
                cout << "Received Message from Server: " << msg << endl;
                if (msg != "chat_ok_reply")
                {
                    cerr << "Unexpected response from server" << endl;
                    SSL_CTX_free(ctx);
                    return;
                }
                // cout<<"........Reconnecting........."<<endl;
                break;
            }
        }

        // Reliability implemented for chat_START_SSL message

        while (true)
        {
            // Send chat_START_SSL message
            strcpy(msg_to_send, "chat_START_SSL");
            if (sendto(clientSocket, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr *)&serverAddr, serverLen) < 0)
            {
                cerr << "Error sending message to server..." << endl;
                return;
            }

            // Receive chat_START_SSL_ACK message
            reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&serverAddr, &serverLen);

            if (reply > 0)
            {
                msg_from_server[reply] = '\0';

                string msg = "";
                for (int i = 0; i < reply; i++)
                {
                    msg += buffer[i];
                }

                cout << "Received Message from Server: " << msg << endl;

                if (msg == "chat_START_SSL_NOT_SUPPORTED")
                {
                    cout << "\n***Alert***" << endl;
                    cerr << "Bob does not have capability to set up secure chat communication" << endl;
                    SSL_CTX_free(ctx);
                    timeout.tv_sec = 20;
                    timeout.tv_usec = 0;
                    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
                    normal_socket_communication(clientSocket, serverAddr); // Fallback to normal socket communication
                    return;
                }

                else if (msg != "chat_START_SSL_ACK")
                {
                    cerr << "Unexpected response from server" << endl;
                    SSL_CTX_free(ctx);
                    return;
                }
                else if (msg == "chat_START_SSL_ACK")
                {
                    break;
                }
            }
            else
            {
                cout << ".......Reconnecting......." << endl;
            }
        }

        // Reset timeout value
        timeout.tv_sec = 20;
        timeout.tv_usec = 0;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

        // Load CA certificate and set up verification locations
        if (SSL_CTX_load_verify_locations(ctx, COMBINED_CERT_PATH, NULL) != 1)
        {
            perror("Failed to load CA certificate for verification");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            cout << ":" << endl;
            return;
        };

        int f = 0;
        while (true)
        {
            SSL_set_fd(ssl, clientSocket);

            // Perform SSL handshake
            if (SSL_connect(ssl) <= 0)
            {
                perror("SSL handshake failed");
                SSL_free(ssl);
                SSL_CTX_free(ctx);

                return;
            }
            else
            {
                f = 1;
                break;
            }
        }

        // DTLS v1.2 Handshake Successful
        cout << "....DTLS v1.2 Handshake Successful...." << endl;

        cout << "====================================================" << endl;

        // Now actual messages can be exchanged
        while (true)
        {

            char msg[BUFFER_SIZE];
            cout << "Send Message: ";
            cin.getline(msg, BUFFER_SIZE);
            SSL_write(ssl, msg, strlen(msg));

            string chatmsg = "";
            for (int i = 0; i < 10; i++)
            {
                chatmsg += msg[i];
            }

            if (chatmsg == "chat_close")
            {
                cout << "\n***Alert***" << endl;
                cout << "Closing Client ...." << endl;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                return;
            }

            cout << "Waiting for Server Message..." << endl;
            reply = SSL_read(ssl, msg_from_server, BUFFER_SIZE);

            if (reply == 0)
            {
                cout << "\n***Alert***" << endl;
                cout << "Closing Client ...." << endl;
                cout << "-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x" << endl;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                return;
            }
            if (reply > 0)
            {
                msg_from_server[reply] = '\0';
                cout << "Received Message: " << msg_from_server << endl;
                string chatgotmsg = "";
                for (int i = 0; i < reply; i++)
                {
                    chatgotmsg += msg_from_server[i];
                }

                if (chatgotmsg == "chat_close")
                {
                    cout << "\n***Alert***" << endl;
                    cout << "Closing Client ...." << endl;
                    cout << "-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x" << endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return;
                }
            }
            else
            {
                return;
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }

    void normal_socket_communication(int clientSocket, struct sockaddr_in serverAddr)
    {

        cout << "\n***Alert***" << endl;
        cout << "Fallback to normal socket communication..." << endl;
        cout << endl;
        char buffer[BUFFER_SIZE];
        int reply;

        cout << "====================================================" << endl;

        while (true)
        {

            // struct sockaddr_in serverAddr;
            socklen_t serverLen = sizeof(serverAddr);
            cout << "Send Message: ";
            cin.getline(buffer, BUFFER_SIZE);

            ssize_t sent_bytes = sendto(clientSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&serverAddr, serverLen);

            if (sent_bytes < 0)
            {
                cerr << "Error sending reply to client..." << endl;
                return;
            }

            string chatsendmsg = "";
            for (int i = 0; i < strlen(buffer); i++)
            {
                chatsendmsg += buffer[i];
            }

            if (chatsendmsg == "chat_close")
            {
                cout << "\n***Alert***" << endl;
                cout << "Normal socket communication terminated." << endl;
                return;
            }

            // Receive message from client
            reply = recvfrom(clientSocket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&serverAddr, &serverLen);
            if (reply < 0)
            {
                cerr << "No message from server, connection closed..." << endl;
                return;
            }

            // Process received message
            buffer[reply] = '\0';
            cout << "Received Message: " << buffer << endl;

            string chatgotmsg = "";
            for (int i = 0; i < reply; i++)
            {
                chatgotmsg += buffer[i];
            }

            if (chatgotmsg == "chat_close")
            {
                cout << "\n***Alert***" << endl;
                cout << "Normal socket communication terminated." << endl;
                return;
            }
        }
    }
};

class Server
{
public:
    int setup_udp_socket()
    {
        int serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (serverSocket == -1)
        {
            perror("Socket creation failed");
            return -1;
        }

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
        serverAddr.sin_port = htons(SERVER_PORT);

        if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
        {
            perror("Bind failed");
            close(serverSocket);
            return -1;
        }

        return serverSocket;
    }

    static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
    {
        memcpy(cookie, "cookie", 6);
        *cookie_len = 6;

        return 1;
    }

    static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
    {
        return 1;
    }

    void normal_socket_communication_server(int serverSocket, struct sockaddr_storage clientAddr, socklen_t clientLen)
    {
        cout << "\n***Alert***" << endl;
        cout << "Fallback to normal socket communication..." << endl;
        char buffer[BUFFER_SIZE];
        int reply;

        while (true)
        {

            // Send reply to client
            cout << "Send Reply: ";
            cin.getline(buffer, BUFFER_SIZE);

            ssize_t sent_bytes = sendto(serverSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&clientAddr, clientLen);
            if (sent_bytes < 0)
            {
                cerr << "Error sending reply to client..." << endl;
                break;
            }
            string chatsendmsg = "";
            for (int i = 0; i < strlen(buffer); i++)
            {
                chatsendmsg += buffer[i];
            }

            if (chatsendmsg == "chat_close")
            {
                cout << "\n***Alert***" << endl;
                cout << "Normal socket communication terminated." << endl;

                return;
            }

            // Receive message from client
            reply = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &clientLen);
            if (reply < 0)
            {
                cerr << "No message from client connection closed..." << endl;
                break;
            }

            // Process received message
            buffer[reply] = '\0';
            cout << "Received Message: " << buffer << endl;

            string chatgotmsg = "";
            for (int i = 0; i < reply; i++)
            {
                chatgotmsg += buffer[i];
            }

            if (chatgotmsg == "chat_close")
            {
                cout << "\n***Alert***" << endl;
                cout << "Normal socket communication terminated." << endl;
                return;
            }
        }
        cout << "\n***Alert***" << endl;
        cout << "Normal socket communication terminated." << endl;
        return;
    }

    int dtls_server()
    {

        serverSocket = setup_udp_socket();

        while (true)
        {

            // Initialize OpenSSL library functions
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();

            // Create SSL context using TLS_server_method() for DTLS compatibility
            SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());

            if (!ctx)
            {
                perror("Failed to create SSL context");
                return -1;
            }

            // Load Bob's certificate and private key
            if (SSL_CTX_use_certificate_file(ctx, BOB_CERT_PATH, SSL_FILETYPE_PEM) <= 0)
            {
                perror("Failed to load Bob's certificate file");
                SSL_CTX_free(ctx);
                return -1;
            }

            if (SSL_CTX_use_PrivateKey_file(ctx, BOB_KEY_PATH, SSL_FILETYPE_PEM) <= 0)
            {
                perror("Failed to load Bob's private key file");
                SSL_CTX_free(ctx);
                return -1;
            }

            SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
            SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
            SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

            // For session resumption
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
            SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"DTLS", strlen("DTLS"));

            // Set the cipher suites for perfect forward secrecy (PFS) at server side
            const char *cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
            if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1)
            {
                cerr << "Failed to set cipher list" << endl;
                SSL_CTX_free(ctx);
                return -1;
            }

            SSL *ssl = NULL;

            if (serverSocket == -1)
            {
                break;
            }

            struct sockaddr_storage clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);

            // Exchange application layer control messages
            char msg_from_client[BUFFER_SIZE];
            char msg_to_send[BUFFER_SIZE];
            string chat_hello = "chat_hello";
            char *chat_ok_reply = "chat_ok_reply";

            // Wait for chat_hello message from client

            struct timeval timeout;
            timeout.tv_sec = 20; // 5 seconds timeout
            timeout.tv_usec = 0;
            if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
            {
                std::cerr << "Error setting socket options: " << strerror(errno) << std::endl;
                close(serverSocket);
                return -1;
            }
            int len;
            string msg;
            while (true)
            {
                len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
                msg = "";
                for (int i = 0; i < len; i++)
                {
                    msg += msg_from_client[i];
                }

                if (len > 0)
                {
                    msg_from_client[len] = '\0';
                    if (msg != "chat_hello")
                    {
                        continue;
                    }
                    cout << "Received Message: " << msg << endl;
                    break;
                }
            }
            // Accept the connection and create a new SSL object
            ssl = SSL_new(ctx);

            if (!ssl)
            {
                perror("Failed to accept connection");
                SSL_CTX_free(ctx);
                close(serverSocket);
                return -1;
            }
            int flg = 0;
            // Send chat_ok_reply message
            while (true)
            {
                if (sendto(serverSocket, chat_ok_reply, strlen(chat_ok_reply), 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0)
                {
                    cerr << "Error communicating with client..." << std::endl;
                    SSL_CTX_free(ctx);
                    close(serverSocket);
                    return -1;
                }

                // Exchange SSL control messages

                // Wait for chat_START_SSL message from client
                len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &clientAddrLen);

                if (len > 0)
                {
                    msg_from_client[len] = '\0';
                    msg = "";
                    for (int i = 0; i < len; i++)
                    {
                        msg += msg_from_client[i];
                    }
                    cout << "Received Message: " << msg << endl;

                    if (msg == "chat_close")
                    {
                        flg = 1;
                        break;
                    }
                    // if the message is different form chat_START_SSL server fall back to normal communication
                    if (msg != "chat_START_SSL")
                    {

                        normal_socket_communication_server(serverSocket, clientAddr, clientAddrLen);
                        timeout.tv_sec = 20;
                        timeout.tv_usec = 0;
                        setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
                        flg = 1;
                        break;
                    }
                    if (msg == "chat_START_SSL")
                    {
                        break;
                    }
                }
                else
                {
                    flg = 1;
                    break;
                }
            }
            if (flg == 1)
            {
                // again server is waiting for chat_hello
                cout << "Waiting for client to connect again" << endl;
                continue;
            }

            // time out for server socket
            timeout.tv_sec = 20;
            timeout.tv_usec = 0;
            setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

            // Send chat_START_SSL_ACK message
            strcpy(msg_to_send, "chat_START_SSL_ACK");

            if (sendto(serverSocket, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0)
            {
                cerr << "Error communicating with client..." << std::endl;

                SSL_CTX_free(ctx);
                close(serverSocket);
                return -1;
            }

            BIO *bio = BIO_new_dgram(serverSocket, BIO_NOCLOSE);

            if (!bio)
            {
                perror("Failed to create UDP BIO");
                SSL_CTX_free(ctx);
                close(serverSocket);
                return -1;
            }

            SSL_set_bio(ssl, bio, bio);

            if (DTLSv1_listen(ssl, (BIO_ADDR *)&clientAddr) <= 0)
            {
                cout << "Failed to set DTLS listen" << endl;
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(serverSocket);
                return -1;
            }

            if (SSL_accept(ssl) <= 0)
            {
                cout << "SSL Handshake Failed" << endl;
                cerr << SSL_get_error(ssl, SSL_accept(ssl)) << endl;
                continue;
            }

            // Now actual messages can be exchanged
            while (true)
            {

                char msg[BUFFER_SIZE];
                cout << "Waiting for Client Message..." << endl;
                // Read message from client using SSL_read
                len = SSL_read(ssl, msg, BUFFER_SIZE);
                if (len < 0)
                {
                    cout << "\n***Alert***" << endl;
                    cout << "Connection closed due to inactive conncetion" << endl;
                    break;
                }
                if (len > 0)
                {
                    msg[len] = '\0';
                    cout << "Received Message: " << msg << endl;
                    string msggot = "";

                    for (int i = 0; i < len; i++)
                    {
                        msggot += msg[i];
                    }

                    if (msggot == "chat_close")
                    {
                        cout << "\n***Alert***" << endl;
                        cout << "Connection closed from client side" << endl;
                        break;
                    }
                }
                else
                {
                    perror("Failed to receive message from client");
                    break;
                }

                // Send message to client using SSL_write
                cout << "Send Message: ";
                cin.getline(msg, BUFFER_SIZE);
                SSL_write(ssl, msg, strlen(msg));

                if (strcmp(msg, "chat_close") == 0)
                {
                    cout << "....connection closed...." << endl;
                    break;
                }
            }
            // Cleanup
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
        close(serverSocket);
        return 0;
    }
};

int main(int argc, char *argv[])
{
    int opt;
    bool is_client = false;
    bool is_server = false;
    string server_name;

    if (argc != 2 && argc != 3)
    {
        cerr << "Usage: secure_chat_app [-c] [-s server_name]" << endl;
    }

    string option = argv[1];

    if (option == "-c")
    {
        Client client(server_name);
        struct hostent *host = gethostbyname(argv[2]);
        struct in_addr *address = (struct in_addr *)host->h_addr_list[0];

        SERVER_IP = inet_ntoa(*address);

        int clientSocket = client.setting_up_udp_sock_for_conn();

        if (clientSocket == -1)
        {
            return 1;
        }

        client.dtls_client(clientSocket);

        close(clientSocket);
    }
    else if (option == "-s")
    {
        cout << ".................. Server started ................." << endl;

        Server server;

        server.dtls_server();
    }
    else
    {
        cout << "No connection";
    }

    return 0;
}
