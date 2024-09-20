
# Secure Chat App using DTLSv1.2 and UDP in C++

#### Linux CLI commands to run the secure_chat_app.cpp as a server and client.
Follow the below given instructions:

### Client
```
g++ secure_chat_app.cpp -lssl -lcrypto
./a.out -c <client_ip_addr/hostname>
```

### Server
```
g++ secure_chat_app.cpp -lssl -lcrypto
./a.out -s
```

Now, you can start using the Secure Chat App.