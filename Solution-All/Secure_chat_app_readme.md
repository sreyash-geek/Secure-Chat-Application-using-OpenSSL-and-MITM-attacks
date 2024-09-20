# Secure Chat App using OpenSSL with MITM attacks

This assignment has 4 major tasks. But for Task 1 there are many commands to run and those are greatly mention in the report step by step. So here in this readme going to discuss about the Task 2, 3 and 4 only (how to run them and steps to follow).

**Setup:** Alice (client), Trudy (interceptor), Bob (server). 

Below are the instructions for each task:

## Task 2: Secure Chat App
To compile the secure_chat_app.cpp file at Alice (client) and Bob (server).
```
g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app
```
To run as a Alice (client): ```./secure_chat_app -c bob1```

To run as a Bob (server):```./secure_chat_app -s```

Use respective terminals / conatiners for the client and server to initiate the chat.

## Task 3: Downgrading the START_SSL
1. Poisoning the DNS resolver of Alice (client) and Bob (server) using the TAs-created file. Run the below mention command in the VM (not in any container).
```bash ./poison_alice1_bob1.sh```

2. Compile and run the Trudy (interceptor)
```g++ secure_chat_interceptor.cpp -o secure_chat_interceptor```

```./secure_chat_interceptor -d alice1 bob1```

3. Compile and run the Bob (server)
```g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app```

```./secure_chat_app -s```

4. Compile and run the client (Alice)
```g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app```

```./secure_chat_app -c bob1```

Start chatting (alice - bob) while Trudy (interceptor) observes the communication after the downgrade.

## Task 4: Active Interceptor
1. Poisoning the DNS resolver of Alice (client) and Bob (server) using the TAs-created file. Run the below mention command in the VM (not in any container). 
```bash ./poison_alice1_bob1.sh```

2. Compile and run the Trudy (active interceptor)
```g++ secure_chat_active_interceptor.cpp -lssl -lcrypto -o secure_chat_active_interceptor```

```./secure_chat_active_interceptor -m alice1 bob1```

3. Compile and run the Bob (server)
```g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app```

```./secure_chat_app -s```

4. Compile and run the Alice (client)
```g++ secure_chat_app.cpp -lssl -lcrypto -o secure_chat_app```

```./secure_chat_app -c bob1```

Initiate the chat where Alice's messages are intercepted by Trudy and then sent to Bob, and vice versa.

**Note: Ensure proper setup and understanding of the tasks before executing the commands. We have stored all the required files according to the Task. So while executing the above commands make sure that you are in the correct directory of container.** 

To check ip mapping at respective conatiner. Run the below command
```cat /etc/hosts```
