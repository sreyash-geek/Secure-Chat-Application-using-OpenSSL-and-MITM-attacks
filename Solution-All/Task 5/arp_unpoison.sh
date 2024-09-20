# Define Alice and Bob's IP addresses
bob_ip="172.31.0.149"
alice_ip="172.31.0.168"


# Flush ARP cache on Alice and Bob
echo "...Flushing ARP cache on Alice and Bob..."
sudo ip neigh flush all

# Send ARP requests to refresh the ARP cache with the correct MAC addresses
echo "Sending ARP requests to refresh ARP cache..."
sudo arping -U -I eth0 -c 3 $alice_ip
sudo arping -U -I eth0 -c 3 $bob_ip

echo "ARP cache has been restored to its original state."
