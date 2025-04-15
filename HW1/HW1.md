# NYCU NA 2025 HW1

#### Spec: https://nasa.cs.nycu.edu.tw/na/2025/slides/HW1.pdf

#### OS: Debian 12.9.0

---

## WireGuard Installation and Configuration

```bash
sudo apt install wireguard

# Move WireGuard configuration
sudo mv wg0.conf /etc/wireguard

# Enable WireGuard on boot
sudo systemctl enable wg-quick@wg0

# Start WireGuard
sudo wg-quick up wg0
```
## Network Interfaces Configuration

```bash
# Check Interfaces
ip a
```

####  Edit `/etc/network/interfaces`

```vim=
# External Interface (WAN) - Dynamic IP via DHCP
allow-hotplug enp0s3
iface enp0s3 inet dhcp

# Internal Interface (LAN) - Static IP
allow-hotplug enp0s8
iface enp0s8 inet static
    address 192.168.4.254
    netmask 255.255.255.0
```

## Enable Packet Forwarding

### Method 1
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### Method 2

#### Edit `/etc/sysctl.conf`

```vim=
net.ipv4.ip_forward
```


```bash
# Apply Changes
sudo sysctl -p
```

## Configure NAT (Masquerading)

```bash
# NAT on external interface
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

# Install iptables-persistent to make rules persistent
sudo apt install iptables-persistent
```

> On first install, the current iptables rules are saved to `/etc/iptables/rules.v4`

```bash
# View current NAT settings
sudo iptables -t nat -L -v -n
```

## Setup DHCP Server

```bash
sudo apt install isc-dhcp-server
```

#### Edit `/etc/default/isc-dhcp-server`

```vim=
INTERFACESv4="enp0s8"
```

#### Edit `/etc/dhcp/dhcpd.conf`

```vim=
subnet 192.168.4.0 netmask 255.255.255.0 {
  range 192.168.4.111 192.168.4.222;
  option routers 192.168.4.254;
}

host agent {
  hardware ethernet XX:XX:XX:XX:XX:XX;
  fixed-address 192.168.4.234;
}
```

```bash
sudo systemctl restart isc-dhcp-server
```

## Firewall Configuration

###  
```bash
# Save current iptables settings
sudo netfilter-persistent save

# Flush and reset iptables
sudo iptables -F
sudo iptables -X
```

### Set Default Policies

```bash
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

### Allow Required Services

```bash
# Accept Loopback Interface
sudo iptables -A INPUT -i lo -j ACCEPT
# Drop SSH from VPN zone to Router
sudo iptables -A INPUT -i wg0 -p tcp --dport 22 -j DROP
# ICMP to Router
sudo iptables -A INPUT -p icmp -j ACCEPT                                   

# Forward ICMP packets
sudo iptables -A FORWARD -p icmp -j ACCEPT				       
# SSH to Agent 
sudo iptables -A FORWARD -p tcp --dport 22 -d 192.168.4.234 -j ACCEPT   
# HTTP from Private LAN to VPN zone
sudo iptables -A FORWARD -i enp0s8 -o wg0 -p tcp --dport 80 -j ACCEPT
# HTTPS from Private LAN to VPN zone
sudo iptables -A FORWARD -i enp0s8 -o wg0 -p tcp --dport 443 -j ACCEPT
```

### Restrict Traffic Between Zones

```bash
# Drop from Internet to Private LAN
sudo iptables -A FORWARD -i enp0s3 -d 192.168.4.0/24 -j DROP

# Drop VPN zone to Private LAN
sudo iptables -A FORWARD -i wg0 -d 192.168.4.0/24 -j DROP

# Do NOT enable this (Drop from Private LAN to VPN zone)
# sudo iptables -A FORWARD -i enp0s8 -o wg0 -j DROP
```
