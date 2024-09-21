
# Setting Up a DNS Server on Linux Using BIND9

This guide will walk you through setting up a DNS server on a Linux-based system using BIND (Berkeley Internet Name Domain) version 9.

## Prerequisites
- A Linux-based server (Ubuntu, Debian, or CentOS).
- Root or `sudo` access.
- A static IP address for your server.

## Step 1: Update Your Server
Before installing any packages, make sure your server is up-to-date.

### On Ubuntu/Debian:
```bash
sudo apt update && sudo apt upgrade -y
```

### On CentOS:
```bash
sudo yum update -y
```

## Step 2: Install BIND9

### On Ubuntu/Debian:
```bash
sudo apt install bind9 bind9utils bind9-doc -y
```

### On CentOS:
```bash
sudo yum install bind bind-utils -y
```

## Step 3: Configure BIND

### 1. **Edit BIND Configuration File**
Open the BIND configuration file located in `/etc/bind/named.conf.options` for Ubuntu/Debian or `/etc/named.conf` for CentOS.

#### On Ubuntu/Debian:
```bash
sudo nano /etc/bind/named.conf.options
```

#### On CentOS:
```bash
sudo nano /etc/named.conf
```

### 2. **Update the Configuration:**
Add or modify the following options:
```bash
options {
    directory "/var/cache/bind";
    
    // Use your server's IP in the 'listen-on' directive
    listen-on { 127.0.0.1; your_server_ip; };
    
    // Specify trusted IPs (for recursion)
    allow-query { localhost; your_network/24; };
    
    recursion yes;
    dnssec-validation auto;
    auth-nxdomain no;
};
```

### 3. **Configure a Forward and Reverse Zone**
Create a forward zone file to map domain names to IP addresses and a reverse zone file to map IP addresses to domain names.

#### Create the Forward Zone
Edit the `/etc/bind/named.conf.local` file:
```bash
sudo nano /etc/bind/named.conf.local
```

Add the forward zone configuration:
```bash
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
};
```

#### Create the Reverse Zone
Add the reverse zone configuration in the same file:
```bash
zone "1.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.192.168.1";
};
```

### 4. **Create Zone Files**

#### Create a Directory for Zone Files
```bash
sudo mkdir /etc/bind/zones
```

#### Create the Forward Zone File
```bash
sudo nano /etc/bind/zones/db.example.com
```

Add the following content:
```bash
$TTL    604800
@       IN      SOA     ns1.example.com. admin.example.com. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.example.com.
@       IN      A       192.168.1.10
ns1     IN      A       192.168.1.10
www     IN      A       192.168.1.10
```

#### Create the Reverse Zone File
```bash
sudo nano /etc/bind/zones/db.192.168.1
```

Add the following content:
```bash
$TTL    604800
@       IN      SOA     ns1.example.com. admin.example.com. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.example.com.
10      IN      PTR     example.com.
```

### 5. **Set Proper File Permissions**
Ensure that the BIND user can read the zone files:
```bash
sudo chown bind:bind /etc/bind/zones/db.example.com /etc/bind/zones/db.192.168.1
```

## Step 4: Verify and Start BIND9

### 1. **Check BIND Configuration**
Use the following command to check for any syntax errors in the configuration:
```bash
sudo named-checkconf
```

### 2. **Check Zone Files**
Verify the syntax of your zone files:
```bash
sudo named-checkzone example.com /etc/bind/zones/db.example.com
sudo named-checkzone 1.168.192.in-addr.arpa /etc/bind/zones/db.192.168.1
```

### 3. **Start BIND9 Service**

#### On Ubuntu/Debian:
```bash
sudo systemctl restart bind9
sudo systemctl enable bind9
```

#### On CentOS:
```bash
sudo systemctl restart named
sudo systemctl enable named
```

## Step 5: Test the DNS Server

### 1. **Update Your Local DNS Resolver**
Edit the `/etc/resolv.conf` file on your local machine or server and set your DNS server:
```bash
sudo nano /etc/resolv.conf
```

Add:
```bash
nameserver 192.168.1.10  # Your DNS server's IP
```

### 2. **Test Using the `dig` Command**
Use `dig` to query your DNS server:
```bash
dig @192.168.1.10 example.com
```

You should see a response with the A record pointing to `192.168.1.10`.

---

Your BIND9 DNS server is now set up and running. You can configure additional zones and records as needed.
