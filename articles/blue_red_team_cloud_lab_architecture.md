
# Blue Team and Red Team Cloud Lab Architecture

In this cloud lab setup, we will create a virtual environment with different machines mimicking a Blue Team and Red Team scenario for cybersecurity testing and learning. The lab will include:
- **1 Domain Controller (DC)** (Windows Server),
- **2 Windows Workstations**,
- **1 Linux Server**,
- **1 Linux Workstation**, and
- **1 ELK/SIEM Machine** to monitor and analyze logs.

This architecture will simulate a small network environment with appropriate segmentation, routing, and logging, following best practices for security, logging, and isolation.

## Architecture Overview

### **1. VPC Setup (Virtual Private Cloud)**

We will create **one VPC** for the whole environment to keep everything in a single network, but with multiple subnets to logically separate network components.

- **VPC CIDR**: `10.0.0.0/16`

### **2. Subnet and Network Segmentation**

We will divide the VPC into **three subnets** to isolate different components:

1. **Management Subnet (Public Subnet)**: Hosts for administration (e.g., the ELK/SIEM machine) that need public internet access.
   - **CIDR**: `10.0.0.0/24`
   - Machines: ELK/SIEM, Management tools

2. **Blue Team Subnet (Private Subnet)**: Hosts for the Blue Team including the Domain Controller, workstations, and Linux machines.
   - **CIDR**: `10.0.1.0/24`
   - Machines: DC, Windows Workstations, Linux Workstation, Linux Server

3. **Red Team Subnet (Private Subnet)**: Hosts for the Red Team, typically isolated to simulate attacks.
   - **CIDR**: `10.0.2.0/24`
   - Machines: Can be reserved for Red Team attack machines if needed.

### **3. Security Groups**

Security Groups (SGs) control inbound and outbound traffic at the instance level. We will create separate security groups for each set of machines based on their roles.

#### **ELK/SIEM Security Group (SG_ELK)**

- **Inbound Rules**:
  - Allow traffic from **Blue Team Subnet (10.0.1.0/24)** for log forwarding (TCP/UDP 5044, 5601).
  - Allow RDP/SSH from **Management Subnet** for remote management.
- **Outbound Rules**:
  - Allow all outbound to internal network.
  - Allow outbound to the Internet for updates.

#### **Blue Team Security Group (SG_BlueTeam)**

- **Inbound Rules**:
  - Allow inbound RDP (3389) and SSH (22) from **Management Subnet** for administration.
  - Allow specific traffic for domain communications (e.g., Kerberos, LDAP, DNS) within the subnet.
  - Allow logging/metric traffic to the **ELK/SIEM machine**.
- **Outbound Rules**:
  - Allow all outbound traffic to the **SIEM** (for logging).
  - Block Internet access (except updates from allowed domains).

#### **Red Team Security Group (SG_RedTeam)**

- **Inbound Rules**:
  - Minimal inbound rules for isolation.
  - Allow specific inbound connections only from the **Management Subnet**.
- **Outbound Rules**:
  - Allow outbound to the **Blue Team Subnet** (for attack simulation).
  - Block access to the Internet (unless for controlled testing).

### **4. Route Tables and Internet Gateway**

- **Public Subnet (Management)** will be associated with a route table that directs **0.0.0.0/0** traffic through the **Internet Gateway (IGW)**.
- **Private Subnets (Blue Team & Red Team)** will use **NAT Gateway** for accessing the Internet for updates and patches, without exposing them directly to the Internet.

### **5. Elastic Load Balancer (Optional)**

If you want to simulate load-balancing scenarios for Blue Team or Red Team, an **Elastic Load Balancer (ELB)** can be set up between subnets.

## Detailed Machine Configuration

### **1. Domain Controller (Windows Server 2019/2022)**
- **Role**: Centralized authentication and management (Active Directory, DNS).
- **Subnet**: Blue Team Subnet (10.0.1.0/24)
- **Security Group**: SG_BlueTeam
- **Logging**: Forward logs to ELK.

### **2. Windows Workstations (Windows 10/11)** (2 Machines)
- **Role**: Test Blue Team defenses, simulate user activity.
- **Subnet**: Blue Team Subnet (10.0.1.0/24)
- **Security Group**: SG_BlueTeam
- **Logging**: Forward event logs to ELK.

### **3. Linux Server (Ubuntu/CentOS)**
- **Role**: Host services like web servers, simulate attacks against it.
- **Subnet**: Blue Team Subnet (10.0.1.0/24)
- **Security Group**: SG_BlueTeam
- **Logging**: Forward logs to ELK.

### **4. Linux Workstation (Kali/Ubuntu)**
- **Role**: Blue Team tool use (e.g., packet capture, analysis).
- **Subnet**: Blue Team Subnet (10.0.1.0/24)
- **Security Group**: SG_BlueTeam
- **Logging**: Forward logs to ELK.

### **5. ELK/SIEM Machine (Ubuntu with ELK Stack)**
- **Role**: Centralized log collection and SIEM (Elasticsearch, Logstash, Kibana).
- **Subnet**: Management Subnet (10.0.0.0/24)
- **Security Group**: SG_ELK
- **Access**: Accessible from Management Subnet for remote management.

## Network Diagram

```
                     +-------------------------+
                     |      Internet Gateway    |
                     +-------------------------+
                                  |
                      +-----------------------------+
                      | VPC: 10.0.0.0/16            |
                      +-----------------------------+
                                  |
             +-----------------------------------------+
             |                Route Table             |
             +--------------------+--------------------+
                                  |
                  +-----------------------+
                  |    Management Subnet   |    (Public)
                  |     10.0.0.0/24       |    (IGW)
                  +-----------------------+
                           |
        +-----------------------------+
        | ELK/SIEM Machine             |
        +-----------------------------+
         
         +-------------------------------+
         | Blue Team Subnet (10.0.1.0/24) |  (Private)
         +--------------------------------+
                 |            |         |
           +------------+  +------------+  +------------+
           | Domain Ctrl |  | Workstation |  | Linux WS  |
           +------------+  +------------+  +------------+
                |               |              |
           +------------+   +------------+   +------------+
           |  Linux Srv  |   | Workstation 2 |   
           +------------+   +------------+

         +-------------------------------+
         | Red Team Subnet (10.0.2.0/24)  |  (Private, optional)
         +-------------------------------+
         
```

## Additional Considerations

- **Monitoring**: Ensure that all machines have metrics and logs sent to the ELK/SIEM server. Use **Beats** (e.g., Filebeat, Metricbeat) on each machine to forward logs to the ELK server.
- **Isolation**: Ensure that Red Team machines are isolated as much as possible, with minimal communication allowed between Blue Team and Red Team except for controlled simulations.
- **Automation**: Consider using **AWS CloudFormation** or **Terraform** to automate the deployment of this architecture.

This setup provides an effective sandbox for Blue and Red Team cybersecurity exercises, with sufficient network segmentation and security configurations to simulate real-world scenarios.
