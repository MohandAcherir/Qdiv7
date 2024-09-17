# Active Directory (AD) and AD Pentesting Crash Course

## Table of Contents
1. [What is Active Directory (AD)?](#what-is-active-directory-ad)
2. [Core Components of AD](#core-components-of-ad)
    - [Domains](#domains)
    - [Organizational Units (OUs)](#organizational-units-ous)
    - [Objects](#objects)
    - [Domain Controllers (DCs)](#domain-controllers-dcs)
    - [Forest](#forest)
    - [Trust Relationships](#trust-relationships)
3. [AD Authentication and Access](#ad-authentication-and-access)
    - [Kerberos Authentication](#kerberos-authentication)
    - [NTLM Authentication](#ntlm-authentication)
    - [Group Policy](#group-policy)
4. [AD Security Groups and Roles](#ad-security-groups-and-roles)
    - [Administrators](#administrators)
    - [Domain Admins](#domain-admins)
    - [Enterprise Admins](#enterprise-admins)
5. [Pentesting AD](#pentesting-ad)
    - [Reconnaissance](#reconnaissance)
    - [Privilege Escalation](#privilege-escalation)
    - [Lateral Movement](#lateral-movement)
    - [Persistence](#persistence)
6. [Common AD Pentesting Tools](#common-ad-pentesting-tools)
7. [AD Pentesting Methodology](#ad-pentesting-methodology)

---

## What is Active Directory (AD)?
**Active Directory (AD)** is Microsoft's directory service that allows centralized management of resources such as users, computers, and services within a Windows environment. It is widely used by enterprises for authentication and authorization purposes.

## Core Components of AD

### Domains
A domain is a logical grouping of objects (users, computers, etc.) within AD. It forms the basic unit of AD, where all objects within a domain share a common database.

### Organizational Units (OUs)
An **Organizational Unit (OU)** is a container within a domain that helps organize users, groups, and computers for easier management. OUs can have policies applied to them and provide a hierarchical structure.

### Objects
Objects are the various entities within AD. Common objects include:
- **Users**: Represents individuals or service accounts.
- **Groups**: Collections of users or computers, often assigned specific permissions.
- **Computers**: Systems joined to the domain.

### Domain Controllers (DCs)
A **Domain Controller (DC)** is a server responsible for handling authentication requests and enforcing AD policies. It stores the AD database, which includes all objects and security information.

### Forest
A **Forest** is a collection of one or more domains. It is the topmost container in AD, and it defines the security boundary for the entire network.

### Trust Relationships
Trust relationships allow domains to share resources. Trusts can be one-way or two-way, allowing users in one domain to access resources in another.

## AD Authentication and Access

### Kerberos Authentication
Kerberos is the default authentication protocol in AD. It involves issuing **tickets** for access to resources. Key components include:
- **Ticket Granting Ticket (TGT)**: Issued by the Key Distribution Center (KDC).
- **Service Tickets**: Used to access specific services on the network.

### NTLM Authentication
NTLM (NT LAN Manager) is an older authentication protocol still used in some legacy systems. It’s more vulnerable to attacks like pass-the-hash or NTLM relay attacks.

### Group Policy
Group Policy is used to apply settings and configurations across users and computers in the domain. It allows administrators to enforce security settings, software installations, scripts, etc.

## AD Security Groups and Roles

### Administrators
The **Administrators** group has full control over the domain and all objects within it.

### Domain Admins
Members of the **Domain Admins** group have administrative privileges across all machines in the domain.

### Enterprise Admins
**Enterprise Admins** can manage AD objects across the entire AD Forest.

## Pentesting AD

### Reconnaissance
1. **Enumerate AD users, groups, and computers**:
   - Use tools like `ldapsearch` or `BloodHound` to query LDAP for AD objects.
   - PowerShell command to list AD users: 
     ```powershell
     Get-ADUser -Filter *
     ```
2. **Map network shares**:
   - Use tools like `smbmap`, `nmap`, and `rpcclient` to find shared resources.

3. **Find privileged accounts**:
   - Look for accounts in groups like "Domain Admins," "Administrators," or "Enterprise Admins."

### Privilege Escalation
1. **Kerberoasting**:
   - Extract service accounts with SPNs and crack their hashes offline using `GetUserSPNs.py` from Impacket or `Invoke-Kerberoast` in PowerShell.

2. **AS-REP Roasting**:
   - Target users with the "Do not require Kerberos pre-authentication" flag set and extract their hashes using `GetNPUsers.py`.

3. **Exploiting Vulnerable GPOs**:
   - Misconfigured Group Policy Objects can lead to privilege escalation by pushing malicious scripts or settings.

### Lateral Movement
1. **Pass-the-Hash (PtH)**:
   - Using a stolen NTLM hash to authenticate without knowing the plaintext password. Tools like `Mimikatz` and `Impacket` can perform this.

2. **Pass-the-Ticket (PtT)**:
   - Reusing Kerberos tickets extracted from memory to authenticate on other machines. Mimikatz can dump tickets using the `sekurlsa::tickets` module.

3. **Overpass-the-Hash**:
   - Combine NTLM hashes with Kerberos tickets to perform attacks on Kerberos-enabled systems.

### Persistence
1. **Golden Ticket Attack**:
   - Create a forged Kerberos TGT to impersonate any user in the domain, including Domain Admins.
   
2. **Skeleton Key**:
   - Deploy a "skeleton key" on a Domain Controller using Mimikatz to allow authentication using a backdoor password for any user.

## Common AD Pentesting Tools
- **BloodHound**: Graphical tool for AD enumeration and attack path visualization.
- **Mimikatz**: Tool for dumping credentials from memory, performing pass-the-hash, pass-the-ticket, and golden ticket attacks.
- **Impacket**: Collection of Python scripts for network attacks, including Kerberoasting, NTLM relay, and Pass-the-Hash.
- **PowerView**: PowerShell toolkit for network and AD enumeration.

## AD Pentesting Methodology

1. **Information Gathering**:
   - Perform network scanning and enumerate AD structure (users, groups, shares).
   - Use tools like `BloodHound` to map relationships between AD objects.

2. **Privilege Escalation**:
   - Exploit misconfigurations or weak credentials to elevate privileges (Kerberoasting, AS-REP roasting).

3. **Lateral Movement**:
   - Move through the network using compromised accounts (Pass-the-Hash, Pass-the-Ticket).

4. **Persistence**:
   - Deploy techniques to maintain access, such as creating rogue admin accounts or using Golden Tickets.

5. **Cleanup**:
   - Remove tools and scripts to avoid detection but leave persistence mechanisms in place if needed.

