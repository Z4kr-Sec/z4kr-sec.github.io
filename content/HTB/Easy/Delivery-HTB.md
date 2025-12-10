---
categories:
- write-up
- Linux
- Easy
date: "2024-12-12T00:00:00Z"
title: Delivery - Hack The Box
toc: true
displayUpdatedDate: true
enableInlineShortcodes: true
layout: list
---

![](/assets/images/HTB/Delivery/Delivery-Logo.png)

This Hack The Box machine details a penetration testing journey, starting with initial access gained by exploiting a misconfigured Mattermost server through a ticket registration system. The write-up then covers leveraging exposed credentials found within the Mattermost chat to access a MySQL database, followed by extracting and cracking password hashes using Hashcat to achieve full root compromise.

{{< callout type="info" >}}
  Tags:

{{% details title="show tags"  closed="true" %}}

- Mattermost
- MySQL
- Hashcat

{{% /details %}}
{{< /callout >}}

## Enumeration
### Port Scan
We start with an Nmap scan:
* nmap -sS -sV -sC -p- -vvv -oA nmap/allPorts 10.10.10.222

```bash
# Nmap 7.93 scan initiated Fri Mar  3 10:50:32 2023 as: nmap -sS -sV -sC -p- -vvv -oA nmap/allPorts 10.10.10.222
Nmap scan report for 10.10.10.222
Host is up, received echo-reply ttl 63 (0.047s latency).
Scanned at 2023-03-03 10:50:32 EST for 216s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c40fa859b01acac0ebc0c19518aee27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCq549E025Q9FR27LDR6WZRQ52ikKjKUQLmE9ndEKjB0i1qOoL+WzkvqTdqEU6fFW6AqUIdSEd7GMNSMOk66otFgSoerK6MmH5IZjy4JqMoNVPDdWfmEiagBlG3H7IZ7yAO8gcg0RRrIQjE7XTMV09GmxEUtjojoLoqudUvbUi8COHCO6baVmyjZRlXRCQ6qTKIxRZbUAo0GOY8bYmf9sMLf70w6u/xbE2EYDFH+w60ES2K906x7lyfEPe73NfAIEhHNL8DBAUfQWzQjVjYNOLqGp/WdlKA1RLAOklpIdJQ9iehsH0q6nqjeTUv47mIHUiqaM+vlkCEAN3AAQH5mB/1
|   256 5a0cc03b9b76552e6ec4f4b95d761709 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAiAKnk2lw0GxzzqMXNsPQ1bTk35WwxCa3ED5H34T1yYMiXnRlfssJwso60D34/IM8vYXH0rznR9tHvjdN7R3hY=
|   256 b79df7489da2f27630fd42d3353a808c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV5D6eYjySqfhW4l4IF1SZkZHxIRihnY6Mn6D8mLEW7
80/tcp   open  http    syn-ack ttl 63 nginx 1.14.2
|_http-title: Welcome
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Fri, 03 Mar 2023 15:39:20 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: rqguydjcq7fu7my6o44o7sw5pc
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Fri, 03 Mar 2023 15:52:43 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Fri, 03 Mar 2023 15:52:43 GMT
|_    Content-Length: 0

```



As I usually do, I start with the port that I feel most comfortable with, which in this case is port 80. This is a standard page, but if we go to the **contact us** page, we can find the hostname for the webserver and a subdomain. 
![](/assets/images/HTB/Delivery/Delivery-1.png)

![](/assets/images/HTB/Delivery/Delivery-2.png)

From this, we see that we need a **@delivery.htb** email address to access the **Mattermost** server that is hosted on port 8065. To access these two pages, we need to add them to the `/etc/hosts` file:

- http://helpdesk.delivery.htb
- http://delivery.htb
## Foothold
### Support Page.

On http://helpdesk.delivery.htb, we find a support ticketing system.

![](/assets/images/HTB/Delivery/Delivery-3.png)

Since we don't have any credentials or a ticket number, we proceed to create a new ticket (filling in only the mandatory fields).


![](/assets/images/HTB/Delivery/Delivery-4.png)


After creating the ticket, the system indicates that we can add more information by sending an email to **6153164@delivery.htb**.


![](/assets/images/HTB/Delivery/Delivery-5.png)

If we try to check or update the ticket, we can change details (such as the ticket name or add more comments), but we are not able to do much more from here.

Now looking for other alternatives, I proceed to check the page that's hosting the Mattermost Service. This is an online chat with file sharing, search, and integrations. Also created as an internal chat for organizations and companies, it is also considered **a viable alternative to SLACK**. If you want to read more about Mattermost please refer to their [documentation](https://docs.mattermost.com/about/product.html#the-mattermost-platform).

### Mattermost.

Moving on, I went to *http://Delivery.htb:8065* and I was able to find mattermost's login page.

![](/assets/images/HTB/Delivery/Delivery-6.png)

Until this point, I don't have any credentials. So I opt for creating a new account, but if we recall from the earlier enumeration, we need a **@Delivery.htb** email to access the chat server.


When we try to complete the process with a random email (winzacar@yopmail.com) it says that it will send a confirmation email to validate the user. Our problem here is that the boxes from HTB are not connected to the internet, thus we cannot receive any "external" emails.

My theory at this point was to register with **6153164@delivery.htb** as our email, so the confirmation email would update our ticket, allowing me to verify my Mattermost registration.

![](/assets/images/HTB/Delivery/Delivery-7.png)

![](/assets/images/HTB/Delivery/Delivery-8.png)

Now, we have to go back to *http://helpdesk.delivery.htb* and check the ticket status. For this, I need to "login" with our email and the ticket number. We are able to see that the comments have been updated with the Mattermost email confirmation.


![](/assets/images/HTB/Delivery/Delivery-9.png)

#### Mattermost Login

It says I'm registered successfully. By clicking the confirmation link, our email is verified, and we can now log in to Mattermost.

![](/assets/images/HTB/Delivery/Delivery-10.png)

After logging in, we are prompted to select a team to join; in our case, we only have one option, which is "Internal".

![](/assets/images/HTB/Delivery/Delivery-11.png)

After selecting the team, we are added to a chat and can see some credentials that are being reused in other places.

![](/assets/images/HTB/Delivery/Delivery-12.png)

- **user =** maildeliverer
- **Pass =** Youve_G0t_Mail!

Then, I tested the credentials with `crackmapexec` to check if they were valid for SSH.
```bash
crackmapexec ssh 10.10.10.222 -u maildeliverer  -p Youve_G0t_Mail!
```
### SSH Login

After confirming that they are valid, I proceed to log in to the machine via SSH.
```bash
ssh maildeliverer@10.10.10.222
```
![](/assets/images/HTB/Delivery/Delivery-13.png)

Here, we are able to get the ***user.txt*** flag.

![](/assets/images/HTB/Delivery/Delivery-14.png)

## Privilege Escalation 

Moving on with privilege escalation, I decided to check which users have the ability to execute shell commands and found three:
```bash
cat /etc/passwd | grep sh$
```

![](/assets/images/HTB/Delivery/Delivery-15.png)


As we are logged in as `mailserver`, my first idea after finding these users was to check the Mattermost folder. For that, I just ran the following command and was able to find it in the `/opt` directory.

```bash
find / -user mattermost 2>/dev/null | grep -v -E 'sys|proc|run'
```
After looking into the files contained in that folder, I'm able to find inside the `config` folder a `config.json` file that contains credentials to log in to the SQL server.

![](/assets/images/HTB/Delivery/Delivery-16.png)
### MySQL Server
I connected to the MySQL database with the credentials. For an extra explanation on how to connect to the database, please refer to the following [Link](https://www.jetbrains.com/help/datagrip/how-to-connect-to-mysql-with-unix-sockets.html#ec6a30bd).

```bash
mysql -h localhost -u mmuser -p
# The password is: Crack_The_MM_Admin_PW
```
- **-h** --> hostname 
- **-u** --> username
- **-p** --> password

With the help of `netstat` (or `linpeas`), I was able to see that port 3306 was listening on localhost.
![](/assets/images/HTB/Delivery/Delivery-17.png)

Then, after being logged in, we can find the *Mattermost* database.
```sql
show databases;
```

![](/assets/images/HTB/Delivery/Delivery-18.png)

```sql
use mattermost;
show tables;
```

![](/assets/images/HTB/Delivery/Delivery-19.png)

Traversing the data, I'm able to find some usernames and passwords in the `Users` table.

```sql
SELECT Username, Password, EmailVerified FROM Users;
```
![](/assets/images/HTB/Delivery/Delivery-20.png)


## Getting Root Password
From the following query, I was able to find the root user's hash. We can identify the hash type using `hashid`. To find more on how to [identify Hashes](https://miloserdov.org/?p=1254).
```bash
hashid -m '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO'
```

![](/assets/images/HTB/Delivery/Delivery-21.png)

As seen in the Mattermost chat, I need to create some variants (add some rules) of the password **PleaseSubscribe** to crack the hash that we got. To learn more about how to add rules to an existing password, please refer to the following [link](https://www.youtube.com/watch?v=SAvo_h7WSUc).

```bash
hashcat --force pass.txt -r /usr/share/hashcat/rules/best64.rule --stdout
```

![](/assets/images/HTB/Delivery/Delivery-22.png)

With the new dictionary created, we are able to crack the password with the help of Hashcat.

```bash
hashcat -m 3200 hash_root dict.txt
```
![](/assets/images/HTB/Delivery/Delivery-23.png)

Finally, I just need to log in as root with the cracked password, and we are able to find the **root.txt** flag.

```bash
ssh root@10.10.10.222
```

![](/assets/images/HTB/Delivery/Delivery-24.png)
