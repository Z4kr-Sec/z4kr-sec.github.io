---
title: "HTB Write-Ups"
date: 2025-04-26T16:19:56-04:00
toc: false
displayUpdatedDate: true
enableInlineShortcodes: true
layout: list
draft: false
---


{{< figure
  src="/assets/images/HTB/HTB-main-logo.png"
  height= 350
  width= 650
>}}

## 2025

{{% details title="Heal" closed="true" %}}


{{< figure
  src="/assets/images/HTB/Heal/Heal-LOGO.png"
  link="/htb/medium/heal-htb/"
  height= 400
  width= 400
>}}

Heal is a Medium-rated Linux machine on Hack The Box that challenges us to exploit a web API and leverage misconfigurations in internal services. The initial foothold involves identifying an LFI vulnerability within a resume builder application, which leads to leaking the database of a LimeSurvey instance. After cracking the administrator password, we exploit an authenticated RCE (CVE-2021-44967) to gain a shell. Lateral movement is achieved by finding credentials in configuration files, and root privileges are obtained by exploiting a misconfigured Consul service using CVE-2021-41805.

Continue to **[Heal](/htb/medium/heal-htb/)**

##### Hands On!
{{< icon "HTB-icon" >}} Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/580)**

{{% /details %}}

{{% details title="Administrator" closed="true" %}}

{{< figure
  src="/assets/images/HTB/Administrator/Administrator-LOGO.png"
  link="/htb/medium/administrator/"
  height= 400
  width= 400
>}}

This Hack The Box machine focuses on exploiting Active Directory weaknesses. Starting with user credentials, we use Bloodhound to map the domain and identify exploitable `GenericAll` permissions, which allows for a password reset using tools like `net rpc`. The investigation then uncovers an FTP server with a PasswordSafe file. Cracking this file with `pwsafe2john` and John the Ripper provides further credentials, which are leveraged to exploit ForceChangePassword privileges and perform a targeted Kerberoast attack. The final step involves a `DCSync` attack via Impacket to retrieve domain admin hashes and gain complete control.

Continue to **[Administrator](/htb/medium/administrator/)**

##### Hands On!
{{< icon "HTB-icon" >}}  Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/634)**

{{% /details %}}


{{% details title="Sea" closed="true" %}}

{{< figure
  src="/assets/images/HTB/Sea/sea%20LOGO.png"
  link="/htb/easy/sea-htb/"
  height= 400
  width= 400
>}}

Sea is an Easy-rated Linux machine on Hack The Box that requires thorough web enumeration to uncover hidden directories and identify a vulnerable theme. Exploiting CVE-2023-41425 allows for remote code execution, leading to an initial foothold. A hashed password found in a database file is cracked to gain SSH access as a user. Privilege escalation is achieved by tunneling into a locally hosted service, leveraging access logs to execute commands as root.

Continue to **[Sea](/htb/easy/sea-htb/)**

##### Hands On!
{{< icon "HTB-icon" >}} Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/620)**

{{% /details %}}

## 2024

{{% details title="Surveillance" closed="true" %}}

{{< figure
  src="/assets/images/HTB/surveillance/Surveillance-LOGO.png"
  link="/htb/medium/surveillance-htb/"
  height= 400
  width= 400
>}}

Surveillance is a Medium-rated machine on Hack The Box. The machine begins with identifying a CMS vulnerability on the webpage hosted on port 80, which grants initial access to the system. Through enumeration, I uncovered a database file containing an encrypted password. Cracking this password allows me to access a ZoneMinder instance running on localhost. By exploiting a known vulnerability in ZoneMinder, I elevate my access to the 'zoneminder' user. The final step involves leveraging sudo privileges to achieve full root access.

Continue to **[Surveillance](/htb/medium/surveillance-htb/)**

##### Hands On!
{{< icon "HTB-icon" >}} Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/580)**

{{% /details %}}

{{% details title="Analytics" closed="true"%}}

{{< figure
  src="/assets/images/HTB/Analytics/Analitics-LOGO.png"
  link="/htb/easy/analytics-htb/"
  height= 400
  width= 400
>}}

This Easy-rated Linux machine on Hack The Box focuses on exploiting a vulnerable instance of *Metabase* to gain initial access. With the help of the exploit - CVE-2023-38646, we obtain command execution on the target. The next phase involves navigating a Docker container environment, leveraging exposed credentials, and transitioning to an SSH session with user-level access. Finally, the privilege escalation is achieved by exploiting a known vulnerability (CVE-2023-2640) in the operating system to gain root access.

Continue to **[Analytics](/htb/easy/analytics-htb/)**

##### Hands On!
{{< icon "HTB-icon" >}}  Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/569)**

{{% /details %}}

{{% details title="Delivery" closed="true" %}}

{{< figure
  src="/assets/images/HTB/Delivery/Delivery-Logo.png"
  link="/htb/easy/delivery-htb/"
  height= 400
  width= 400
>}}

This Easy-rated Linux machine details a penetration testing journey, starting with initial access gained by exploiting a misconfigured Mattermost server through a ticket registration system. The write-up then covers leveraging exposed credentials found within the Mattermost chat to access a MySQL database, followed by extracting and cracking password hashes using Hashcat to achieve full root compromise.

Continue to **[Delivery](/htb/easy/delivery-htb/)**
##### Hands On!
{{< icon "HTB-icon" >}}  Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/308)**

{{% /details %}}


