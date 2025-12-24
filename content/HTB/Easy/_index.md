---
title: "Easy"
date: 2025-04-27T23:09:18-04:00
draft: false
weight: 1
---
{{< figure
  src="/assets/images/HTB/easy.jpg"
  height= 200
  width= 400
>}}


## 2025


{{% details title="Editor" closed="true" %}}

{{< figure
  src="/assets/images/HTB/Editor/Editor-LOGO.png"
  link="/htb/easy/editor-htb/"
  height= 400
  width= 400
>}}

Editor is a Linux machine on Hack The Box that highlights the dangers of unpatched *wiki software* and insecure configurations in monitoring tools. The journey starts with identifying a Critical RCE in XWiki (**CVE-2025-24893**) caused by improper input sanitization in Groovy macros. After gaining a foothold, I found database credentials in a configuration file, which allowed for lateral movement to a user via password reuse. Finally, root privileges were obtained by exploiting a vulnerability in the *Netdata agent* (**CVE-2024-32019**) through PATH manipulation.

Continue to **[Editor](/htb/easy/editor-htb/)**

##### Hands On!
{{< icon "HTB-icon" >}}  Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/Editor)**

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
{{< icon "HTB-icon" >}}  Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/620)**

{{% /details %}}


## 2024


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

