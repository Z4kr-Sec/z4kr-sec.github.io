---
title: "Medium"
date: 2025-04-27T23:09:51-04:00
weight: 2
draft: false
---
{{< figure
  src="/assets/images/HTB/medium.jpg"
  height= 200
  width= 400
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
{{< icon "HTB-icon" >}} Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/Heal)**

{{% /details %}}

{{% details title="Administrator" closed="true" %}}


{{< figure
  src="/assets/images/HTB/Administrator/Administrator-LOGO.png"
  link="/htb/medium/administrator/"
  height= 400
  width= 400
>}}

This Medium-rated Windows machine on Hack The Box focuses on the exploitation of Active Directory weaknesses. The path begins with using Bloodhound to map the domain, identifying exploitable `GenericAll` permissions that allow for a password reset. The investigation then uncovers an FTP server with a PasswordSafe file. Cracking this file provides credentials to exploit ForceChangePassword privileges and perform a Kerberoast attack, leading to a full `DCSync` via Impacket for domain dominance.

Continue to **[Administrator](/htb/medium/administrator/)**

##### Hands On!
{{< icon "HTB-icon" >}} Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/634)**

{{% /details %}}

## 2024

{{% details title="Surveillance" closed="true" %}}


{{< figure
  src="/assets/images/HTB/surveillance/Surveillance-LOGO.png"
  link="/htb/medium/surveillance-htb/"
  height= 400
  width= 400
>}}

Surveillance is a Medium-rated Linux machine on Hack The Box that starts with exploiting a vulnerability in the website's CMS for initial access. Enumeration reveals a database file containing an encrypted password, which, once cracked, grants access to a ZoneMinder instance. By exploiting a known vulnerability in ZoneMinder, access is elevated to the `zoneminder` user. The final step involves leveraging sudo privileges to achieve full root access.

Continue to **[Surveillance](/htb/medium/surveillance-htb/)**

##### Hands On!
{{< icon "HTB-icon" >}} Turn on the machine on **[Hack The Box.](https://app.hackthebox.com/machines/580)**

{{% /details %}}