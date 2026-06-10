---
title: "Connected"
date: 2026-06-07
side: "red"
tags: ["htb", "linux", "machine", "sqli", "rce", "cve"]
summary: "Machine Linux. SQLi non authentifiée menant à une RCE, puis root via un déclencheur incron exécuté sur un chemin inscriptible."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Connected résolue](/images/connected.png)

Machine Linux.

## Techniques mises en oeuvre

- Reconnaissance, name-based virtual hosting détecté via le certificat TLS
- Fingerprinting (logiciel de téléphonie et version)
- RCE via une injection SQL non authentifiée (CVE)
- Énumération locale automatisée et surveillance des processus root
- Identification d'un déclencheur incron exécuté en root sur un chemin inscriptible
- Root par injection de code chargé par le script root (bash SUID)

## Outils utilisés

- nmap
- ffuf
- Metasploit
- pspy
- LinPEAS
