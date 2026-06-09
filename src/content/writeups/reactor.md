---
title: "Reactor"
date: 2026-06-01
side: "red"
tags: ["htb", "linux", "machine", "rce", "deserialization", "ssh-tunneling"]
summary: "Machine Linux. RCE pré-authentification par désérialisation, exfiltration d'une base SQLite, crack de hash, puis root via abus d'un débogueur interne."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Reactor résolue](/images/reactor.png)

Machine Linux.

## Techniques mises en oeuvre

- Reconnaissance, identification du framework web
- RCE pré-authentification par désérialisation non sécurisée (CVE)
- Exfiltration et lecture d'une base de données SQLite
- Crack d'un hash MD5
- Accès SSH
- Découverte d'un débogueur interne par énumération des ports locaux
- Redirection de port vers le débogueur
- Root via abus du débogueur (exécution de code en contexte root)

## Outils utilisés

- nmap
- hashcat
- ssh (redirection de port)
- Chromium DevTools
- PoC public de la CVE
