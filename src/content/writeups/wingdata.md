---
title: "WingData"
date: 2026-05-25
side: "red"
tags: ["htb", "linux", "machine", "rce", "cve", "hash-cracking"]
summary: "Machine Linux. RCE pré-authentification sur un service proxifié, extraction et crack de hashes salés, puis root via une CVE d'extraction d'archive."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine WingData résolue](/images/wingdata.png)

Machine Linux.

## Techniques mises en oeuvre

- Reconnaissance, identification d'une application proxifiée derrière le serveur web
- RCE pré-authentification via une CVE (injection)
- Énumération interne et extraction de fichiers de configuration
- Extraction de hashes et découverte du sel utilisé
- Crack de hashes salés (SHA256 avec sel)
- Accès SSH
- Root via une CVE d'extraction d'archive permettant une écriture arbitraire (abus de liens symboliques et physiques)

## Outils utilisés

- nmap
- ffuf
- hashcat
- ssh
- PoC public de la CVE
