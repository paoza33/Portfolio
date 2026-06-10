---
title: "Kobold"
date: 2026-03-24
side: "red"
tags: ["htb", "linux", "machine", "rce", "cve", "docker"]
summary: "Machine Linux. RCE non authentifiée sur un service exposé, puis élévation root via un abus du socket Docker."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Kobold résolue](/images/kobold.png)

Machine Linux.

## Techniques mises en oeuvre

- Énumération de sous-domaines
- RCE non authentifiée via une CVE sur un service exposé (injection de commande)
- Stabilisation du shell
- Énumération des appartenances de groupe
- Bascule de groupe pour accéder au socket Docker sans mot de passe
- Root via abus du socket Docker (montage du système de fichiers hote et binaire SUID)

## Outils utilisés

- nmap
- ffuf
- Burp Suite
- netcat
- docker
