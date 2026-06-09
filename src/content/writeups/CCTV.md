---
title: "CCTV"
date: 2026-06-09
side: "red"
tags: ["htb","machine", "linux", "sqli", "rce", "privesc"]
summary: "Machine Linux résolue. Chaîne web vers root : CVE sur l'application, réutilisation d'identifiants, pivot SSH, puis injection de commande sur un service local en root."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine CCTV résolue](/images/CCTV.png)

Machine Linux, compromise de bout en bout jusqu'au root.

## Techniques mises en oeuvre

- Reconnaissance et identification précise de la version du logiciel web
- Accès initial via une CVE de l'application web (injection SQL) permettant l'extraction de secrets en base
- Crack d'un hash bcrypt par attaque par dictionnaire
- Réutilisation d'identifiants pour un accès SSH
- Énumération des services internes à l'hote
- Pivot via tunneling SSH (redirection de port) vers un service accessible seulement en local
- Élévation de privilèges par injection de commande dans un service local exécuté en root (RCE)

## Outils utilisés

- PoC public de la CVE
- john (crack du hash)
- ssh (accès et redirection de port)
- netcat (réception du shell)
- curl (déclenchement de l'exécution)