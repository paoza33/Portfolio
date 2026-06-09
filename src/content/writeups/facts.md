---
title: "Facts"
date: 2026-05-05
side: "red"
tags: ["htb", "linux", "machine", "web", "cve", "hash-cracking"]
summary: "Machine Linux. Élévation de privilèges applicative par mass assignment, extraction de secrets de stockage objet, clé SSH dans un bucket, puis root via un binaire sudo."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Facts résolue](/images/facts.png)

Machine Linux.

## Techniques mises en oeuvre

- Reconnaissance et fingerprinting (identification du CMS et de sa version exacte)
- Élévation de privilèges applicative par mass assignment via une CVE (compte client promu administrateur)
- Extraction de secrets de stockage objet compatible S3 depuis la configuration
- Récupération d'une clé SSH privée dans un bucket exposé
- Identification de l'utilisateur via le commentaire de la clé publique
- Crack de la passphrase de la clé SSH
- Accès SSH
- Root par abus d'un binaire autorisé en sudo, capable de charger du code arbitraire

## Outils utilisés

- nmap
- ffuf
- Burp Suite
- client de stockage objet (mc)
- john
- ssh
