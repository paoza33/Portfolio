---
title: "Cohort"
date: 2026-08-03
side: "red"
tags: ["htb", "linux", "machine", "web", "ssrf"]
summary: "Machine Linux (facile). Un SSRF réfléchi ouvre l'accès à des services internes, jusqu'à une exécution de code pré-authentifiée puis une élévation locale via une race condition."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Cohort résolue](/images/cohort.png)

Machine Linux, difficulté facile.

## Techniques mises en oeuvre

- Reconnaissance web et découverte d'un portail de validation d'URL
- Analyse d'un bundle JavaScript obfusqué et chiffré côté client pour reconstituer l'API
- SSRF réfléchi (Server-Side Request Forgery)
- Contournement d'un filtre anti-loopback par représentation alternative d'adresse IP
- Cartographie des services internes via le SSRF
- Fuite d'information via un endpoint interne révélant un vhost non devinable
- Exécution de code à distance pré-authentifiée sur un service interne exposé via WebSocket
- Énumération post-exploitation orientée versions des démons privilégiés
- Élévation de privilèges via une race condition (TOCTOU) dans un service privilégié exposé par D-Bus

## Outils utilisés

- nmap
- curl
- débogueur JavaScript du navigateur
- LinPEAS