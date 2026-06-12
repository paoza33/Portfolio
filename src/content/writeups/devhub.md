---
title: "DevHub"
date: 2026-06-05
side: "red"
tags: ["htb", "linux", "machine", "cve"]
summary: "Machine Linux (Ubuntu 24.04). CVE sur un service exposé, pivot vers un service interne, puis root par abus d'un composant privilégié."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine DevHub résolue](/images/devhub.png)
Machine Linux (Ubuntu 24.04).

## Techniques mises en oeuvre

- Énumération
- Exploitation de CVE
- Pivoting
- Élévation vers un utilisateur intermédiaire
- Root par abus d'un composant privilégié

## Outils utilisés

- Outils d'énumération
- Outils de pivot
- ssh