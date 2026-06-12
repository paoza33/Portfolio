---
title: "CCTV"
date: 2026-03-13
side: "red"
tags: ["htb","machine", "linux", "sqli"]
summary: "Machine Linux. Chaîne web vers root : exploitation d'une vulnérabilité de l'application, erreur huamine, pivoting, puis élévation par mauvaise configuration."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine CCTV résolue](/images/CCTV.png)
Machine Linux, compromise de bout en bout jusqu'au root.

## Techniques mises en oeuvre

- Énumération
- Exploitation de CVE
- Extraction de secrets
- Obtention d'informations sensibles
- Pivoting
- Root par abus d'un composant privilégié

## Outils utilisés

- Outils d'énumération
- Outils d'exploitation
- Outils de crackage
- ssh