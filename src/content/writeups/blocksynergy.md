---
title: "BlockSynergy"
date: 2026-09-03
side: "red"
tags: ["htb", "linux", "machine", "web", "ssrf"]
summary: "Machine Linux (insane). Chaîne d'exploitation web complète, d'un abus de logique applicative à l'exécution de code via SSRF, puis élévation root par une race condition."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine BlockSynergy résolue](/images/blocksynergy.png)

Machine Linux, difficulté insane.

## Techniques mises en oeuvre

- Abus de logique applicative : falsification d'une transaction pour débloquer un accès privilégié dans l'application (expéditeur non vérifié cryptographiquement)
- SSRF non aveugle avec contournement du filtre loopback
- Chaînage d'un open redirect pour atteindre un panneau d'administration interne via la SSRF
- Injection de commande via une divergence d'analyse d'URL, menant à l'exécution de code (accès utilisateur)
- Mouvement latéral via un path traversal dans un hook de debug, aboutissant au dépôt d'une clé SSH
- Élévation de privilèges via une race condition TOCTOU sur un service de restauration privilégié (accès root)

## Outils utilisés

- nmap
- curl
- python
- netcat