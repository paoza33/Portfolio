---
title: "Paperwork"
date: 2026-07-16
side: "red"
tags: ["htb", "linux", "machine", "injection", "path-traversal"]
summary: "Machine Linux (facile). Trois services d'impression personnalisés exposent une injection de commande, un path traversal et une fuite de file descriptor via socket Unix."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Paperwork résolue](/images/paperwork.png)

Machine Linux, difficulté facile.

## Techniques mises en oeuvre

- Enumération de services réseau non-standard
- Analyse de code source fourni via la page web cible
- Injection de commande dans un service d'impression personnalisé (protocole LPD)
- Evasion d'échappement shell par encodage base64
- Interaction manuelle avec un protocole réseau via socket Python
- Path traversal dans un système de fichiers virtuel exposé par un second service d'impression (PJL)
- Ecriture arbitraire de fichier via path traversal pour implantation de clé SSH
- Identification de services internes via énumération depuis le shell obtenu
- Lecture de file descriptor transmis par socket Unix (SCM_RIGHTS) pour accès à un fichier root

## Outils utilisés

- nmap
- Python (sockets)