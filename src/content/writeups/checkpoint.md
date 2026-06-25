---
title: "Checkpoint"
date: 2026-06-14
side: "red"
tags: ["htb", "windows", "machine", "active-directory"]
summary: "Machine Windows Active Directory (difficulté moyenne). D'un compte de domaine de départ jusqu'à la compromission complète du domaine, par enchaînement d'abus de permissions et de récupération de secrets."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Checkpoint résolue](/images/checkpoint.png)

Machine Windows Server 2025, Active Directory, difficulté moyenne.

## Techniques mises en oeuvre

- Énumération Active Directory authentifiée
- Abus de permissions et d'objets de l'annuaire
- Élévation via abus de comptes de service
- Exécution de code via un canal de déploiement interne
- Récupération de secrets d'authentification
- Compromission complète du domaine

## Outils utilisés

- nmap
- netexec
- bloodyAD
- Impacket
- evil-winrm