---
title: "Garfield"
date: 2026-04-27
side: "red"
tags: ["htb", "windows", "machine", "active-directory", "kerberos", "acl-abuse"]
summary: "Machine Windows Active Directory (difficile). Abus de permissions et de mauvaise configuration, de simples identifiants jusqu'à la compromission complète du domaine."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Garfield résolue](/images/garfield.png)
Machine Windows, Active Directory, difficulté élevée.

## Techniques mises en oeuvre

- Énumération Active Directory authentifiée
- Abus de permissions
- Rebond vers un compte d'administration
- Accès distant
- Compromission d'un contrôleur mal configurée
- Extraction des secrets

## Outils utilisés

- Outils d'énumération
- Outils d'extraction de credentials
- Outils de post-exploitation