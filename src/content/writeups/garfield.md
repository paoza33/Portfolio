---
title: "Garfield"
date: 2026-04-27
side: "red"
tags: ["htb", "windows", "machine", "active-directory", "kerberos", "acl-abuse"]
summary: "Machine Windows Active Directory (difficile). Chaîne d'abus d'ACL et de délégation Kerberos, de simples identifiants jusqu'à la compromission complète du domaine."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Garfield résolue](/images/garfield.png)

Machine Windows, Active Directory, difficulté élevée.

## Techniques mises en oeuvre

- Énumération AD authentifiée (utilisateurs, groupes, SID, tentatives AS-REP Roasting et Kerberoasting)
- Abus d'ACL : droit d'écriture sur l'attribut scriptPath d'un utilisateur, via une appartenance de groupe
- Logon Script Hijacking (détournement du script de connexion pour obtenir un shell)
- Abus d'ACL : ForceChangePassword sur un compte d'administration de tier
- Accès distant via WinRM
- Auto-ajout à un groupe privilégié (administrateurs d'un RODC)
- Resource-Based Constrained Delegation (RBCD) et abus S4U pour compromettre le RODC
- Exécution en SYSTEM via un ticket S4U
- Extraction des secrets Kerberos du RODC (clé krbtgt dédiée)
- Manipulation de la Password Replication Policy du RODC
- Golden Ticket et KeyList Attack pour récupérer le hash du compte Administrateur du domaine
- Pass-the-Hash vers le contrôleur de domaine pour la compromission finale

## Outils utilisés

- nmap
- netexec
- BloodHound
- Impacket
- Rubeus
- Mimikatz
- evil-winrm
