---
title: "DarkZeroReturns"
date: 2026-29-07
side: "red"
tags: ["htb", "linux", "machine", "active-directory", "web"]
summary: "Machine Linux jointe à un domaine Active Directory (difficile). Du foothold web à la compromission complète de l'environnement, via une chaîne Kerberos et un abus de CI/CD."
draft: false
---

> Machine saisonnière, actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine DarkZeroReturns résolue](/images/darkzeroreturns.png)

Machine Linux jointe à un domaine Active Directory, difficulté élevée.

## Techniques mises en oeuvre

- Énumération web d'une application Node.js authentifiée
- Injection de template côté serveur (SSTI) menant à une exécution de code à distance
- Récupération d'identifiants applicatifs en base de données
- Cassage de hachages bcrypt hors ligne
- Réutilisation d'identifiants pour un accès SSH
- Machine jointe au domaine : récupération d'un ticket Kerberos de session
- Accès à un service interne via tunnel (port forwarding)
- Authentification Kerberos négociée (SPNEGO) sur un service web interne
- Abus de CI/CD : empoisonnement de pipeline via fork et contournement du contrôle d'approbation des workflows
- Exécution directe sur l'hôte via le runner CI/CD et exfiltration d'un keytab de service
- Reconstitution d'un ticket Kerberos à partir du keytab
- Élévation locale via un binaire SUID adossé à Kerberos
- Extraction des secrets du domaine (DCSync)
- Forge de ticket Kerberos (Golden Ticket) avec injection de SID-History
- Abus de la relation d'approbation inter-forêts
- Réplication de hachages via un compte à droits de sauvegarde
- Pass-the-Hash vers le contrôleur de domaine

## Outils utilisés

- nmap
- hashcat
- chisel
- Impacket
- netexec
- outils clients Kerberos (kinit, klist)