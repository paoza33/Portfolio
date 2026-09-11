---
title: "DanglingTree"
date: 2026-08-15
side: "red"
tags: ["htb", "windows", "machine", "active-directory", "adcs"]
summary: "Machine Windows Active Directory (moyenne). Du compte guest à l'Administrateur du domaine, via une console d'administration exposée, une chaîne de vol d'identifiants et un abus d'AD CS."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine DanglingTree résolue](/images/danglingtree.png)

Machine Windows, Active Directory, difficulté moyenne.

## Techniques mises en oeuvre

- Énumération SMB via le compte guest : accès en lecture à un partage et RID cycling pour lister les comptes du domaine
- Récupération d'identifiants en clair dans un document laissé sur un partage
- Exécution de code via une console web d'administration exposée (contournement d'autorisation)
- Pivot par tunnel (port forwarding et proxy SOCKS) vers des services internes
- Rétro-ingénierie d'un binaire .NET pour déchiffrer un mot de passe stocké
- Extraction de secrets DPAPI en contexte utilisateur, sans privilèges SYSTEM
- Récupération d'identifiants mis en cache (gestionnaire d'identifiants Windows)
- Abus d'ACL : ForceChangePassword sur un compte cible
- Abus d'AD CS : recréation d'un template en référence orpheline (dangling) et exploitation ESC1 pour obtenir un certificat d'authentification à sujet arbitraire
- Authentification Kerberos par certificat (PKINIT) pour dériver le hash du compte Administrateur
- Pass-the-Hash vers le contrôleur de domaine

## Outils utilisés

- nmap
- netexec
- BloodHound
- Burp Suite
- chisel
- proxychains
- ILSpy
- RunasCs
- SharpDPAPI
- certipy
- Impacket
- evil-winrm