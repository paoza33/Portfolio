---
title: "Kerberoasting et AS-REP Roasting : casser les comptes AD hors ligne"
date: 2026-06-10
side: "red"
tags: ["active-directory", "kerberos", "kerberoasting", "asreproast", "credential-access"]
summary: "Deux attaques cousines qui détournent Kerberos pour récupérer un hash crackable hors ligne, souvent sans privilège au départ. Leur point commun : la robustesse du mot de passe est la seule vraie défense."
draft: false
---

Kerberoasting et AS-REP Roasting sont deux attaques cousines qui exploitent le fonctionnement normal de Kerberos pour récupérer un hash de mot de passe crackable hors ligne. Aucune des deux ne demande de privilège élevé au départ, et l'une ne demande meme pas d'identifiant valide. Leur point commun est aussi leur seule parade : tout repose sur la robustesse du mot de passe ciblé. Cet article approfondit les phases 2 et 3 de la méthodologie pentest AD.

## Le mécanisme détourné

Kerberos repose sur un centre de distribution de clés, le KDC, hébergé sur le contrôleur de domaine. Il émet deux types de tickets : le TGT, qui prouve l'identité du client, et le TGS, qui donne accès à un service précis. Ces tickets sont chiffrés avec des clés dérivées de hash de mots de passe. C'est exactement cette propriété que les deux attaques retournent contre l'annuaire : obtenir un ticket, c'est obtenir une donnée chiffrée avec le hash d'un compte, donc une cible pour le cassage hors ligne.

## Kerberoasting

Un compte de service est souvent associé à un SPN, l'identifiant unique qui relie un service à son compte AD. Quand un client demande un TGS pour ce service, Kerberos le chiffre avec le hash NTLM du compte de service. Or n'importe quel utilisateur authentifié du domaine peut demander un TGS pour n'importe quel SPN, sans privilège particulier. L'attaque tient là : on demande les tickets des comptes à SPN, on les exporte, et on tente de les casser hors ligne. Si le mot de passe du compte de service est faible, il tombe.

Un détail compte, le chiffrement. Le KDC choisit par défaut l'algorithme le plus fort supporté, mais un attaquant force volontairement un downgrade vers RC4, beaucoup plus rapide à casser que l'AES.

Côté Windows, l'enchainement classique se fait avec Rubeus puis Hashcat :

```text
.\Rubeus.exe kerberoast /outfile:spn.txt
hashcat -m 13100 -a 0 spn.txt wordlist.txt --outfile cracked.txt
```

Depuis Linux, le combo Impacket et netexec fait la meme chose, ce dernier listant et roastant les comptes à SPN directement depuis l'énumération LDAP :

```bash
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request -outputfile spn.txt
nxc ldap <IP> -u <user> -p <pass> --kerberoasting kerb.txt
```

L'impact dépend du compte visé. Si le compte de service est privilégié, admin local, lié à une GPO ou à une délégation, le cassage de son mot de passe ouvre une escalade directe vers le domaine.

## AS-REP Roasting

La seconde attaque vise non pas des comptes de service mais des comptes utilisateurs ayant l'option « Do not require Kerberos preauthentication » activée. Pour ces comptes, le KDC renvoie une réponse AS-REP chiffrée avec le hash du mot de passe de l'utilisateur, sans pré-authentification préalable. Là encore, cette réponse est crackable hors ligne.

La différence clé avec le Kerberoasting est double. AS-REP Roasting cible des comptes utilisateurs sans SPN, et surtout il ne nécessite aucun identifiant valide : une simple liste de noms d'utilisateurs suffit, ce qui en fait une attaque exploitable dès la phase d'énumération non authentifiée.

```text
.\Rubeus.exe asreproast /outfile:asrep.txt
hashcat -m 18200 -a 0 asrep.txt wordlist.txt --outfile cracked.txt
```

Depuis Linux, sans aucun identifiant :

```bash
GetNPUsers.py <domain>/ -dc-ip <IP> -no-pass -usersfile users.txt
```

L'AS-REP est généralement en RC4, rapide à casser. Comme pour le Kerberoasting, un compte sans privilège n'a que peu d'intérêt, mais un compte appartenant à un groupe sensible ou portant des droits AD débouche sur une escalade.

## En un coup d'oeil

| | Kerberoasting | AS-REP Roasting |
| --- | --- | --- |
| Cible | Comptes de service avec SPN | Comptes users sans pré-auth |
| Prérequis | Un identifiant valide | Une simple liste d'utilisateurs |
| Ticket exploité | TGS | AS-REP |
| Mode Hashcat | 13100 | 18200 |
| Chiffrement forcé | RC4 (downgrade) | RC4 |

## Pourquoi ça marche, et la seule vraie défense

Les deux attaques ne cassent rien dans Kerberos, elles exploitent son fonctionnement légitime. La donnée chiffrée est récupérée sans effraction, et tout le reste se joue hors ligne, hors de portée de toute détection. La conséquence est nette : la seule défense de fond est la robustesse du mot de passe. Concrètement, des mots de passe longs et aléatoires pour les comptes de service, idéalement des comptes managés de groupe (gMSA) dont le mot de passe est géré et tourné automatiquement, la suppression des SPN inutiles, et le bannissement de l'option de pré-authentification désactivée sauf justification métier, assortie d'une politique de mot de passe dédiée.

## Côté défense

Ces attaques laissent une trace côté contrôleur de domaine. Le Kerberoasting génère l'événement 4769 (demande de TGS), l'AS-REP Roasting l'événement 4768, et dans les deux cas le chiffrement RC4 dans un environnement censé etre AES est l'anomalie à traquer, tout comme un volume de tickets anormal par compte. Les honeypots, un compte factice à SPN ou sans pré-auth dont toute sollicitation est suspecte, complètent le dispositif. Le détail de cette détection côté Blue est traité dans le write-up du Sherlock Campfire-1, qui déroule justement la chasse au Kerberoasting dans les logs.

## Pour s'entrainer

La machine Garfield de Hack The Box, dont le write-up figure dans la section write-ups, fait passer par des tentatives d'AS-REP Roasting et de Kerberoasting en phase d'énumération. Pour le versant détection, le Sherlock Campfire-1 montre l'autre bout de la chaine, depuis les logs du contrôleur de domaine. Les deux ensemble couvrent l'attaque et sa traque.