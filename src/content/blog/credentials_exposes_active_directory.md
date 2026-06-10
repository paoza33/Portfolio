---
title: "Credentials exposés dans Active Directory : SYSVOL, partages et propriétés d'objets"
date: 2026-06-10
side: "red"
tags: ["active-directory", "credentials", "gpp", "sysvol", "loot"]
summary: "Parfois, inutile d'exploiter quoi que ce soit : il suffit de lire. Trois endroits où Active Directory laisse fuiter des identifiants en clair, tous accessibles à un simple utilisateur du domaine."
draft: false
---

Toutes les attaques Active Directory ne demandent pas un exploit. Les plus rentables consistent souvent à lire ce qui ne devrait pas l'etre. Trois endroits laissent fuiter des identifiants, et ils ont un point commun redoutable : ils sont lisibles par n'importe quel utilisateur du domaine, sans privilège. Ce sont fréquemment ces fuites qui fournissent le premier identifiant, celui qui relance toute la méthodologie de pivot décrite en phase 3 du pattern AD.

## GPP cpassword dans SYSVOL

Le partage SYSVOL est accessible en lecture à tous les utilisateurs authentifiés. Historiquement, les Group Policy Preferences y stockaient des identifiants dans des fichiers XML, sous une propriété nommée cpassword. Le mot de passe y était chiffré, donc en apparence protégé.

La faille tient à la clé : le chiffrement repose sur une clé AES statique, identique pour tous les environnements, et publiée par Microsoft. Autrement dit, tout cpassword est déchiffrable hors ligne, sans aucun privilège. Plusieurs outils le font automatiquement, en parcourant les XML de SYSVOL et en déchiffrant ce qu'ils trouvent.

```bash
# netexec, en ligne
nxc smb <IP> -u <user> -p <pass> -M gpp_password

# Impacket, en ligne ou hors ligne sur un SYSVOL monté
impacket-Get-GPPPassword <domain>/<user>:<pass>@<DC_IP>
gpp-decrypt <CPASSWORD>
```

Le correctif KB2962486 de 2014 empeche la création de nouveaux mots de passe GPP, mais ne supprime pas les anciens. Tout domaine construit avant 2014, ou mal administré depuis, reste potentiellement vulnérable. Les identifiants exposés sont souvent ceux de comptes de service, donc privilégiés.

## Credentials dans les partages

Deuxième mine d'or, les partages réseau. Ils sont souvent ouverts trop largement, à Everyone ou au groupe Users qui inclut Domain Users, et contiennent des scripts et fichiers de configuration où dorment des secrets en clair, dans des `.bat`, `.ps1`, `.ini` ou `.config`. Les causes sont toujours les memes : un partage temporaire jamais refermé, un script testé en local mais sur un dossier partagé, ou la fausse impression de sécurité d'un partage caché avec un dollar.

On commence par énumérer les partages accessibles, puis on cherche les mots-clés sensibles.

```bash
nxc smb <IP> -u <user> -p <pass> --shares
nxc smb <IP> -u <user> -p <pass> -M spider_plus
```

Les motifs efficaces sont les termes pass, pw, password, le nom NetBIOS du domaine, et surtout les commandes `net use` ou `runas` avec un mot de passe en clair. Sur Windows, un `findstr` récursif fait le travail, mais les scans massifs sont désormais repérés par Defender, donc on reste mesuré.

## Credentials dans les propriétés d'objets

Le troisième canal est le plus discret. Chaque objet AD porte des propriétés lisibles par tout utilisateur du domaine, et certains administrateurs ont stocké des mots de passe en clair dans les champs Description ou Info, croyant ces champs restreints. Ils ne le sont pas. Une simple requete LDAP suffit à les moissonner, et l'opération est quasi indétectable puisqu'une lecture LDAP est parfaitement légitime.

```bash
nxc ldap <IP> -u <user> -p <pass> -M get-desc-users
```

Côté Windows, un script PowerShell qui filtre les utilisateurs sur les termes pass, password ou pwd dans Description et Info donne le meme résultat, sans aucune élévation préalable.

## Le fil rouge

Ces trois fuites n'exploitent rien, elles tirent parti d'une mauvaise hygiène. Toutes sont accessibles à un simple utilisateur du domaine, et toutes exposent fréquemment des comptes de service, donc des comptes à privilèges. C'est exactement le carburant de la boucle de pivot : un identifiant trouvé dans SYSVOL, un partage ou un champ Description relance une énumération complète, qui révèle le droit ou le compte suivant. La sophistication viendra après, le point d'entrée, lui, est souvent une simple négligence.

## Côté défense

Le dénominateur commun de la détection est l'authentification du compte exposé. Un compte de service qui s'authentifie depuis un poste utilisateur, via les événements 4624, 4625 et 4768, est anormal et mérite une alerte. Au delà, chaque canal a ses spécificités. Pour GPP, on active l'audit fichier sur les XML sensibles comme Groups.xml, l'événement 4663 signalant une lecture, ce qui est redoutable sur un faux XML honeypot. Pour les partages, la gouvernance stricte des permissions et un scan périodique de mots-clés sont la base, complétés par la détection d'un poste qui touche des centaines de machines, signature d'un scan de partages. Pour les propriétés d'objets, l'événement 4738 ne précise pas l'attribut modifié, la détection est donc surtout indirecte.

Le levier le plus efficace reste le honeypot : un compte de service au mot de passe volontairement faux, placé dans un XML, un partage ou un champ Description, dont le mot de passe a été changé avant la fuite. Aucun usage légitime n'existe, donc toute tentative d'authentification, repérée via les échecs 4625, 4771 et 4776, signe une activité malveillante certaine.

