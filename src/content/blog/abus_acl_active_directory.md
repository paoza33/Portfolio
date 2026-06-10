---
title: "Abus d'ACL Active Directory : du droit d'écriture à la compromission"
date: 2026-06-10
side: "red"
tags: ["active-directory", "acl", "dacl", "bloodhound", "bloodyad"]
summary: "Active Directory est un graphe de permissions. Un simple droit d'écriture mal placé sur un objet devient un chemin vers le domaine. Voici comment lire ces droits et les transformer en compromission."
draft: false
---

Active Directory n'est pas une hiérarchie, c'est un graphe de permissions. Chaque objet, utilisateur ou machine, porte une liste de contrôle d'accès qui dit qui peut le modifier et comment. Un droit d'écriture mal placé, hérité d'une délégation oubliée ou d'un groupe trop large, devient alors un chemin direct vers un compte privilégié. C'est exactement ce qu'exploitent les phases 4 et 5 de la méthodologie pentest AD : repérer ce que l'on peut écrire, puis le transformer en accès.

## ACL, ACE et droits qui comptent

Une ACL est la liste des accès attachée à un objet. Chaque entrée de cette liste est une ACE, qui associe un trustee, c'est à dire un principal de sécurité, à un type d'accès. On distingue la DACL, qui contrôle qui accède à l'objet, de la SACL, dédiée à l'audit. En pratique, seuls quelques droits ouvrent une attaque :

- GenericAll, le controle total sur l'objet,
- GenericWrite, la modification des attributs,
- WriteOwner, le changement de propriétaire,
- WriteDacl, la modification des ACL elles-memes,
- ForceChangePassword, le reset de mot de passe sans connaitre l'actuel,
- AddMember, l'ajout dans un groupe.

On les repère de deux façons complémentaires : dans BloodHound, en inspectant les droits sortants du compte compromis, et avec bloodyAD, qui répond directement à la question utile.

```bash
bloodyAD -d <domain> -u <user> -p <pass> --host <IP> get writable --detail
```

## Abuser d'un droit sur un utilisateur

Quand le droit porte sur un compte utilisateur, le plus direct est le reset de mot de passe. Avec ForceChangePassword ou GenericAll, on réécrit le mot de passe de la cible, puis on se connecte avec et on hérite de tous ses droits.

```bash
bloodyAD -d <domain> -u <user> -p <pass> --host <IP> set password <cible> 'NewPass123!'
```

Le reset est bruyant et casse l'accès du compte légitime. Une alternative plus discrète, avec GenericWrite ou GenericAll, est le Kerberoasting ciblé : on ajoute un SPN bidon à la cible, on demande son TGS, on le casse hors ligne, puis on retire le SPN pour effacer ses traces.

```text
Set-DomainObject -Identity <cible> -SET @{serviceprincipalname='fake/svc'}
.\Rubeus.exe kerberoast /user:<cible> /nowrap
```

Toujours plus discret, les Shadow Credentials exploitent l'attribut msDS-KeyCredentialLink : on y ajoute une clé que l'on controle, ce qui permet de s'authentifier via PKINIT sans toucher au mot de passe. Certipy automatise l'opération.

```bash
certipy shadow auto -u <user>@<domain> -p <pass> -account <cible> -dc-ip <IP>
```

## Abuser d'un droit sur une machine

Sur un objet ordinateur, deux chemins dominent. Le premier, si LAPS est en place, est de lire directement le mot de passe administrateur local stocké dans l'attribut dédié.

```bash
nxc ldap <IP> -u <user> -p <pass> --laps
```

Le second est la délégation basée ressource (RBCD) : avec GenericAll ou GenericWrite sur la machine, on configure l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity pour qu'un compte que l'on controle puisse usurper n'importe quel utilisateur sur cette machine via S4U. C'est un sujet à part entière, traité dans l'article sur la délégation Kerberos.

```bash
bloodyAD -d <domain> -u <user> -p <pass> --host <IP> add rbcd <machine_cible> <compte_controle>
```

## Quand le droit n'est pas exploitable directement

WriteOwner et WriteDacl ne donnent pas d'accès immédiat, mais ils permettent de s'en octroyer un. Avec WriteOwner, on devient propriétaire de l'objet, ce qui autorise à réécrire sa DACL. Avec WriteDacl, on s'ajoute directement une ACE GenericAll. Dans les deux cas, on retombe ensuite sur les abus décrits plus haut. C'est la mécanique de chainage typique de l'AD : un droit faible se transforme en droit fort, étape par étape.

```bash
bloodyAD -d <domain> -u <user> -p <pass> --host <IP> set owner <cible> <user>
bloodyAD -d <domain> -u <user> -p <pass> --host <IP> add genericAll <cible> <user>
```

## Le flux typique

Le schéma se répète. BloodHound ou bloodyAD révèle un droit, par exemple GenericAll de notre compte vers un autre utilisateur. On choisit l'abus, reset ou Kerberoast ciblé selon la discrétion voulue, on récupère l'accès à la cible, et si cette cible appartient à un groupe privilégié, le domaine tombe. Sur un objet machine, le meme droit mène à LAPS ou à la délégation, puis au pivot vers le contrôleur de domaine. Chaque gain rouvre l'énumération, comme le rappelle le pattern général.

## Côté défense

Ces abus laissent des traces, meme imparfaites. L'ajout d'un SPN ou le reset déclenchent les événements 4738 et 4724 sur un compte utilisateur, la modification d'un objet machine l'événement 4742. Ces journaux ne précisent pas toujours l'attribut modifié, d'où l'intérêt d'une convention de nommage : tout événement de modification visant un compte privilégié hors du préfixe attendu devient suspect. Au delà, un audit continu des ACL débusque les misconfigurations à la source, et des comptes honeypot, modifiables par tous mais sans usage légitime, transforment toute modification en alerte immédiate.

## Pour s'entrainer

La machine Garfield de Hack The Box, dont le write-up figure dans la section write-ups, repose en partie sur une chaine d'abus d'ACL, d'un droit d'écriture sur un attribut sensible jusqu'à un ForceChangePassword sur un compte d'administration. C'est un terrain idéal pour pratiquer le raisonnement décrit ici, lire un droit dans BloodHound puis le convertir en accès.