---
title: "Détecter le credential dumping sur LSASS"
date: 2026-06-09
side: "blue"
tags: ["detection", "sysmon", "credential-dumping", "T1003"]
summary: "Voler les identifiants en mémoire ne passe pas par le chargement d'une DLL, mais par l'accès à un processus sensible. Voici pourquoi LSASS est la cible, et comment l'Event ID 10 de Sysmon trahit la tentative."
draft: false
---

Après une première compromission, l'attaquant cherche presque toujours à récupérer des identifiants pour se déplacer dans le réseau. Sa cible privilégiée est `lsass.exe`, le processus qui gère l'authentification sous Windows. Cet article change un peu de logique par rapport aux précédents : ici on ne détecte pas un chargement de module, mais une tentative d'accès à un processus protégé.

## Pourquoi LSASS

Le Local Security Authority Subsystem Service garde en mémoire vive tout ce qui touche aux sessions ouvertes : hashs NTLM, tickets Kerberos, et selon la configuration, des secrets liés à WDigest, MSV ou TSPKG. Pour un attaquant, lire la mémoire de LSASS, c'est récolter d'un coup de quoi rejouer des authentifications et rebondir vers d'autres machines.

L'outil emblématique de cette opération est Mimikatz, dont la commande la plus connue est `sekurlsa::logonpasswords`. Elle exige au préalable l'activation de `SeDebugPrivilege`, un privilège puissant qui autorise à inspecter la mémoire d'autres processus. Cette demande de privilège est déjà, en soi, un signal à surveiller.

## La bonne logique de détection

Comme l'accès à la mémoire d'un processus ne se traduit pas par un chargement de DLL, l'Event ID 7 ne sert à rien ici. Le bon événement est l'**Event ID 10 (ProcessAccess)** de Sysmon, qui enregistre précisément ce qu'on cherche : quel processus en ouvre un autre, depuis quel binaire, et avec quels droits.

Pour le capturer, on bascule le bloc `ProcessAccess` de la configuration Sysmon en mode `exclude` sans règle interne, ce qui revient à tout journaliser le temps de l'analyse.

## Lire l'événement

Quand Mimikatz accède à LSASS, l'Event ID 10 expose plusieurs champs parlants :

- `SourceImage` : le binaire qui demande l'accès, par exemple un exécutable renommé pour passer inapercu.
- `TargetImage` : ici `lsass.exe`, la cible.
- `GrantedAccess` : les droits obtenus. Une valeur comme `0x1410` combine la lecture mémoire et l'interrogation du processus, exactement ce dont on a besoin pour extraire des secrets.
- `SourceUser` différent de `TargetUser` : un compte utilisateur classique accédant à un processus tournant en SYSTEM est anormal.

La synthèse des indicateurs tient en quelques points : un processus inconnu qui accède à LSASS, un binaire situé dans un chemin inhabituel comme Téléchargements ou Bureau, l'usage de `SeDebugPrivilege`, un `SourceUser` distinct du `TargetUser`, et un `GrantedAccess` traduisant une lecture mémoire. La régle de fond est radicale : en dehors des antivirus, EDR et fournisseurs de sécurité légitimes, toute lecture de la mémoire de LSASS doit etre traitée comme suspecte.

## La requete SPL

On isole les accès à LSASS en écartant les processus légitimes connus pour le faire, et on remonte le binaire source, l'utilisateur et les droits obtenus pour le triage.

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
| eval source=lower(mvindex(split(SourceImage,"\\"), -1))
| search NOT source IN ("wininit.exe","services.exe","csrss.exe","msmpeng.exe","wmiprvse.exe")
| table _time, Computer, SourceImage, SourceUser, GrantedAccess, CallTrace
| sort - _time
```

La liste d'exclusion reste à ajuster à ton parc : les solutions de sécurité installées accèdent légitimement à LSASS et doivent etre connues, sinon elles génèrent du bruit. Le champ `CallTrace` est précieux au triage, car un accès passant par des DLL inhabituelles renforce le soupcon.

## Ce qu'il faut retenir

Le credential dumping illustre un principe clé de la détection défensive : ce n'est pas l'outil qu'on cherche, mais le comportement. Mimikatz peut etre renommé, recompilé, obfusqué, mais il devra toujours ouvrir un handle en lecture sur LSASS. C'est ce geste, et non la signature du binaire, qui constitue le point de détection durable.
