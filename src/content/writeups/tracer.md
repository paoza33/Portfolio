---
title: "Tracer"
date: 2026-06-17
side: "blue"
tags: ["htb", "windows", "sherlock", "dfir", "lateral-movement", "psexec"]
summary: "Sherlock DFIR Windows : confirmation et caractérisation d'un mouvement latéral par PsExec sur une station cible, via le Prefetch, les logons réseau et la télémétrie Sysmon corrélés dans Splunk."
draft: false
---

*Investigation d'un mouvement latéral via PsExec. Sherlock DFIR, plateforme Hack The Box. Corrélation Prefetch (PECmd), journaux Sysmon/Security et Splunk.*

## Contexte

L'équipe SOC suspecte la présence d'un adversaire dans l'environnement, utilisant **PsExec** pour se déplacer latéralement. Un analyste junior a spécifiquement rapporté l'usage de PsExec sur une station de travail. L'objectif de cette investigation est de confirmer et caractériser cette activité à partir des artefacts disponibles sur la machine cible.

### Périmètre et artefacts

L'analyse repose sur les artefacts de la station **Forela-Wkstn002.forela.local** (machine cible) :

- **Prefetch** Windows (`C:\Windows\prefetch\`) : preuve d'exécution
- **Journaux d'événements** (`Security.evtx`, journaux Sysmon) ingérés dans Splunk (index `dfir`)

D'autres journaux existent mais ne sont pas exploités ici, seuls ces deux artefacts servent à l'investigation.

Une limite de visibilité est à noter d'emblée : l'ensemble des logs provient de WKSTN002. Les journaux de la machine source du mouvement latéral (WKSTN001) ne sont **pas** disponibles dans ce périmètre.

### Outils utilisés

- **PECmd** (Eric Zimmerman) : parsing des fichiers Prefetch
- **EvtxECmd** (Eric Zimmerman) : conversion EVTX vers JSON pour ingestion Splunk
- **Splunk** : corrélation et analyse temporelle

## Résolu

![Sherlock Tracer résolu](/images/tracer.png)

---

## Task 1 - Nombre d'exécutions de PsExec

> *How many times was PsExec executed by the attacker on the system?*

L'analyste junior ayant signalé l'usage de PsExec, on inspecte le Prefetch correspondant. PsExec dépose sur la machine cible un binaire de service, `PSEXESVC.EXE`, dont l'exécution est tracée par le Prefetch.

```
pecmd -f .\PSEXESVC.EXE-AD70946C.pf
```

Sortie :

```
Run count: 9
Last run: 2023-09-07 12:10:03
Other run times: 2023-09-07 12:09:09, 2023-09-07 12:08:54, 2023-09-07 12:08:23,
                 2023-09-07 12:06:54, 2023-09-07 11:57:53, 2023-09-07 11:57:43,
                 2023-09-07 11:55:44
```

**Note technique sur le décompte :** le `Run count` affiche **9**, mais le Prefetch ne liste que **8 horodatages** (1 *Last run* + 7 *Other run times*). le format Prefetch ne conserve que les **8 derniers** temps d'exécution (limite structurelle sur Windows 10/11). Le 9e run a bien eu lieu, mais son horodatage a été poussé hors de la fenêtre des 8 slots disponibles. Le compteur de runs reste donc fiable même quand il dépasse le nombre de timestamps stockés.

**Réponse : `9`**

---

## Task 2 - Binaire de service déposé par PsExec

> *What is the name of the service binary dropped by PsExec tool allowing attacker to execute remote commands?*

Le parsing Prefetch de la Task 1 référence le binaire chargé :

```
01: \VOLUME{01d951602330db46-52233816}\WINDOWS\PSEXESVC.EXE (Executable: True)
```

**Réponse : `PSEXESVC.EXE`**

---

## Task 3 - Horodatage de la 5e dernière instance

> *What is the timestamp when the PsExec Service binary ran (5th Last instance)?*

On ordonne chronologiquement les 8 horodatages d'exécution et on compte 5 en remontant depuis le plus récent :

| Rang (depuis la fin) | Timestamp |
|---|---|
| 1 (Last run) | 2023-09-07 12:10:03 |
| 2 | 2023-09-07 12:09:09 |
| 3 | 2023-09-07 12:08:54 |
| 4 | 2023-09-07 12:08:23 |
| **5** | **2023-09-07 12:06:54** |
| 6 | 2023-09-07 11:57:53 |
| 7 | 2023-09-07 11:57:43 |
| 8 | 2023-09-07 11:55:44 |

**Réponse : `07/09/2023 12:06:54`**

---

## Task 4 - Hostname de la station source du mouvement latéral

> *Can you confirm the hostname of the workstation from which attacker moved laterally?*

notes pour des futurs analyses:
Le champ `Computer` d'un EVTX correspond toujours à la machine qui **écrit** le log (ici WKSTN002, la cible) : il ne contient jamais le hostname de la machine source. La source d'un mouvement latéral se trouve dans le champ `WorkstationName`, via les événements **4624 (Logon Type 3, network logon)**. La compromission initiale de WKSTN001 ne peut être prouvée directement faute de logs côté source, seulement suggérée, ce que l'exercice ne demande pas par ailleurs.

### Préparation des données

L'analyse a nécessité d'ajuster au préalable des fichiers de configuration Splunk pour que l'ingestion et l'extraction de champs fonctionnent correctement. Les requêtes ci-dessous dépendent de cette configuration locale : ces requêtes renvoie *zéro event* pour les autres avec les configurations splunk par défaut.

### Identification de la source

Requête sur les logons réseau (Type 3) hors bruit local :

```
index="dfir" sourcetype="_json" EventId=4624 LogonType=3
| stats count by WorkstationName, IpAddress
| sort - count
```

Résultat :

```
WorkstationName    IpAddress         count
FORELA-WKSTN001    172.17.79.129     7
FORELA-WKSTN002    -                 18
FORELA-WKSTN002    127.0.0.1         53
FORELA-WKSTN002    172.17.79.133     2
FORELA-WKSTN002    ::1               9
kali               172.17.79.133     1
```

Notes importantes :

- Les lignes `FORELA-WKSTN002` avec `-`, `127.0.0.1`, `::1` sont du **logon local/loopback** (la machine sur elle-même), soit du bruit système.
- L'adresse **172.17.79.133** apparaît sous deux noms déclarés (`kali` et `FORELA-WKSTN002`) : c'est la **box de l'attaquant** (Kali), qui s'annonce sous un `WorkstationName` variable. Rappel méthodologique : `WorkstationName` est une chaîne auto-déclarée dans le paquet NTLM, **non vérifiée et falsifiable**. Une *même IP* ne signifie pas *même machine*, mais **même origine réseau sous deux identités annoncées**. L'`IpAddress`, en revanche, est fiable.
- **FORELA-WKSTN001 (172.17.79.129)** est la seule station interne distincte se connectant à WKSTN002 : c'est le **pivot** du mouvement latéral.

La corrélation avec le Prefetch confirme : les logons Type 3 depuis .129 s'alignent sur les horodatages d'exécution de `PSEXESVC.EXE` (voir timeline ci-dessous).

**Réponse : `Forela-Wkstn001`**

---

## Task 5 - Fichier Key déposé par la 5e dernière instance

> *What is the full name of the Key File dropped by 5th last instance of the PsExec?*

La 5e dernière instance a eu lieu à **12:06:54** (Task 3). On recherche les créations de fichiers (Sysmon **Event ID 11, FileCreate**) à partir de cet instant :

```
index="dfir" earliest="09/07/2023:12:06:54" EventId=11
| table _time, TargetFilename
| sort _time
```

La création la plus proche de l'exécution :

```
2023-09-07 12:06:55.064   C:\Windows\PSEXEC-FORELA-WKSTN001-95F03CFE.key
```

Ce fichier `.key` est déposé par PsExec lors de l'établissement de la session. Son nom intègre le hostname de la machine source (**FORELA-WKSTN001**), ce qui recoupe et confirme la réponse de la Task 4.

**Réponse : `PSEXEC-FORELA-WKSTN001-95F03CFE.key`**

---

## Task 6 - Horodatage de création du fichier Key

> *Creation timestamp of the Key File.*

On affiche le champ `CreationUtcTime` de l'event de création (Sysmon Event ID 11). On aurait aussi pu ouvrir l'event vu précédemment et lire directement le champ CreationUtcTime :

```
index="dfir" earliest="09/07/2023:12:06:54" EventId=11
| table _time, TargetFilename, CreationUtcTime
| sort _time
```

```
CreationUtcTime : 2023-09-07 12:06:55.054
```

**Réponse : `07/09/2023 12:06:55`**

---

## Task 7 - Named Pipe se terminant par stderr

> *What is the full name of the Named Pipe ending with the "stderr" keyword for the 5th last instance of the PsExec?*

### Rappel : qu'est-ce qu'un Named Pipe

Un **named pipe** (tuyau nommé) est un mécanisme de communication inter-processus (IPC) sous Windows : un canal nommé par lequel deux processus échangent des données, accessible sous `\\.\pipe\` (local) ou `\\<machine>\pipe\` (distant via SMB).

PsExec exécute une commande sur une machine distante mais l'opérateur est sur la machine source. Pour transporter les flux d'entrée/sortie de la commande distante à travers le réseau, PsExec crée des named pipes dédiés à chacun des trois flux standards : **stdin**, **stdout** et **stderr**. Le pipe se terminant par `stderr` transporte le flux d'erreur. Cette convention de nommage (`PSEXESVC-<host>-<pid>-<flux>`) en fait un **indicateur de détection** classique du mouvement latéral via PsExec.

### Recherche

La création d'un named pipe est journalisée par **Sysmon Event ID 17 (Pipe Created)**. On filtre à partir de la 5e dernière instance :

```
index="dfir" earliest="09/07/2023:12:06:54" EventId=17
| table _time, PipeName
| sort _time
```

Le pipe `stderr` le plus proche de l'exécution :

```
\\PSEXESVC-FORELA-WKSTN001-3056-stderr
```

On retrouve à nouveau le hostname source **FORELA-WKSTN001** dans le nom du pipe : troisième recoupement indépendant confirmant l'origine du mouvement latéral.

**Réponse : `\PSEXESVC-FORELA-WKSTN001-3056-stderr`**

---

## Synthèse de l'investigation

### Timeline du mouvement latéral

L'analyse des événements 4624 (Logon Type 3) depuis **172.17.79.129 (FORELA-WKSTN001)** sur la fenêtre des exécutions PsExec révèle une série de pivots. Chaque run PsExec s'accompagne d'un couple d'authentifications quasi simultanées (~20-30 ms d'écart) :

| Heure (UTC) | TargetUserName | Auth | WorkstationName | Source |
|---|---|---|---|---|
| 11:52:30 | simon.stark | NTLM | FORELA-WKSTN001 | .129 |
| 11:53:02 | Administrator | NTLM | FORELA-WKSTN001 | .129 |
| 11:53:02 | alonzo.spire | Kerberos | - | .129 |
| 11:55:44 | Administrator | NTLM | FORELA-WKSTN001 | .129 |
| 11:55:44 | alonzo.spire | Kerberos | - | .129 |
| 11:57:43 | alonzo.spire | Kerberos | - | .129 |
| 11:57:53 | Administrator / alonzo.spire | NTLM / Kerberos | - | .129 |
| 12:06:54 | alonzo.spire | Kerberos | - | .129 |
| 12:08:23 | alonzo.spire | Kerberos | - | .129 |
| 12:08:54 | Administrator / alonzo.spire | NTLM / Kerberos | - | .129 |
| 12:09:09 | Administrator / alonzo.spire | NTLM / Kerberos | - | .129 |
| 12:10:03 | Administrator / alonzo.spire | NTLM / Kerberos | - | .129 |

Les horodatages des logons s'alignent précisément sur les runs PsExec du Prefetch (notamment 12:10:03, identique au *Last run*).

### Observations sur les comptes

- **Administrator** : compte de **domaine** (`TargetDomainName = FORELA`), authentifié en **NTLM** avec `WorkstationName` et `RemoteHost` renseignés à WKSTN001. Un compte de domaine s'authentifiant en NTLM (plutôt qu'en Kerberos) est une signature compatible avec une attaque **Pass-the-Hash**.
- **alonzo.spire** : compte de **domaine** (`FORELA.LOCAL`), authentifié en **Kerberos**. Le `WorkstationName` est vide (`-`) car le protocole Kerberos ne renseigne pas ce champ NTLM ; la machine source reste néanmoins identifiable via `IpAddress` (.129).
- **simon.stark** : première connexion à 11:52:30 en NTLM depuis WKSTN001. Premier compte observé dans la fenêtre PSExec, vraisemblablement le point d'entrée, mais non prouvable puisque les logs de **WKSTN001 ne sont pas disponibles**.
