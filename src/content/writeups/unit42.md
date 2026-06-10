---
title: "Unit42"
date: 2026-06-10
side: "blue"
tags: ["htb", "windows", "sherlock", "sysmon", "dfir", "timestomp"]
summary: "Sherlock HTB (DFIR, très facile) : reconstruire l'accès initial d'une campagne UltraVNC à partir d'un journal Sysmon, en s'appuyant sur les Event IDs clés."
draft: false
---

> Sherlock retiré, write-up complet.

## Le scénario

Un seul artefact : `Microsoft-Windows-Sysmon-Operational.evtx`, 169 événements. Le contexte s'inspire d'une campagne documentée par l'Unit42 de Palo Alto, où des attaquants distribuaient une version backdoorée d'UltraVNC pour conserver l'accès aux machines. L'objectif est de reconstruire l'étape d'accès initial à partir des seuls journaux Sysmon.

![Sherlock Unit42 résolu](/images/unit42.png)

L'analyse tient dans l'observateur d'événements Windows, complété par VirusTotal. Sur un volume plus important, je serais passé par EvtxECmd pour convertir l'EVTX en CSV et pivoter dans Timeline Explorer, mais 169 événements se lisent très bien à la main.

## Cadrage

Avant de filtrer, deux réflexes. D'abord, lister les Event IDs Sysmon utiles à ce type d'enquête :

- **1** création de processus (image, parent, ligne de commande, hashes)
- **2** modification de la date de création d'un fichier (timestomping)
- **3** connexion réseau (process, IP et port de destination)
- **5** fin de processus
- **11** création de fichier
- **22** requête DNS

Ensuite, une mise en garde sur le temps : la colonne affichée dans l'observateur est l'heure locale de ma machine. L'heure de référence est le champ `UtcTime` dans le détail de l'événement. Pour corréler une chronologie, on travaille en UTC.

Pour se faire la main sur le filtrage (Filter Current Log par Event ID), on compte les créations de fichiers :

```
Event ID = 11  ->  56 événements
```

## Identifier le processus malveillant

Le point d'entrée logique, c'est la création de processus. On filtre l'Event ID 1, et seulement six événements remontent : assez peu pour les lire un par un plutôt que de bricoler une recherche.

```
Filter Current Log -> Event ID 1   (6 événements)
```

Un événement sort du lot. Les champs utiles :

```
Image:            C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
OriginalFileName: Preventivo 2.2024.exe
Product:          Photo and vn
ParentImage:      C:\Windows\explorer.exe
```

Trois signaux concordants. Le binaire porte une double extension `.exe.exe`, classique pour tromper l'œil. Il s'exécute depuis `Downloads`, pas depuis un chemin d'installation légitime. Et ses métadonnées le présentent comme un logiciel "Photo and vn", ce qui ne colle pas avec un fichier lancé manuellement depuis les téléchargements : c'est du masquerading. Le parent `explorer.exe` confirme que l'utilisateur l'a lancé lui-même par double-clic.

Sysmon embarque les empreintes du binaire. Je pivote sur le hash dans VirusTotal pour corroborer :

```
SHA256: 0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
```

Largement flaggé, étiqueté comme un trojan de la famille WinVNC/UltraVNC. Le pivot par hash confirme l'intuition, mais reste un complément : l'essentiel du raisonnement vient déjà des champs du log.

Processus malveillant : `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`.

## Retrouver le vecteur de livraison

Comment ce fichier est-il arrivé là ? Je regarde les requêtes DNS (Event ID 22) autour de la création du binaire, et je les corrèle avec les créations de fichiers (Event ID 11).

```
Filter Current Log -> Event ID 22   (3 événements)
```

L'une des requêtes pointe vers Dropbox. En remettant l'Event ID 11 dans le filtre, on voit juste avant la création du `.exe` final des fichiers temporaires `.part` de Firefox, signature d'un téléchargement par le navigateur.

La livraison se reconstitue : téléchargement depuis Dropbox via Firefox, puis exécution. Les services cloud comme Dropbox sont un vecteur courant, justement parce qu'ils passent rarement pour malveillants au niveau du périmètre.

Drive utilisé : Dropbox.

## Reconstituer l'activité du binaire

Une fois lancé, le binaire dépose des fichiers, brouille les pistes, teste sa connectivité, puis s'efface.

**Dépôt de fichiers (Event ID 11).** En cherchant `once.cmd` dans les créations de fichiers, deux résultats apparaissent : un par `msiexec`, un par le binaire malveillant. C'est ce dernier qui nous intéresse.

```
Image:          ...\Preventivo24.02.14.exe.exe
TargetFilename: C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd
```

**Timestomping (Event ID 2).** Le binaire modifie la date de création de plusieurs fichiers qu'il dépose, pour les faire passer pour anciens. Sur un `.pdf` déposé, la date est réécrite :

```
CreationUtcTime (nouvelle): 2024-01-14 08:10:06
PreviousCreationUtcTime:    2024-02-14 03:41:58
```

L'écart d'un mois est tout l'intérêt de la manœuvre : donner au fichier l'air d'avoir toujours été là. L'Event ID 2 la trahit en conservant l'ancien et le nouveau timestamp côte à côte.

**Vérification de connectivité (Event ID 22 puis 3).** Le binaire interroge un domaine neutre, `www.example.com`, pour tester l'accès Internet avant la suite.

```
Event ID 22 -> www.example.com
Event ID 3  -> 93.184.216.34:80   (TCP, Initiated: true)
```

**Auto-terminaison (Event ID 5).** Une fois le backdoor en place, le processus se termine de lui-même.

```
Event ID 5 -> Preventivo24.02.14.exe.exe se termine à 2024-02-14 03:41:58 (UTC)
```

## Chronologie reconstituée

En UTC, le déroulé de l'accès initial :

- Téléchargement du binaire depuis Dropbox via Firefox (fichiers `.part`).
- `03:41:26` création de `Preventivo24.02.14.exe.exe` dans `Downloads`.
- Exécution par double-clic (parent `explorer.exe`), masquerading en "Photo and vn".
- Dépôt de fichiers, dont `once.cmd`, sous `AppData\Roaming\Photo and Fax Vn\...`.
- Timestomping des fichiers déposés (un `.pdf` redaté au `2024-01-14 08:10:06`).
- Test de connectivité vers `www.example.com` / `93.184.216.34:80`.
- `03:41:58` auto-terminaison du processus.

## MITRE ATT&CK

- **T1204 User Execution** : lancement manuel du binaire par l'utilisateur.
- **T1036 Masquerading** : double extension et métadonnées usurpées.
- **T1070.006 Timestomp** : réécriture des dates de création des fichiers déposés.

## IOCs

- Fichier : `Preventivo24.02.14.exe.exe` dans `Downloads`
- SHA256 : `0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3`
- MD5 : `32F35B78A3DC5949CE3C99F2981DEF6B`
- Staging : `...\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\`
- Livraison : Dropbox
- Connectivité : `www.example.com`, `93.184.216.34`

## Ce que j'en retire

Sysmon couvre toute la chaîne, à condition de savoir quel Event ID interroge quoi : l'exécution (1), la livraison (22 et 11), l'évasion (2), la sortie réseau (3), la fin (5). La vraie valeur n'est pas dans une réponse isolée mais dans la corrélation : croiser DNS, création de fichiers et artefacts du navigateur reconstitue un vecteur de livraison qu'aucun événement seul ne donne. Deux réflexes à garder : raisonner en `UtcTime` et non en heure locale, et lire les champs `OriginalFileName` et `Product`, qui démasquent un binaire déguisé avant même tout pivot externe.