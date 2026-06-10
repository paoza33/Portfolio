---
title: "Campfire-1"
date: 2026-05-14
side: "blue"
tags: ["htb", "windows", "sherlock", "kerberoasting", "active-directory", "dfir"]
summary: "Investigation d'un Kerberoasting sur Active Directory en chaînant trois artefacts : logs Security du contrôleur de domaine, logs PowerShell-Operational de la workstation et fichiers prefetch. Reconstruction de la timeline d'attaque à la seconde près."
draft: false
---

> Sherlock résolu. Les artefacts ne sont pas redistribués, seules la méthode et les requêtes le sont. Appartient à la liste tracks CDSA.

## Contexte

Alonzo a repéré des fichiers suspects sur son poste et a prévenu le SOC. L'hypothèse de départ : une attaque Kerberoasting sur le domaine. Le travail consiste à confirmer ou infirmer cette piste à partir de trois sources :

- les logs Security du contrôleur de domaine,
- les logs PowerShell-Operational de la workstation touchée,
- les fichiers prefetch de cette même workstation.

Tout l'intérêt de l'exercice est de croiser ces trois artefacts pour reconstruire une chronologie cohérente.

![Sherlock campfire_1 résolu](/images/campfire_1.png)

## Côté contrôleur de domaine : la demande de ticket malveillante

Le Kerberoasting laisse une trace nette dans les logs Security du DC, l'Event ID 4769 (demande de ticket de service Kerberos). On filtre dessus, puis on cherche l'événement qui réunit les critères suivants :

- type de chiffrement du ticket à `0x17`, c'est à dire RC4,
- nom de service qui ne se termine pas par `$` (on exclut les comptes machines) et qui n'est pas `krbtgt`,
- code d'échec à `0x0` (la demande a réussi).

Le RC4 est l'anomalie centrale. Un domaine moderne négocie de l'AES, alors qu'un attaquant force volontairement le RC4 (`0x17`) parce que le hash extrait du ticket se casse plus facilement hors ligne. Un 4769 en RC4 visant un compte de service est donc la signature même de l'attaque.

L'événement qui coche toutes les cases nous donne trois réponses d'un coup. Le service ciblé est `MSSQLService`, la demande provient du compte `alonzo.spire@FORELA.LOCAL` depuis l'adresse client `::ffff:172.17.79.129`, et l'horodatage est `2024-05-21 03:18:09`.

En SIEM, la même logique de détection se traduit ainsi côté Splunk :

```spl
Event.EventData.TicketEncryptionType="0x17" Event.System.EventID="4769" Event.EventData.ServiceName!="*$"
| table Event.EventData.ServiceName, Event.EventData.TargetUserName, Event.EventData.IpAddress
```

Le `table` final isole directement le service visé, le compte qui mène l'attaque et l'adresse source. De quoi pivoter immédiatement vers la workstation.

## Côté workstation : remonter à l'énumération

On connaît maintenant le poste source. On bascule sur ses logs PowerShell-Operational et on filtre l'Event ID 4104, qui journalise le contenu complet des blocs de script (ScriptBlock logging).

Juste avant l'attaque, à `03:16:29`, un premier bloc révèle un contournement de la politique d'exécution :

```text
powershell -ep bypass
```

Un classique : l'attaquant désactive les restrictions d'exécution pour lancer des scripts offensifs sans entrave. Suivent, à `03:16:32`, une série de blocs qui appartiennent au même script. Leur en-tête trahit l'outil :

```text
PowerSploit File: PowerView.ps1
```

C'est PowerView, le module d'énumération Active Directory de PowerSploit, utilisé ici pour cartographier le domaine et repérer les comptes kerberoastables. Le fichier est `powerview.ps1`, exécuté à `2024-05-21 03:16:32`. Point à retenir : le 4104 enregistre le script en clair, donc on identifie sa nature réelle même s'il avait été renommé.

## Le prefetch : confirmer l'outil d'attaque

Reste à prouver avec quel outil le Kerberoasting a effectivement été lancé. Le prefetch dit quels exécutables ont tourné et quand. On le parse avec PECmd d'Eric Zimmerman :

```text
PECmd.exe -d "chemin-vers-prefetch" --csv . --csvf analysis.csv
```

On ouvre le CSV dans Timeline Explorer et on filtre le champ `Last Run` sur la date de l'incident pour réduire le bruit. Une astuce efficace : ne garder que les entrées dont le `Last Run` est rempli mais le `Previous Run` vide. Ce sont les exécutables lancés pour la première fois sur la machine, donc les plus suspects.

Un nom saute aux yeux, `RUBEUS.EXE`. Rubeus est l'outil de référence pour les attaques Kerberos, dont le Kerberoasting. Son dernier lancement est daté de `2024-05-21 03:18:08`, soit exactement une seconde avant l'événement 4769 du DC. La colonne `Files Loaded` donne le chemin complet du binaire :

```text
c:\Users\Alonzo.spire\Downloads\Rubeus.exe
```

## Timeline reconstituée

| Heure (UTC) | Artefact | Action |
| --- | --- | --- |
| 03:16:29 | PowerShell 4104 | `powershell -ep bypass`, contournement de l'execution policy |
| 03:16:32 | PowerShell 4104 | Exécution de `powerview.ps1`, énumération AD et repérage des comptes kerberoastables |
| 03:18:08 | Prefetch | Exécution de `Rubeus.exe` depuis le dossier Downloads d'Alonzo |
| 03:18:09 | Security 4769 | Demande de ticket RC4 (`0x17`) pour `MSSQLService`, le Kerberoasting |

L'écart d'une seconde entre l'exécution de Rubeus sur la workstation et la demande de ticket enregistrée sur le DC est l'élément qui relie les deux mondes. C'est lui qui transforme une suite d'indices isolés en une kill chain établie.

## Aide-mémoire des artefacts

| Source | Repère | Ce qu'il révèle |
| --- | --- | --- |
| Security (DC) | Event ID 4769 + RC4 `0x17` | La demande de ticket Kerberoasting, le service visé, le compte et l'IP source |
| PowerShell-Operational | Event ID 4104 | Le contenu des scripts (bypass, PowerView) et leur horodatage |
| Prefetch | PECmd + Timeline Explorer | L'exécution de Rubeus, son chemin et son `Last Run` |

## Ce qu'on en retire

Le Kerberoasting a une signature côté DC qui ne trompe pas : un 4769 en RC4 (`0x17`) visant un compte de service réel, c'est à dire un nom qui ne finit pas par `$` et qui n'est pas `krbtgt`. C'est la détection à industrialiser en priorité. Le RC4 est l'anomalie à traquer, puisqu'un attaquant le force pour casser le hash hors ligne. Côté endpoint, le 4104 (ScriptBlock) expose l'identité réelle d'un script même renommé, et le prefetch confirme l'exécution avec son horodatage, l'astuce `Last Run` rempli mais `Previous Run` vide isolant les premières exécutions. Au final, c'est le chaînage des trois artefacts qui reconstruit la chronologie et corrèle l'activité workstation à l'événement DC à la seconde près.