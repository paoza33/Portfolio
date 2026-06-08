---
title: "Détecter l'injection de processus avec Sysmon"
date: 2026-06-08
side: "blue"
tags: ["detection", "sysmon", "injection", "T1055"]
summary: "L'injection de code ne crée pas de nouveau processus suspect : elle se cache dans un processus légitime. Voici la chaîne d'événements Sysmon qui la trahit, et le signal le plus parlant pour la repérer."
draft: false
---

L'injection de processus est une technique furtive par nature. Plutot que de lancer son propre exécutable, qui apparaitrait dans le gestionnaire des taches, l'attaquant fait exécuter son code par un processus légitime déjà en cours. Résultat : en surface, rien d'anormal. C'est précisément ce qui la rend intéressante à détecter, parce que la défense doit regarder ailleurs que la simple liste des processus.

## Processus contre thread

Pour comprendre la détection, il faut distinguer deux notions. Un processus est un conteneur : sa propre mémoire, ses handles, ses modules chargés. Un thread est la plus petite unité d'exécution à l'intérieur d'un processus, et plusieurs threads d'un meme processus partagent la meme mémoire.

L'injection exploite cette mécanique : l'attaquant n'a pas besoin de créer un nouveau processus, il lui suffit de faire naitre un thread portant son code à l'intérieur d'un processus cible existant.

## La chaine d'injection vue par Sysmon

Une injection classique laisse une trace en plusieurs temps, et Sysmon capture chaque étape avec un Event ID distinct :

- **Event ID 1** : création du processus injecteur.
- **Event ID 10** : l'injecteur ouvre un handle sur le processus cible (`OpenProcess`), c'est la préparation.
- **Event ID 8** : création d'un thread distant dans la cible (`CreateRemoteThread`), c'est le déclenchement.
- **Event ID 7** : la cible charge de nouveaux modules, conséquence directe du code injecté.

Lue dans l'ordre, cette séquence raconte toute l'histoire : un processus en ouvre un autre, y écrit, y démarre un thread, et la cible se met à charger des choses qu'elle ne chargeait pas avant.

## Le signal le plus parlant

Parmi ces étapes, l'Event ID 7 offre souvent le signal le plus net, à condition de savoir quoi chercher.

Le code .NET (C#) ne s'exécute jamais directement : il passe par le CLR, le Common Language Runtime. Tout processus qui exécute du .NET charge donc `clr.dll` et `clrjit.dll`. C'est normal pour `powershell.exe`. Ca ne l'est pas du tout pour un processus système comme `spoolsv.exe`, `lsass.exe` ou `winlogon.exe`, qui n'ont aucune raison d'exécuter du .NET.

La régle se résume alors à une phrase : le chargement de `clr.dll` ou `clrjit.dll` par un processus qui n'est pas censé exécuter du .NET est un indicateur fort de compromission. Ce seul détecteur attrape une large famille de techniques : injection PowerShell, compilation C# inline, chargement d'assembly .NET en mémoire, et la plupart des outils offensifs modernes batis sur ce socle.

## La requete SPL

On traduit cette logique en une recherche qui isole les chargements de DLL .NET par des processus qui ne devraient jamais le faire. La liste d'exclusion regroupe les processus légitimement managés ; tout le reste remonte.

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
(ImageLoaded="*\\clr.dll" OR ImageLoaded="*\\clrjit.dll")
| eval processus=lower(mvindex(split(Image,"\\"), -1))
| search NOT processus IN ("powershell.exe","powershell_ise.exe","w3wp.exe","devenv.exe","msbuild.exe")
| stats count values(ImageLoaded) as modules min(_time) as premier_chargement by Computer, Image, User
| sort - count
```

La liste d'exclusion est à adapter à ton parc : chaque environnement a ses propres applications .NET légitimes. C'est tout l'enjeu d'une bonne détection comportementale, ne pas partir d'une liste universelle mais l'ajuster à la baseline réelle.

## Ce qu'il faut retenir

L'injection ne se voit pas dans la liste des processus, elle se lit dans la télémétrie comportementale. La chaine Sysmon 1, 10, 8, 7 en donne le déroulé complet, et le chargement anormal d'une DLL .NET en est le révélateur le plus simple à exploiter. C'est un bon exemple de ce que la détection moderne attend d'un analyste : raisonner sur ce qu'un processus a le droit de faire, pas seulement sur ce qu'il est.
