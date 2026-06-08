---
title: "BYOL : détecter les outils .NET chargés en mémoire"
date: 2026-06-11
side: "blue"
tags: ["detection", "sysmon", "byol", "T1620"]
summary: "Les attaquants embarquent de plus en plus leurs propres outils .NET et les exécutent directement en mémoire, sans jamais écrire sur le disque. Voici pourquoi c'est furtif, et le signal qui les trahit malgré tout."
draft: false
---

Pendant longtemps, les attaquants ont privilégié les LOLBins, ces binaires légitimes déjà présents sur le système, pour rester discrets. L'étape suivante s'appelle le BYOL, pour Bring Your Own Land : plutot que de se limiter aux outils natifs, l'attaquant embarque ses propres outils .NET, comme Seatbelt, Rubeus, SharpHound ou Certify, et les charge directement en mémoire. L'intéret pour lui est considérable, et c'est précisément ce qui en fait un cas de détection intéressant.

## Pourquoi c'est furtif

La force du BYOL tient en une phrase : rien n'est écrit sur le disque. L'assembly .NET est chargée et exécutée directement en mémoire, sans créer de fichier. Or une bonne partie des défenses classiques reposent sur le disque : l'analyse antivirus à l'écriture d'un fichier, la comparaison de hash, l'inspection des exécutables présents. Sans artefact sur disque, tous ces mécanismes sont aveugles. L'attaquant peut ainsi exécuter un outil de reconnaissance Active Directory complet sans laisser le moindre fichier à analyser.

Il faut donc renoncer à chercher un fichier, et chercher plutot une trace d'exécution. C'est là que le comportement du runtime .NET devient notre allié.

## La constante du runtime .NET

Le code .NET ne s'exécute jamais seul. Il a besoin du CLR, le Common Language Runtime, pour tourner. Tout processus qui exécute du .NET charge donc inévitablement certaines bibliothèques du runtime, en particulier `clr.dll` et `mscoree.dll`, cette dernière étant le composant d'amorçage du .NET.

C'est le talon d'Achille du BYOL. L'attaquant peut éviter le disque, obfusquer son code, renommer son outil, mais il ne peut pas exécuter du .NET sans charger le runtime. Et si ce runtime apparait dans un processus qui n'a aucune raison d'exécuter du .NET, le drapeau se lève.

## Le raisonnement de détection

On part d'une baseline simple. Certains processus sont managés par conception et chargent le runtime normalement : `powershell.exe`, les applications web sous `w3wp.exe`, les outils de développement. À l'inverse, une foule de processus système ou utilitaires n'ont jamais à toucher au .NET. Voir `mscoree.dll` ou `clr.dll` se charger dans l'un d'eux signale qu'on y a injecté ou exécuté du code .NET, ce qui est exactement la signature du BYOL.

On surveille donc, via l'Event ID 7 de Sysmon, le chargement des bibliothèques du runtime, en écartant les hotes .NET légitimes.

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
(ImageLoaded="*\\clr.dll" OR ImageLoaded="*\\mscoree.dll" OR ImageLoaded="*\\clrjit.dll")
| eval processus=lower(mvindex(split(Image,"\\"), -1))
| search NOT processus IN ("powershell.exe","powershell_ise.exe","w3wp.exe","devenv.exe","msbuild.exe","dotnet.exe")
| stats values(ImageLoaded) as runtime min(_time) as premier_chargement by Computer, Image, User
| sort - premier_chargement
```

Comme toujours, la liste d'exclusion doit refléter ton parc : un environnement de développement aura beaucoup plus de processus .NET légitimes qu'un serveur de production verrouillé, où le moindre chargement de runtime hors des hotes attendus mérite l'attention.

## Ce qu'il faut retenir

Le BYOL déplace le terrain de jeu du disque vers la mémoire, et oblige le défenseur à faire de meme. On ne cherche plus un fichier malveillant, on cherche l'empreinte inévitable de son exécution. C'est une illustration nette d'un glissement plus général en sécurité : à mesure que les attaques deviennent sans fichier, la détection devient comportementale. Le runtime .NET chargé là où il ne devrait pas etre est l'un des signaux les plus fiables de cette catégorie.
