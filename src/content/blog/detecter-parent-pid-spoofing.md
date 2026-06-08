---
title: "Parent PID Spoofing : quand Sysmon ment et ETW rétablit la vérité"
date: 2026-06-10
side: "blue"
tags: ["detection", "sysmon", "etw", "T1134"]
summary: "Certaines relations parent-enfant entre processus ne devraient jamais exister. Mais un attaquant peut falsifier le parent affiché et tromper Sysmon. Voici comment le détecter, et pourquoi il faut parfois descendre au niveau du kernel."
draft: false
---

Sous Windows, chaque processus connait son parent, celui qui l'a lancé. Ces relations forment une baseline comportementale : certaines sont normales, d'autres ne devraient jamais arriver. `explorer.exe` qui lance `cmd.exe`, c'est banal. `spoolsv.exe`, le service d'impression, qui lance `whoami.exe`, ca n'a aucun sens. Repérer ces filiations impossibles est l'une des détections les plus efficaces qui soient. Sauf qu'un attaquant peut mentir sur son parent, et c'est là que l'histoire devient intéressante.

## Le mécanisme du spoofing

Le Parent PID Spoofing consiste à faire croire au système qu'un processus a été lancé par un autre que son véritable parent. L'attaquant s'appuie sur une fonctionnalité légitime de l'API Windows, `UpdateProcThreadAttribute` avec l'attribut `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, qui permet de désigner explicitement un parent au moment de créer un processus.

Concrètement, si `powershell.exe` lance `cmd.exe` en spécifiant `spoolsv.exe` comme faux parent, le système enregistrera `spoolsv.exe` comme géniteur. L'intérêt pour l'attaquant est double : se fondre dans une filiation plausible, et tromper les outils de détection qui se fient à ce lien de parenté.

## Niveau 1 : détecter les filiations impossibles

La première ligne de défense reste très utile : surveiller les relations parent-enfant qui ne devraient jamais exister. Sysmon enregistre la création de chaque processus avec son parent dans l'Event ID 1. On peut donc lever une alerte dès qu'un processus système réputé silencieux engendre un interpréteur de commandes ou un outil de reconnaissance.

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent=lower(mvindex(split(ParentImage,"\\"), -1))
| eval enfant=lower(mvindex(split(Image,"\\"), -1))
| search parent IN ("spoolsv.exe","lsass.exe","services.exe","winlogon.exe")
    AND enfant IN ("cmd.exe","powershell.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe")
| table _time, Computer, ParentImage, Image, User, CommandLine
| sort - _time
```

Cette requete attrape les attaquants maladroits, et c'est déjà beaucoup. Mais elle a une faille de fond.

## La limite : Sysmon se fait tromper

Quand le spoofing est en place, Sysmon affiche le faux parent. Dans son Event ID 1, on verra `spoolsv.exe` comme parent de `cmd.exe`, alors que le véritable lanceur était `powershell.exe`. Autrement dit, l'attaquant peut soit fabriquer une filiation parfaitement crédible pour échapper à la requete ci-dessus, soit pousser un faux parent qui brouille l'enquete. Sysmon journalise fidèlement ce que l'API user-mode lui rapporte, et cette API a été manipulée.

C'est une leçon importante : une source de télémétrie n'est fiable que jusqu'au niveau où elle observe. Sysmon travaille en user-mode, donc tout ce qui ment en user-mode peut le tromper.

## Niveau 2 : descendre au kernel avec ETW

Pour retrouver la vérité, il faut une source que l'attaquant ne peut pas falsifier aussi facilement : le noyau. ETW, le mécanisme de traçage intégré à Windows, expose via le provider `Microsoft-Windows-Kernel-Process` la réalité des créations de processus telles que le kernel les voit, indépendamment de l'attribut de parent manipulé en user-mode.

Un outil comme SilkETW simplifie l'abonnement à ce provider :

```text
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\Windows\temp\etw.json
```

Dans la capture résultante, on retrouve le vrai lien : `powershell.exe` a réellement créé `cmd.exe`, là où Sysmon montrait `spoolsv.exe`. ETW contourne l'évasion parce qu'il observe à un niveau que la manipulation user-mode n'atteint pas.

## Ce qu'il faut retenir

Le Parent PID Spoofing illustre un principe central de la détection : ne jamais faire reposer une décision critique sur une source unique. La surveillance des filiations impossibles via Sysmon reste un excellent premier filet, peu couteux et très rentable. Mais face à un adversaire qui sait tromper le user-mode, la corrélation avec une source kernel comme ETW fait la différence entre une détection contournable et une détection robuste. Penser en couches, c'est le réflexe défensif par excellence.
