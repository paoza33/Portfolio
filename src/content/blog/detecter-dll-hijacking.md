---
title: "Détecter un DLL hijacking"
date: 2026-06-08
side: "blue"
tags: ["detection", "sysmon", "dll-hijacking", "T1574"]
summary: "Un exécutable parfaitement légitime peut charger une DLL malveillante sans le savoir, simplement à cause de l'ordre de recherche de Windows. Voici comment l'attaque fonctionne et les trois indicateurs qui la trahissent."
draft: false
---

Le DLL hijacking est une technique élégante par sa discrétion : l'exécutable lancé est légitime, signé, connu. Ce qui est malveillant, c'est la DLL qu'il charge à son insu. Aucun fichier suspect ne s'exécute directement, le processus visible est un binaire de confiance. Tout repose sur une faiblesse de conception dans la facon dont Windows va chercher ses bibliothèques.

## L'ordre de recherche des DLL

Quand un programme a besoin d'une DLL, Windows ne la cherche pas à un seul endroit. Il suit un ordre de priorité : d'abord le dossier courant de l'application, puis les répertoires système comme `System32`, puis les chemins du PATH. Le premier fichier trouvé portant le bon nom est chargé, sans autre vérification.

C'est là que réside la faille. Si un attaquant parvient à placer une DLL malveillante du meme nom qu'une DLL système, dans un dossier examiné en priorité, c'est sa version qui sera chargée à la place de la légitime.

## Comment l'attaque se met en place

Le scénario typique tient en quelques étapes. L'attaquant renomme sa DLL malveillante avec le nom d'une bibliothèque attendue, par exemple `WININET.dll`. Il dépose cette DLL à coté d'un exécutable légitime, comme `calc.exe`, dans un dossier où il a les droits d'écriture : le Bureau, le dossier Téléchargements, n'importe quel emplacement non standard. Puis il lance l'exécutable depuis ce dossier.

Au démarrage, `calc.exe` cherche `WININET.dll`, trouve d'abord celle qui est juste à coté de lui, et la charge à la place de la version saine de `System32`. Le code malveillant s'exécute alors dans le contexte d'un processus de confiance.

## Les trois indicateurs

Pour détecter ce comportement, on journalise tous les chargements de modules avec Sysmon, via l'Event ID 7 (ImageLoad). Trois indicateurs, pris ensemble, constituent une signature très forte :

- Une DLL chargée depuis un chemin inhabituel, c'est à dire ailleurs que `System32`, `SysWOW64` ou les emplacements système attendus.
- Une DLL non signée (`Signed = false`), alors que son équivalent système légitime l'est.
- Un exécutable légitime lancé hors de son emplacement normal, signe qu'on a recopié le binaire ailleurs pour mettre en place le piège.

Aucun de ces signaux n'est concluant seul. Une DLL non signée peut etre parfaitement bénigne, un logiciel peut légitimement vivre hors de `Program Files`. C'est leur conjonction qui fait basculer le diagnostic.

## La requete SPL

On cherche donc les chargements de DLL qui sont à la fois non signés et hors des chemins système. Le but n'est pas d'alerter sur chaque DLL non signée, mais sur celles qui se trouvent là où une bibliothèque système ne devrait jamais etre.

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| eval chemin=lower(ImageLoaded)
| where Signed="false"
    AND NOT match(chemin, "\\\\windows\\\\(system32|syswow64|winsxs)\\\\")
    AND NOT match(chemin, "\\\\program files")
| stats count by Computer, Image, ImageLoaded, Signed
| sort - count
```

Pour aller plus loin, on peut croiser ce résultat avec une liste des noms de DLL système connus : voir `wininet.dll`, `version.dll` ou `dbghelp.dll` chargée depuis un dossier utilisateur est nettement plus parlant qu'une DLL applicative inconnue au meme endroit.

## Ce qu'il faut retenir

Le DLL hijacking exploite une mécanique normale de Windows, pas une vulnérabilité logicielle classique. La défense ne consiste donc pas à chercher un exploit, mais une anomalie de contexte : une bibliothèque au mauvais endroit, sans signature, à coté d'un binaire déplacé. C'est un raisonnement de localisation et de confiance, typique de l'analyse défensive.
