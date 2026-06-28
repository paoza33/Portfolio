---
title: "Enigma"
date: 2026-06-28
side: "red"
tags: ["htb", "linux", "machine", "web", "credential-access"]
summary: "Machine Linux (facile). D'un partage réseau exposé jusqu'à root, par enchaînement de réutilisation de credentials, d'une exécution de code applicative et d'un abus de service privilégié."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Enigma résolue](/images/enigma.png)

Machine Linux, difficulté facile.

## Techniques mises en oeuvre

- Énumération des services exposés et des hôtes virtuels
- Récupération de credentials sur un partage réseau mal configuré
- Réutilisation de credentials et pivot entre comptes
- Exécution de code à distance via une application web vulnérable
- Récupération et cassage de secrets pour rebondir vers un compte local
- Élévation vers root par abus d'un service privilégié

## Outils utilisés

- Outils d'énumération
- Outils d'exploitation web
- Outils de cassage de hash hors ligne
- Outils de pivot réseau