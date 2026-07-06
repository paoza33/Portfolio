---
title: "MakeSense"
date: 2026-07-06
side: "red"
tags: ["htb", "linux", "machine", "web", "credential-access"]
summary: "Machine Linux (difficulté moyenne). D'une vulnérabilité web exploitée à distance jusqu'à root, par enchaînement de prise de contrôle applicative, de réutilisation de credentials et d'un abus de service privilégié."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine MakeSense résolue](/images/makesense.png)

Machine Linux, difficulté moyenne.

## Techniques mises en oeuvre

- Énumération web et découverte de services internes
- Exploitation d'une vulnérabilité web avec droit admin
- Exécution de code côté serveur
- Réutilisation de credentials
- Accès à un service interne exposé uniquement en local
- Élévation vers root par abus d'un service privilégié

## Outils utilisés

- Outils d'énumération web
- Outils d'exploitation web
- ssh