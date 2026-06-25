---
title: "Nimbus"
date: 2026-06-25
side: "red"
tags: ["htb", "linux", "machine", "cloud", "container-escape"]
summary: "Machine Linux (difficile). D'une vulnérabilité web exposée jusqu'à la compromission root de l'hôte, en passant par un environnement interne conteneurisé."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

Cette machine est sans aucun doute la plus dure de cette moitié de saison !

![Machine Nimbus résolue](/images/nimbus.png)

Machine Linux, difficulté élevée.

## Techniques mises en oeuvre

- Énumération des services exposés et des hôtes virtuels
- Exploitation d'une vulnérabilité web côté serveur
- Vol et réutilisation de credentials d'un service interne
- Exécution de code à distance via un service interne
- Accès à un environnement conteneurisé
- exploitation de mauvaise configuration du cloud AWS (Amazon Web Service)
- Évasion de conteneur vers l'hôte
- Root par abus d'un composant privilégié

## Outils utilisés

- Outils d'énumération
- Outils d'exploitation web
- Outils d'interaction avec des services internes