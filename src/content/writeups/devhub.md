---
title: "DevHub"
date: 2026-06-05
side: "red"
tags: ["htb", "linux", "machine", "rce", "cve", "ssh-tunneling"]
summary: "Machine Linux (Ubuntu 24.04). RCE non authentifiée sur un service exposé, pivot vers un service interne via tunnel, puis root par abus d'un service privilégié."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine DevHub résolue](/images/devhub.png)

Machine Linux (Ubuntu 24.04).

## Techniques mises en oeuvre

- Reconnaissance, service exposé sur un port inhabituel
- RCE non authentifiée via une CVE (injection de commande)
- Stabilisation du shell
- Découverte d'un service interne, token d'authentification fuité dans la ligne de commande d'un processus
- Pivot par tunnel inverse vers ce service interne
- Exécution de code en tant qu'utilisateur intermédiaire
- Root par abus d'un service interne tournant en root (outil non documenté, clé d'API en dur, lecture de la clé SSH root)

## Outils utilisés

- nmap
- netcat
- chisel
- curl
- ssh
