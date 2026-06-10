---
title: "Silentium"
date: 2026-04-25
side: "red"
tags: ["htb", "linux", "machine", "web", "rce", "ssh-tunneling"]
summary: "Machine Linux (facile). Account takeover par fuite de token, RCE via injection de code, pivot vers l'hote par secrets exposés, puis root via une CVE sur un service interne."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Silentium résolue](/images/silentium.png)

Machine Linux, difficulté facile.

## Techniques mises en oeuvre

- Énumération de vhost et de sous-domaine
- Account takeover via une fuite de token (information disclosure liée à une CVE)
- Énumération d'utilisateurs par différence de réponse
- RCE par injection de code dans la plateforme web (CVE)
- Pivot vers l'hote via des secrets exposés dans les variables d'environnement d'un conteneur
- Accès SSH
- Découverte d'un service interne par énumération des ports en écoute
- Redirection de port pour atteindre ce service
- Root via une CVE sur le service interne

## Outils utilisés

- nmap
- ffuf
- curl
- Metasploit
- ssh (redirection de port)
