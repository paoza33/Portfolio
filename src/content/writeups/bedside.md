---
title: "Bedside"
date: 2026-07-19
side: "red"
tags: ["htb", "linux", "machine", "deserialization", "docker", "path-traversal"]
summary: "Machine Linux (medium). Chaîne de désérialisations pickle et de contournements de validation, d'un portail d'upload médical jusqu'à la compromission complète via un pipeline d'entraînement IA."
draft: false
---

> Machine actuellement active. Par respect des règles de la plateforme Hack The Box, je ne fournis pas de write-up détaillé ni de flag. Voici les techniques et les outils mis en oeuvre pour la résoudre.

## Résolue

![Machine Bedside résolue](/images/bedside.png)

Machine Linux, difficulté medium.

## Techniques mises en oeuvre

- Fuzzing de sous-domaines et de répertoires
- Analyse d'un formulaire d'upload (validation MIME, liste blanche d'extensions, comportement par type)
- Contournement de la validation d'upload via une extension faiblement contrôlée
- Identification d'une librairie côté serveur via les headers HTTP de réponse
- Exploitation d'une désérialisation pickle dans un parseur PDF (CMap poisoning via un PDF crafté)
- Énumération d'un container Docker (réseau, montages, processus sans outils classiques)
- Exploitation d'un path traversal sur un serveur de développement interne pour lire des fichiers du host
- Extraction d'une clé SSH privée et pivot vers le host
- Exploitation d'une désérialisation pickle dans un checkpoint de machine learning chargé par un script exécutable en sudo

## Outils utilisés

- nmap
- ffuf
- curl
- Python (pickle, gzip, génération PDF et PNG)
- netcat