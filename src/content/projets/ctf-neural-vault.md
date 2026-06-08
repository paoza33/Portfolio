---
title: "CTF Neural Vault (Reverse / Crypto)"
date: 2026-03-05
side: "red"
tags: ["CTF", "Reverse", "Crypto", "Unity", "Stéganographie"]
summary: "Challenge original de difficulté élevée mêlant reverse engineering d'un binaire Unity IL2CPP, cryptographie maison et stéganographie."
draft: false
---

> Page témoin. Remplace par ton write-up ou ta présentation du challenge.

## Le challenge

Neural Vault est un challenge original que j'ai conçu, classé difficile, combinant plusieurs disciplines :

- **Reverse engineering** d'un binaire Unity compilé en IL2CPP.
- **Cryptographie** : une fonction de dérivation de clé (KDF) maison et des rounds de Feistel.
- **Stéganographie** : dissimulation par LSB.

## L'intention de conception

L'idée était de forcer le joueur à enchaîner les disciplines plutôt qu'à exceller dans une seule, en récompensant la patience et la méthode.

## Ce que ce projet démontre

La création de challenge, c'est l'envers du pentest : il faut comprendre une technique assez bien pour la mettre en scène proprement et la rendre résoluble.
