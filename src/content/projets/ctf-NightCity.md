---
title: "Night City (Reverse / Crypto)"
date: 2026-03-05
side: "red"
tags: ["CTF", "Reverse", "Crypto", "Unity", "Stéganographie"]
summary: "Challenge original de difficulté élevée mêlant reverse engineering d'un binaire Unity IL2CPP, cryptographie maison et stéganographie."
draft: false
---

## Le challenge

Night City est un challenge que j'ai conçu de bout en bout pour la plateforme [cyberwave](https://training.cyberwave.network/challenges), classé difficile, dans un univers cyberpunk : le joueur doit forcer le coffre de données neurales arraché au cadre d'une mégacorpo. Le flag est verrouillé derrière une chaîne d'étapes qui obligent à passer par plusieurs disciplines.

Particularité : le livrable n'est pas un binaire classique mais un jeu Unity compilé en IL2CPP sur Windows x64. Ce choix retire d'emblée la voie facile. Pas de DLL managée à ouvrir directement : il faut reconstruire le code à partir du binaire natif et des métadonnées, puis aller fouiller les assets du jeu.

vous pouvez retrouvez le writeup [ici](https://github.com/paoza33/Cyber/blob/main/misc/writeup_NightCity.md).

## Comment le challenge est construit

Le flag final est protégé par un empilement volontaire de couches :

- **Reverse IL2CPP** : reconstruire le code managé depuis le binaire natif et la métadonnée globale, pour comprendre le flux de déchiffrement.
- **Extraction d'assets Unity** : l'IV du chiffrement est caché par stéganographie dans un canal de couleur d'une texture, et le matériel de clé vit dans un ScriptableObject binaire rempli de blobs obfusqués. Lire le code ne suffit pas, il faut extraire et décoder les ressources du jeu.
- **KDF maison à reconstituer** : une dérivation de clé multi-étapes (sous-clés SHA-256, S-box générée par un Fisher-Yates seedé, fonction de tour façon Feistel avec clé de chaînage) à réimplémenter hors du binaire.
- **Déchiffrement final** en AES-256-CBC, une fois la clé et l'IV reconstitués.

## L'intention de conception

L'objectif était de récompenser la méthode et la lecture attentive du code, pas la vitesse ni un seul talent. Mais aussi d'éviter l'utilisation abusif de LLM. Deux mécanismes y travaillent :

- **Des leurres crédibles.** Le challenge contient deux faux chemins qui produisent chacun un flag d'apparence valide, dont un assez élaboré pour justifier à lui seul la présence de classes entières qui ne servent qu'à la diversion. Le vrai déchiffrement vit dans une méthode jamais appelée à l'exécution, donc impossible à repérer en se contentant d'observer ce que le programme fait tourner.
- **Des pièges anti-script.** Le KDF cache des détails qui font diverger silencieusement la clé si on le réimplémente à partir d'une lecture trop rapide : un re-hash périodique du keystream, un décalage modulaire avec rebouclage, un nombre de tours dérivé d'une somme. C'est ce qui sépare ceux qui lisent vraiment le code de ceux qui devinent.

## Un pont avec mon parcours

Ancien développeur gameplay, j'ai repris Unity, l'outil que je connaissais déjà côté création, pour le retourner côté sécurité. Concevoir ce challenge m'a poussé à comprendre l'interne d'IL2CPP et la composition de primitives cryptographiques bien plus en profondeur que si je m'étais contenté de résoudre un challenge existant.

## Ce que ce projet démontre

La conception de challenge est l'envers du pentest : il faut maîtriser une technique assez bien pour la mettre en scène proprement, doser la difficulté, et garantir qu'elle reste résoluble. Le projet couvre du reverse engineering avancé (Unity IL2CPP, extraction d'assets), de la cryptographie appliquée (composer correctement SHA-256, AES-CBC, Fisher-Yates et une structure de Feistel), et une vraie pensée d'attaquant, puisque les leurres et les pièges anticipent le comportement de celui qui cherche à résoudre.