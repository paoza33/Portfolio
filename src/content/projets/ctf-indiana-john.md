---
title: "CTF Indiana John (Stéganographie / OSINT)"
date: 2026-01-20
side: "red"
tags: ["CTF", "Stéganographie", "OSINT"]
summary: "Challenge original de difficulté moyenne, orienté investigation : recherche en sources ouvertes et dissimulation d'informations."
draft: false
---

## Le challenge

Indiana John est un challenge que j'ai conçu pour la plateforme [cyberwave](https://training.cyberwave.network/challenges), de difficulté moyenne, construit comme une enquête narrative. Le point de départ : un explorateur, John, sans nouvelles depuis des mois, dont on reçoit la photo intrigante d'un homme qui « cache quelque chose ». Le joueur remonte le fil de ses traces jusqu'à un secret final.

L'ensemble enchaîne trois disciplines, chaque étape débloquant la suivante :

- **OSINT** : identifier un personnage réel par recherche d'image inversée, dont les travaux fournissent le mot-clé qui ouvre l'étape suivante.
- **Stéganographie et forensic de fichiers** : des données dissimulées dans l'image, puis un travail de nettoyage binaire pour retirer une pollution injectée dans le flux du fichier, sur plusieurs couches imbriquées (un fichier caché dans un fichier).
- **Lecture d'un artefact final** dans un format qu'on n'associe pas spontanément à un CTF.

vous pouvez retrouvez le writeup [ici](https://github.com/paoza33/Cyber/blob/main/misc/writeup_Indiana_John.md).

## L'intention de conception

Proposer une enquête progressive et sans impasse frustrante, accessible à un public intermédiaire. Trois principes ont guidé la conception :

- **Chaque indice mène au suivant.** Le joueur n'est jamais bloqué sans piste : la note laissée à chaque étape oriente vers la mécanique à employer, sans donner la réponse.
- **Une histoire qui avance.** Les messages de John à chaque palier tissent un récit, ce qui entretient l'envie de continuer au-delà de la simple résolution technique.
- **Des fausses pistes maîtrisées.** Quelques leurres ralentissent sans punir, pour récompenser la rigueur sans transformer le challenge en piège gratuit.

## Ce que ce projet démontre

Une sensibilité réelle à l'investigation en sources ouvertes, utile des deux côtés : en reconnaissance offensive comme en threat intelligence défensive, un axe directement lié à mon objectif de poste d'analyste SOC. Le projet montre aussi la maîtrise du forensic de fichiers (formats, données dissimulées, manipulation binaire) et le soin apporté à la conception d'un parcours : doser la difficulté, guider sans tenir la main, et garder le joueur engagé du premier indice au dernier.