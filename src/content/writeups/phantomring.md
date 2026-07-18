---
title: "PhantomRing"
date: 2026-07-18
side: "blue"
tags: ["htb", "linux", "sherlock", "malware-analysis", "reverse-engineering"]
summary: "Sherlock HTB - Analyse statique d'un agent post-exploitation Linux. Extraction des IoC, cartographie des capacités et identification d'une technique d'évasion EDR basée sur io_uring."
draft: false
---

> Sherlock actuellement actif sur Hack The Box. Par respect des règles de la plateforme, ce write-up ne contient ni solution détaillée ni réponses aux tâches. Il présente uniquement les techniques et outils mis en oeuvre.

## Résolue

![Sherlock PhantomRing résolu](/images/phantomring.png)

Sherlock Linux, analyse statique de malware.

## Contexte

L'équipe SOC détecte un binaire suspect lors d'une opération de threat hunting sur un serveur Linux. Le fichier est trouvé dans `/var/tmp` avec un nom inhabituel et tente d'établir des connexions sortantes. La mission : analyse statique pour identifier les capacités de l'agent, extraire les indicateurs de compromission et comprendre l'infrastructure de l'attaquant.

## Techniques mises en oeuvre

- Hachage du binaire pour identification et recherche dans les bases de threat intel
- Extraction d'IoC statiques : adresse IP et port C2 codés en dur, délai de reconnexion
- Reconstruction du protocole C2 : cartographie des commandes supportées par l'agent
- Analyse de la technique d'évasion EDR par détournement d'une interface I/O kernel asynchrone
- Identification des capacités de reconnaissance post-exploitation (utilisateurs, processus, connexions réseau, binaires SUID)
- Analyse des mécanismes d'anti-forensique : désactivation du tracing kernel, neutralisation des agents de sécurité basés sur eBPF, autodestruction du binaire

## Outils utilisés

- PowerShell (`Get-FileHash`)
- Ghidra