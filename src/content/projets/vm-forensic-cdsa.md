---
title: "VM d'analyse forensique (préparation CDSA)"
date: 2026-05-02
side: "blue"
tags: ["Forensic", "DFIR", "Volatility", "YARA", "Splunk"]
summary: "Mise en place d'un environnement d'analyse forensique Windows complet pour l'entraînement DFIR : toolchain, ingestion de logs et analyse mémoire."
draft: false
---

> Page témoin. Remplace par le tien, garde le frontmatter à jour.

## Objectif

Construire un poste d'analyse forensique reproductible pour m'entraîner à l'investigation numérique (préparation de la certification CDSA).

## La toolchain installée

- **Analyse système et timeline** : EZ Tools, Sysinternals.
- **Détection sur logs** : Chainsaw, Hayabusa, YARA (plusieurs jeux de règles).
- **Analyse mémoire** : Volatility 3, avec repli sur Volatility 2 pour certains plugins sur cibles anciennes.
- **Analyse de binaires** : PEStudio, DIE, FLOSS, CAPA, x64dbg, Ghidra.
- **SIEM** : Splunk Enterprise en mode forensic à la demande, piloté par scripts PowerShell.

## Difficultés résolues

Plusieurs points de friction réels : conflits de versions Python pour Volatility (résolus via environnement virtuel dédié), ingestion d'EVTX en état dirty, et filtrage des sources dans Splunk.

## Ce que ce projet démontre

L'autonomie sur la mise en place d'un environnement DFIR de bout en bout, et la capacité à débloquer des problèmes d'outillage concrets.
