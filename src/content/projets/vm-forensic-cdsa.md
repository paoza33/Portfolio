---
title: "VM d'analyse forensique (préparation CDSA)"
date: 2026-05-02
side: "blue"
tags: ["Forensic", "DFIR", "Volatility", "YARA", "Splunk"]
summary: "Mise en place d'un environnement d'analyse forensique Windows complet pour l'entraînement DFIR : toolchain, ingestion de logs et analyse mémoire."
draft: false
---

## Objectif

Construire un poste d'analyse forensique reproductible pour m'entraîner à l'investigation numérique, en préparation de la certification CDSA (Certified Defensive Security Analyst, HTB).

Un parti pris cadre tout le reste : il s'agit d'une station d'analyse, pas d'un endpoint instrumenté ni d'un SOC. La VM examine des artefacts qui viennent de l'extérieur (les dumps mémoire, EVTX et PCAP fournis dans les Sherlocks HTB), elle ne génère pas elle-même les données à analyser. Cette distinction dicte la plupart des choix qui suivent : tout ce qui produirait du bruit propre à la machine est volontairement écarté.

## Environnement

VM Windows Server 2022 sous VMware Workstation, 16 GB de RAM. Un snapshot est pris à chaque étape majeure de l'installation, ce qui permet de revenir à un état stable sans tout réinstaller. L'état de référence final est prêt à attaquer un Sherlock en quelques minutes.

## Toolchain

Les outils sont organisés par fonction d'analyse :

- **Système et timeline** : EZ Tools (Eric Zimmerman) pour parser MFT, Registry, Prefetch, ShellBags, et Sysinternals pour l'analyse de processus et d'autoruns.
- **Hunt sur journaux** : Chainsaw et Hayabusa (moteurs Sigma en Rust) pour le hunt EVTX exhaustif et la production de timelines exploitables.
- **Analyse mémoire** : Volatility 3, avec Volatility 2 en repli pour les dumps Windows anciens et les plugins jamais portés (clipboard, userassist, shellbags).
- **Analyse de binaires** : DIE, FLOSS, CAPA et PEStudio pour le triage statique, x64dbg et Ghidra pour l'analyse dynamique et la décompilation.
- **Détection par signatures** : YARA avec plusieurs jeux de règles communautaires (signature-base de Florian Roth, Elastic, Yara-Rules).
- **SIEM** : Splunk Enterprise en mode forensic à la demande, piloté par des scripts PowerShell.

## Choix structurants

Au-delà de la liste d'outils, plusieurs décisions reflètent la philosophie de station d'analyse :

- **Sysmon n'est pas installé en service.** Une VM d'analyse n'a aucun intérêt à générer ses propres events Sysmon : ce ne serait que du bruit (navigation, lancement d'outils) qui polluerait l'investigation. Il reste disponible pour une détonation contrôlée ponctuelle, puis désinstallé.
- **Splunk en forensic à la demande, pas en SIEM permanent.** Pas d'auto-start, pas de forwarder, pas de monitoring temps réel des journaux locaux. Splunk ne tourne que pendant une investigation, n'ingère que les artefacts qu'on lui pousse, et les indexes sont purgés une fois le Sherlock terminé. La licence Free (500 MB/jour) suffit largement à cet usage.
- **CLI privilégiée sur le GUI** quand c'est possible, pour la reproductibilité et la scriptabilité. Les interfaces graphiques (Timeline Explorer, Ghidra, x64dbg) ne sont mobilisées que quand la navigation visuelle apporte vraiment quelque chose.
- **L'hôte Kali sert de complément.** Tout ce qui est lourd ou natif Linux (Zeek, Suricata, acquisition mémoire via suspend VMware) reste sur l'hôte. La VM Windows reste légère et spécialisée.

## Difficultés résolues

Le setup a buté sur plusieurs problèmes d'outillage concrets, chacun documenté avec sa cause et sa solution :

- **Crash des EZ Tools au lancement** lié à la protection mémoire matérielle Intel CET, mal gérée par le runtime .NET 9 sur Server 2022. Réglé par une mitigation appliquée par exécutable, persistante aux reboots.
- **Volatility 3 incompatible avec le Python système** (3.14, trop récent pour les dépendances yara-python, capstone, pycryptodome). Réglé par un environnement virtuel Python 3.12 dédié, sans toucher au Python système.
- **Ingestion EVTX dans Splunk** : plusieurs pièges silencieux où Splunk reporte une ingestion réussie mais ne renvoie aucun event. Le principal venait d'une résolution AD tentée par défaut sur une VM hors domaine, qui faisait échouer tout le pipeline de parsing. Diagnostic confirmé via l'audit de configuration effective (`btool`), pas par lecture manuelle des fichiers.

## Ce que ce projet démontre

L'autonomie sur la construction d'un environnement DFIR de bout en bout, et la capacité à débloquer des problèmes d'outillage réels plutôt que de suivre un tutoriel. Surtout, une compréhension du pourquoi de chaque choix : un environnement n'est pas une accumulation d'outils, c'est une logique cohérente alignée sur un usage précis.