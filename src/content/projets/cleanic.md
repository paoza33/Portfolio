---
title: "Cleanic : infrastructure sécurisée d'une clinique"
date: 2026-04-10
updated: 2026-05-20
side: "blue"
tags: ["pfSense", "VLAN", "WireGuard", "Wazuh", "EBIOS"]
summary: "Conception et sécurisation de l'infrastructure réseau d'une clinique fictive : segmentation VLAN, pare-feu redondant, VPN, supervision et analyse de risque."
draft: false
---

> Ceci est une page témoin. Remplace le contenu par le tien, garde le frontmatter à jour.

## Contexte

Projet support de la certification AIS, articulé autour d'une clinique fictive (Cleanic). L'objectif : concevoir une infrastructure sécurisée de bout en bout, de l'analyse de risque jusqu'à la supervision, en appliquant une démarche Secure by Design.

## Architecture mise en place

- **Pare-feu pfSense en haute disponibilité** (CARP), pour éliminer le point de défaillance unique.
- **Segmentation VLAN** isolant les postes de soin, l'administratif, les équipements médicaux et l'infrastructure.
- **VPN WireGuard** pour l'accès distant des praticiens, avec authentification forte.
- **Supervision Wazuh** : centralisation des logs, détection d'intrusion et alerting.

## Analyse de risque

Démarche EBIOS Risk Manager pour identifier les scénarios de menace, et scoring CVSS sur les vulnérabilités retenues. Le tout débouche sur un plan de traitement priorisé.

## Ce que ce projet démontre

Une capacité à penser la sécurité de façon globale : pas seulement des outils, mais une architecture cohérente alignée sur un référentiel de risque.
