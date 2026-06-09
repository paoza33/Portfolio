---
title: "Cleanic : infrastructure sécurisée d'une clinique"
date: 2026-04-10
updated: 2026-05-20
side: "blue"
tags: ["pfSense", "VLAN", "WireGuard", "Wazuh", "EBIOS"]
summary: "Conception et sécurisation de l'infrastructure réseau d'une clinique fictive : segmentation VLAN, pare-feu redondant, VPN, supervision et analyse de risque."
draft: false
---

## Contexte

Projet support du titre Administrateur d'Infrastructures Sécurisées (AIS, RNCP 37680). L'objectif : concevoir et sécuriser de bout en bout l'infrastructure d'une clinique pluridisciplinaire fictive (Cleanic), de l'analyse de risque jusqu'à la supervision, en appliquant une démarche Secure by Design.

La clinique manipule des données de santé sensibles (dossiers patients, rendez-vous, prescriptions), ce qui place le RGPD et les recommandations de l'ANSSI au centre de chaque décision. Le dimensionnement reste celui d'une structure de taille moyenne : les choix doivent rester tenables pour une petite équipe IT.

Retrouvez le projet complet Cleanic en suivant ce lien : [Cleanic](https://github.com/paoza33/Cyber/blob/main/AIS/Cleanic.pdf)

## Architecture

![Architecture Cleanic](/images/cleanic_infra.png)

Le réseau est segmenté en VLAN isolés, chacun limité à un usage unique : DMZ web, backend, base de données, Active Directory, serveur de fichiers, postes employés, postes d'administration IT, sauvegardes et supervision. Le passage d'un VLAN à un autre n'est possible qu'à travers le pare-feu, qui applique un filtrage deny by default : tout flux non explicitement autorisé est bloqué.

- **Pare-feu pfSense en haute disponibilité** (cluster CARP master/backup, synchronisation sur lien dédié). C'est la seule HA complète de l'infrastructure, justifiée par le rôle central du pare-feu : sa panne couperait tout le réseau.
- **Segmentation VLAN** isolant chaque zone fonctionnelle, avec des flux limités au strict nécessaire entre les couches applicatives (le frontend ne peut pas joindre directement la base, il doit passer par le backend).
- **VPN WireGuard** pour l'accès distant des praticiens et de l'équipe IT, avec une paire de clés et une IP individuelle par utilisateur pour tracer chaque connexion.
- **Supervision Wazuh** : agents déployés sur l'ensemble des serveurs et postes, centralisation des journaux, détection d'anomalies et alerte. Le serveur de supervision est en position d'écoute seule, ce qui réduit le risque de pivot s'il est compromis.

## Choix techniques

Chaque brique a été retenue pour un compromis entre sécurité, intégration avec l'écosystème métier et maintenabilité par une équipe restreinte.

- **Frontend** : Debian et Nginx en reverse-proxy (terminaison TLS, masquage de la topologie interne, WAF possible via ModSecurity). Authentification par JWT, Fail2Ban sur les tentatives répétées.
- **Backend** : Debian et Node.js/Express. Logique métier, validation des utilisateurs via l'AD, requêtes SQL paramétrées contre l'injection, RBAC applicatif.
- **Base de données** : PostgreSQL conteneurisée sous Docker. Retenue pour ses garanties ACID, son contrôle d'accès fin et l'audit via pgAudit, indispensables pour des données médicales.
- **Active Directory** sur Windows Server 2022 : gestion centralisée des identités, organisation en OU par service, modèle AGDLP, GPO de durcissement et politique de mots de passe alignée ANSSI.
- **Serveur de fichiers** Windows Server en SMB, intégré à l'AD : accès différencié par rôle via ACL NTFS, SMB signé et chiffré, SMBv1 désactivé.
- **Sauvegardes** : deux NAS spécialisés (base et fichiers), chiffrement systématique, réplication hors site vers un prestataire certifié HDS selon la règle 3-2-1.

Plusieurs limites sont assumées et documentées plutôt que masquées : certificats auto-signés en lab, redondance disque RAID 10 prévue mais non implémentable sous GNS3, HA limitée au pare-feu. Chaque écart est reporté en recommandation pour un passage en production.

## Analyse de risque

L'analyse suit la méthodologie EBIOS Risk Manager (scénarios de menace structurés) couplée à un scoring CVSS pour la gravité. Les risques retenus (accès non autorisé aux données patients, ransomware, injection, interception, escalade de privilèges) sont chacun associés à deux ensembles distincts : les mesures réellement implémentées dans le lab et celles recommandées pour la production. Cette séparation évite de présenter comme actives des protections qui ne le sont pas.

## Évolution : téléconsultation

Le projet intègre un volet d'évolution maîtrisée : l'ajout d'un service de téléconsultation auto-hébergé (Jitsi Meet), isolé dans un nouveau VLAN et branché sur les briques existantes par JWT, sans toucher à l'AD ni à la base patients. Cette partie applique un durcissement Docker plus poussé (utilisateur non-root, capabilities réduites, secrets Docker, scan d'images) et une supervision outillée par des règles dédiées, des playbooks et un cycle d'amélioration continue.

## Ce que ce projet démontre

Une capacité à penser la sécurité de façon globale : pas un empilement d'outils, mais une architecture cohérente alignée sur un référentiel de risque, où chaque flux ouvert répond à un besoin métier identifié et chaque restriction réduit une surface d'attaque. Le projet couvre les deux blocs du titre AIS : administrer et sécuriser une infrastructure, puis la faire évoluer dans un cadre contrôlé sans dégrader l'existant.