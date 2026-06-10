---
title: "Aide-mémoire : les Event IDs Windows et Sysmon"
date: 2026-06-09
side: "blue"
tags: ["reference", "event-id", "windows", "sysmon", "siem"]
summary: "Référence rapide des identifiants d'événements Windows et Sysmon utiles en détection et en investigation, classés par journal, avec ce que chacun révèle et l'angle de détection associé. Inclut les types de logon, les codes d'échec Kerberos et NTLM, et les chaînes d'attaque courantes."
draft: false
---

Cette page est un aide-mémoire de référence, pensée pour le triage et l'investigation. Elle rassemble les Event IDs que je croise en analyse, classés par journal, avec en regard leur signification et l'angle de détection associé. Beaucoup de ces événements ne sont pas activés par défaut et nécessitent une politique d'audit adaptée, point sur lequel je reviens en fin de page.

## Journal Security

C'est le journal le plus dense pour la détection : authentification, élévation de privilèges, persistance, couverture de traces et activité Active Directory.

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 1102 | Effacement du journal Security | Couverture de traces (T1070.001) |
| 1116 | Détection d'un malware par Defender | Confirmation d'infection, pivot timeline |
| 1118 / 1119 | Remédiation Defender : début / succès | Cycle de remédiation |
| 1120 | Échec de remédiation Defender | Critique : Defender n'a pas pu nettoyer (T1562.001) |
| 4624 | Ouverture de session réussie | Pivot universel : PtH (Type 9), RDP (Type 10), accès partage (Type 3) |
| 4625 | Ouverture de session échouée | Force brute, password spraying (voir codes SubStatus) |
| 4634 | Fermeture de session | Corrélation de la durée de session |
| 4648 | Connexion avec identifiants explicites | Mouvement latéral, runas, signal Responder |
| 4656 | Demande de handle sur un objet | Accès à un fichier ou une clé sensible |
| 4662 | Accès à un objet de l'annuaire (audit DS Access requis) | DCSync : Access_Mask 0x100 + GUID Get-Changes (T1003.006) |
| 4663 | Lecture d'un objet audité | Accès à des fichiers d'identifiants, honeypot GPP |
| 4670 | Modification des permissions d'un objet | Persistance ou élévation |
| 4672 | Attribution de privilèges spéciaux | SeDebug, SeTcb : activité sensible, signal Silver Ticket |
| 4675 | SID filtrés en cross-domain | Abus de SID History (T1134.005) |
| 4688 | Création d'un nouveau processus (natif) | LOLBins, PowerShell encodé (CommandLine longue), MSBuild |
| 4689 | Fin d'un processus | Corrélation du cycle de vie |
| 4697 | Installation d'un service via le SCM | Persistance, mouvement latéral (T1543.003) |
| 4698 | Création d'une tache planifiée | Persistance, exécution différée (T1053.005) |
| 4699 | Suppression d'une tache planifiée | Nettoyage par l'attaquant |
| 4700 / 4701 | Tache planifiée activée / désactivée | Persistance, masquage |
| 4702 | Tache planifiée modifiée | Modification de payload |
| 4719 | Modification de la stratégie d'audit | Réduction du logging (T1562.002) |
| 4720 | Création d'un compte utilisateur | Comptes pirates, base de référence Silver Ticket (T1136) |
| 4722 | Activation d'un compte | Réactivation d'un compte dormant |
| 4723 | Changement de mot de passe par l'utilisateur | Activité normale, à corréler |
| 4724 | Réinitialisation de mot de passe par un admin | Abus de l'ACL ForceChangePassword (T1098) |
| 4725 | Désactivation d'un compte | Réponse à incident ou attaquant désactivant des comptes |
| 4726 | Suppression d'un compte | Couverture de traces |
| 4728 | Ajout à un groupe global de sécurité | Élévation de privilèges domaine |
| 4732 | Ajout à un groupe local | Élévation locale, ajout à Administrators (T1078.003) |
| 4733 | Retrait d'un groupe local | Suppression de traces |
| 4738 | Modification d'un compte utilisateur | Ajout de SPN (préparation Kerberoasting) |
| 4740 | Verrouillage de compte | Conséquence d'une force brute |
| 4742 | Modification d'un compte ordinateur | DCShadow : ajout de SPN sur une machine (T1207) |
| 4768 | Demande de TGT Kerberos (AS-REQ) | AS-REProast (Pre-Auth Type 0), force brute Kerberos (T1558.004) |
| 4769 | Demande de ticket de service (TGS-REQ) | Kerberoasting (RC4 sans 4648), Pass-the-Ticket (T1558.003) |
| 4770 | Renouvellement d'un ticket de service | À combiner avec 4768/4769 pour Pass-the-Ticket |
| 4771 | Échec de pré-authentification Kerberos | Force brute Kerberos (codes 0x18, 0x6) |
| 4776 | Validation d'identifiants NTLM sur un DC | Force brute NTLM (0xC0000064, 0xC000006A) |
| 4778 | Reconnexion d'une session RDP | Mouvement latéral RDP (T1021.001) |
| 4779 | Déconnexion d'une session RDP | Corrélation RDP |
| 4781 | Renommage d'un compte | Couverture de traces |
| 4798 | Énumération de l'appartenance aux groupes locaux | Reconnaissance (net localgroup, BloodHound) |
| 4799 | Énumération des membres d'un groupe local | Reconnaissance (net localgroup administrators) |
| 4886 / 4887 | Demande / émission de certificat sur une CA | AD CS ESC1 (T1649) |
| 4907 | Modification des paramètres d'audit d'un objet | Affaiblissement de la journalisation |
| 4929 / 4930 | Source de réplication AD retirée / ajoutée | DCShadow possible (T1207) |
| 5001 | Changement de configuration de l'antivirus temps réel | Désactivation de Defender (T1562.001) |
| 5136 | Modification d'un objet de l'annuaire (dont GPO) | Abus de GPO (T1484.001) |
| 5140 | Accès à un partage réseau | Mouvement latéral, exploration de partages |
| 5142 | Création d'un partage réseau | Exfiltration possible |
| 5143 / 5144 | Modification / suppression d'un partage | Couverture de traces sur 5144 |
| 5145 | Vérification des droits sur un partage | Cartographie réseau suspecte (T1135) |
| 5156 | Connexion autorisée par le Windows Filtering Platform | Visibilité réseau sans Sysmon |
| 5157 | Connexion bloquée par le Windows Filtering Platform | Trafic potentiellement malveillant |
| 5447 | Filtre WFP modifié | Modification de pare-feu (T1562.004) |

## Journal System

Plus léger que Security, mais critique pour la persistance et le tampering.

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 104 | Effacement du journal System | Couverture de traces (équivalent du 1102) |
| 1074 | Arret ou redémarrage initié | Indicateur de manipulation |
| 6005 | Démarrage du service Event Log | Repère de démarrage pour la timeline |
| 6006 | Arret du service Event Log | Précède souvent un effacement de traces |
| 6008 | Arret inattendu | Tampering possible |
| 6013 | Uptime du système | Un uptime anormalement bas trahit un reboot suspect |
| 7036 | Changement d'état d'un service | Arret d'AV ou de Sysmon : évasion (T1562.001) |
| 7040 | Changement du mode de démarrage d'un service | Mécanisme de persistance (T1543.003) |
| 7045 | Installation d'un nouveau service | Persistance, PSExec, Cobalt Strike (T1543.003) |

## Journal Application

Surtout utile pour l'AV et les sources personnalisées comme les honeypots.

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 1116 | Détection d'un malware par Defender | Confirmation d'infection |
| 1118 à 1120 | Cycle de remédiation Defender | Le 1120 (échec) est critique |
| Source custom | Source Application créée à la main | Honeypot LLMNR : un nom inexistant qui résout signale Responder (T1557.001) |

## Sysmon (Microsoft-Windows-Sysmon/Operational)

Sysmon complète le journal Security : il voit les comportements host-level (injection, DLL, accès mémoire) que Windows ne journalise pas nativement.

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 1 | Création de processus (avec parent, ligne de commande, hash) | Reconnaissance native, PowerShell encodé, parent suspect (T1059) |
| 2 | Modification du timestamp de création d'un fichier | Timestomping (T1070.006) |
| 3 | Connexion réseau initiée par un processus | Beaconing C2, Overpass-the-Hash sur port 88 |
| 4 | Changement d'état du service Sysmon | Tentative de désactivation de Sysmon (T1562.001) |
| 5 | Fin d'un processus | Corrélation du cycle de vie |
| 6 | Chargement d'un driver | Driver malveillant, BYOVD (T1014, T1068) |
| 7 | Chargement d'une DLL ou d'un module | DLL hijacking, injection .NET (clr.dll), BYOL (T1574, T1055) |
| 8 | Création d'un thread distant | Indicateur fort d'injection de processus (T1055) |
| 9 | Accès raw au disque | Lecture directe du système de fichiers, contournement (T1006) |
| 10 | Un processus en lit ou manipule un autre | Credential dumping LSASS, GrantedAccess 0x1410 (T1003.001) |
| 11 | Création d'un fichier | Drop de payload, ADS, persistance |
| 12 | Création ou suppression d'une clé de registre | Persistance via clés Run (T1547.001) |
| 13 | Modification d'une valeur de registre | Persistance Run keys, services (T1547.001) |
| 14 | Renommage d'une clé ou d'une valeur | Couverture de traces |
| 15 | Création d'un flux alternatif NTFS (ADS) | Marqueur Zone.Identifier, payload caché (T1564.004) |
| 16 | Modification de la configuration Sysmon | Tentative d'évasion (T1562.001) |
| 17 / 18 | Création / connexion à un named pipe | C2 via pipes, par exemple Cobalt Strike (T1559.001) |
| 19 / 20 / 21 | Filtre, consommateur, binding WMI | Persistance WMI (T1546.003) |
| 22 | Requete DNS | Responder/LLMNR, tunneling DNS (T1071.004) |
| 23 | Suppression de fichier journalisée (avec archive) | Couverture de traces (T1070.004) |
| 24 | Modification du presse-papiers | Vol de données collées |
| 25 | Tampering de processus détecté | Process hollowing (T1055.012) |
| 26 | Suppression de fichier (sans archive) | Couverture de traces |
| 27 / 28 | Exécution ou suppression bloquée par règle Sysmon | Réponse, pas attaque |
| 29 | Création d'un exécutable PE détectée | Drop de binaire (T1105) |
| 255 | Erreur interne Sysmon | Sysmon en panne, évasion possible |

## PowerShell (Microsoft-Windows-PowerShell/Operational)

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 400 | Démarrage du moteur PowerShell | Downgrade attack : EngineVersion 2.0 suspect |
| 403 | Arret du moteur PowerShell | Corrélation du cycle de vie |
| 4103 | Module logging (cmdlets et paramètres) | Cmdlets sensibles, Invoke-* |
| 4104 | Script Block Logging (contenu des scripts) | Scripts déobfusqués, Base64, reconnaissance AD (T1059.001) |
| 4105 / 4106 | Début / fin d'un script block | Reconstitution des scripts longs multi-blocs |

L'activation des 4103 et 4104 passe par une GPO dédiée, ils ne sont pas journalisés par défaut.

## WinRM (Microsoft-Windows-WinRM/Operational)

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 6 | Début de traitement d'une requete client | Mouvement latéral via PSRemoting (T1021.006) |
| 91 | Session WinRM créée côté serveur | Mouvement latéral entrant |
| 142 | Échec d'une opération WinRM | Force brute WinRM |
| 161 | Échec d'authentification WinRM | Force brute |
| 169 | Authentification WinRM réussie | Mouvement latéral confirmé |

Un logon WinRM produit aussi un 4624 de type 3 dans le journal Security.

## Tache planifiée (Microsoft-Windows-TaskScheduler/Operational)

Complément aux 4698 à 4702 du journal Security, avec la trace de l'exécution réelle.

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 100 / 102 | Tache démarrée / terminée | Persistance en action (T1053.005) |
| 101 | Échec de démarrage d'une tache | Diagnostic |
| 106 | Tache enregistrée | Persistance (T1053.005) |
| 140 | Tache mise à jour | Modification de persistance |
| 141 | Tache supprimée | Nettoyage par l'attaquant |
| 200 / 201 | Action de tache démarrée / terminée | Trace de l'exécution réelle |

## Defender (Microsoft-Windows-Windows Defender/Operational)

| Event ID | Signification | À surveiller |
|----------|---------------|--------------|
| 1006 | Malware détecté | Confirmation d'infection |
| 1007 | Action exécutée sur le malware | Cycle de remédiation |
| 1008 | Échec d'action sur le malware | Échec de remédiation, critique (T1562.001) |
| 1015 | Comportement suspect détecté | Détection heuristique |
| 5001 | Désactivation de la protection temps réel | Évasion (T1562.001) |
| 5004 / 5007 | Configuration modifiée, exclusions | Évasion via exclusions (T1562.001) |
| 5010 / 5012 | Scan ou antivirus désactivé | Évasion |

## RDP (Terminal Services)

| Event ID | Channel | Signification | À surveiller |
|----------|---------|---------------|--------------|
| 1149 | RemoteConnectionManager | Authentification RDP réussie côté gateway | Premier signal RDP, avant le 4624 |
| 261 | RemoteConnectionManager | Le listener recoit une connexion | Force brute RDP, scan du port 3389 |
| 21 | LocalSessionManager | Connexion de session réussie | Mouvement latéral RDP |
| 22 | LocalSessionManager | Démarrage du shell de session | Confirme l'exécution dans la session |
| 23 | LocalSessionManager | Déconnexion propre | Corrélation de durée |
| 24 / 25 | LocalSessionManager | Session déconnectée / reconnectée | Reprise de mouvement latéral |

## Types de logon (champ LogonType des 4624 et 4625)

| Type | Nom | Quand on le voit | Suspect si |
|------|-----|------------------|-----------|
| 2 | Interactive | Console locale, runas normal | Hors heures, sur un DC, depuis un compte de service |
| 3 | Network | SMB, RPC, partages, WinRM | Compte privilégié sur un poste utilisateur, volume anormal |
| 4 | Batch | Tache planifiée sous un compte | Compte utilisateur plutot que compte de service |
| 5 | Service | Service démarrant sous un compte | Compte utilisateur plutot que LocalSystem |
| 7 | Unlock | Déverrouillage de la station | Hors heures, sur un serveur |
| 8 | NetworkCleartext | Authentification réseau en clair | Toujours suspect, mot de passe non chiffré |
| 9 | NewCredentials | runas /netonly | Pass-the-Hash (Type 9 + seclogo + accès LSASS) |
| 10 | RemoteInteractive | RDP, Terminal Services | Compte de service en RDP, RDP hors heures ou depuis Internet |
| 11 | CachedInteractive | Identifiants en cache (laptop hors domaine) | Sur un serveur ou un DC |
| 12 / 13 | CachedRemoteInteractive / CachedUnlock | Variantes en cache | Rares, toujours à investiguer |

Schéma précis du Pass-the-Hash : LogonType 9, LogonProcessName seclogo, et accès à LSASS (Sysmon 10) dans la meme minute. Un runas /netonly légitime ne déclenche pas l'accès à LSASS.

## Codes d'échec Kerberos (4768, 4769, 4771)

| Code | Nom | Implication |
|------|-----|-------------|
| 0x6 | C_PRINCIPAL_UNKNOWN | Compte inexistant : énumération d'utilisateurs si volume élevé |
| 0x7 | S_PRINCIPAL_UNKNOWN | Service inexistant, scan de SPN |
| 0x12 | CLIENT_REVOKED | Compte verrouillé ou désactivé, confirme un ciblage |
| 0x17 | KEY_EXPIRED | Mot de passe expiré |
| 0x18 | PREAUTH_FAILED | Mauvais mot de passe : force brute ou spraying Kerberos |
| 0x19 | PREAUTH_REQUIRED | Comportement normal au premier AS-REQ, à filtrer en détection |
| 0x1F | BAD_INTEGRITY | Ticket forgé invalide ou clé incorrecte |
| 0x22 | REPEAT | Replay détecté |
| 0x25 | SKEW | Décalage horaire, souvent légitime mais possible Golden Ticket |

## Codes d'échec NTLM (4776) et SubStatus (4625)

Le champ Status du 4625 est souvent générique (0xC000006D) ; le SubStatus donne la vraie cause.

| Code | Description | Implication |
|------|-------------|-------------|
| 0xC0000064 | Utilisateur inexistant | Énumération d'utilisateurs |
| 0xC000006A | Mauvais mot de passe | Force brute |
| 0xC0000071 | Mot de passe expiré | À corréler |
| 0xC0000072 | Compte désactivé | Spraying ciblant les comptes désactivés |
| 0xC0000133 | Décalage horaire trop grand | Possible Golden Ticket sur un DC restauré |
| 0xC000015B | Type de logon non autorisé | Politique d'accès |
| 0xC0000193 | Compte expiré | À corréler |
| 0xC0000234 | Compte verrouillé | Conséquence d'une force brute |

## GUID de réplication pour DCSync (4662)

Lors d'un DCSync, le champ Properties du 4662 contient un GUID qui distingue cet accès d'un accès AD ordinaire.

| GUID | Permission | Implication |
|------|-----------|-------------|
| 1131f6aa-... | DS-Replication-Get-Changes | Première moitié des droits de réplication |
| 1131f6ad-... | DS-Replication-Get-Changes-All | Droit critique pour un DCSync complet, dont KRBTGT |
| 19195a5b-... | Get-Changes-In-Filtered-Set | Variante filtrée, DCSync moderne |
| 89e95b76-... | DS-Replication-Synchronize | Utilisé par les DC légitimes |

Subtilité : pendant un DCSync, l'Account Name apparait souvent comme le compte machine du DC qui exécute la réplication. Il faut filtrer pour ne garder que les comptes non-DC déclenchant la réplication, en mettant en liste blanche les DC et les outils de synchronisation légitimes.

## Chaînes d'événements par type d'attaque

| Attaque | Suite d'événements |
|---------|--------------------|
| Pass-the-Hash | Sysmon 10 (TargetImage lsass.exe) puis 4624 (Type 9 + seclogo) en moins d'une minute |
| Pass-the-Ticket / Golden Ticket | 4769 sans 4768 préalable dans la durée de vie du TGT |
| Kerberoasting | 4769 chiffrement RC4 sur un SPN de service, sans 4648 dans les minutes qui suivent |
| AS-REProasting | 4768 avec Pre-Auth Type 0 |
| DCSync | 4662 Access_Mask 0x100 avec le GUID Get-Changes-All, depuis un compte non-DC |
| DCShadow | 4742 avec ajout d'un SPN sur un compte ordinateur |
| Injection de processus | Sysmon 1 puis 10 puis 8 puis 7 (la cible charge clr.dll) |
| Credential dumping LSASS | Sysmon 10 (lsass.exe, GrantedAccess de lecture) + 4672 (SeDebug) |
| Responder / LLMNR | Sysmon 22 (nom inexistant qui résout) + 4648 vers une cible inhabituelle |
| PSExec / Cobalt Strike | 7045 (nouveau service) + Sysmon 1 (parent services.exe, binaire au nom aléatoire) |
| Parent PID Spoofing | Sysmon 1 montre un parent qui diffère du vrai parent vu par ETW kernel |
| BYOL .NET | Sysmon 7 (clr.dll ou mscoree.dll chargé par un processus atypique) |
| Persistance Run key | Sysmon 1 puis 13 (TargetObject pointant vers une clé Run) |
| Persistance par service | Sysmon 1 puis 7045 puis relance du service avec parent services.exe |
| Effacement post-compromission | 6006 (arret Event Log) puis 1102 (Security) puis 104 (System) |

## Sysmon ou Security : lequel privilégier ?

| Comportement | Source à privilégier |
|--------------|----------------------|
| Création de processus | Sysmon 1, plus riche que 4688 (parent, hash, ligne de commande parent) |
| Authentification réseau | Security 4624/4625, Sysmon ne journalise pas les auth |
| Connexion réseau d'un processus | Sysmon 3, relié au processus |
| Création de fichier | Sysmon 11, couvre tous les chemins par défaut |
| Modification de registre | Sysmon 13/14, couverture par défaut |
| Installation de service | System 7045, plus standard que 4697 |
| Chargement de DLL | Sysmon 7, pas d'équivalent natif |
| Accès à un processus (LSASS) | Sysmon 10, pas d'équivalent natif |
| Création de thread distant | Sysmon 8, pas d'équivalent natif |
| Requete DNS cliente | Sysmon 22, pas d'équivalent natif |
| Effacement de journal | Security 1102 |

Règle d'or : Sysmon complète le journal Security, il ne le remplace pas. Les attaques d'authentification et d'Active Directory vivent dans Security, les attaques host-level (injection, DLL, dump d'identifiants) sont mieux vues par Sysmon. Et Sysmon peut etre trompé, par exemple par le Parent PID Spoofing, auquel cas ETW au niveau du kernel prend le relais.

## Un rappel sur l'audit

Beaucoup des événements les plus utiles ne sont pas actifs par défaut. La création de processus (4688) et sa ligne de commande, l'audit DS Access indispensable pour voir un DCSync (4662), l'audit des objets (4656, 4663) qui exige une SACL sur la cible, ou encore le Script Block Logging PowerShell (4104) sont autant de réglages à activer explicitement. Vérifier la configuration d'audit en place fait partie des premiers réflexes quand une détection attendue ne remonte rien.
