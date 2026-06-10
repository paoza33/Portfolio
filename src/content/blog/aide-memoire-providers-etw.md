---
title: "Aide-mémoire : les providers ETW utiles en sécurité"
date: 2026-06-09
side: "blue"
tags: ["reference", "etw", "windows", "detection"]
summary: "ETW expose une télémétrie bien plus riche que les journaux Windows classiques, au niveau du noyau. Voici les providers les plus utiles en détection, ce que chacun observe, et les providers restreints qui voient ce que Sysmon ne voit pas."
draft: false
---

ETW, pour Event Tracing for Windows, est un mécanisme de traçage haute performance intégré au noyau de Windows. Là où les journaux classiques de l'Observateur d'événements n'exposent qu'une vue limitée, ETW collecte en temps réel une télémétrie bien plus large : appels système, création de processus, accès mémoire, opérations sur le registre et les fichiers, activité réseau. C'est la base de la détection comportementale moderne, et c'est ce sur quoi reposent la plupart des EDR sérieux.

L'intéret pour un défenseur est double. D'une part, la richesse : ETW voit des choses qu'aucun journal natif n'expose. D'autre part, la fiabilité : ETW observe à un niveau que certaines techniques d'évasion ne peuvent pas tromper. Le Parent PID Spoofing, par exemple, ment à Sysmon en user-mode, mais le provider noyau rétablit la vérité.

## Les providers à connaitre

Chaque provider couvre un domaine technique. On ne s'abonne qu'à ceux dont on a besoin, pour garder un volume exploitable.

| Provider | Ce qu'il observe | Valeur en détection |
|----------|------------------|---------------------|
| Microsoft-Windows-Kernel-Process | Activité des processus au niveau noyau | Injection de processus, hollowing, comportements avancés |
| Microsoft-Windows-Kernel-File | Opérations sur les fichiers | Accès non autorisés, ransomware, exfiltration |
| Microsoft-Windows-Kernel-Network | Trafic réseau bas niveau | Connexions anormales, C2, exfiltration |
| Microsoft-Windows-Kernel-Registry | Opérations sur le registre | Persistance, altérations critiques |
| Microsoft-Windows-DNS-Client | Activité DNS | Tunneling DNS, C2 |
| Microsoft-Windows-SMBClient / SMBServer | Partages SMB | Mouvement latéral, exfiltration via SMB |
| Microsoft-Windows-DotNETRuntime | Exécution de code .NET | Chargement d'assemblies suspects, abus du runtime, BYOL |
| Microsoft-Windows-PowerShell | Exécution PowerShell | Script block logging, post-exploitation |
| Microsoft-Windows-CodeIntegrity | Intégrité du code et des drivers | Drivers non signés, contournement de sécurité |
| Microsoft-Windows-Security-Mitigations | Mécanismes de protection | Tentatives de contournement, exploitation |
| Microsoft-Antimalware-Service | Service antimalware | AV désactivé, modifications de configuration |
| Microsoft-Antimalware-Protection | Mécanismes antimalware | Désactivation, évasion AV ou EDR |
| WinRM | Gestion à distance | Mouvement latéral, exécution distante |
| Microsoft-Windows-TerminalServices-LocalSessionManager | Sessions RDP locales | Accès RDP suspects |
| Microsoft-Windows-VPN-Client | Connexions VPN | Sessions VPN suspectes |
| OpenSSH | Activité SSH | Connexions suspectes, force brute |

## Les providers restreints (PPL)

Certains providers livrent une télémétrie particulièrement précieuse mais sont protégés : seuls les processus s'exécutant en PPL, pour Protected Process Light, peuvent s'y abonner. Ce statut est difficile à obtenir, ce qui protège ces données sensibles tout en permettant de détecter des attaques sophistiquées invisibles ailleurs.

Le plus connu est `Microsoft-Windows-Threat-Intelligence`. Il expose des comportements bas niveau que Sysmon ne voit pas, et c'est l'une des sources sur lesquelles s'appuient les EDR pour repérer l'injection avancée ou la manipulation mémoire furtive.

## Consommer ETW

ETW n'est pas un journal qu'on ouvre comme l'Observateur d'événements, il faut s'y abonner. Quelques outils simplifient cela : SilkETW, un wrapper open source pratique pour cibler un provider et exporter vers un fichier ou un SIEM ; le Moniteur de performances intégré à Windows ; et EtwExplorer pour une exploration graphique. Un abonnement typique vise un provider précis et écrit la sortie dans un fichier exploitable ensuite.

## Ce qu'il faut retenir

ETW est le niveau de visibilité en dessous des journaux et de Sysmon. On y descend quand on a besoin de voir ce que les couches supérieures ne montrent pas, ou quand on soupconne une évasion qui trompe le user-mode. Connaitre les bons providers permet de cibler la télémétrie utile sans noyer l'analyse sous le volume, car ETW peut produire énormément de données si on s'abonne trop largement.
