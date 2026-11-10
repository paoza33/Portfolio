---
title: "Artefacts forensiques Windows : mémo de triage DFIR"
date: 2026-07-11
updated: 2026-11-10
side: "blue"
tags: ["dfir", "windows", "forensic", "triage", "ntfs", "evtx", "iis"]
summary: "Mémo de référence des artefacts forensiques Windows croisés au fil des investigations : métafichiers NTFS, ruches de registre, journaux EVTX, artefacts d'exécution et de persistance, navigateur, serveur web IIS, secrets locaux, mémoire et réseau. Ce qu'ils apportent, où ils vivent, leurs pièges et l'outil pour les lire."
draft: false
---

Au fil des Sherlocks et des exercices DFIR, les mêmes familles d'artefacts reviennent : les métafichiers NTFS, les ruches de registre, les journaux d'événements, les traces d'exécution, l'historique navigateur, les logs du serveur web. Cette page les rassemble en un mémo unique. Elle sert de référence rapide et de prise de notes CDSA. Chaque artefact est situé, expliqué par ce qu'il permet de prouver, rattaché à l'outil qui le lit et, quand il a déjà servi, à l'investigation concernée.

Trois principes traversent tout le mémo :

- **Triage n'est pas extraction.** Les sorties déjà parsées (LiveResponse, moteurs de détection) disent *où* regarder ; la matière brute (disque, registre) dit *tout* sur un fait. Quand les deux divergent, la source brute fait foi.
- **Choisir l'artefact qui contient le fait.** Pour relier deux informations, prendre celle où elles co-existent, pas un log où l'une manque.
- **Toujours recouper.** Un artefact isolé est une hypothèse ; la preuve naît de la convergence (MFT plus EVTX plus registre plus réseau).

## Tableau de référence

| Artefact | Famille | Emplacement | Ce qu'il apporte | Outil |
|---|---|---|---|---|
| `$MFT` | NTFS | racine du volume | Fichiers, timestamps $SI/$FN, données résidentes, offsets | MFTECmd |
| `$UsnJrnl:$J` | NTFS | `$Extend\$J` | Cycle de vie horodaté (create/rename/delete) | MFTECmd `-f $J` |
| `$LogFile` | NTFS | racine du volume | Opérations de métadonnées, désallocations | NTFS Log Tracker |
| `$Boot` | NTFS | racine du volume | Géométrie du volume (cluster, MFT) | lecture hex / MFTECmd |
| `$Secure:$SDS` | NTFS | racine du volume | Descripteurs de sécurité (ACL, propriétaire) | outils NTFS dédiés |
| `$Recycle.Bin` | NTFS | racine du volume | `$I` (date suppression, chemin), `$R` (contenu) | lecture `$I` / RBCmd |
| Shadow copies | Volume | `System Volume Information` | Versions antérieures des fichiers, ruches et EVTX | VSCMount, KAPE `--vss` |
| `SYSTEM` | Registre | `Windows\System32\config` | ControlSet, hostname, services, partages SMB, Shimcache, BAM | Registry Explorer, RECmd |
| `SOFTWARE` | Registre | `Windows\System32\config` | Logiciels installés, Winlogon, TaskCache | Registry Explorer, RECmd |
| `SAM` + `SECURITY` | Registre | `Windows\System32\config` | Comptes locaux, hash NT, secrets LSA | secretsdump (LOCAL) |
| `NTUSER.DAT` | Registre | racine du profil | WordWheelQuery, MRU, UserAssist | Registry Explorer, RECmd |
| `UsrClass.dat` | Registre | `AppData\Local\Microsoft\Windows` | Classes HKCU (handlers, commandes), Shellbags | Registry Explorer, SBECmd |
| `Amcache.hve` | Registre | `Windows\AppCompat\Programs` | Inventaire d'exécution, SHA-1 des binaires | Registry Explorer |
| `Security.evtx` | EVTX | `winevt\Logs` | 4624/4625, 4648, 4672, 4688, 4697, 4698, 4719, 4720/4732, 1102 | EvtxECmd, Hayabusa |
| `System.evtx` | EVTX | `winevt\Logs` | 104 (log effacé), 7045 (service) | EvtxECmd, Hayabusa |
| `Application.evtx` | EVTX | `winevt\Logs` | MsiInstaller 1033/1034 | EvtxECmd |
| `Windows PowerShell.evtx` | EVTX | `winevt\Logs` | 400/600/403, HostApplication | EvtxECmd |
| `PowerShell/Operational` | EVTX | `winevt\Logs` | 4103 (module), 4104 (script block) | EvtxECmd |
| `Defender-Operational` | EVTX | `winevt\Logs` | 1116 (détection), 1117 (action) | EvtxECmd |
| MPLog | Defender | `ProgramData\Microsoft\Windows Defender\Support` | Journal interne : détections, scans, processus | lecture texte |
| Quarantaine Defender | Defender | `ProgramData\Microsoft\Windows Defender\Quarantine` | Copie chiffrée des fichiers mis en quarantaine | outils dédiés |
| `Firewall-Firewall` | EVTX | `winevt\Logs` | 2004 (règle ajoutée, direction) | EvtxECmd |
| `Sysmon/Operational` | EVTX | `winevt\Logs` | 1, 3, 7, 8, 10, 11, 12 à 14, 17/18, 22 | EvtxECmd, Chainsaw |
| `TaskScheduler/Operational` | EVTX | `winevt\Logs` | 106, 140, 141, 200/201 | EvtxECmd |
| `TerminalServices-*` | EVTX | `winevt\Logs` | RDP : 21/24/25 (session), 1149 (authentification) | EvtxECmd |
| `WMI-Activity/Operational` | EVTX | `winevt\Logs` | 5861 (abonnement WMI permanent) | EvtxECmd |
| Prefetch (`.pf`) | Exécution | `Windows\Prefetch` | Preuve d'exécution, run count, ressources | PECmd |
| `.lnk` / Jump Lists | Exécution | `…\Recent` | Chemin cible, MAC times, chemin réseau | LECmd |
| Shimcache | Exécution | `SYSTEM` (`AppCompatCache`) | Binaires vus par le système, chemin, date de modification | AppCompatCacheParser |
| BAM | Exécution | `SYSTEM` (`Services\bam`) | Dernière exécution par SID | Registry Explorer, RECmd |
| PSReadLine | Exécution | `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine` | Historique des commandes PowerShell interactives | éditeur texte |
| SRUM (`SRUDB.dat`) | Exécution | `Windows\System32\sru` | Usage réseau et ressources par application | SrumECmd |
| Tâches planifiées | Persistance | `Windows\System32\Tasks` | Définition XML, action, compte d'exécution | lecture XML |
| Dépôt WMI | Persistance | `Windows\System32\wbem\Repository` | Abonnements WMI permanents | PyWMIPersistenceFinder |
| Historique Chrome/Edge | Navigateur | profil `…\Default\History` | urls, downloads, chaîne de redirection | DB Browser, SQLECmd |
| Logs IIS (W3C) | Serveur web | `inetpub\logs\LogFiles\W3SVC<ID>` | Requêtes HTTP, IP client, User-Agent, code retour | Log Parser, Timeline Explorer |
| `applicationHost.config` | Serveur web | `Windows\System32\inetsrv\config` | Sites, chemins physiques, pools, chemin des logs | lecture XML |
| `web.config` | Serveur web | racine du site | Config de l'application, chaînes de connexion | lecture XML |
| Temporary ASP.NET Files | Serveur web | `Windows\Microsoft.NET\Framework64\v4.0.30319` | DLL compilées des pages dynamiques | MFTECmd (dates) |
| HTTPERR | Serveur web | `Windows\System32\LogFiles\HTTPERR` | Requêtes rejetées par HTTP.sys | lecture texte |
| `Unattend.xml` | Secrets | `Windows\Panther` | Comptes et mots de passe d'installation automatisée | lecture XML |
| Credential Manager | Secrets | `AppData\Roaming\Microsoft\Credentials` + `Protect` | Identifiants enregistrés, chiffrés DPAPI | Mimikatz, Impacket dpapi |
| LiveResponse | KAPE | dossier de collecte | Snapshots d'état (autoruns, pslist, netstat) | Timeline Explorer |
| Dump mémoire | Mémoire | fichier `.vmem/.dmp` | Processus, réseau, SID, fichiers, registre en RAM | Volatility 2/3 |
| Capture réseau | Réseau | fichier `.pcapng` | Provenance, C2, fichiers transférés | Wireshark |

---

## Métafichiers NTFS

Les fichiers commençant par `$` sont les structures internes que NTFS utilise pour se gérer. Ils ne s'ouvrent pas comme des fichiers ordinaires et sont la matière la plus riche d'un triage disque.

**`$MFT` (Master File Table)**
- Emplacement : racine du volume.
- Apporte : un enregistrement par fichier et dossier. Les timestamps existent en deux jeux, `$SI` (attribut `$STANDARD_INFORMATION`, `0x10`, modifiable en espace utilisateur) et `$FN` (`$FILE_NAME`, `0x30`, maintenu par le noyau). Un fichier de moins de ~700-800 octets est *résident* : son contenu tient dans l'enregistrement MFT, donc récupérable même après suppression.
- Outil : MFTECmd. `--dr` dumpe les données résidentes, `--de <entry-seq>` dumpe un enregistrement complet avec son offset réel, `--fl` peuple les attributs `$FN`.
- Piège : l'offset d'un enregistrement n'est **pas** `EntryNumber × 1024` dès que la MFT est fragmentée. On laisse `--de` donner l'offset vrai.
- Vu dans : Jinkies, Gemini, Trojan.

**`$UsnJrnl:$J` (journal des changements USN)**
- Emplacement : `$Extend\$J`.
- Apporte : chaque événement du cycle de vie d'un fichier, horodaté, avec un `UpdateReason` (création, écriture, rename, suppression). Source de choix pour dater une suppression.
- Piège : une suppression vers la Corbeille apparaît comme `RenameOldName` vers `RenameNewName` (`$R…`), pas comme un `FileDelete`. Le timestamp du rename est le moment de la suppression.
- Piège : plus généralement, tout renommage apparaît comme une paire `RenameOldName` / `RenameNewName` partageant le même `EntryNumber`. C'est ce qui permet de suivre un fichier qui change de nom ou d'extension après dépôt.
- Vu dans : Gemini.

**`$LogFile` (journal transactionnel NTFS)**
- Emplacement : racine du volume.
- Apporte : les opérations de métadonnées récentes (pour la cohérence et le rollback), utile pour repérer des désallocations.
- Outil : NTFS Log Tracker, LogFileParser.
- Note : listé au triage et cité comme source de datation, mais pas encore exploité en profondeur dans nos exos.
- Vu dans : Jinkies (triage), Gemini (cité).

**`$Boot`**
- Emplacement : racine du volume.
- Apporte : la géométrie du volume (taille de cluster, emplacement de la MFT), nécessaire à certains calculs d'offset.
- Note : présent au triage, peu exploité.
- Vu dans : Jinkies (triage).

**`$Secure:$SDS`**
- Emplacement : racine du volume.
- Apporte : le flux des descripteurs de sécurité (ACL, propriétaire) associés aux fichiers.
- Note : présent au triage, peu exploité.
- Vu dans : Jinkies (triage).

**`$Recycle.Bin`**
- Emplacement : racine du volume, sous-dossier par SID.
- Apporte : pour chaque fichier supprimé, un `$I…` (chemin d'origine plus date de suppression au format FILETIME) et un `$R…` (le contenu, récupérable).
- Vu dans : Gemini (confirmation de suppression).

**Shadow copies (Volume Shadow Copies)**
- Emplacement : `System Volume Information`, à la racine du volume.
- Apporte : des versions antérieures des fichiers, des ruches et des EVTX, prises à chaque point de restauration. Utile quand un journal a été effacé ou un fichier remplacé.
- Outil : KAPE peut les collecter (`--vss`), VSCMount les monte.

---

## Ruches de registre

Le registre est une base hiérarchique répartie en plusieurs fichiers (ruches). Réflexe d'hygiène : travailler sur une copie et rejouer les transaction logs `.LOG1/.LOG2` quand une ruche est marquée *dirty*.

**`SYSTEM`**
- Emplacement : `Windows\System32\config`.
- Apporte : le ControlSet actif (via la clé `Select`, valeur `Current`), le `ComputerName`, la configuration des services et du réseau. `Services\LanmanServer\Shares` liste les partages SMB. Contient aussi le Shimcache et le BAM, détaillés dans les artefacts d'exécution.
- Piège : `CurrentControlSet` n'existe pas tel quel hors ligne, il faut résoudre le bon `ControlSet00X` via `Select`.
- Vu dans : Trojan (hostname), Jinkies (partages).

**`SOFTWARE`**
- Emplacement : `Windows\System32\config`.
- Apporte : les logiciels installés (`Microsoft\Windows\CurrentVersion\Uninstall`, et `WOW6432Node` pour le 32 bits), la configuration machine. `Microsoft\Windows NT\CurrentVersion\Winlogon` porte `DefaultUserName`, et `DefaultPassword` en clair si l'ouverture de session automatique est configurée. `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` (`Tree` et `Tasks`) indexe les tâches planifiées.
- Pièges : un `DefaultPassword` absent ne veut pas dire pas d'autologon, le mot de passe peut être stocké dans les secrets LSA (`SECURITY`). Une tâche peut subsister dans `TaskCache` alors que son fichier XML a été supprimé, et inversement.
- Vu dans : Gemini (vraie version du MSI, `DisplayVersion`).

**`SAM` et `SECURITY`**
- Emplacement : `Windows\System32\config`.
- Apporte : comptes locaux et hash NT (`SAM`), secrets LSA (`SECURITY`). Le déchiffrement exige la bootkey portée par `SYSTEM`.
- Outil : secretsdump en mode `LOCAL` avec les trois ruches.
- Vu dans : Jinkies (réutilisation de credential).

**`NTUSER.DAT` (une par profil utilisateur)**
- Emplacement : racine du profil.
- Apporte : l'activité de l'utilisateur. `WordWheelQuery` conserve les recherches de l'Explorateur (stockées en UTF-16LE, ordonnées par `MRUListEx`). Même famille : RecentDocs, TypedPaths, RunMRU, UserAssist.
- Outil : Registry Explorer (bookmarks) ou RECmd.
- Vu dans : Gemini (WordWheelQuery).

**`UsrClass.dat` (une par profil utilisateur)**
- Emplacement : `AppData\Local\Microsoft\Windows\UsrClass.dat`.
- Apporte : la partie utilisateur de `HKCU\Software\Classes` (associations de fichiers, handlers de protocoles et commandes associées), et les Shellbags (dossiers parcourus dans l'Explorateur, y compris supprimés ou sur un support amovible).
- Piège : une clé créée sous `HKCU\Software\Classes` prend le pas sur celle de `HKLM`. Une commande inattendue sous `<classe>\shell\open\command` mérite attention, en particulier pour `ms-settings` ou `mscfile`, cibles connues des contournements UAC. La date LastWrite de la clé date la modification.
- Outil : Registry Explorer, SBECmd pour les Shellbags.

**`Amcache.hve`**
- Emplacement : `Windows\AppCompat\Programs`.
- Apporte : un inventaire d'exécution qui stocke le SHA-1 des exécutables, y compris supprimés. Utile pour pivoter sur un hash quand le binaire n'est plus là.
- Note : cité en alternative, pas encore exploité à fond.
- Vu dans : Gemini (cité).

---

## Journaux d'événements (EVTX)

Les EVTX vivent dans `Windows\System32\winevt\Logs`. On les convertit (EvtxECmd, CSV ou JSON) pour Timeline Explorer ou Splunk, et on les trie avec Hayabusa/Chainsaw (moteurs de détection Sigma) pour savoir où regarder. Le détail de l'ingestion Splunk est traité dans l'article dédié.

**`Security.evtx`**
- 4624 : logon réussi. Le `LogonType` change le sens (2 = console, 3 = réseau, 10 = RDP).
- 4625 : échec d'ouverture de session. `Status` et `SubStatus` distinguent compte inconnu et mauvais mot de passe.
- 4648 : ouverture de session avec identifiants explicites (runas, connexion vers une autre machine).
- 4672 : privilèges spéciaux attribués à une ouverture de session.
- 4719 : changement de politique d'audit.
- 4697 : service installé (nécessite l'audit « Security System Extension »).
- 4698 : création de tâche planifiée (embarque la définition XML complète).
- 4688 : création de process, si l'audit est actif. Sous Windows 10, porte aussi `ParentProcessName`, ce qui permet de lire une filiation sans Sysmon.
- 4720 / 4732 : compte local créé / membre ajouté à un groupe local.
- 1102 : journal Security effacé.
- Piège : la ligne de commande n'apparaît dans le 4688 que si la stratégie « Include command line in process creation events » est activée.
- Vu dans : LogJammer, Tracer, Jinkies.

**`System.evtx`**
- 104 : un journal d'événements a été effacé (le canal visé est nommé dans l'event).
- 7045 : installation d'un service (pertinent pour PsExec, ex. `PSEXESVC`).
- Vu dans : LogJammer (104).

**`Application.evtx`**
- MsiInstaller 1033 : un produit MSI a été installé (nom, `ProductVersion`, langue, statut), émis à la fin de la transaction. 1034 pour la désinstallation. Source d'autorité pour la vraie version et la date d'installation.
- Vu dans : Gemini.

**`Windows PowerShell.evtx`**
- 400/600 : démarrage du moteur et cycle des providers, portent `HostApplication` (la ligne de commande d'invocation). 403 : arrêt du moteur.
- Utile comme substitut quand l'audit de création de process (Sysmon 1, Security 4688) est absent.
- Vu dans : Gemini.

**`PowerShell/Operational.evtx`**
- 4103 : module logging, les cmdlets exécutées et leurs paramètres, si la stratégie est activée.
- 4104 : script block logging, capture le contenu réel du code soumis. Ne voit pas les binaires externes (`schtasks.exe`, `net.exe`), pour lesquels on retombe sur 4688/Sysmon 1.
- Piège : même sans stratégie, PowerShell journalise automatiquement en 4104, niveau Warning, les blocs de script qu'il juge suspects. Quelques 4104 présents ne signifient donc pas que le script block logging est activé ni que tout a été capturé.
- Transcriptions : si elles sont activées, un fichier texte par session (par défaut dans les `Documents` de l'utilisateur, sinon dans le dossier défini par la stratégie).
- Vu dans : LogJammer, Gemini.

**`Windows Defender-Operational.evtx`**
- 1116 : détection. 1117 : action prise. À distinguer : une action `Allow` signifie détecté mais non remédié. La clé `Detection ID` relie les deux.
- Hors EVTX, MPLog : `ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`, journal texte interne de Defender, plus détaillé que l'EVTX (détections, scans, processus et fichiers observés).
- Hors EVTX, quarantaine : `ProgramData\Microsoft\Windows Defender\Quarantine`. Les fichiers y sont chiffrés avec une clé connue et peuvent être restaurés pour analyse.
- Vu dans : LogJammer.

**`Windows Firewall-Firewall.evtx`**
- 2004 : règle ajoutée. Le champ `Direction` (1 = inbound, 2 = outbound) se lit dans le brut, ne pas le déduire des ports.
- Vu dans : LogJammer.

**`Sysmon/Operational.evtx`**
- 1 : création de process (avec ligne de commande et parent). Les champs `User` et `IntegrityLevel` montrent un changement de contexte (un enfant qui tourne soudain en SYSTEM ou en intégrité High).
- 3 : connexion réseau. 7 : chargement de DLL. 8 : CreateRemoteThread. 10 : accès à un process (`GrantedAccess`, par exemple sur `lsass.exe`).
- 11 : création de fichier. 12/13/14 : registre (clé, valeur, renommage).
- 17 : création de named pipe (indicateur classique de PsExec). 18 : connexion à un named pipe. 22 : requête DNS.
- Piège : Sysmon ne journalise que ce que sa configuration retient. Les événements 3, 7, 10 et 12 à 14 sont souvent filtrés : leur absence ne prouve rien tant que la config déployée n'a pas été vérifiée.
- Vu dans : Tracer, Jinkies.

**`TaskScheduler/Operational.evtx`**
- 106 : tâche enregistrée. 140 : mise à jour. 141 : suppression. 200/201 : action lancée / terminée.
- Piège : ce journal peut être désactivé (c'est le cas par défaut sur de nombreux postes Windows 10). La 4698 de Security et les fichiers de `Windows\System32\Tasks` prennent alors le relais.

**RDP (`TerminalServices-LocalSessionManager/Operational`, `TerminalServices-RemoteConnectionManager/Operational`)**
- LocalSessionManager 21 : ouverture de session, 24 : déconnexion, 25 : reconnexion. RemoteConnectionManager 1149 : authentification réseau réussie.
- Piège : un 1149 ne prouve pas l'ouverture de session, seulement l'authentification. Confirmer avec le 21 ou un 4624 de type 10.

**`WMI-Activity/Operational.evtx`**
- 5861 : création d'un abonnement WMI permanent (filtre, consommateur, liaison). À recouper avec le dépôt WMI.

---

## Artefacts d'exécution

**Prefetch (`.pf`)**
- Emplacement : `Windows\Prefetch`, un fichier par exécutable.
- Apporte : la preuve d'exécution. Run count, les 8 derniers temps d'exécution (limite structurelle sur Windows 10/11), et les fichiers/dossiers touchés dans les premières secondes.
- Piège : le compteur de runs peut dépasser le nombre de timestamps stockés (fenêtre de 8), ce n'est pas une anomalie. On se fie aux run times embarqués, pas aux MAC times du `.pf`.
- Outil : PECmd.
- Vu dans : Trojan, Tracer.

**`.lnk` et Jump Lists**
- Emplacement : `…\Recent` et dossiers de jump lists.
- Apporte : le chemin cible, les timestamps MAC de la cible, le chemin réseau (`NetworkPath`) qui révèle un accès via un partage. Le `.lnk` survit souvent au fichier qu'il pointe.
- Outil : LECmd.
- Vu dans : Jinkies (raccourci d'un fichier supprimé).

**Shimcache (AppCompatCache)**
- Emplacement : ruche `SYSTEM`, `ControlSet00X\Control\Session Manager\AppCompatCache`.
- Apporte : les exécutables vus par le système, leur chemin et la date de dernière modification du fichier.
- Pièges : sous Windows 10, une entrée ne prouve pas l'exécution. La date est celle du fichier, pas de l'exécution. Le cache n'est écrit dans la ruche qu'à l'arrêt ou au redémarrage : une collecte faite à chaud ne contient pas les entrées de la session en cours.
- Outil : AppCompatCacheParser.

**BAM (Background Activity Moderator)**
- Emplacement : ruche `SYSTEM`, `Services\bam\State\UserSettings\<SID>` (`Services\bam\UserSettings` sur les builds plus anciens).
- Apporte : le chemin complet d'un exécutable et sa dernière exécution, rattachés à un SID.
- Pièges : n'existe qu'à partir de Windows 10 1709. Rétention courte, les entrées anciennes sont purgées.
- Outil : Registry Explorer, RECmd.

**Historique PSReadLine**
- Emplacement : `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, un par utilisateur.
- Apporte : les commandes PowerShell tapées en session interactive, en clair, y compris des mots de passe saisis en ligne de commande.
- Piège : un PowerShell lancé par un autre processus (service, tâche, webshell) n'est pas interactif et n'y écrit en général rien. Un fichier vide ou absent ne prouve pas l'absence d'activité. Penser aussi au profil du compte de service concerné.

**SRUM**
- Emplacement : `Windows\System32\sru\SRUDB.dat` (base ESE).
- Apporte : par application et par utilisateur, les octets envoyés et reçus, le temps d'activité. Utile pour quantifier une exfiltration.
- Piège : la base est écrite périodiquement, la dernière période peut ne pas y figurer. SrumECmd prend la ruche `SOFTWARE` en complément.
- Outil : SrumECmd.

---

## Persistance

**Tâches planifiées**
- Emplacement : `Windows\System32\Tasks` (un fichier XML par tâche), index dans `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`.
- Apporte : l'action exécutée, le déclencheur, et le compte sous lequel la tâche tourne (`Principal`).
- Piège : recouper les trois sources (fichier XML, `TaskCache`, 4698 et journal TaskScheduler), une tâche peut manquer dans l'une d'elles.

**Dépôt WMI** (vu mais aucune mise en pratique, juste un retour théorique, peut donc comporter des erreurs de compréhension)
- Emplacement : `Windows\System32\wbem\Repository` (`OBJECTS.DATA`).
- Apporte : les abonnements WMI permanents (filtre, consommateur, liaison), mécanisme de persistance sans fichier.
- Outil : PyWMIPersistenceFinder, ou parsing manuel de `OBJECTS.DATA`.

---

## Artefacts navigateur

**Historique Chrome / Edge (SQLite)**
- Emplacement : `…\User Data\Default\History`.
- Apporte : tables `urls` (navigation), `downloads` (fichiers reçus), `downloads_url_chains` (chaque hop de redirection). Les horodatages sont au format WebKit (microsecondes depuis le 1601-01-01).
- Pièges : le `referrer` d'un download n'est pas sa source réelle, c'est la page qui a référé ; la vraie source est le dernier `chain_index` de `downloads_url_chains`. Ne pas convertir un timestamp WebKit comme du Unix.
- Outil : DB Browser for SQLite (lecture directe, préférable pour les blobs) ou SQLECmd.
- Vu dans : Jinkies (exfil vers pastes.io), Gemini (vraie source du download).

---

## Serveur web IIS

**Logs d'accès (W3C)**
- Emplacement par défaut : `inetpub\logs\LogFiles\W3SVC<ID>\u_exAAMMJJ.log`, `<ID>` étant l'identifiant du site. Le chemin peut être déplacé, il se vérifie dans `applicationHost.config`.
- Apporte : chaque requête avec `cs-method`, `cs-uri-stem`, `cs-uri-query`, `c-ip`, `cs(User-Agent)`, `sc-status`, `time-taken`.
- Pièges : horodatage en UTC, pas en heure locale. Le corps d'un POST n'est pas journalisé : on voit qu'une page a été appelée ou qu'un fichier a été envoyé, pas ce qui a été transmis. Derrière un reverse proxy, `c-ip` est l'adresse du proxy. Les logs sont écrits par buffer, les dernières requêtes peuvent manquer. Vérifier que la cible KAPE choisie a bien collecté ce dossier.
- Outil : Log Parser, Timeline Explorer, ou Splunk.

**`applicationHost.config`**
- Emplacement : `Windows\System32\inetsrv\config`.
- Apporte : la liste des sites, leur dossier physique, les pools d'applications et leur identité, l'emplacement des logs. C'est la carte du serveur, à lire en premier.

**`web.config`**
- Emplacement : racine de chaque site ou application.
- Apporte : la configuration de l'application, parfois des chaînes de connexion avec identifiants en clair.

**Temporary ASP.NET Files**
- Emplacement : `Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files` (`Framework` si le pool tourne en 32 bits).
- Apporte : les assemblies compilées par ASP.NET à la première requête d'une page dynamique (`.aspx`, `.ashx`...). Leur date de création, lue dans la MFT, date la première exécution de la page côté serveur.
- Piège : avec la compilation par lot, une même DLL peut regrouper plusieurs pages d'un dossier.

**HTTPERR**
- Emplacement : `Windows\System32\LogFiles\HTTPERR`.
- Apporte : les requêtes rejetées par HTTP.sys avant d'atteindre IIS (timeouts, requêtes mal formées).

---

## Secrets et identifiants locaux

Au-delà de `SAM` et `SECURITY`, plusieurs emplacements conservent des identifiants.

- **Winlogon** : voir la ruche `SOFTWARE`.
- **`web.config` et `applicationHost.config`** : chaînes de connexion, identités des pools d'applications.
- **`Unattend.xml`** : `Windows\Panther`, `Windows\Panther\Unattend`, `Windows\System32\Sysprep`. Les mots de passe y sont souvent encodés en base64, pas chiffrés.
- **Credential Manager et DPAPI** : blobs dans `AppData\Roaming\Microsoft\Credentials` (et `AppData\Local`), masterkeys dans `AppData\Roaming\Microsoft\Protect\<SID>`. Le déchiffrement exige la masterkey, elle-même protégée par le mot de passe de l'utilisateur (ou par la clé `DPAPI_SYSTEM` des secrets LSA pour les blobs machine). Outils : Mimikatz `dpapi`, Impacket `dpapi.py`.
- **PSReadLine** : voir les artefacts d'exécution.

---

## Sorties LiveResponse (KAPE)

- Nature : des snapshots d'état déjà parsés, pris à l'instant de la collecte (autoruns, pslist, dirlist, regdump, connexions réseau). Fichiers `.txt` / `.csv` hétérogènes.
- Usage : orientation rapide, lecture directe dans Timeline Explorer ou à l'oeil. Rien à parser.
- Limite : c'est une photo à un instant T, à confirmer sur la matière brute (disque, registre) dès qu'une preuve doit être étayée.
- Vu dans : Jinkies.

---

## Mémoire vive

- Nature : un dump `.vmem`, `.dmp` ou `.raw` capture l'état vivant de la machine. Catégorie volatile, distincte du triage disque.
- Outil : Volatility 2/3. Plugins mobilisés dans nos exos : `windows.info` (build OS), `pstree` (arbre des processus et lignes de commande), `filescan` et `dumpfiles` (fichiers présents en RAM), `netscan` (connexions), `getsids` (attribution d'un process à un SID), `registry.hivelist` et `registry.printkey` (registre chargé en mémoire).
- Pièges : `pstree` est un instantané, un lien parent-enfant peut être cassé si l'intermédiaire est mort avant le dump ; `filescan` sort des chemins en format device NT sans lettre de lecteur ; une clé de registre non résidente en RAM n'est pas lisible via `printkey` et doit se reconstruire autrement.
- Vu dans : Trojan, ReliableThreat, Recollection, RogueOne.

---

## Capture réseau

- Nature : un fichier `.pcapng`, capture du trafic. Comme la mémoire, ce n'est pas un artefact de triage hôte mais une source complémentaire décisive pour la provenance.
- Apporte : l'origine réelle d'un téléchargement, les canaux C2, les fichiers transférés (réassemblés), les en-têtes révélateurs (`Content-Disposition` pour le vrai nom d'un binaire, `User-Agent` non standard).
- Outil : Wireshark.
- Vu dans : Trojan.

---

## Réflexes transverses

- **SI vs FN.** Pour une timeline fiable, privilégier `$FN` (`0x30`, noyau) sur `$SI` (`0x10`, modifiable). Un `$SI` antérieur au `$FN` est une signature de timestomping. Dans MFTECmd, peupler `$FN` avec `--fl`.
- **Les formats de temps.** Unix (secondes depuis 1970), FILETIME et WebKit (depuis 1601, en 100 ns ou en microsecondes) ne se convertissent pas de la même façon. Se tromper de format donne des dates absurdes.
- **Fuseaux horaires.** Les logs IIS sont en UTC, l'affichage Windows en heure locale. Tout aligner sur UTC avant de construire la timeline.
- **Preuve d'exécution contre preuve de présence.** Un fichier vu par `filescan` est présent en RAM, pas forcément exécuté ni téléchargé. L'exécution se prouve par le Prefetch ou le process tree, le download par le réseau ou l'historique navigateur. Même logique pour le Shimcache : une entrée prouve que le système a vu le binaire, pas qu'il l'a exécuté.
- **L'absence ne prouve rien.** Une trace manquante renseigne souvent sur la configuration, pas sur l'activité : 4688 sans ligne de commande, Sysmon filtré, PSReadLine vide pour un PowerShell non interactif, journal des tâches désactivé. Avant de conclure, vérifier ce qui était réellement journalisé.
- **Collecte à chaud.** Certains artefacts ne sont écrits qu'à l'arrêt ou périodiquement (Shimcache, SRUM, buffers des logs IIS). Une collecte faite avant arrêt peut ne pas les contenir.
- **Fichier absent.** Pour hasher un binaire qui n'est plus là : Amcache (SHA-1) ou une sandbox publique via le nom. Pour dater une suppression : `$UsnJrnl:$J`, puis `$LogFile`, puis la Corbeille `$I`. Pour retrouver une version antérieure : les shadow copies.
- **Hygiène.** Copie des ruches et bases SQLite avant lecture, rejeu des transaction logs, `Get-ChildItem -Force` pour voir les métafichiers NTFS cachés.

Ce mémo se lit en complément des write-ups où chaque artefact a été mis en pratique (Tracer, ReliableThreat, Jinkies etc ...) et de l'article sur l'ingestion des EVTX dans Splunk.