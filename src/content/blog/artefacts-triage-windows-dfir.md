---
title: "Artefacts forensiques Windows : mémo de triage DFIR"
date: 2026-07-11
side: "blue"
tags: ["dfir", "windows", "forensic", "triage", "ntfs", "evtx"]
summary: "Mémo de référence des artefacts forensiques Windows croisés au fil des investigations : métafichiers NTFS, ruches de registre, journaux EVTX, artefacts d'exécution et navigateur, mémoire et réseau. Ce qu'ils apportent, où ils vivent, avec quel outil les lire."
draft: false
---

Au fil des Sherlocks et des exercices DFIR, les mêmes familles d'artefacts reviennent : les métafichiers NTFS, les ruches de registre, les journaux d'événements, les traces d'exécution, l'historique navigateur. Cette page les rassemble en un mémo unique. Elle sert de référence rapide et de prise de notes CDSA. Chaque artefact est situé, expliqué par ce qu'il permet de prouver, et rattaché à l'outil qui le lit et à l'investigation où il a servi.

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
| `SYSTEM` | Registre | `Windows\System32\config` | ControlSet, hostname, services, partages SMB | Registry Explorer, RECmd |
| `SOFTWARE` | Registre | `Windows\System32\config` | Logiciels installés (Uninstall, WOW6432Node) | Registry Explorer, RECmd |
| `SAM` + `SECURITY` | Registre | `Windows\System32\config` | Comptes locaux, hash NT, secrets LSA | secretsdump (LOCAL) |
| `NTUSER.DAT` | Registre | racine du profil | WordWheelQuery, MRU, UserAssist | Registry Explorer, RECmd |
| `Amcache.hve` | Registre | `Windows\AppCompat\Programs` | Inventaire d'exécution, SHA-1 des binaires | Registry Explorer |
| `Security.evtx` | EVTX | `winevt\Logs` | 4624, 4719, 4698, 4688, 1102 | EvtxECmd, Hayabusa |
| `System.evtx` | EVTX | `winevt\Logs` | 104 (log effacé), 7045 (service) | EvtxECmd, Hayabusa |
| `Application.evtx` | EVTX | `winevt\Logs` | MsiInstaller 1033/1034 | EvtxECmd |
| `Windows PowerShell.evtx` | EVTX | `winevt\Logs` | 400/600/403, HostApplication | EvtxECmd |
| `PowerShell/Operational` | EVTX | `winevt\Logs` | 4104 (script block) | EvtxECmd |
| `Defender-Operational` | EVTX | `winevt\Logs` | 1116 (détection), 1117 (action) | EvtxECmd |
| `Firewall-Firewall` | EVTX | `winevt\Logs` | 2004 (règle ajoutée, direction) | EvtxECmd |
| `Sysmon/Operational` | EVTX | `winevt\Logs` | 1 (process), 11 (fichier), 17 (pipe) | EvtxECmd, Chainsaw |
| Prefetch (`.pf`) | Exécution | `Windows\Prefetch` | Preuve d'exécution, run count, ressources | PECmd |
| `.lnk` / Jump Lists | Exécution | `…\Recent` | Chemin cible, MAC times, chemin réseau | LECmd |
| Historique Chrome/Edge | Navigateur | profil `…\Default\History` | urls, downloads, chaîne de redirection | DB Browser, SQLECmd |
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

---

## Ruches de registre

Le registre est une base hiérarchique répartie en plusieurs fichiers (ruches). Réflexe d'hygiène : travailler sur une copie et rejouer les transaction logs `.LOG1/.LOG2` quand une ruche est marquée *dirty*.

**`SYSTEM`**
- Emplacement : `Windows\System32\config`.
- Apporte : le ControlSet actif (via la clé `Select`, valeur `Current`), le `ComputerName`, la configuration des services et du réseau. `Services\LanmanServer\Shares` liste les partages SMB.
- Piège : `CurrentControlSet` n'existe pas tel quel hors ligne, il faut résoudre le bon `ControlSet00X` via `Select`.
- Vu dans : Trojan (hostname), Jinkies (partages).

**`SOFTWARE`**
- Emplacement : `Windows\System32\config`.
- Apporte : les logiciels installés (`Microsoft\Windows\CurrentVersion\Uninstall`, et `WOW6432Node` pour le 32 bits), la configuration machine.
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
- 4719 : changement de politique d'audit.
- 4698 : création de tâche planifiée (embarque la définition XML complète).
- 4688 : création de process (ligne de commande), si l'audit est actif.
- 1102 : journal Security effacé.
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
- 4104 : script block logging, capture le contenu réel du code soumis. Ne voit pas les binaires externes (`schtasks.exe`, `net.exe`), pour lesquels on retombe sur 4688/Sysmon 1.
- Vu dans : LogJammer, Gemini.

**`Windows Defender-Operational.evtx`**
- 1116 : détection. 1117 : action prise. À distinguer : une action `Allow` signifie détecté mais non remédié. La clé `Detection ID` relie les deux.
- Vu dans : LogJammer.

**`Windows Firewall-Firewall.evtx`**
- 2004 : règle ajoutée. Le champ `Direction` (1 = inbound, 2 = outbound) se lit dans le brut, ne pas le déduire des ports.
- Vu dans : LogJammer.

**`Sysmon/Operational.evtx`**
- 1 : création de process (avec ligne de commande et parent). 11 : création de fichier. 17 : création de named pipe (indicateur classique de PsExec).
- Vu dans : Tracer, Jinkies.

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

---

## Artefacts navigateur

**Historique Chrome / Edge (SQLite)**
- Emplacement : `…\User Data\Default\History`.
- Apporte : tables `urls` (navigation), `downloads` (fichiers reçus), `downloads_url_chains` (chaque hop de redirection). Les horodatages sont au format WebKit (microsecondes depuis le 1601-01-01).
- Pièges : le `referrer` d'un download n'est pas sa source réelle, c'est la page qui a référé ; la vraie source est le dernier `chain_index` de `downloads_url_chains`. Ne pas convertir un timestamp WebKit comme du Unix.
- Outil : DB Browser for SQLite (lecture directe, préférable pour les blobs) ou SQLECmd.
- Vu dans : Jinkies (exfil vers pastes.io), Gemini (vraie source du download).

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
- **Preuve d'exécution contre preuve de présence.** Un fichier vu par `filescan` est présent en RAM, pas forcément exécuté ni téléchargé. L'exécution se prouve par le Prefetch ou le process tree, le download par le réseau ou l'historique navigateur.
- **Fichier absent.** Pour hasher un binaire qui n'est plus là : Amcache (SHA-1) ou une sandbox publique via le nom. Pour dater une suppression : `$UsnJrnl:$J`, puis `$LogFile`, puis la Corbeille `$I`.
- **Hygiène.** Copie des ruches et bases SQLite avant lecture, rejeu des transaction logs, `Get-ChildItem -Force` pour voir les métafichiers NTFS cachés.

Ce mémo se lit en complément des write-ups où chaque artefact a été mis en pratique (Tracer, ReliableThreat, Jinkies etc ...) et de l'article sur l'ingestion des EVTX dans Splunk.