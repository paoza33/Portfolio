---
title: "Jinkies"
date: 2026-06-30
side: "blue"
tags: ["htb", "windows", "sherlock", "dfir", "ntfs-forensics", "exfiltration"]
summary: "Sherlock DFIR Windows sur triage KAPE : d'un partage SMB trop large à l'exfiltration via tunnel VS Code et pastes.io, en recoupant MFT, registre, EVTX et historique navigateur. Réutilisation de credentials et récupération d'un fichier supprimé résident."
draft: false
---

*Sherlock orienté DFIR sur triage KAPE (LiveResponse plus triage disque C:). Plateforme Hack The Box. EZ Tools, Splunk (forensic on-demand), Impacket, undrop-for-innodb.*

## Contexte et matériel d'analyse

> You’re a third-party IR consultant and your manager has just forwarded you a case from a small-sized startup named cloud-guru-management ltd. They’re currently building out a product with their team of developers, but the CEO has received word of mouth communications that their Intellectual Property has been stolen and is in use elsewhere.

The user in question says she may have accidentally shared her Documents folder and they have stated they think the attack happened on the 6th of October. The user also states she was away from her computer on this day.

There is not a great deal more information from the company besides this. An investigation was initiated into the root cause of this potential theft from Cloud-guru; however, the team has failed to discover the cause of the leak. They have gathered some preliminary evidence for you to go via a KAPE triage. It’s up to you to discover the story of how this all came to be. ** Warning : This Sherlock requires an element of OSINT and players will need to interact with 3rd party services on the internet.**

Le triage KAPE se découpe en deux ensembles qu'il faut traiter **différemment** :

- **LiveResponse** : des *snapshots d'état* déjà parsés, pris à l'instant de la collecte (06/10/2023 ~10:44-10:47). Fichiers `.txt` / `.csv` hétérogènes (autoruns, pslist, dirlist, regdump, connexions réseau…). Rien à " parser " : ouverture directe dans **Timeline Explorer** ou lecture à l'oeil.
- **Triage disque C:**, la matière brute : `$MFT`, `$LogFile`, `$Boot`, `$Secure_$SDS`, l'arborescence `users\` et `Windows\`. C'est ici que vivent les EVTX, les hives registre, les artefacts d'exécution.

Principe directeur de toute l'investigation : **info de contexte / orientation rapide -> LiveResponse ; preuve à étayer ou artefact absent du live -> disque + registre.** Quand les deux divergent, la source brute fait foi.

Outillage mobilisé : EZ Tools (MFTECmd, LECmd, SQLECmd, EvtxECmd), Splunk (mode forensic on-demand), Impacket, et une VM Kali pour `undrop-for-innodb` (mais ce dernier a été inutile).

## Résolu

![Sherlock Jinkies résolu](/images/jinkies.png)

## Pipeline d'ingestion Splunk (note technique)

Les EVTX du triage disque (`Windows\System32\winevt\Logs\*.evtx`) ont été convertis en CSV via **EvtxECmd**, puis ingérés dans Splunk. Point clé qui a coûté du temps : **le timestamp**.

EvtxECmd produit une colonne `TimeCreated` au format `2020-11-06 12:22:57.5684851` (espace, pas de `T`, 7 décimales, UTC sans offset). Le `props.conf` correct :

```ini
[evtx_csv]
TIME_PREFIX = TimeCreated,
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%7N
MAX_TIMESTAMP_LOOKAHEAD = 50
SHOULD_LINEMERGE = false
INDEXED_EXTRACTIONS = csv
```

Piège rencontré : tant que `_time` n'est pas aligné sur `TimeCreated`, **aucun filtre temporel ne fonctionne**. Et dans un `where`, comparer `TimeCreated` (chaîne) à `strptime(...)` (epoch) ne filtre rien, il faut d'abord convertir : `eval tc=strptime(TimeCreated, "%Y-%m-%d %H:%M:%S.%7N")`.

Le `$MFT` a été parsé séparément (`MFTECmd -f $MFT --csv .`) et ingéré dans son propre index `mft`.

---

## Task 1 - Quels dossiers étaient partagés sur l'hôte ?

La source autoritaire des partages SMB, c'est le registre, hive **SYSTEM** :

```
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
```

Dans `CrowdResponse_regdump.csv` (Timeline Explorer), en filtrant sur cette clé, le champ `value` révèle deux chemins partagés.

**Réponse : `C:\Users\Velma\Documents, C:\Users`**

> Observation importante pour la suite : un share sur **tout** `C:\Users` est une exposition anormale, et le partage SMB est **récursif**, l'attaquant accédant à `C:\Users` peut descendre dans toute l'arborescence des profils. Ce share est très probablement le vecteur d'accès et le share de Velma est sûrement un indice pour la suite.

---

## Task 2 - Quel fichier a donné à l'attaquant l'accès au compte utilisateur ?

Confirmation que SMB est exposé, dans `network_connections.txt` :

```
TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4
```

Le `$MFT` permet de reconstruire la timeline d'accès aux fichiers du share. On trie sur la date de dernier accès, en utilisant **`LastAccess0x30` (FN)** plutôt que `0x10` (SI) :

```spl
index="mft" ParentPath="*\\Velma\\Documents\\*"
| table LastAccess0x30, ParentPath, FileName
| sort -LastAccess0x30
```

> **Rappel SI vs FN :**
> `0x10` = `$STANDARD_INFORMATION` : timestamps " classiques " visibles dans l'explorateur, **modifiables** en espace utilisateur (cibles du timestomping).
> `0x30` = `$FILE_NAME` : timestamps maintenus par le **noyau** NTFS, bien plus difficiles à falsifier. Plus fiables pour une timeline forensique.

L'énumération du dossier s'arrête sur **`bk_db.ibd`**, un fichier de données InnoDB (MySQL/MariaDB). En l'ouvrant (`strings` / Notepad), on y trouve **emails, identifiants et mots de passe en clair**. C'est par ce fichier que l'attaquant a récupéré les credentials du compte.

**Réponse : `bk_db.ibd`**

---

## Task 3 - Combien de credentials dans le fichier ?

Le `.ibd` est **orphelin** (pas de `.frm`, pas de `.cfg`, pas de `datadir`), donc le rattachement propre dans une instance MariaDB via `IMPORT TABLESPACE` n'est pas possible (il faut le schéma exact). Le parsing structuré via `undrop-for-innodb` (`stream_parser` plus `c_parser`) sur Kali fonctionne mais, sans schéma, découpe les colonnes de travers. Tout ça n'a servi à rien donc un simple comptage `strings` est la méthode fiable.

L'email est l'ancre la plus régulière (un par record) :

```powershell
strings.exe -n 4 ".\bk_db.ibd" | Select-String "@gmail" | Measure-Object -Line
```

**Réponse : `256`**

> Note méthodo : la table `bk_db` (" backup db ") pleine de creds en clair est le **butin** (objet du vol), pas le vecteur d'accès initial, distinction à garder en tête. Et un `.ibd` orphelin ne se lit proprement qu'au niveau des données ; la lecture en colonnes nommées n'est pas atteignable de façon fiable sans le schéma d'origine.

---

## Task 4 - NT hash du mot de passe de l'utilisateur

Les mots de passe sont en clair dans `bk_db.ibd`, dont celui de Velma : `peakTwins2023fc`.

Le hash NT est un **calcul direct** (pas une extraction) : `MD4(UTF-16LE(password))`, via Impacket.

```python
from impacket.ntlm import compute_nthash
print(compute_nthash("peakTwins2023fc").hex())
```

**Réponse : `967452709ae89eaeef4e2c951c3882ce`**

---

## Task 5 - Le mot de passe Windows est-il le même que celui du `.ibd` ?

Question de **réutilisation de credential** : on compare le hash calculé (Task 4) aux hash NT des comptes Windows, extraits hors-ligne des hives SAM/SECURITY/SYSTEM.

```
secretsdump.py -security .\SECURITY -sam .\SAM -system .\SYSTEM LOCAL
```

> Détails : `LOCAL` déclenche le mode hors-ligne ; SYSTEM porte la **bootkey** indispensable au déchiffrement/chiffrement de la SAM.

Résultat :

```
Velma:1002:aad3b435b51404eeaad3b435b51404ee:967452709ae89eaeef4e2c951c3882ce:::
```

Le 4e champ (hash NT) **correspond exactement** au hash de `peakTwins2023fc`. Velma réutilise son mot de passe applicatif pour son compte Windows.

**Réponse : `Yes`**

---

## Task 6 - Heure de la première connexion interactive de l'attaquant

On filtre les 4624 ciblant le **compte** Velma (et non le nom machine), en regardant le **Logon Type** :

```spl
index=dfir SourceFile="*Security.evtx" EventId=4624
| where like(PayloadData1, "%Velma%") OR like(Payload, "%Velma%")
| table TimeCreated, EventId, PayloadData1, PayloadData2, PayloadData3
| sort TimeCreated
```

```
2023-10-06 17:15:56   LogonType 3    (réseau)
2023-10-06 17:16:09   LogonType 3    (réseau)
2023-10-06 17:17:23   LogonType 3    (réseau)
2023-10-06 17:17:24   LogonType 10   (RemoteInteractive - sûrement du RDP, confirmé plus tard)
2023-10-06 17:37:18   LogonType 2    (interactif console)
```

La séquence raconte l'intrusion : trois **Type 3** (accès réseau, via le share) en ~90 s, rythme non humain, évoquant un outil, puis bascule en **Type 10** (session graphique distante, RDP). La question portant sur la première connexion **interactive**, le dernier Type 3 qui amorce la prise de contrôle est le marqueur retenu.

**Réponse : `2023-10-06 17:17:23`**

---

## Task 7 - Première commande de l'attaquant en ligne de commande

On suit les Sysmon Event 1 (création de process) sous Velma après le logon, en convertissant le timestamp pour que le filtre fonctionne :

```spl
index=dfir EventId=1 UserName="*Velma"
| eval tc=strptime(TimeCreated, "%Y-%m-%d %H:%M:%S.%7N")
| where tc > strptime("2023-10-06 17:17:24", "%Y-%m-%d %H:%M:%S")
| table TimeCreated, ExecutableInfo
| sort TimeCreated
```

Les premières lignes ne sont que du **bruit d'ouverture de session** (taskhostw, userinit, explorer, svchost, ctfmon, vmtoolsd…). Le premier acte volontaire de l'attaquant apparaît quand `cmd.exe` se lance, suivi de whoami.

**Réponse : `whoami`**

---

## Task 8 - Fichier ouvert dans VS Code juste avant le navigateur

(Toujours en parcourant les commandes de l'attaquant avec notre requête splunk (Task7).
En continuant la timeline, après le lancement de Spotify/Chrome, première commande VS Code à `17:18:26` :

```
"...\Microsoft VS Code\Code.exe"
  "C:\Users\Velma\Desktop\cloud-gurustuff\official guru terminal aws script\Version-1.0.1 - TERMINAL LOGIN.py"
```

Un script Python nommé " TERMINAL LOGIN " dans un dossier lié à AWS, cible évidente (logique de login / credentials cloud).

**Réponse : `Version-1.0.1 - TERMINAL LOGIN.py`**

---

## Task 9 - Domaine d'exfiltration

(Toujours en parcourant les commandes de l'attaquant avec notre requête splunk (Task7).
Juste après l'ouverture du fichier, l'attaquant manipule un **tunnel VS Code** :

```
17:18:31   cmd.exe /d /s /c "wsl.exe -l -q"
17:18:32   code-tunnel.exe tunnel status
```

Le VS Code tunnel ouvre un canal sortant **HTTPS vers l'infrastructure Microsoft**, accès distant furtif, car le trafic paraît légitime. C'est confirmé côté réseau :

```
TCP  192.168.157.144:50323  20.90.156.32:443  ESTABLISHED  3192
```

`20.90.156.32` = Microsoft Corporation, cohérent avec le tunnel. Le PID 3192 se résout en `svchost` (rien d'exploitable directement, d'où l'intérêt du tunnel pour l'attaquant).

> Point de méthode : " IP Microsoft " **n'innocente pas**, c'est précisément ce qui rend le tunnel VS Code intéressant pour un attaquant. Ce qui tranche, c'est de relier la connexion au process et de chercher le **vrai** canal d'exfil ailleurs.

~10 s après le tunnel, lancement de Chrome (`17:18:41`). On peut peut-être y trouver des indices dans l'historique. L'historique du navigateur se trouve ici :

```
C:\Users\Velma\AppData\Local\Google\Chrome\User Data\Default\History   (SQLite)
```

Parsé avec **SQLECmd** (`sqlecmd -f .\History --csv ...`), qui produit notamment `ChromiumBrowser_HistoryVisits`. Dans Timeline Explorer :

```
2023-10-06 17:19:35   recherche pastes.io
2023-10-06 17:19:38   accès à pastes.io
```

`pastes.io` est un service de partage de texte brut en public, moyen d'exfiltration crédible pour le contenu du script AWS.

**Réponse : `pastes.io`**

---

## Task 10 - Handle de l'attaquant

> La consigne annonce de l'OSINT, mais la réponse est en réalité **entièrement dans les artefacts**, le service pastes.io passe en accès privé/incognito ensuite, donc l'OSINT externe est une fausse piste. Ou alors peut-être existe-il un moyen de retrouver le compte utilisateur de l'attaquant sur Pastes.io mais je n'ai pas réussi.

Deux commandes Notepad ressortent dans la timeline de l'attaquant :

```
NOTEPAD.EXE  ...\Version-1.0.1 - TERMINAL LOGIN.py
NOTEPAD.EXE  C:\Users\Velma\Pictures\learn.txt
```

Le dossier `Pictures` (et `learn.txt`) a été **supprimé**. Dans le `$MFT`, le fichier a été accédé le jour de l'intrusion, et le lendemain son **raccourci** (`.lnk`) a été touché, lui, toujours présent dans `C\users\Velma\Appdata\Roaming\Microsoft\Windows\Recent`. On le lit avec **LECmd** :

```powershell
lecmd -f .\learn.txt.lnk --csv ...
```

```
TargetCreated  : 2023-10-06 17:23:46
TargetModified : 2023-10-06 17:23:46
TargetAccessed : 2023-10-06 17:23:46
LocalPath      : C:\Users\
NetworkPath    : \\VELMAD100\Users
CommonPath     : Velma\Pictures\learn.txt
```

Le `NetworkPath \\VELMAD100\Users` confirme un accès **via le share** identifié en Task 1, pendant la fenêtre d'intrusion. Le `.lnk` annonçait `FileSize: 0` (taille captée à la création), mais le **`$MFT` indique 55 octets**, le fichier avait donc du contenu, et 55 octets = **resident** dans l'enregistrement MFT, donc récupérable malgré la suppression.

Dump des données résidentes via MFTECmd (option `--dr` sur cette version) :

```powershell
mftecmd -f '.\$MFT' --csv "$PWD" --csvf mft.csv --dr
```

```
type .\Resident\78533-23-1_learn.txt.bin   (55 octets)
```

Contenu :

```
lol check your drives next time, idiot

~pwnmaster12
```

L'attaquant a laissé une belle note, signée de son handle.

**Réponse : `pwnmaster12`**

---

## Récapitulatif - kill chain reconstituée

| Étape | Action | Artefact / preuve |
|-------|--------|-------------------|
| Exposition | Share SMB récursif sur `C:\Users` | Registre `LanmanServer\Shares` |
| Accès aux données | Énumération du share -> `bk_db.ibd` | `$MFT` (FN timestamps), strings sur l'`.ibd` |
| Vol de creds | 256 credentials en clair, dont Velma | `strings` / comptage emails |
| Réutilisation | Mot de passe `.ibd` = mot de passe Windows | `secretsdump` vs `compute_nthash` |
| Connexion | Logon réseau (Type 3) -> RDP (Type 10) | EVTX Security 4624 |
| Exécution | `whoami`, puis ouverture du script AWS dans VS Code | Sysmon Event 1 |
| Accès distant | Tunnel VS Code (HTTPS sortant) | `code-tunnel.exe`, netstat, PID 3192 |
| Exfiltration | Upload vers `pastes.io` | Historique Chrome (SQLECmd) |
| Signature | Note `learn.txt` supprimée, récupérée du MFT résident | LECmd + MFTECmd `--dr` |

**Acteur : `pwnmaster12`**

---

## Leçons et réflexes retenus

- **EVTX -> Splunk** : convertir avec EvtxECmd (CSV) et soigner `TIME_FORMAT`/`_time`, sinon tout filtre temporel est faussé. `wevtutil` (XML) reste une alternative pour le TA Windows, mais sensible aux fichiers partiellement corrompus issus d'une collecte KAPE.
- **SI vs FN** : privilégier `0x30` (FN, noyau) pour les timelines ; une divergence SI/FN incohérente est un indicateur de timestomping.
- **`.ibd` orphelin** : sans schéma, pas de rattachement MariaDB fiable, `strings` pour le contenu, `undrop-for-innodb` pour l'exhaustivité (records supprimés inclus).
- **NT hash** : plaintext -> hash = calcul direct (`compute_nthash`) ; hives -> hash = extraction (`secretsdump`). Ne pas confondre.
- **Tunnel VS Code** : canal d'accès distant légitime-en-apparence, l'IP Microsoft n'innocente rien.
- **Fichier supprimé < ~700 o** : resident dans le `$MFT`, récupérable via `MFTECmd --dr`. Le `.lnk` survit au fichier et porte taille/timestamps/chemin/MAC.
- **Toujours recouper** : un artefact isolé est une hypothèse ; la preuve naît de la convergence (MFT + EVTX + registre + réseau).