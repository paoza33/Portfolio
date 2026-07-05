---
title: "NOM_DU_SHERLOCK"
date: 2024-03-19
side: "blue"
tags: ["htb", "windows", "sherlock", "dfir", "ntfs-forensics", "browser-forensics"]
summary: "Sherlock DFIR Windows sur triage KAPE : reconstruction d'une chaîne d'infection par malvertising (faux " Google AI Gemini " via un post Facebook), de la vraie source du téléchargement jusqu'à l'extension de navigateur malveillante, avec démasquage du timestomping."
draft: false
---

*Sherlock orienté DFIR (piste CDSA), plateforme Hack The Box. Triage KAPE de la station Forela-Wkstn001, utilisateur compromis alonzo.spire. DB Browser for SQLite, EZ Tools (MFTECmd, RECmd), Registry Explorer, Timeline Explorer, Splunk (forensic offline).*

## Contexte

> Alonzo Spire tombe sur un post sponsorisé (page Facebook 200k+ abonnés) présentant un " outil IA de Google ". Il télécharge le fichier fourni, l'installe, mais ne retrouve aucun outil sur sa machine -> suspicion -> incident signalé. Objectif : retrouver la **vraie source** de l'infection et reconstruire la chaîne complète.

## Résolu

![Sherlock NOM_DU_SHERLOCK résolu](/images/detroit_become_human.png)

## Artefacts et outils

| Artefact | Emplacement | Ce qu'il apporte |
|---|---|---|
| Historique Edge (SQLite) | `…\Edge\User Data\Default\History` | navigation, downloads, chaîne de redirection |
| `$MFT` | `C\$MFT` | fichiers, timestamps `$SI`/`$FN`, données résidentes, offsets |
| `$UsnJrnl:$J` | `C\$Extend\$J` | cycle de vie des fichiers (create/rename/delete) horodaté |
| `NTUSER.DAT` | profil `alonzo.spire` | `WordWheelQuery` (recherches Explorateur) |
| `SOFTWARE` hive | `C\Windows\System32\config\software` | entrée d'install (Uninstall / WOW6432Node) |
| `Application.evtx` | `…\winevt\logs` | `MsiInstaller` EID 1033 (install) |
| `Windows PowerShell.evtx` | `…\winevt\logs` | EID 400/600/403, `HostApplication` |

**Outils** : DB Browser for SQLite, EZ Tools (MFTECmd, RECmd), Registry Explorer, Timeline Explorer, Splunk (mode forensic offline, index `dfir` / `mft`).

> **Réflexe systématique :** toujours travailler sur une **copie** des hives et bases SQLite (lock plus préservation de la source), et rejouer les **transaction logs** (`.LOG1`/`.LOG2`) quand une hive est marquée *dirty*.

---

## Task 1 - What is the full link of a social media post which is part of the malware campaign, and was unknowingly opened by Alonzo spire?

On ouvre l'historique Edge au chemin `Triage\C\Users\alonzo.spire\AppData\Local\Microsoft\Edge\User Data\Default\History` dans **DB Browser for SQLite** (pas la conversion CSV : SQLECmd aplatit les blobs binaires et rend Timeline Explorer illisible). Table `urls`, colonne `title` -> plusieurs entrées " Gemini ", dont une louche :

`Gemini.AI - Introducing AI 🇬🇪🇲🇮🇳🇮 special version for… | Facebook`

Le champ `url` associé confirme le post Facebook cliqué.

**Réponse :**
```
https://www.facebook.com/AI.ultra.new/posts/pfbid0BqpxXypMtY5dWGy2GDfpRD4cQRppdNEC9SSa72FmPVKqik9iWNa2mRkpx9xziAS1l
```

---

## Task 2 - Can you confirm the timestamp in UTC when alonzo visited this post?

Sur la même ligne, `last_visit_time = 13355296200136503`.

**Ce n'est pas un timestamp Unix.** C'est du **WebKit/Chrome** : microsecondes depuis le **1601-01-01**. Un convertisseur Unix classique renvoie une date absurde (genre 1970). Avec une conversion avec `https://www.epochconverter.com/webkit`:
```
UTC: mardi 19 mars 2024 à 04:30:00
```

**Réponse :** `2024-03-19 04:30:00`

---

## Task 3 - Alonzo downloaded a file on the system thinking it was an AI Assistant tool. What is name of the archive file downloaded?

Table `downloads` de la base History. En suivant le timestamp, le fichier téléchargé juste après la visite (`13355296222571356` -> 2024-03-19 04:30:22) est l'archive.

**Réponse :** `AI.Gemini Ultra For PC V1.0.1.rar`

---

## Task 4 - What was the full direct url from where the file was downloaded?

Mon erreur sur ce que je pensais être la vraie source. Le champ `referrer` de `downloads` donne :

```
https://l.facebook.com/l.php?u=https%3A%2F%2Fdrive.usercontent.google.com%2Fu%2F2%2Fuc%3Fid%3D1z-SGnYJCPE0HA_Faz6N7mD5qf0E-A76H%26export%3Ddownload&h=AT2dsRb4dQeh4oPNOqp3eHhaSewnHh17zEIwZ18CVTFj5edI8V33q55EWDtVjXyMp3LQ5aaUwqq_ZtWpkTcAkWi9q9hzpI2JUJnZRl4io5nnOxgGHc8zB1e3lIXn6zJw9Agr73knOb4_acb9ZDFB&__tn__=-UK-R&c[0]=AT2pAxNrMkue5u710VTAYLmU_EsFxntsYANT148AzvKn8e_d8-lnf430pHC75tcwjB6fr7YWhA0N5FN3C0ojZ86fcSure9rJt1OGqeRq4y5q-bLgDmnLi7vugPXdNuZ511hTSoxa8vJ8dR-ak14a_4m_WAudOrCiudtoRPLo9mLdo7krRbqXEtIKydoSuioHjI5NVuMWVA
```

**Le `referrer` n'est pas la source du fichier.** Le `referrer` est la **page qui a référé** le download = le shim de redirection Facebook `l.facebook.com/l.php` (confirme le vecteur : clic depuis le post). Le fichier n'a pas été servi *par* Facebook, Facebook a redirigé.

Décodage du seul paramètre `u=` (le reste, `&h=`, `__tn__` et `c[0]`, est du tracking Facebook) :
```
https://drive.usercontent.google.com/u/2/uc?id=1z-SGnYJCPE0HA_Faz6N7mD5qf0E-A76H&export=download
```

Mais la **bonne réponse** vient de la table **`downloads_url_chains`**, qui enregistre chaque **hop de redirection**. `downloads` montre l'URL d'*entrée* ; la chaîne déroule jusqu'à l'URL **finale** qui sert réellement les octets :

```
chain_index 0 : https://l.facebook.com/l.php?u=…              (clic Facebook)
chain_index 1 : …/u/2/uc?id=…&export=download                  (entrée Drive)
chain_index 2 : …/download?id=…&export=download                (résolu, sert le fichier)
```

Différence `/u/2/uc` vs `/download` : `/u/2/` = compte n°2 connecté ; l'endpoint `uc` renvoie une **redirection serveur** vers l'endpoint `/download` qui abandonne le contexte de compte. " downloaded from " = le **dernier hop**.

**Réponse :**
```
https://drive.usercontent.google.com/download?id=1z-SGnYJCPE0HA_Faz6N7mD5qf0E-A76H&export=download
```

**À retenir :** pour la source réelle d'un download, le **dernier `chain_index`** de `downloads_url_chains` est presque toujours la réponse, il reflète une redirection serveur que ni le `referrer` ni la colonne d'entrée de `downloads` ne montrent.

---

## Task 5 - Alonzo then proceeded to install the newly download app, thinking that its a legit AI tool. What is the true product version which was installed?

Le dossier `Downloads` n'est pas dans le triage. Dump `$MFT` :
```powershell
mftecmd -f '.\C\$MFT' --csv .\csv\ --csvf mft.csv --fl
```

Comme vu précédemment avec l'archive, le nom de fichier annonce `V1.0.1`, **texte arbitraire, sans valeur d'autorité**. La vraie version vit dans les métadonnées MSI (`ProductVersion`), enregistrée à l'install par **Windows Installer** -> `Application.evtx`, provider `MsiInstaller`, **EID 1033**.
Dans notre cas, Event ID 1033 (MsiInstaller) : émis par Windows Installer à la fin d'une transaction MSI.

```spl
index=dfir EventId=1033
| eval tc=strptime(TimeCreated, "%Y-%m-%d %H:%M:%S.%7N")
| where tc > strptime("2024-03-19 04:30:00", "%Y-%m-%d %H:%M:%S")
```
On obtient un log, contenant une information utile dans son champ payload.
Payload : `Name, Version, Lang, Status, Manufacturer: Install, 3.32.3, 1033, 0, Google, (NULL)`


**Réponse :** `3.32.3`

Un autre moyen est d'ouvrir la hive SOFTWARE (C\Windows\System32\config\software) dans Registry Explorer. L'entrée d'install setrouve sous WOW6432Node (et non la branche Uninstall native).
> Note: Sur un Windows 64 bits, les applications 32 bits sont redirigées là. 

Chemin :
WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ABC2CE01-78A5-4554-A32A-4402A4E83BB3}
> EID 1033 a un champ binary qui nous as montré sur le log précédent que ABC2CE01-78A5-4554-A32A-4402A4E83BB3 est Alonzo.

ensuite, des valeurs confirmant la version : DisplayVersion = 3.32.3, VersionMajor = 3, VersionMinor = 32, et le DWORD Version = 52428803 (0x03200003 -> 3.32.3 encodé).

---

## Task 6 - When was the malicious product/package successfully installed on the system?

`TimeCreated` de l'EID 1033 de la Task 5. L'event " A program was installed " est émis à la **fin** de la transaction MSI.

**Réponse :** `2024-03-19 04:31:33`

---

## Task 7 - The malware used a legitimate location to stage its file on the endpoint. Can you find out the Directory path of this location?

En analysant le MFT (convertit en csv auparavant) dans timelineExporer en cherchant les données juste avant la fin d'install (04:31:33), on remarque que plusieurs fichiers ont été déposés au même moment à **04:31:20** (`$FN`) dans `Program Files (x86)\Google\Install\`:

**Réponse :** `C:\Program Files (x86)\Google`

> **Signal timestomping**: `$SI` (`Created0x10`) = **2024-01-22** vs `$FN` (`Created0x30`) = **2024-03-19 04:31:20**.

---

## Task 8 - The malware executed a command from a file. What is name of this file?

Deux scripts candidats parmis les fichiers déposés : `install.cmd` et `ru.ps1`. On suppose que le `.cmd` est le **point d'entrée** (lancé par le MSI) qui **appelle** le `.ps1`. La question viserai la **racine** de la chaîne : `MSI -> install.cmd -> powershell ru.ps1`.

On teste les 2 réponses dans hack the box et on trouve la bonne (on confirmera notre supposition à la task 9).

**Réponse :** `install.cmd`

---

## Task 9 - What are the contents of the file from question 8? Remove whitespace to avoid format issues.

on regarde ce que nous dit $MFT pour le fichier "install.cmd" avec splunk:
index=mft "install.cmd"

On obtient un seul log nous affichant une information utile:
FileSize = 94
install.cmd à une taille de fichier de 94 -> petit -> probablement **résident**. Dump des données résidentes :

```powershell
mftecmd -f '.\C\$MFT' --csv .\csv\ --csvf mft.csv --dr
ls .\Resident\ | findstr install.cmd
#  -a---           6/30/2026  5:53 AM             94 51471-4-1_install.cmd.bin   (94 o, taille complète)
type .\Resident\51471-4-1_install.cmd.bin
```
```bat
@echo off
powershell -ExecutionPolicy Bypass -File "%~dp0nmmhkkegccagdldgiimedpic/ru.ps1"
```

Confirme que `install.cmd` pilote `ru.ps1` (justifie la Task 8).

**Réponse :** `@echooffpowershell-ExecutionPolicyBypass-File"%~dp0nmmhkkegccagdldgiimedpic/ru.ps1"`

> `--dr` (dump resident) est **additif** : il écrit le contenu résident (< ~700-800 o, logé dans l'entrée MFT) dans des fichiers séparés, sans altérer le dump CSV principal. Le `.bin` = simple extension de sortie de l'outil (pas " fichier supprimé " comme j'ai pû le penser). Format du nom : `<entry>-<seq>-<attrID>_<nom>.bin`.

---

## Task 10 - What was the command executed from this file according to the logs?

on regarde dans nos logs windows tout évenement en lien avec ru.ps1:

```spl
index=dfir "ru.ps1"
```

On voit plusieurs evenements powershell (event id 253,400,600,403), avec tous la même valeur dans le champ `payload1 = HostApplication=powershell -ExecutionPolicy Bypass -File C:\Program Files (x86)\Google\Install\nmmhkkegccagdldgiimedpic/ru.ps1`
HostApplication est le champ qui enregistre la ligne de commande complète qui a démarré le moteur PowerShell.

réponse: powershell -ExecutionPolicy Bypass -File C:\Program Files (x86)\Google\Install\nmmhkkegccagdldgiimedpic/ru.ps1 

> Pas d'EID 1 (Sysmon) ni 4688 (Security) dans ce triage -> l'audit de création de process n'était pas actif.
> - **400** = Engine Available (démarrage), porte `HostApplication`
> - **600** = Provider lifecycle, porte aussi `HostApplication`
> - **403** = Engine Stopped (fin) -> 400/403 encadrent l'exécution de `ru.ps1`

---

## Task 11 - Under malware staging Directory, a js file resides which is very small in size.What is the hex offset for this file on the filesystem?


on a vu parmis les fichiers déposés par l'installation msi, deux fichiers .js: content.js et background.js, on vérifie leur taille dans $MFT:
`content.js` (258 o) vs `background.js` (17208 o) -> le " très petit " = **content.js**.

Petite taille = potentiellement dans les fichiers résidents, et on le trouve sous le nom:
`64067-4-1_content.js.bin`

On laisse MFTECmd donner l'offset avec `--de` (dump entry) :

```powershell
mftecmd -f '..\C\$MFT' --de 64067-4
```

`--de` prend la clé `EntryNumber-SequenceNumber` et dump **tout un record** : les 3 attributs (`$SI`, `$FN`, `$DATA`), les timestamps des deux, le contenu résident en hex plus ASCII, et l'**`Offset:` réel** du record.

Sortie : `Offset: 0x3E90C00`

**Réponse :** `0x3E90C00`

> Le dump `--de` confirme aussi le timestomping sur ce fichier : `$SI Created 2024-01-22` vs `$FN Created 2024-03-19 04:31:20`. Et il donne l'ASCII de `content.js` directement (utile Task 12).

---

## Task 12 - Recover the contents of this js file so we can forward this to our RE/MA team for further analysis and understanding of this infection chain. To sanitize the payload, remove whitespaces.

```powershell
type .\Resident\64067-4-1_content.js.bin
```
```js
var isContentScriptExecuted = localStorage.getItem('contentScriptExecuted');
if (!isContentScriptExecuted) {
chrome.runtime.sendMessage({ action: 'executeFunction' }, function (response) {
  localStorage.setItem('contentScriptExecuted', true);
});
}
```

Logique : content script injecté dans les pages, exécuté **une seule fois** (flag `localStorage`), qui envoie un message `executeFunction` au **background script** (`background.js`, 17208 o) via `chrome.runtime.sendMessage`. -> la vraie payload est dans `background.js`. `content.js` n'est que le déclencheur (MITRE **T1176** Browser Extensions).

**Réponse :** `varisContentScriptExecuted=localStorage.getItem('contentScriptExecuted');if(!isContentScriptExecuted){chrome.runtime.sendMessage({action:'executeFunction'},function(response){localStorage.setItem('contentScriptExecuted',true);});}`

---

## Task 13 - Upon seeing no AI Assistant app being run, alonzo tried searching it from file explorer. What keywords did he use to search?

L'historique de recherche de l'Explorateur vit dans `NTUSER.DAT\…\Explorer\WordWheelQuery`.
```powershell
recmd -f ".\NTUSER.DAT" --kn "Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" --csv "…\" --csvf wordwheel.csv
```
```
Value #1 - Name: 0 (RegBinary)
Data: 47-00-6F-00-6F-00-67-00-6C-00-65-00-20-00-41-00-69-00-20-00-47-00-65-00-6D-00-69-00-6E-00-69-00-20-00-74-00-6F-00-6F-00-6C-00-00-00
```

Après décodage sur cyberchef (from Hex), on obtient `Google Ai Gemini tool`. (Registry Explorer décode tout ça via son bookmark WordWheelQuery.)

**Réponse :** `Google Ai Gemini tool`

---

## Task 14 - When did alonzo searched it?

`Last write time` de la clé `WordWheelQuery` (fournie par la commande RECmd).

**Réponse :** `2024-03-19 04:32:11`

> Timeline cohérente : visite `04:30:00` -> download `04:30:22` -> install `04:31:33` -> recherche Explorateur `04:32:11` (environ 38 secondes après la fin d'install).

---

## Task 15 - After alonzo could not find any AI tool on the system, he became suspicious, contacted the security team and deleted the downloaded file. When was the file deleted by alonzo?

" the downloaded file " = l'**archive `.rar`** (le fichier *téléchargé* ; le `.msi` a été *extrait*, pas téléchargé). On parse le **journal USN** (`$UsnJrnl:$J`, exporté ici sous forme du stream `$J` dans `$Extend`) :

```powershell
mftecmd -f ".\`$Extend\`$J" --csv '.\$Extend\' --csvf usnjrnl.csv
```

Timeline Explorer, filtre `AI.Gemini Ultra For PC V1.0.1.rar`. Pas de `FileDelete`, mais dernier event `UpdateReason: RenameOldName` à **2024-03-19 04:34:16**.

**Pourquoi un rename = suppression :** une suppression " normale " via l'Explorateur **envoie le fichier à la Corbeille** = déplacement plus renommage en `$R….rar` dans `$Recycle.Bin\<SID>\`. Dans le `$J`, ça apparaît comme `RenameOldName` (ancien nom) -> `RenameNewName` (`$R…`). Le timestamp du rename = moment de la suppression.

**Réponse :** `2024-03-19 04:34:16`

> Confirmation possible (non dispo ici) : fichier `$I….rar` dans `$Recycle.Bin` -> stocke date de suppression (FILETIME @ offset 0x10) plus chemin d'origine (@ offset 0x18). Sources pour dater une suppression, par ordre : `$UsnJrnl:$J` (`FileDelete` / `RenameOldName`), `$LogFile` (désallocation), Corbeille `$I`. Le `$MFT` seul dit qu'un fichier est supprimé (flag `InUse=False`) mais **pas quand**. Le registre : non.

---

## Task 16 - Looking back at the starting point of this infection, please find the md5 hash of the malicious installer.

Le `.msi` n'est pas récupérable depuis le triage (non-résident, clusters non collectés). J'ai donc chercher le nom de l'installeur sur Google pour voir si il était connus.

`Google AI Gemini Ultra For PC V1.0.1.msi` est bien connu, puisque je vois un rapport **AnyRun** :
`https://any.run/report/bb7c3b78f2784a7ac3c090331326279476c748087188aeb69f431bbd70ac6407/…`

Ce rapport nous fournit divers informations dont le MD5.

**Réponse :** `BF17D7F8DAC7DF58B37582CEC39E609D`

> Alternative si le fichier avait été présent : `Get-FileHash -Algorithm MD5`. Pour un hash d'un fichier **absent**, les artefacts qui stockent un hash indépendamment du contenu : **Amcache.hve** (`InventoryApplicationFile` -> **SHA-1**, exécutables même supprimés) -> pivot VirusTotal (la page VT donne MD5/SHA-1/SHA-256). Ici AnyRun via le nom a suffi.

---

## Chaîne d'infection reconstruite

```
Post Facebook (page 200k+)  ->  l.facebook.com/l.php (shim)
   ->  drive.usercontent.google.com/uc  ->  /download   (Google Drive, contenu uploadé, PAS un produit Google)
      ->  AI.Gemini Ultra For PC V1.0.1.rar   (04:30:22)
         ->  extraction -> Google AI Gemini Ultra …V1.0.1.msi   (ProductVersion 3.32.3, faux "Google")
            ->  install MSI dans C:\Program Files (x86)\Google\Install\   (04:31:20 -> 04:31:33)
               ├─ install.cmd  ->  powershell -ep Bypass -File ru.ps1
               └─ extension navigateur (ID usurpé nmmhkkegccagdldgiimedpic)
                     content.js -> sendMessage -> background.js (payload réelle)
   Alonzo cherche l'outil (WordWheelQuery 04:32:11) -> introuvable
      -> supprime le .rar (Corbeille, 04:34:16)
```

---

## Concepts clés (révision)

- **Timestamp WebKit/Chrome** : µs depuis 1601. `unix = val/1e6 - 11644473600`. Piège n°1 des artefacts navigateur.
- **Le `referrer` n'est pas la source du download.** La source réelle = dernier hop de `downloads_url_chains` (redirection serveur invisible ailleurs).
- **Nom de fichier = déclaratif**. Version réelle d'un MSI = `ProductVersion` (EID 1033 `MsiInstaller`, `DisplayVersion` registre, DWORD `Version` encodé `Major.Minor.Build`).
- **ProductCode** décodé du champ `Binary` de l'EID 1033 = lien d'attribution log ↔ paquet.
- **Timestomping** : comparer `$SI` (`Created0x10`, modifiable user-land) et `$FN` (`Created0x30`, noyau, fiable). Peupler `$FN` avec **`--fl`** dans MFTECmd. `$SI < $FN` = back-dating.
- **MFTECmd** : `--dr` (dump données résidentes), `--de <entry-seq>` (dump complet d'un record plus **offset réel**, pas `entry × 1024`, faux si MFT fragmentée), `--fl` (attributs `$FN`), `-f $J` (parse journal USN).
- **Logs PowerShell** : `HostApplication` (400/600) = ligne de commande d'invocation ; substitut quand EID 1/4688 absents. `4104` = contenu de script.
- **WordWheelQuery** (`NTUSER.DAT`) = recherches Explorateur, stockées UTF-16LE, ordre via `MRUListEx`.
- **Suppression** : `$UsnJrnl:$J` (`FileDelete` ou `RenameOldName`->`$R…` = Corbeille), Corbeille `$I…`, `$LogFile`. `$MFT` dit *si* (`InUse=False`), pas *quand*.
- **Hash d'un fichier absent** : Amcache (SHA-1) -> pivot VT ; ou sandbox publique via nom (AnyRun).
- **Hygiène** : copie des hives/SQLite, rejeu des transaction logs (`.LOG1/.LOG2`), `Get-ChildItem -Force` pour voir les métafichiers NTFS cachés.