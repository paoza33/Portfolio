---
title: "Trojan"
date: 2026-06-15
side: "blue"
tags: ["htb", "windows", "sherlock", "dfir", "memory-forensics", "malware-analysis"]
summary: "Sherlock DFIR Windows : corrélation tri-sources (mémoire, disque, réseau) pour reconstituer l'infection d'un poste par un faux logiciel de récupération de données, jusqu'au déballage d'un installeur Inno Setup chiffré."
draft: false
---

*Sherlock orienté DFIR (parcours CDSA), plateforme Hack The Box. Corrélation mémoire (Volatility 3), disque (Prefetch, FTK Imager) et réseau (Wireshark).*

## Contexte

John Grunewald supprimait d'anciens documents comptables lorsqu'il a effacé par erreur un fichier important sur lequel il travaillait. Paniqué, il a téléchargé un logiciel de récupération de données ; après installation, son poste a commencé à se comporter étrangement. Il a alerté l'IT, qui a verrouillé la machine et collecté des preuves forensiques. À nous d'analyser ces preuves pour reconstituer ce qui s'est passé.

**Ressources fournies :**

- `disk_artifacts.ad1` : image logique (collecte FTK Imager)
- `memory.vmem` : dump mémoire
- `memory.vmsn` : snapshot VMware associé
- `network.pcapng` : capture réseau

## Résolu

![Sherlock Trojan résolu](/images/trojan.png)

---

## Task 1 - Build de l'OS

> *What is the build version of the operating system?*

On interroge les informations système directement depuis la mémoire :

```
vol -q -f '.\memory capture\memory.vmem' windows.info
```

La ligne pertinente :

```
Major/Minor     15.19041
```

Le `19041` est le **numéro de build**. Le `15` est le `NtMajorVersion` (partagé par Windows 10 et 11, il n'est pas discriminant à lui seul, donc on ne s'y fie pas pour identifier la version). Le build 19041 correspond à **Windows 10 version 2004**.

Ce build est aussi la base des versions suivantes (même socle, builds incrémentés) : 2004 (19041), 20H2 (19042), 21H1 (19043), 21H2 (19044).

**Réponse : `19041`**

---

## Task 2 - Hostname

> *What is the computer hostname?*

Le hostname est stocké dans le hive **SYSTEM**, sous le ControlSet actif. Avant de cibler une clé en dur, on identifie les hives chargés et leurs offsets :

```
vol -q -f '.\memory capture\memory.vmem' windows.registry.hivelist
```

On récupère l'offset du hive SYSTEM :

```
0x8a0d9148a000  \REGISTRY\MACHINE\SYSTEM
```

Le chemin de config Windows passe par `CurrentControlSet`, qui n'existe pas tel quel en mémoire (lien symbolique résolu par le kernel). On détermine donc le ControlSet actif via la clé `Select`, valeur `Current` :

```
vol -q -f '.\memory capture\memory.vmem' windows.registry.printkey --key "Select"
```
```
REG_DWORD  \REGISTRY\MACHINE\SYSTEM\Select  Current  1  False
```

`Current = 1` → le ControlSet actif est **ControlSet001**. On cible la clé `ComputerName` en utilisant l'offset du hive SYSTEM pour rester déterministe (sans `--offset`, `printkey` chercherait dans tous les hives chargés) :

```
vol -q -f '.\memory capture\memory.vmem' windows.registry.printkey --offset 0x8a0d9148a000 --key "ControlSet001\Control\ComputerName\ComputerName"
```
```
REG_SZ  ...\ControlSet001\Control\ComputerName\ComputerName  ComputerName  DESKTOP-38NVPD0  False
```

> **Note :** deux sous-clés cohabitent sous `Control\ComputerName` : `ComputerName` (nom configuré, persistant) et `ActiveComputerName` (nom courant en RAM). Sur une machine saine les deux sont identiques ; un écart constitue un IOC (renommage récent, usurpation).

**Réponse : `DESKTOP-38NVPD0`**

---

## Task 3 - Nom du ZIP téléchargé

> *What is the name of the downloaded ZIP file?*

### Étape 1 - Localiser le fichier suspect (mémoire)

Le `filescan` révèle un fichier au nom évocateur dans `Downloads` :

```
vol -q -f '.\memory capture\memory.vmem' windows.filescan | findstr /i "download"
```
```
0xb38177761640   \Users\John\Downloads\Data_Recovery.zip
```

Autre voie : ouvrir `disk_artifacts.ad1` avec FTK Imager et parcourir l'arborescence → `Data_Recovery.zip` apparaît dans `\Users\John\Downloads\`.

HTB valide cette réponse, mais en contexte réel cela ne **prouve pas** le téléchargement : `filescan` n'atteste que de la présence en mémoire, pas de la provenance. On *suppose* le download. On extrait le contenu pour analyse ultérieure :

```
vol -q -f '.\memory capture\memory.vmem' windows.dumpfiles --virtaddr 0xb38177761640
```

### Étape 2 - Vérifier l'exécution (mémoire)

```
vol -q -f '.\memory capture\memory.vmem' windows.pstree | findstr /i "Recovery"
```
```
484   Recovery_Setup   ...\Downloads\Data_Recovery\Recovery_Setup.exe
  └── 5956  is-NJBAT.tmp  ...\Temp\is-VIBV9.tmp\is-NJBAT.tmp /SL4 $A033C ...Recovery_Setup.exe
```

Le `.exe` tourne depuis `\Downloads\Data_Recovery\` (donc extrait du zip). On a la preuve de l'exécution, mais pas celle du download : `pstree`/`cmdline` n'enregistrent pas l'origine réseau d'un fichier (sauf téléchargement en ligne de commande).

### Étape 3 - Confirmer le download et sourcer l'URL (PCAP)

```
http.request and http.request.uri contains "Data_Recovery"
```

On isole le `GET`, et la réponse donne toute la chaîne :

```
GET /wp-content/uploads/2023/05/Data_Recovery.zip HTTP/1.1
Host: praetorial-gears.000webhostapp.com

HTTP/1.1 200 OK
Content-Type: application/zip
Content-Length: 2149533
Server: awex
```

| Élément | Valeur |
|---|---|
| Méthode | `GET` |
| URL source | `http://praetorial-gears.000webhostapp.com/wp-content/uploads/2023/05/Data_Recovery.zip` |
| IP serveur | `145.14.144.155` |
| IP victime | `192.168.116.133` |
| Date | 30 May 2023 06:56:05 UTC |
| Taille | 2 149 533 octets |

**Preuve du transfert complet** : Wireshark a réassemblé exactement `2149533` octets de corps (`File Data: 2149533`), correspondant au `Content-Length` annoncé → le fichier a transité intégralement, pas juste un `200 OK` partiel.

> **Note IOC :** l'hébergement sur `000webhostapp.com` (hébergeur gratuit, `Server: awex`) est un motif récurrent de distribution de malware : abus d'un service gratuit, attribution difficile. Le domaine et l'IP `145.14.144.155` sont des IOC réseau.

### Corrélation des sources

```
Mémoire  : filescan/dumpfiles → fichier présent dans Downloads     (présence)
           pstree → Recovery_Setup.exe                             (exécution)
PCAP     : GET ...Data_Recovery.zip → 200 OK application/zip       (download confirmé + source)
Disque   : Data_Recovery.zip présent, taille identique (2 149 533) (corrélation taille/chemin)
```

**Réponse : `Data_Recovery.zip`**

---

## Task 4 - Domaine de téléchargement (3e niveau inclus)

> *What is the domain of the website (including the third-level domain) from which the file was downloaded?*

Repris de la requête HTTP observée dans le PCAP :

```
GET /wp-content/uploads/2023/05/Data_Recovery.zip HTTP/1.1
Host: praetorial-gears.000webhostapp.com
```

**Réponse : `praetorial-gears.000webhostapp.com`**

---

## Task 5 - PID du processus suspect

> *The user then executed the suspicious application found in the ZIP archive. What is the process PID?*

Le `pstree` (Task 3) montre l'exécution de l'installeur extrait du zip :

```
484   Recovery_Setup   C:\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
  └── 5956  is-NJBAT.tmp  C:\Windows\Temp\is-VIBV9.tmp\is-NJBAT.tmp /SL4 $A033C ...Recovery_Setup.exe
```

**Réponse : `484`**

---

## Task 6 - Chemin complet du processus suspect

> *What is the full path of the suspicious process?*

Donné directement par le `pstree` :

**Réponse : `C:\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe`**

---

## Task 7 - SHA-256 de l'exécutable suspect

> *What is the SHA-256 hash of the suspicious executable?*

FTK Imager affiche en natif le MD5 et le SHA-1 dans les propriétés du fichier, mais pas le SHA-256. Deux approches :

1. **Via VirusTotal** (si l'échantillon est connu) : coller le MD5 → VT affiche le SHA-256 de l'échantillon correspondant. *Limite : on récupère le hash d'un fichier que VT considère identique, pas le calcul de notre propre fichier.*

2. **Calcul local (méthode rigoureuse)** : clic droit sur `Recovery_Setup.exe` → Export Files → puis en PowerShell :
   ```powershell
   Get-FileHash .\Recovery_Setup.exe -Algorithm SHA256
   ```
   Cette voie exporte le malware en entier sur le disque, à faire **uniquement dans une VM d'analyse**, sans jamais double-cliquer le fichier. Calculer un hash est une opération en lecture seule, sans risque.

**Réponse : `c34601c5da3501f6ee0efce18de7e6145153ecfac2ce2019ec52e1535a4b3193`**

---

## Task 8 - Première exécution du programme malveillant

> *When was the malicious program first executed?*

Le `pstree` donne `2023-05-30 02:07:59`, mais ce n'est **que l'heure de démarrage de l'instance vivante au moment du dump**, il ne dit rien des exécutions antérieures.

La véritable source de l'historique d'exécution est le **Prefetch** (`C:\Windows\Prefetch\`, un `.pf` par exécutable). On le récupère depuis l'AD1 avec FTK Imager : `RECOVERY_SETUP.EXE-A808CDAB.pf`, puis on le parse avec **PECmd** :

```
pecmd -f .\RECOVERY_SETUP.EXE-A808CDAB.pf
```
```
Run count: 2
Last run: 2023-05-30 02:07:59
Other run times: 2023-05-30 02:06:29
```

`Run count: 2` confirme deux exécutions. La plus ancienne (`Other run times`) est la première.

> **Détail appris pendant l'exo :** le `.pf` est *créé* après le premier lancement (Windows génère le cache en réaction à l'exécution, avec ~10 s de délai). C'est pourquoi un `Run time` peut être antérieur au `Created` du fichier `.pf`. On se fie toujours aux **Run times embarqués**, pas aux MAC times du `.pf` (altérables).

**Réponse : `2023-05-30 02:06:29`**

---

## Task 9 - Nombre total d'exécutions

> *How many times in total has the malicious application been executed?*

Donné par le parsing Prefetch de la Task 8 : `Run count: 2`.

**Réponse : `2`**

---

## Task 10 - Le second fichier .TMP référencé

> *The malicious application references two .TMP files, one is IS-NJBAT.TMP, which is the other?*

Le Prefetch enregistre aussi **toutes les ressources (fichiers et dossiers) chargées ou touchées** pendant les ~10 premières secondes d'exécution. Dans la sortie de `pecmd` :

```
61: \VOLUME{...}\USERS\JOHN\APPDATA\LOCAL\TEMP\IS-T97VD.TMP\IS-R7RFP.TMP (Keyword: True)
```

Ce fichier ne ressort **pas** dans `windows.pstree` ni `windows.filescan` car il avait déjà été **supprimé** au moment du dump, son `_FILE_OBJECT` n'était plus en mémoire. Le Prefetch, lui, en conserve la trace persistante. C'est un cas d'école de complémentarité mémoire/disque : la mémoire montre l'état vivant, le Prefetch l'historique.


**Réponse : `IS-R7RFP.TMP`**

---

## Task 11 - URLs détectées comme malveillantes par VirusTotal

> *How many of the URLs contacted by the malicious application were detected as malicious by VirusTotal?*

Sur la page VirusTotal de l'échantillon (hash Task 7), onglet **Relations** → l'application contacte 8 URLs, dont 4 signalées comme malveillantes.

**Réponse : `4`**

---

## Task 12 - Binaire téléchargé depuis le C2

> *The malicious application downloaded a binary file from one of the C2 URLs, what is the name of the file?*

On filtre dans Wireshark les requêtes vers les URLs C2 trouvés sur virus total et on isole celle qui retourne un binaire :

```
http.request.full_uri == http://45.12.253.72/default/puk.php
```

La requête est un `GET` vers le C2, la réponse révèle le téléchargement :

```
GET /default/puk.php HTTP/1.1
Host: 45.12.253.72
User-Agent: OK

HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: attachment; filename="fuckingdllENCR.dll";
Content-Transfer-Encoding: binary
Content-Type: application/octet-stream
Content-Length: 95248
```

Le nom du fichier est donné par l'en-tête **`Content-Disposition`**, qui force le téléchargement en pièce jointe sous son nom d'origine.

| Élément | Valeur |
|---|---|
| URL C2 | `http://45.12.253.72/default/puk.php` |
| IP serveur C2 | `45.12.253.72` |
| Fichier téléchargé | `fuckingdllENCR.dll` ou `puk.php` |
| Taille | 95 248 octets |
| Type | `application/octet-stream` (binaire) |

> **Notes IOC :** un `.php` qui sert un `.dll` est anormal ; le `User-Agent: OK` est non standard (chaîne codée en dur, pas un navigateur) ; l'`Accept-Language: ru-RU` suggère une origine russophone. Le nom réel du fichier se lit dans `Content-Disposition`, pas dans l'URI (`puk.php`, trompeuse), pourtant la bonne réponse est puk.php, sur ce point, je n'ai pas compris.

**Réponse : `puk.php`**

---

## Task 13 - Nom et version réels du programme usurpé

> *Can you find any indication of the actual name and version of the program that the malware is pretending to be?*

### Étape 1 - Identifier le type d'installeur (statique)

`Recovery_Setup.exe` est un installeur. On le déballe avec **innounp** (Inno Setup Unpacker), sans l'exécuter :

```
innounp.exe -v Recovery_Setup.exe
```
```
Inno Setup version detected:  5.1.2
   2494459  2023-05-28 17:38     {app}\Rec528.exe
    553405  2010-04-26 10:37     {app}\finalrecovery.chm
      1949  2010-04-11 16:40     {app}\Readme.txt
    791040  2008-11-23 22:51     {app}\Preview.exe
      6452  2010-04-11 15:42     {app}\data\Config.xml
      1883  ...                  install_script.iss
```

Le fichier `finalrecovery.chm` (non renommé) donne le **nom** du produit usurpé : **Final Recovery**. Les dates 2008-2010 confirment un vrai logiciel ancien réempaqueté.

### Étape 2 - Le piège des métadonnées du script

Le `install_script.iss` contient un `[Setup]` trompeur :

```
AppName=Rec528
AppVerName=Cov 1.0.5.28
DefaultDirName={pf}\FLSCover\Rec528
; Encryption=yes
; PasswordHash=0dd5b472391efcaffefe1cf9ec254c93
; PasswordSalt=4428546ccae49465
```

`AppName=Rec528` et `AppVerName=Cov 1.0.5.28` sont des **étiquettes d'obfuscation**, pas le vrai nom/version. La ligne `Encryption=yes` est la clé : les fichiers embarqués sont **chiffrés**. J'ai perdu beaucoup de temps à croire que la version était celle-ci, mais c'est avec ce que je montre ci-dessous que j'ai compris mon erreur.

### Étape 3 - L'extraction statique bloquée

```
innounp.exe -x Recovery_Setup.exe
→ Type in a password (empty string to quit)
```

Le chiffrement Inno Setup empêche de lire `Readme.txt`, `finalrecovery.chm` ou `Rec528.exe` statiquement. Le mot de passe n'est connu que du loader, fourni à l'exécution uniquement. C'est un **IOC** : l'attaquant chiffre l'installeur pour entraver l'analyse statique et l'AV.

### Étape 4 - Déchiffrement par détonation contrôlée

Le contenu n'étant accessible qu'à l'exécution, on détonne l'installeur dans un **lab isolé** :

- VM dédiée, jetable, réseau **host-only** (gateway bidon `172.16.242.1` pour permettre l'interception sans sortie réelle)
- **FakeNet-NG** (admin) pour intercepter/simuler le réseau C2 (`45.12.253.x`) et générer un PCAP
- **ProcMon** pour le suivi process/fichiers/registre, **Regshot** (1er shot avant détonation)
- Windows Defender désactivé (Tamper Protection off), snapshot avant
- Transfert du sample via **ISO** (lecture seule, éjectable), partage coupé avant détonation

L'installeur déchiffre alors les fichiers et les dépose en clair :

```
dir "C:\Program Files (x86)\FLSCover\Rec528"
    finalrecovery.chm
    Preview.exe
    Readme.txt
    Rec528.exe
    data\
```

### Étape 5 - Lecture de la version

Le `Readme.txt` déchiffré contient nom et version en clair :

```
 F i n a l R e c o v e r y    v3.0.7.0325
```

La version réelle (`3.0.7.0325`) n'apparaît **que** dans les fichiers déchiffrés du produit légitime, l'`AppVerName=Cov 1.0.5.28` du script était un leurre.

**Réponse : `FinalRecovery v3.0.7.0325`**

### Note méthodologique

La détonation n'a pas servi à observer un comportement, mais à **forcer un déballage impossible statiquement** (installeur chiffré). Une fois les fichiers déchiffrés sur disque, la version se lit dans un simple `Readme.txt`, inutile d'analyser le VersionInfo du binaire ou de chercher une création de fichier. Quand plusieurs fichiers sont déchiffrés, les fichiers d'accompagnement (`.txt`, `.chm`, `Config.xml`) donnent souvent le nom + version plus directement que les métadonnées PE.

*Alternative sans lab :* la corrélation threat intel sur le hash (MalwareBazaar / VirusTotal, rapports de sandbox publics) donne la même réponse sans détonner, utile en contexte opérationnel, la détonation restant l'option la plus formatrice car pas besoin que le malware soit déjà connu.

---

## Synthèse - chronologie de l'attaque

1. John supprime un document par erreur
2. Recherche un outil de récupération → télécharge Data_Recovery.zip depuis praetorial-gears.000webhostapp.com (145.14.144.155)
3. Extrait et exécute Recovery_Setup.exe, installeur Inno Setup chiffré se faisant passer pour Final Recovery v3.0.7.0325 (logiciel légitime trojanisé)
4. Première exécution : 2023-05-30 02:06:29 (2 exécutions au total)
5. Le loader (is-NJBAT.tmp, is-R7RFP.tmp) déploie le payload
6. Contact C2 vers 45.12.253.x → téléchargement de fuckingdllENCR.dll
7. IT verrouille le poste, collecte mémoire + disque + PCAP

## Sources et méthodologie

| Source | Outils | Apporte |
|---|---|---|
| Mémoire (`memory.vmem`) | Volatility 3 (`windows.info`, `registry.*`, `filescan`, `pstree`, `dumpfiles`) | État vivant : OS, hostname, processus, présence fichiers |
| Disque (`disk_artifacts.ad1`) | FTK Imager, PECmd, innounp | Historique persistant : Prefetch, fichiers, métadonnées installeur |
| Réseau (`network.pcapng`) | Wireshark | Provenance : URL de download, C2, binaire récupéré |
| Threat intel | VirusTotal, MalwareBazaar | Détections, relations, contexte |
| Analyse dynamique | VM isolée + FakeNet-NG + ProcMon + Regshot | Déchiffrement de l'installeur protégé |