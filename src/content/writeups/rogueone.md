---
title: "RogueOne"
date: 2026-06-10
side: "blue"
tags: ["htb", "windows", "sherlock", "memory-forensics", "volatility", "masquerading"]
summary: "Investigation forensique d'un dump mémoire Windows 10. Un faux svchost.exe lancé depuis Downloads échappe au coup d'oeil sur le task manager mais pas à l'analyse de filiation. Identification du processus, du canal C2 et collecte des IOC avec Volatility 3."
draft: false
---

> Sherlock résolu. Le dump n'est pas redistribué, seules la méthode et les commandes le sont.

## Contexte

Le SIEM de Forela a levé plusieurs alertes de communication C2 en moins d'une minute, toutes pointant vers le poste de Simon Stark. Simon ne remarque rien d'anormal, et les captures de son gestionnaire de tâches ne montrent aucun processus suspect. Pourtant les alertes continuent. Le SOC contient le poste et en extrait un dump mémoire. Mission : retrouver le processus à l'origine du trafic C2.

Le détail qui oriente l'enquête est là, dans l'énoncé : rien ne ressort du task manager. C'est précisément le signe d'un processus qui usurpe un nom légitime pour se fondre dans la liste. L'analyse mémoire va le démasquer.

![Sherlock RogueOne résolu](/images/rogueone.png)

## Prise en main du dump

On valide d'abord l'intégrité du dump face au MD5 fourni, puis on attaque avec Volatility 3. Le fichier est `20230810.mem`, une capture d'environ 5 Go. On commence par le contexte système :

```text
python3 vol.py -f 20230810.mem windows.info
```

La sortie indique un Windows 10 (build 19041) et une acquisition datée du `2023-08-10 11:32:00`. Cela borne la fenêtre d'analyse.

## La filiation qui cloche

On liste les processus :

```text
python3 vol.py -f 20230810.mem windows.pslist
```

Au premier coup d'oeil, rien de criant : beaucoup d'instances de `svchost.exe`, ce qui est parfaitement normal sous Windows. Le point d'ancrage est ailleurs. Un `svchost` légitime n'a qu'un seul parent possible, `services.exe`, lancé depuis `%SystemRoot%\System32`. Dans ce dump, `services.exe` porte le PID 788, et l'immense majorité des `svchost` ont bien 788 pour parent.

C'est exactement le réflexe de la filiation impossible. On cherche donc l'intrus : un `svchost` dont le parent n'est pas 788. On le trouve, PID `6812`, dont le parent est `7436`. Or 7436 est une instance d'`explorer.exe`. Un `svchost` lancé par `explorer.exe`, ça n'existe pas dans un système sain. À noter : ici l'attaquant n'a même pas falsifié le parent affiché, contrairement au [Parent PID Spoofing](/blog/detecter-parent-pid-spoofing). Il l'a laissé visible, ce qui rend la détection directe.

On confirme avec la ligne de commande complète :

```text
python3 vol.py -f 20230810.mem windows.cmdline
```

Le résultat est sans appel :

```text
6812  svchost.exe  "C:\Users\simon.stark\Downloads\svchost.exe"
```

Un vrai `svchost` ne tourne jamais depuis le dossier Downloads d'un utilisateur. C'est du masquerading : un malware renommé `svchost.exe` pour passer inaperçu dans la liste des processus, d'où le gestionnaire de tâches en apparence propre. Le processus malveillant est confirmé, PID `6812`. Son offset mémoire, lu dans la colonne `Offset(V)` du `pslist`, est `0x9e8b87762080`.

## Le canal d'exécution

On cherche maintenant ce que ce faux `svchost` a engendré, en filtrant le `pslist` sur son PID :

```text
python3 vol.py -f 20230810.mem windows.pslist | findstr 6812
```

Un `cmd.exe` de PID `4364` apparaît, avec 6812 pour parent. Le processus malveillant a ouvert un interpréteur de commandes, donnant à l'attaquant les moyens d'exécuter ses commandes sur le poste.

## Extraire l'échantillon pour le reverse

L'équipe de reverse engineering a besoin du binaire. On dumpe les fichiers liés au processus, en ciblant le PID pour éviter le bruit :

```text
python3 vol.py -f 20230810.mem windows.dumpfiles --pid 6812
```

Parmi les fichiers extraits, on récupère l'`ImageSectionObject` de `svchost.exe`. On le renomme pour s'y retrouver, puis on calcule son empreinte :

```text
get-filehash -algorithm md5 .\dumped_svc.img
```

Le MD5 obtenu est `5bd547c6f5bfc4858fe62c8867acfbb5`. C'est l'IOC à transmettre au reverse et à soumettre aux plateformes de threat intel.

## Le C2

On connaît le PID du processus malveillant, donc on filtre directement les connexions réseau sur lui :

```text
python3 vol.py -f 20230810.mem windows.netscan | findstr 6812
```

On obtient une connexion `ESTABLISHED` vers `13.127.155.166` sur le port `8888`, dont le propriétaire est bien notre `svchost.exe` de PID 6812. La colonne `Created` horodate cette connexion au `2023-08-10 11:30:03`, qui marque à la fois l'exécution du processus et l'établissement du canal C2.

## Pivot threat intel

En soumettant le MD5 à VirusTotal, plus de quarante moteurs classent l'échantillon comme malveillant, avec des étiquettes de type shellcode, Marte et Meterpreter. L'onglet Details, section History, donne la première soumission du fichier : `2023-08-10 11:58:10 UTC`. Utile pour situer l'échantillon dans le temps et le rapprocher d'autres campagnes éventuelles.

## Timeline reconstituée

| Heure (UTC) | Source | Événement |
| --- | --- | --- |
| 2023-08-10 11:30:03 | netscan | Exécution du faux `svchost` (PID 6812) et établissement du C2 vers 13.127.155.166:8888 |
| 2023-08-10 11:30:57 | pslist | Lancement de `cmd.exe` (PID 4364) pour l'exécution de commandes |
| 2023-08-10 11:32:00 | windows.info | Acquisition du dump mémoire |
| 2023-08-10 11:58:10 | VirusTotal | Première soumission de l'échantillon |

## IOC collectés

| Type | Valeur |
| --- | --- |
| Processus malveillant | `svchost.exe`, PID 6812, depuis `C:\Users\simon.stark\Downloads\` |
| Processus enfant | `cmd.exe`, PID 4364 |
| MD5 | `5bd547c6f5bfc4858fe62c8867acfbb5` |
| C2 | `13.127.155.166:8888` |

## Ce qu'on en retire

Un faux nom de processus trompe l'oeil humain mais pas l'analyse de filiation. Le `svchost` ne ressortait pas dans le task manager, et c'est justement ce camouflage qui le désigne : son seul parent légitime est `services.exe`, jamais `explorer.exe`. Le chemin d'exécution est un second signal fort, un binaire système qui tourne depuis Downloads est malveillant par défaut. Pivoter par PID à travers les plugins, de `pslist` à `cmdline` puis `dumpfiles` et `netscan`, garde l'investigation focalisée sur la bonne cible. Et surtout, l'analyse mémoire produit directement des IOC actionnables, hash et IP:port, prêts pour le threat hunting à l'échelle de l'environnement.