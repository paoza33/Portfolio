---
title: "Streamer"
date: 2026-07-12
side: "blue"
tags: ["htb", "sherlock", "windows", "dfir", "malware"]
summary: "Investigation DFIR d'un poste développeur compromis par un faux installeur OBS diffusé via une publicité Google. Reconstitution de la chaîne complète, du téléchargement piégé jusqu'au backdoor, sa persistance par tâche planifiée déguisée et son exfiltration vers un bucket S3."
draft: true
---

> Sherlock CDSA. Investigation à partir d'un triage d'artefacts Windows. Les questions sont conservées en anglais, comme dans l'énoncé original.

## Contexte

Simon Stark, développeur chez Forela, prévoit de streamer des sessions de code avec ses collègues. En cherchant un logiciel de streaming sur Google, il installe ce qu'il croit être une copie légitime d'OBS, trouvée parmi les premiers résultats sponsorisés. Le fichier était en réalité piégé, et un incident de sécurité s'ensuit. L'objectif est de reconstituer précisément le déroulé de la compromission à partir des artefacts triés.

## Résolu

![Sherlock Streamer résolu](/images/streamer.png)

## Task 1 - What's the original name of the malicious zip file which the user downloaded thinking it was a legit copy of the software?

Dans `C:\Users\Simon.stark\AppData\Roaming\Microsoft\Windows\Recent`, un raccourci colle au contexte : `OBS-Studio-28.1.2-Full-Installer-x64.lnk`. Un `.lnk` conserve le chemin de sa cible au moment de l'accès. On le parse avec LECmd :

```
lecmd -f "OBS-Studio-28.1.2-Full-Installer-x64.lnk"
```

Le champ `Absolute path` pointe vers `This PC\Downloads\OBS-Studio-28.1.2-Full-Installer-x64.zip`. Le fichier a donc atterri dans `Downloads` sous son nom d'origine.

Réponse : `OBS-Studio-28.1.2-Full-Installer-x64.zip`

> Note : on aurait aussi pû trouver ça avec le dump de $J comme ci-dessous, mais cette méthode est différente de ce qu'on peut voir pour ce genre de question.

## Task 2 - Simon Stark renamed the downloaded zip file to something else. What's the renamed Name of the file alongside the full path?

Un renommage se lit dans l'USN Journal, qui journalise création, modification, suppression et rename d'un fichier. On dump le `$J` avec MFTECmd et on analyse le CSV dans Timeline Explorer :

```
mftecmd -f ".\$Extend\$J" --csv ".\$Extend\" --csvf usnjrnl.csv
```

En filtrant sur `OBS-Studio-28.1.2-Full-Installer-x64.zip`, le dernier événement est un `RenameOldName` à `2023-05-05 10:22:23`. L'événement suivant est un `RenameNewName` vers `Obs Streaming Software.zip`. Les deux partagent le même `EntryNumber 129184` et `SequenceNumber 8`, confirmant qu'il s'agit bien du même fichier.

Pour le chemin complet, on résout le parent via le `$MFT`. Le CSV du `$MFT` est ingéré dans Splunk, puis :

```
index="mft" EntryNumber=129184 SequenceNumber=8
```

Deux enregistrements ressortent pour la même entrée : le fichier lui-même, et son ADS `Zone.Identifier`. Les deux portent le même `ParentPath` : `\Users\Simon.stark\Documents\Streaming Software`.

Réponse : `C:\Users\Simon.stark\Documents\Streaming Software\Obs Streaming Software.zip`

## Task 3 - What's the timestamp when the file was renamed?

Déjà obtenu dans l'USN à la Task 2 : l'événement `RenameNewName` du zip.

Réponse : `2023-05-05 10:22:23`

## Task 4 - What's the Full URL from where the software was downloaded?

Le fichier ayant été téléchargé via un navigateur, le Mark of the Web est présent dans l'ADS `...zip:Zone.Identifier`. Le champ `ZoneIdContents` expose deux URL : `ReferrerUrl` (la page d'origine) et `HostUrl` (l'URL directe du fichier). La question porte sur l'emplacement de téléchargement du logiciel, on retient donc `HostUrl`.

Le domaine `obsproicet.net` est un typosquat de `obsproject.com`, le site officiel d'OBS. La source n'est pas légitime.

Réponse : `http://obsproicet.net/download/v28_23/OBS-Studio-28.1.2-Full-Installer-x64.zip`

## Task 5 - Dig down deeper and find the IP Address on which the malicious domain was being hosted.

WHOIS et VirusTotal ne donnent rien d'exploitable en direct. La résolution est présente dans les logs DNS-Client (Microsoft-Windows-DNS-Client/Operational). En filtrant sur `obsproicet.net` et le champ `QueryResults`, plusieurs lignes renvoient la même adresse (enregistrement A).

Réponse : `13.232.96.186`

## Task 6 - Multiple Source ports connected to communicate and download the malicious file from the malicious website. Answer the highest source port number from which the machine connected to the malicious website.

Aucun événement Sysmon dans les logs, et l'audit de la plateforme de filtrage (Security 5156) n'est pas activé. En revanche, le journal texte du pare-feu Windows est activé sur cette machine, présent à `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`. C'est lui qui a figé les ports source des connexions vers le serveur.

```
type .\Firewall\pfirewall.log | findstr 13.232.96.186
2023-05-05 15:19:39 ALLOW TCP 172.17.79.129 13.232.96.186 49996 80 ... SEND
2023-05-05 15:19:39 ALLOW TCP 172.17.79.129 13.232.96.186 49997 80 ... SEND
2023-05-05 15:19:42 ALLOW TCP 172.17.79.129 13.232.96.186 50006 80 ... SEND
2023-05-05 15:19:42 ALLOW TCP 172.17.79.129 13.232.96.186 50007 80 ... SEND
2023-05-05 15:19:45 ALLOW TCP 172.17.79.129 13.232.96.186 50008 80 ... SEND
2023-05-05 15:24:17 ALLOW TCP 172.17.79.129 13.232.96.186 50045 80 ... SEND
```

Toutes les connexions visent le port 80 du serveur. Le plus haut port source utilisé est le dernier de la liste.

Réponse : `50045`

## Task 7 - The zip file had a malicious setup file in it which would install a piece of malware and a legit instance of OBS studio software so the user has no idea they got compromised. Find the hash of the setup file.

En suivant la timeline après le renommage (2023-05-05 10:22:23), le prochain `file created` est le dossier `Obs Streaming Software` puis `About`, preuve de la décompression, suivi de nombreux `.admx` et `.adml` (templates d'administration de stratégie de groupe, sans rapport avec OBS). L'archive contient aussi l'exécutable `OBS-Studio-28.1.2-Full-Installer-x64.exe`, créé à `2023-05-05 10:22:34`.

VirusTotal ne renvoie rien par nom. L'Amcache.hve conserve le SHA-1 des exécutables. On l'ouvre dans Registry Explorer en rejouant les transaction logs (`Amcache.hve`, `Amcache.hve.LOG1`, `Amcache.hve.LOG2` dans le même dossier) pour éviter une lecture en dirty state. Dans `InventoryApplicationFile`, en filtrant sur le nom de l'exécutable, deux chemins ressortent :

```
c:\users\simon.stark\documents\streaming software\obs streaming software\obs-studio-28.1.2-full-installer-x64.exe
c:\program files (x86)\strlocalgate\obs-studio-28.1.2-full-installer-x64.exe
```

Le premier est le fichier tel qu'obtenu par Simon (extrait du zip), c'est celui que vise la question. Le second, sous un dossier `strlocalgate` non standard, est ce que l'installeur a déposé.

Le même SHA-1 est confirmé via AmcacheParser, où l'exécutable apparaît dans `Amcache_UnassociatedFileEntries.csv`, cohérent avec un binaire lancé manuellement et non enregistré comme programme installé.

Réponse : `35e3582a9ed14f8a4bb81fd6aca3f0009c78a3a1`

## Task 8 - The malicious software automatically installed a backdoor on the victim's workstation. What's the name and filepath of the backdoor?

L'exécutable a été lancé le `2023-05-05 10:23:14` (Amcache). Juste après, la timeline montre la création d'un dossier au nom aléatoire `Miloyeki ker konoyogi`, suivi d'un exécutable au nom tout aussi aléatoire `lat takewode libigax weloj jihi quimodo datex dob cijoyi mawiropo.exe` , puis d'un prefetch `OBS-STUDIO.EXE-D27099FE.pf`. On parse ce prefetch avec PECmd :

```
pecmd -f OBS-STUDIO.EXE-D27099FE.pf
```

Il référence le chemin du binaire déposé :

```
\VOLUME{...}\USERS\SIMON.STARK\MILOYEKI KER KONOYOGI\LAT TAKEWODE LIBIGAX WELOJ JIHI QUIMODO DATEX DOB CIJOYI MAWIROPO.EXE
```

Réponse : `C:\Users\Simon.stark\Miloyeki ker konoyogi\lat takewode libigax weloj jihi quimodo datex dob cijoyi mawiropo.exe`

## Task 9 - Find the prefetch hash of the backdoor.

L'exécution du backdoor est prouvée par la création de son prefetch `LAT TAKEWODE LIBIGAX WELOJ JI-D8A6D943.pf` le `2023-05-05 10:23:31`. 

Il ne sert à rien de chercher le hash du prefetch avec *Get-FileHash LAT TAKEWODE LIBIGAX WELOJ JI-D8A6D943.pf* vec tout les algorithm du monde (et ça n'a pas de sens ... oui je l'ai fait ...), ce n'est pas la question.

Le prefetch hash n'est pas un hash de fichier à calculer : c'est le segment hexadécimal du nom du `.pf`, dérivé du chemin d'exécution du binaire. Il se lit directement.

Réponse : `D8A6D943`

## Task 10 - The backdoor is also used as a persistence mechanism in a stealthy manner to blend in the environment. What's the name used for persistence mechanism to make it look legit?

Le prefetch du backdoor indique une exécution unique le `2023-05-05 10:23:21`. Juste après, la timeline ($J comme dans les task précédente) montre la création d'un fichier `COMSurrogate` puis d'un prefetch `SCHTASKS.EXE-DC1676CD.pf`, ce qui pointe vers la création d'une tâche planifiée. On confirme dans `C:\Windows\System32\Tasks\`, où le fichier `COMSurrogate` contient l'action de persistance :

```xml
<Exec>
  <Command>C:\Users\Simon.stark\Miloyeki</Command>
  <Arguments>ker konoyogi\lat takewode libigax weloj jihi quimodo datex dob cijoyi mawiropo.exe</Arguments>
</Exec>
```

La tâche est nommée `COMSurrogate` pour se fondre dans l'environnement, en imitant le processus légitime `dllhost.exe` (COM Surrogate). Le nom se retrouve aussi en filtrant le chemin du backdoor dans les events logs windows, qui remontent l'événement de création de la tâche.

Réponse : `COMSurrogate`

## Task 11 - What's the bogus/invalid randomly named domain which the malware tried to reach?

En corrélant les requêtes DNS avec le moment d'exécution du backdoor (`2023-05-05 10:23:21`), la première résolution qui suit est datée du `2023-05-05 10:23:23` pour un domaine au nom aléatoire. Ce type de résolution vers un domaine manifestement invalide est une vérification d'environnement : une sandbox qui répond positivement à n'importe quel nom donne l'information au malware qu'il n'est pas dans une machine légitime, ce qui permet au malware de conditionner la suite de son exécution. (Cela reste mon hypothèse, peut-être est-ce pour autre chose que j'ignore)

Réponse : `oaueeewy3pdy31g3kpqorpc4e.qopgwwytep`

## Task 12 - The malware tried exfiltrating the data to a s3 bucket. What's the url of s3 bucket?

En suivant toujours dans la timeline $J comme dans les task précédente, la séquence DNS enchaîne sur une requête pour `bitbucket.org` (résolue en `104.192.141.1`), s'en suit des requêtes DNS jusqu'à la requête pour le domaine "bbuseruploads.s3.amazonaws.com", le backend de stockage d'upload de Bitbucket, le `2023-05-05 10:23:28`. Ce backend est hébergé sur S3 et sert de canal d'exfiltration.

Réponse : `bbuseruploads.s3.amazonaws.com`

## Task 13 - What topic was simon going to stream about in week 1? Find a note or something similar and recover its content to answer the question.

On cherche dans le `$MFT`, le filtre sur `week 1`, ce qui remonte un fichier `Week 1 plan.txt`. Une note de ce genre est généralement de petite taille, donc probablement dans l'enregistrement MFT (données résidentes). On dump les données résidentes avec MFTECmd :

```
mftecmd -f "$MFT" --csv .\ --dr
```

On récupère le contenu résident dans le dossier de sortie :

```
ls | findstr /c:"Week 1 plan.txt"
5443-7-1_Week 1 plan.txt.bin

type "5443-7-1_Week 1 plan.txt.bin"
In week 1 we will go through "Filesystem Security" topic.
```

Réponse : `Filesystem Security`

## Task 14 - What's the name of Security Analyst who triaged the infected workstation?

L'activité de navigation dans l'Explorateur se lit dans les shellbags (ruche `NTUSER.DAT` du profil). Dans la catégorie FileFolderAccess, on ouvre le CSV `Simon Stark NTUSER.csv` produit par SBECmd. La colonne `AbsolutePath` reconstruit les chemins des dossiers parcourus, y compris ceux liés à la collecte, dont la structure révèle l'identité de l'analyste et le chemin d'où les outils ont été lancés.

Réponse : `CyberJunkie`

## Task 15 - What's the network path from where acquisition tools were run?

Même source que la Task 14. Le chemin réseau (UNC) depuis lequel les outils d'acquisition ont été exécutés apparaît dans la structure de la colonne `AbsolutePath` du même CSV shellbags.

chaque parcours dans le file folder est répertorié, on peut observer le parcours de CyberJunkie jusqu'au tools donnant:

\\DESKTOP-887GK2L\Users\ -> CyberJunkie -> Desktop -> Forela-Triage-Workstation -> Acquisiton and Triage tools

Réponse : \\DESKTOP-887GK2L\Users\CyberJunkie\Desktop\Forela-Triage-Workstation\Acquisiton and Triage tools

## Synthèse de la chaîne d'attaque

Le poste de Simon Stark est compromis via un faux installeur OBS trouvé par recherche Google et servi depuis un typosquat (`obsproicet.net`, hébergé sur `13.232.96.186`). L'archive téléchargée dans `Downloads` est renommée puis déplacée vers `Documents\Streaming Software`. Elle contient un setup piégé qui installe une vraie instance d'OBS pour masquer l'infection tout en déposant un backdoor sous un nom aléatoire dans le profil utilisateur. Le backdoor établit sa persistance via une tâche planifiée déguisée en `COMSurrogate`, effectue une vérification d'environnement par résolution d'un domaine aléatoire, puis exfiltre des données en s'appuyant sur le backend S3 de Bitbucket. L'investigation combine artefacts de raccourcis (LNK), USN Journal, `$MFT` et données résidentes, Zone.Identifier, journal du pare-feu, DNS-Client, Amcache, Prefetch, tâches planifiées et shellbags pour reconstituer l'ensemble de la chaîne.