---
title: "LogJammer"
date: 2026-06-11
side: "blue"
tags: ["htb", "windows", "sherlock", "dfir", "event-logs", "anti-forensique"]
summary: "Sherlock DFIR Windows (facile) : à partir de cinq journaux EVTX, reconstitution de la chaîne d'attaque d'un utilisateur, du logon initial à l'effacement anti-forensique du journal pare-feu."
draft: false
---

*Sherlock orienté DFIR (parcours CDSA), difficulté facile, plateforme Hack The Box.*

## Contexte

> Forela-Security recrute un consultant DFIR junior et propose une évaluation technique portant sur l'analyse de journaux d'événements Windows. À partir de cinq fichiers EVTX, il faut reconstituer l'activité d'un utilisateur (`cyberjunkie`) et répondre aux questions de l'équipe.

L'objectif n'est pas seulement de trouver les réponses, mais de montrer **pourquoi** chaque artefact est le bon, et de reconstruire la chaîne d'attaque de bout en bout.

Pour cet exercice, on peut convertir les fichiers evtx en json avec :
`EvtxECmd.exe -d ./Event-Logs --sync -json events.json`
puis faire ingérer le json à Splunk.

Mais pour changer, utilisons d'autres outils.

## Résolu

![Sherlock LogJammer résolu](/images/logjammer-solved.png)

## Données fournies

```
Event-Logs/
├── Powershell-Operational.evtx       (12.6 Mo)
├── Security.evtx                     (1.1 Mo)
├── System.evtx                       (2.1 Mo)
├── Windows Defender-Operational.evtx (1.1 Mo)
└── Windows Firewall-Firewall.evtx    (1.1 Mo)
```

## Outillage

| Outil | Rôle |
|---|---|
| **Hayabusa** / **Chainsaw** | Triage : *où* regarder (moteurs de détection Sigma) |
| **EvtxECmd** | Extraction brute EVTX vers CSV : *tout* sur un event identifié |
| **Timeline Explorer** | Lecture, filtrage multi-colonnes, tri |
| **CyberChef** | Décodage / mise en forme des payloads (HTML entity, XML) |
| **auditpol**, **Event Viewer** | Résolution des codes `%%` et GUID Windows |

### Le principe directeur

Tout le Sherlock repose sur une distinction qu'il faut garder en tête à chaque question :

- **Hayabusa et Chainsaw sont des moteurs de détection**, pas des convertisseurs EVTX vers CSV. Pas de règle qui matche = pas de ligne. Leur sortie est une **liste d'alertes triées** qui te dit *où* regarder en priorité, jamais un flux exhaustif.
- **EvtxECmd (ou `chainsaw search`) sort le brut**, sans condition de match. C'est lui qui te donne *tous* les champs d'un event une fois que tu sais lequel regarder.

La règle qui en découle, appliquée partout ci-dessous : **choisis d'abord l'artefact qui contient le fait recherché, filtre ensuite.** Pas l'inverse.

---

## Q1 — Première connexion réussie de `cyberjunkie` (UTC)

**Artefact :** `Security.evtx` → **Event ID 4624** (logon réussi)

```bash
evtxecmd -f .\Event-Logs\Security.evtx --csv . --csvf security.csv
```

Dans Timeline Explorer, filtre `4624` + `cyberjunkie`, tri par timestamp croissant, première ligne.

Le log affiche `2023-03-27 07:37:09 -07:00`. La question demande l'**UTC** : on additionne le décalage (`-07:00` → +7h), sans changement de date.

> **Piège :** le champ `LogonType` du 4624 change le sens de « connexion ». Type 2 = interactif (console), Type 3 = réseau, Type 10 = RDP. Ici c'est bien un Type 2 interactif, la vraie première session de l'utilisateur.

**Réponse :** `27/03/2023 14:37:09`

---

## Q2 — Nom de la règle de pare-feu ajoutée

**Artefact :** `Windows Firewall-Firewall.evtx` → **Event ID 2004** (règle ajoutée)

Triage avec Hayabusa pour localiser l'event rapidement :

```bash
hayabusa csv-timeline --no-wizard -d .\Event-Logs\ -o timeline_all.csv -p super-verbose
```

La détection *« Uncommon New Firewall Rule Added In Windows Firewall Exception List »* pointe l'event et son timestamp (`2023-03-27 07:44:43 -07:00`). On bascule ensuite sur l'extraction brute pour lire le champ `RuleName` :

```bash
evtxecmd -f '.\Event-Logs\Windows Firewall-Firewall.evtx' --csv . --csvf firewall.csv
```

Le champ `RuleName` du 2004 donne directement le nom.

**Réponse :** `Metasploit C2 Bypass`

---

## Q3 — Direction de la règle de pare-feu

**Même event 2004**, champ `Direction`.

C'est ici que l'extraction brute paie : Hayabusa a matché la règle mais **n'affiche pas le champ `Direction`**. L'event 2004 l'encode pourtant explicitement :

| Valeur `Direction` | Sens |
|---|---|
| `1` | Inbound |
| `2` | Outbound |

> **Ne déduis jamais la direction à partir des ports.** « LocalPort = * donc outbound » est une heuristique fragile, une règle inbound peut elle aussi avoir un LocalPort à `*`. On lit le champ, on ne devine pas.

Champs complémentaires de cet event, utiles pour le contexte : `Action: 3` (= Allow), `Protocol: 6` (= TCP), `RemotePort: 4444` (port par défaut de Metasploit). La règle **autorise** donc une connexion sortante vers un C2.

**Réponse :** `Outbound`

---

## Q4 — Sous-catégorie de la politique d'audit modifiée

**Artefact :** `Security.evtx` → **Event ID 4719** (changement de politique d'audit)

Filtre `4719` dans `security.csv`. Un seul event, qui fournit deux pistes encodées :

```
SubcategoryId   : %%12804
SubcategoryGuid : 0cce9227-69ae-11d9-bed3-505054503030
CategoryId      : %%8274   → catégorie parente (Object Access)
```

Les `%%` sont des références de message vers une DLL Windows, l'event ne porte que le pointeur, pas le texte. Deux façons de résoudre :

**Méthode 1 (auditpol, utilisable hors-ligne, source de vérité) :** le GUID est stable et documenté, indépendant de la locale.

```cmd
auditpol /list /subcategory:* /v | findstr 0CCE9227
```
```
Other Object Access Events    {0CCE9227-69AE-11D9-BED3-505054503030}
```

**Méthode 2 (Event Viewer) :** ouvre `Security.evtx`, filtre 4719, onglet *Général* → Windows résout le `%%` tout seul et affiche la sous-catégorie en clair.

> **Cross-check :** le `CategoryId %%8274` correspond à *Object Access*. La sous-catégorie trouvée via le GUID doit logiquement appartenir à cette catégorie, c'est le cas. Double confirmation.

**Réponse :** `Other Object Access Events`

---

## Q5 — Nom de la tâche planifiée créée

**Artefact :** `Security.evtx` → **Event ID 4698** (tâche planifiée créée)

Le 4698 est l'artefact roi pour les tâches : il embarque la **définition XML complète**, donc le nom de la tâche *et* le fichier exécuté co-existent dans le même enregistrement. Filtre `4698` dans `security.csv`.

> **Pourquoi pas le log PowerShell ?** Le PowerShell-Operational ne sait pas qu'un script a été lancé par une tâche planifiée, le nom de la tâche et le chemin du script n'y co-existent jamais. Quand on veut **relier deux faits**, on choisit l'artefact où ils vivent ensemble.

**Réponse :** `HTB-AUTOMATION`

---

## Q6 — Chemin complet du fichier planifié

**Même event 4698.** La définition XML contient le bloc `<Actions><Exec><Command>` :

```xml
<Actions Context="Author">
  <Exec>
    <Command>C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1</Command>
    <Arguments>-A cyberjunkie@hackthebox.eu</Arguments>
  </Exec>
</Actions>
```

**Réponse :** `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1`

---

## Q7 — Arguments de la commande

**Même bloc XML**, champ `<Arguments>`.

Le payload du 4698 est doublement encodé (entités HTML `&lt;`/`&gt;` + virgules à la place des sauts de ligne). Pour le rendre lisible, recette CyberChef : **`From HTML Entity` → `XML Beautify`**. Une fois mis en forme, toute la fiche d'identité de la tâche se lit d'un coup : date de création, déclencheur (`StartBoundary` 09:00, quotidien), commande, arguments, utilisateur.

**Réponse :** `-A cyberjunkie@hackthebox.eu`

---

## Q8 — Outil identifié comme malveillant par l'antivirus

**Artefact :** `Windows Defender-Operational.evtx` → **Event ID 1116** (détection)

```bash
evtxecmd -f '.\Event-Logs\Windows Defender-Operational.evtx' --csv . --csvf antivirus.csv
```

Filtre `1116`, tri par utilisateur. La détection visant `cyberjunkie` :

```
Threat Name : HackTool:PowerShell/SharpHound.B
Severity    : High
Detection ID: {0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}
```

On note le `Detection ID` : c'est la **clé de corrélation** qui reliera la détection (1116) à l'action (1117) en Q10.

**Réponse :** `SharpHound`

---

## Q9 — Chemin complet du malware

**Même event 1116**, champ `Path`. Il donne toute la chaîne de provenance (le `.zip`, le `.ps1` à l'intérieur, l'URL GitHub source). `Source Name: Downloads and attachments` + `Origin: Internet` indiquent une détection au téléchargement.

**Réponse :** `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`

---

## Q10 — Action prise par l'antivirus

**Artefact :** `Windows Defender-Operational.evtx` → **Event ID 1117** (action prise)

Distinction essentielle : **1116 = détection, 1117 = action**. Dans le 1116, le champ action affiche `Not Applicable`, c'est normal, l'action réelle est dans le 1117 compagnon. On pivote via le `Detection ID` `{0EBC4BEA-…}` et on lit le champ `Action Name`.

> **Piège SOC à connaître :** « action prise » n'est pas « menace supprimée ». Un 1117 avec une action `Allow` signifie détecté mais **non remédié** (selon la configuration). On lit toujours la valeur exacte avant de conclure. Ici, c'est bien `Quarantine`.

**Réponse :** `Quarantine`

---

## Q11 — Commande PowerShell exécutée par l'utilisateur

**Artefact :** `Powershell-Operational.evtx` → **Event ID 4104** (script block logging)

```bash
evtxecmd -f .\Event-Logs\Powershell-Operational.evtx --csv . --csvf powershell.csv
```

Le 4104 capture le bloc de code réellement soumis. Mais filtrer sur `cyberjunkie` ne sert à rien, **tout** tourne sous cet utilisateur, y compris le bruit interne de PowerShell (cmdlets internes, chargements de modules). Deux stratégies pour isoler le signal :

**Pivot ciblé (rapide) :** on sait que `Automation-HTB.ps1` est l'objet d'intérêt → filtrer `4104` + `Automation-HTB.ps1`. Un seul résultat :

```powershell
Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1
```

**Méthode robuste (sans connaître la réponse), filtrer sur la *structure*, pas le contenu :**

| Critère | Signal |
|---|---|
| `Path` **vide** | Commande tapée en interactif (vs chargée depuis un `.psm1`/`.ps1`) |
| `MessageTotal = 1` | Commande unitaire (vs gros module splitté en plusieurs parties) |
| `Level` | `Verbose` = anodin · `Warning` = flaggé suspect par l'heuristique PowerShell |

On obtient ainsi la liste complète et triée des commandes interactives, sans dépendre d'un mot-clé connu d'avance. Le `Level: Warning` est un excellent **tri de priorité** (regarde le suspect d'abord) mais pas un verdict, un attaquant qui écrit proprement passe en `Verbose`.

> **Limite à connaître :** une action qui passe par un binaire externe (`schtasks.exe`, `net.exe`, `reg.exe`) n'apparaît **jamais** en 4104. Pour celles-là, le filet équivalent est **Security 4688** / **Sysmon 1** (process creation, ligne de commande complète).

**Réponse :** `Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1`

---

## Q12 — Journal d'événements effacé

**Artefact :** `System.evtx` → **Event ID 104** (journal effacé). L'équivalent pour le journal Security est le **1102**.

Filtre `104` dans `system.csv`. **Plusieurs** clears apparaissent, c'est le piège. On ne soumet pas le premier trouvé : on les **énumère tous**, puis on départage sur trois critères :

1. **Chronologie** : le *dernier* clear est l'action de couverture finale de l'attaquant.
2. **`SubjectUserName`** : la question dit « *the user* deleted », donc on retient le clear signé `cyberjunkie`, pas un compte `SYSTEM` ou un clear de provisioning.
3. **Cohérence narrative** : l'attaquant a ajouté une règle firewall C2 malveillante (Q2/Q3) ; effacer le **journal Firewall** efface précisément cette preuve. Le clear et la règle se répondent.

Le `104` enregistre le **nom du canal** (channel), pas un chemin disque. Le mapping est mécanique : `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` → fichier `Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx` (le `/` devient `%4`, sous `winevt\Logs`).

**Réponse :** `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`

---

## Reconstitution de la chaîne d'attaque

Remise dans l'ordre chronologique (heures locales `-07:00`), l'activité de `cyberjunkie` dessine un scénario cohérent :

| Heure | Action | Artefact | ATT&CK |
|---|---|---|---|
| 07:37 | Connexion interactive | 4624 | T1078 |
| 07:44 | Ajout règle firewall C2 (Metasploit, port 4444, outbound) | 2004 | T1562.004 |
| ~07:xx | Modification de la politique d'audit | 4719 | T1562.002 |
| 07:51 | Création tâche planifiée `HTB-AUTOMATION` | 4698 | T1053.005 |
| 14:42 | Téléchargement de SharpHound puis quarantaine Defender | 1116/1117 | T1087 / T1018 |
| ~xx:xx | `Get-FileHash` sur le script de la tâche | 4104 | T1059.001 |
| (fin) | Effacement du journal Firewall | 104 | T1070.001 |

L'effacement final du journal Firewall n'est pas anodin : c'est précisément le log qui traçait la règle C2 ajoutée plus tôt. Anti-forensique ciblé, pas opportuniste.

---

## Réflexes méthodologiques à retenir

- **Triage n'est pas extraction.** Hayabusa/Chainsaw disent *où* regarder ; EvtxECmd/`chainsaw search` disent *tout* sur l'event. Un champ absent de la sortie de triage (ex. `Direction` du 2004) existe presque toujours dans le brut.
- **Choisir l'artefact qui contient le fait.** Pour relier deux infos (nom de tâche ↔ fichier), prendre l'artefact où elles co-existent (4698), pas un log où l'une des deux manque.
- **Filtrer sur la structure, pas le contenu.** Un mot-clé connu (`Automation-HTB.ps1`) ne marche que par chance ; un critère structurel (`Path` vide = interactif) attrape *toutes* les commandes utilisateur.
- **Résoudre les encodages Windows.** Les `%%` → Event Viewer ou table de messages ; les GUID → `auditpol`. Recopier toujours la valeur **telle que la source l'affiche** (casse, format), ne jamais « normaliser ».
- **Plusieurs instances d'un artefact → énumérer avant de répondre.** Ordonner dans le temps, vérifier qui/quand, choisir selon l'intention de la question, pas selon l'ordre d'apparition dans le filtre.
- **Corréler via les clés stables.** Le `Detection ID` relie 1116↔1117 ; le `Subcategory GUID` survit aux changements de locale ; le timestamp relie les events entre journaux.

## Bilan outillage

Hayabusa/Chainsaw + Timeline Explorer sont très bien sur un volume modéré, mais sur LogJammer, on ressens les limites de vitesse. Dès que les sources se multiplient ou qu'on veut **corréler plusieurs journaux** (EVTX + Sysmon + réseau) avec des requêtes réutilisables, l'ingestion dans **Splunk** est bien mieux : le SPL permet un croisement bien plus précis (`stats`, `transaction`, jointures sur clés). Pour une box mono-machine, le pipeline EvtxECmd → Timeline Explorer suffit ; pour de l'investigation multi-sources, Splunk gagne.