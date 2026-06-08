---
title: "Détecter les commandes PowerShell encodées"
date: 2026-05-28
side: "blue"
tags: ["splunk", "detection", "T1059"]
summary: "Pourquoi l'argument -EncodedCommand est un signal intéressant, et comment le surveiller proprement dans Splunk sans crouler sous les faux positifs."
draft: false
---

> Article témoin montrant comment intégrer une requête commentée dans une note.

L'argument `-EncodedCommand` de PowerShell permet de passer une commande encodée en Base64. C'est parfaitement légitime dans certains scripts, mais c'est aussi un moyen classique de masquer une charge malveillante.

## L'idée

Plutôt que d'alerter sur chaque usage, on agrège par hôte et utilisateur pour distinguer un usage ponctuel d'une activité anormale.

```spl
index=wineventlog EventCode=4688
| search NewProcessName="*powershell.exe"
| regex CommandLine="(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}"
| stats count values(CommandLine) as commandes by host, SubjectUserName
| sort - count
```

## Réduire le bruit

Le seuil sur la longueur de la chaîne Base64 (au moins 20 caractères) écarte une partie des usages anodins. On peut ensuite affiner avec une liste d'exclusion des hôtes connus pour des scripts d'administration légitimes.

Cette requête fait partie de ma bibliothèque SPL, dont la sélection complète est sur la page dédiée.
