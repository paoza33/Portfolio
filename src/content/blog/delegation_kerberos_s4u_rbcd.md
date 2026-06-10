---
title: "Délégation Kerberos : unconstrained, constrained, RBCD et abus S4U"
date: 2026-06-10
side: "red"
tags: ["active-directory", "kerberos", "delegation", "s4u", "rbcd"]
summary: "La délégation Kerberos laisse un service agir au nom d'un utilisateur. Mal bornée, elle devient un chemin direct vers le contrôleur de domaine. Tour des trois types, du moteur S4U, et de leur exploitation."
draft: false
---

La délégation Kerberos est une fonctionnalité légitime : elle permet à un compte de service d'accéder à une ressource au nom d'un utilisateur, sans connaitre son mot de passe. L'exemple type est une application web qui interroge une base SQL pour le compte de l'utilisateur connecté. Le problème surgit quand cette délégation est mal bornée, car elle se transforme alors en un chemin direct vers des comptes privilégiés. Cet article prolonge celui sur les abus d'ACL, où un droit sur une machine menait déjà à la délégation basée ressource.

## Rappel du flux Kerberos

Le KDC, intégré au contrôleur de domaine, délivre deux tickets. L'AS authentifie l'utilisateur et lui remet un TGT, preuve de son identité. Le TGS échange ensuite ce TGT contre un ticket de service pour une ressource précise. La délégation s'insère dans ce flux : elle autorise un compte de service à demander des tickets au nom d'un autre utilisateur. Tout fonctionne au sein d'une meme foret, où les relations de confiance sont transitives.

## Les trois types de délégation

| Type | Périmètre | Risque |
| --- | --- | --- |
| Unconstrained | Vers n'importe quel service | Très élevé |
| Constrained | Vers des services définis sur le compte | Élevé |
| Resource-Based (RBCD) | Configuré sur l'objet cible | Élevé, souvent abusé |

Le point commun dangereux : aucun de ces mécanismes ne restreint les utilisateurs qui peuvent etre impersonnés. La délégation contrainte limite les services cibles, par exemple uniquement http vers un DC, mais le compte peut quand meme usurper n'importe quel utilisateur du domaine, Administrator compris. C'est là que tout se joue.

## S4U, le moteur de l'impersonation

Deux extensions Microsoft à Kerberos rendent l'attaque possible. S4U2Self permet à un compte de service de demander au KDC un ticket pour lui-meme au nom d'un autre utilisateur. Ce ticket ne sert pas à accéder à un service, il fabrique une preuve technique forwardable, celle dont l'étape suivante a besoin. S4U2Proxy reprend cette preuve et demande un ticket vers un service tiers au nom de l'utilisateur visé. Le KDC vérifie que la délégation est autorisée, puis l'émet.

Pris isolément, S4U2Self n'a aucun intérêt offensif. C'est l'enchainement S4U2Self puis S4U2Proxy qui sert de tremplin pour se faire passer pour un administrateur vers un service sensible.

## Constrained delegation en pratique

Un détail change tout : dans Kerberos, le SPN de classe http ne désigne pas un site web mais PowerShell Remoting, autrement dit WinRM. Obtenir un ticket pour http/dc1 ouvre donc un shell distant sur le contrôleur de domaine via Enter-PSSession. Si un compte de service est autorisé à déléguer vers http/dc1 et qu'on le compromet, on impersonne Administrator vers ce service et on prend le DC.

Avec Rubeus sur Windows, l'enchainement S4U se fait en une commande :

```text
.\Rubeus.exe s4u /user:webservice /rc4:<NTLM_HASH> /domain:<domain> /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:<DC_FQDN> /ptt
```

Le `/ptt` injecte directement le ticket en mémoire. L'option `/altservice` permet de viser d'autres services depuis le meme ticket, ldap, cifs ou host, en abusant de la transition de protocole. On vérifie ensuite avec `klist`, puis on ouvre la session.

Depuis Linux, Impacket fait la meme chose :

```bash
getST.py -spn http/dc1 -impersonate Administrator -hashes :<NTLM_HASH> <domain>/webservice -dc-ip <IP>
export KRB5CCNAME=Administrator.ccache
```

L'impact est immédiat : un shell sur le DC en tant qu'Administrator, soit la compromission du domaine.

## Unconstrained delegation en pratique

La délégation non contrainte fonctionne autrement. Quand un utilisateur s'authentifie vers un serveur configuré en unconstrained, son TGT complet est mis en cache dans la mémoire de ce serveur. Un attaquant administrateur sur ce serveur peut extraire ces TGT et les rejouer ailleurs. Les contrôleurs de domaine sont en unconstrained par défaut, donc sans intérêt, les vraies cibles sont les autres serveurs configurés ainsi.

Le scénario qui mène au domaine consiste à capturer le TGT d'un contrôleur de domaine. Pour cela, on le force à s'authentifier vers le serveur compromis, via une attaque par coercition, sujet traité en détail dans l'article dédié à la coercition et au relais NTLM. Une fois la coercition déclenchée, on récupère le ticket :

```text
.\Rubeus.exe monitor /interval:1
.\Rubeus.exe ptt /ticket:<BASE64_TICKET_DC>
```

On est alors le compte machine du DC, ce qui suffit à lancer un DCSync et à extraire tous les secrets du domaine. Côté Linux, le combo krbrelayx pour la capture et secretsdump pour le DCSync remplace Rubeus et Mimikatz.

## RBCD, en lien avec les ACL

La délégation basée ressource a déjà été introduite dans l'article sur les abus d'ACL, car elle s'y configure : avec un droit d'écriture sur une machine cible, on renseigne l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity pour qu'un compte que l'on controle puisse l'impersonner via S4U. L'angle délégation est le meme moteur S4U que ci-dessus, appliqué à une confiance déclarée sur l'objet cible plutot que sur le compte de service.

## Côté défense

La délégation se protège d'abord en marquant les comptes sensibles « Account is sensitive and cannot be delegated », ou en les plaçant dans le groupe Protected Users qui applique cette protection automatiquement. La règle de fond est de traiter tout compte configuré pour la délégation comme extremement privilégié, meme s'il n'est qu'un simple utilisateur du domaine. Côté détection, l'attribut Transited Services dans les journaux de connexion se remplit lors d'un logon issu d'un processus S4U, ce qui trahit l'abus, et la surveillance des comptes privilégiés se connectant hors de leurs machines habituelles complète le dispositif.

## Pour s'entrainer

La machine Garfield de Hack The Box, dont le write-up figure dans la section write-ups, met en oeuvre une délégation basée ressource et un abus S4U pour compromettre un contrôleur de domaine en lecture seule, jusqu'à une exécution en tant que compte système. C'est un terrain complet pour dérouler le moteur S4U décrit ici, de la configuration de la confiance à l'impersonation finale.