---
title: "DCSync et Golden Ticket : du droit de réplication au contrôle du domaine"
date: 2026-06-10
side: "red"
tags: ["active-directory", "dcsync", "golden-ticket", "kerberos", "persistence"]
summary: "DCSync extrait les secrets du domaine sans être contrôleur de domaine. Golden Ticket forge des tickets indiscernables des vrais. Entre les deux, un seul pont : le hash du compte krbtgt."
draft: false
---

DCSync et Golden Ticket marquent la fin de la chaine d'attaque Active Directory, celle où l'on passe de l'accès au controle, et de l'intrusion à la persistance. La première extrait les secrets du domaine sans avoir à etre administrateur d'un contrôleur de domaine. La seconde forge des tickets Kerberos éternels, indiscernables des vrais. Un seul élément relie les deux, le hash du compte krbtgt. Cet article clot la série offensive AD sur ce point de bascule.

## DCSync

DCSync consiste à se faire passer pour un contrôleur de domaine afin de déclencher une réplication ciblée et d'en extraire les hash de mots de passe, NTLM comme Kerberos. Le détail qui fait toute la puissance de l'attaque, c'est qu'elle ne demande aucun accès administrateur local sur le contrôleur. Il suffit de deux droits sur l'objet domaine : Replicating Directory Changes et Replicating Directory Changes All. Avec eux, on dumpe n'importe quel compte, Administrator et krbtgt compris. C'est le sens de la formule qui résume l'attaque : Domain Admin sans etre Domain Admin.

Comment obtient-on ces droits ? Le plus souvent par un abus d'ACL : un WriteDacl sur l'objet domaine permet de s'octroyer soi-meme les droits de réplication, comme vu dans l'article sur les abus d'ACL.

```bash
bloodyAD -d <domain> -u <user> -p <pass> --host <IP> add dcsync <user>
```

L'extraction elle-meme se fait avec Mimikatz sous Windows ou Impacket sous Linux :

```bash
# Windows
lsadump::dcsync /domain:<domain> /user:Administrator

# Linux, ciblé sur krbtgt
secretsdump.py <domain>/<user>:<pass>@<DC_IP> -just-dc-user krbtgt
```

L'option de dump complet rapatrie l'ensemble de l'annuaire d'un coup. Les cibles prioritaires sont Administrator, les comptes de service privilégiés, et surtout krbtgt, qui ouvre la suite.

## Le pont : le hash de krbtgt

Le compte krbtgt est un compte système désactivé et non supprimable, mais sa clé sert à signer tous les TGT du domaine. C'est l'objet de confiance absolue de Kerberos. DCSync sur krbtgt livre donc la clé maitresse qui permet de fabriquer des tickets que le domaine croira sur parole.

## Golden Ticket

Avec le hash de krbtgt, on forge un TGT pour n'importe quel utilisateur, y compris Administrator, signé avec la clé de confiance du domaine. Le ticket forgé est indiscernable d'un ticket légitime, et il n'est jamais validé auprès du KDC puisqu'il porte déjà la signature attendue. C'est à la fois une élévation de privilèges et un mécanisme de persistance longue durée, avec en prime la possibilité d'escalader d'un domaine enfant vers le parent.

La chaine complète enchaine le DCSync de krbtgt, la récupération du SID du domaine, puis la forge :

```text
# Windows, Mimikatz
kerberos::golden /domain:<domain> /sid:<SID_DOMAINE> /rc4:<HASH_KRBTGT> /user:Administrator /id:500 /ptt
```

```bash
# Linux, Impacket
ticketer.py -nthash <HASH_KRBTGT> -domain-sid <SID_DOMAINE> -domain <domain> Administrator
export KRB5CCNAME=Administrator.ccache
```

Le `/ptt` injecte le ticket dans la session courante. On vérifie avec `klist`, puis on confirme l'accès en listant un partage administratif, par exemple `dir \\dc1\c$`. À noter, les options de durée et de renouvellement ne servent ici qu'à la furtivité : comme le KDC n'est jamais contacté, le renouvellement réel n'a pas lieu, ces champs ne font que rendre le ticket crédible.

## Le vrai prérequis

DCSync est le chemin le plus propre et le plus courant vers le hash de krbtgt, mais ce n'est pas le seul. Un dump du fichier ntds.dit depuis une sauvegarde ou un accès disque, ou une compromission directe du contrôleur de domaine via LSASS, IFM ou un snapshot, mènent au meme résultat. Le point commun reste l'accès à des secrets de niveau contrôleur de domaine. À l'inverse, etre administrateur local d'un poste, disposer d'un simple compte utilisateur ou administrer un serveur membre ne suffit jamais. Sans droits de réplication ou sans secrets AD, pas de Golden Ticket. La formule à retenir : si tu as DCSync, tu as Golden Ticket.

## Côté défense

DCSync est impossible à bloquer nativement, puisque la réplication est une fonction légitime d'AD. Il se détecte via l'événement 4662, mais avec une subtilité : l'opération de réplication étant exécutée localement par le compte machine du contrôleur, c'est lui qui apparait dans le journal. L'indicateur fort est donc un compte non contrôleur de domaine qui initie une réplication, repéré en surveillant les attributs de réplication concernés et en whitelistant les contrôleurs et les services légitimes comme Azure AD Connect. La meilleure prévention reste l'hygiène stricte : aucun utilisateur standard ne doit porter ces droits.

Le Golden Ticket est plus difficile à détecter, car le contrôleur ne journalise pas la création d'un ticket forgé. Les points exploitables sont indirects : un événement 4769 pour une demande de TGS sans 4768 préalable, et des connexions anormales de comptes privilégiés, hors de leurs machines d'administration, à des horaires ou depuis des IP inhabituels. La prévention de fond passe par la rotation du mot de passe de krbtgt, à effectuer deux fois en espaçant les resets d'au moins dix heures pour ne pas casser Kerberos, et par l'interdiction faite aux comptes privilégiés de s'authentifier sur des postes standards. En réponse à incident sur un domaine compromis, ce double reset de krbtgt est une étape obligatoire.

## Pour s'entrainer

La machine Garfield de Hack The Box, dont le write-up figure dans la section write-ups, va jusqu'à un Golden Ticket pour récupérer le compte Administrateur du domaine, puis un Pass-the-Hash vers le contrôleur. C'est un bon support pour dérouler la chaine décrite ici, du secret Kerberos extrait jusqu'au ticket forgé et à la compromission finale.