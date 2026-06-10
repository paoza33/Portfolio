---
title: "AD CS : l'attaque ESC1, un certificat pour devenir Administrator"
date: 2026-06-10
side: "red"
tags: ["active-directory", "adcs", "esc1", "certipy", "pkinit"]
summary: "Les services de certificats d'Active Directory sont un vecteur d'escalade majeur. Avec ESC1, un template mal configuré permet à n'importe quel utilisateur de demander un certificat au nom d'Administrator, et de devenir le domaine."
draft: false
---

Les services de certificats d'Active Directory, AD CS, sont devenus un vecteur d'escalade majeur depuis la publication du papier Certified Pre-Owned par SpectreOps, qui a recensé huit techniques numérotées ESC1 à ESC8. Ce qui rend les certificats si dangereux tient à leur nature : ils sont valides plus d'un an, un reset du mot de passe ne les invalide pas, et un template mal configuré permet d'obtenir un certificat pour n'importe quel utilisateur. C'est à la fois une escalade de privilèges et un mécanisme de persistance idéal. Cet article clot la série offensive AD sur ESC1, le cas le plus simple et le plus répandu.

## Les quatre conditions d'ESC1

Un template de certificat est vulnérable à ESC1 quand quatre conditions sont réunies en meme temps.

| Condition | Ce qu'elle implique |
| --- | --- |
| ENROLLEE_SUPPLIES_SUBJECT | Le demandeur choisit lui-meme le SAN, donc peut usurper n'importe quel utilisateur |
| Enrollment ouvert aux Domain Users | N'importe quel utilisateur peut faire une demande |
| Pas d'approbation du manager | Le certificat est émis immédiatement, sans validation |
| Client Authentication activé | Le certificat peut servir à s'authentifier |

La clé de l'attaque est la première condition. Si le demandeur fixe librement le Subject Alternative Name, il lui suffit d'y mettre Administrator pour obtenir un certificat valide au nom de l'administrateur du domaine.

## Le déroulé

L'enchainement est toujours le meme : scanner les templates, demander un certificat au nom d'Administrator, puis s'en servir pour obtenir un TGT. Depuis Linux, certipy fait tout, proprement, en trois commandes.

```bash
# 1. Repérer les templates vulnérables
certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable -stdout

# 2. Demander un certificat au nom d'Administrator
certipy req -u <user>@<domain> -p <pass> -ca <CA_NAME> -template <TEMPLATE> -upn administrator@<domain>

# 3. S'authentifier avec le certificat : TGT et hash NT en sortie
certipy auth -pfx administrator.pfx -dc-ip <IP>
```

La derniere commande utilise PKINIT pour échanger le certificat contre un TGT Administrator, et récupère au passage le hash NT du compte. De là, accès complet au domaine. Côté Windows, ta fiche déroule l'équivalent avec Certify pour le scan et la demande, openssl pour convertir le PEM en PFX, et Rubeus pour l'asktgt avec injection en mémoire. Les deux chemins mènent au meme résultat.

## Pourquoi c'est redoutable

Le certificat obtenu donne un accès Administrator immédiat, mais surtout il reste valide plus d'un an, indépendamment du mot de passe du compte. Un défenseur qui réinitialise le mot de passe d'Administrator en réponse à un incident ne coupe pas l'accès de l'attaquant, car le certificat continue de fonctionner. C'est ce qui fait d'AD CS un outil de persistance aussi efficace que d'escalade. Dans le pire des cas, la compromission de la clé privée du CA permet meme de forger des Golden Certificates, soit un controle cryptographique durable du domaine.

## ESC1 n'est qu'une porte parmi huit

ESC1 est le scénario le plus direct, mais la famille est large. ESC8, le relais d'une authentification machine vers l'interface web d'enrolment, a déjà été croisé dans l'article sur la coercition et le relais NTLM. D'autres scénarios abusent de droits d'écriture sur les templates ou sur le CA lui-meme. Le réflexe est donc d'inclure systématiquement un scan AD CS dans l'énumération, comme le rappelle la méthodologie générale, car c'est parfois le raccourci le plus court vers le domaine.

## Côté défense

La détection a une particularité à connaitre : les événements de demande et d'émission de certificat, 4886 et 4887, sont générés sur le serveur PKI, pas sur le contrôleur de domaine. Il faut donc les chercher au bon endroit. Leur limite est qu'ils ne montrent pas le SAN demandé, ce qui empeche de voir directement l'usurpation ; pour le retrouver, on inspecte la base du CA avec certutil. Côté contrôleur de domaine, l'événement 4768 d'une authentification par certificat pour un compte administrateur depuis une IP inattendue est le signal d'alerte exploitable.

En prévention, la mesure de fond est de désactiver ENROLLEE_SUPPLIES_SUBJECT sur tous les templates qui n'en ont pas besoin, ce qui supprime la capacité de spécifier un SAN arbitraire. On active l'approbation manuelle du manager sur les templates sensibles, et on scanne régulièrement l'environnement PKI avec certipy ou Certify pour débusquer les templates vulnérables avant l'attaquant.

## Pour s'entrainer

La machine Escape de Hack The Box est le cas d'école d'ESC1 : après un premier accès, on découvre un template UserAuthentication vulnérable, on demande un certificat au nom d'Administrator avec certipy, et on s'authentifie pour récupérer le compte. La machine Authority propose une variante intéressante où l'enrolment passe par un compte machine plutot qu'un utilisateur. Deux bons terrains pour pratiquer le flux décrit ici de bout en bout.