---
title: "Reconnaître les patterns de déni de service dans Wireshark"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "dos", "ddos", "détection"]
summary: "Un déni de service prend deux formes : noyer la cible sous le volume, ou se servir d'un tiers pour la frapper par ricochet. Chacune a une signature nette dans une capture, et le menu Statistics fait le plus gros du travail."
draft: false
---

Un déni de service vise la disponibilité, et il s'y prend de deux façons. Soit l'attaquant noie directement sa cible sous un volume de trafic, soit il se sert d'un tiers comme amplificateur pour frapper la victime par ricochet. Cette distinction n'est pas cosmétique : elle change la forme du trafic dans la capture, donc la façon de le détecter. Cet article clot la série analyse réseau sur le terrain de la disponibilité, après les attaques visant la confidentialité et l'intégrité.

## Les floods directs

Le flood direct est la version brutale : un hote envoie un maximum de paquets vers une cible pour la saturer. Plusieurs variantes, une meme logique.

Le SYN flood envoie des SYN en rafale sans jamais finir les handshakes, épuisant la table de connexions du serveur. La signature est nette : un seul port de destination, et selon l'outil des IP sources aléatoires ou au contraire des ports sources qui s'incrémentent avec des longueurs de paquet toutes identiques, marque d'une génération automatisée peu soignée.

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

L'attaque LAND est une curiosité : l'IP source est égale à l'IP destination, l'hote s'envoie un paquet à lui-meme pour piéger les vieilles piles réseau. L'indice tient en un filtre.

```
ip.src == ip.dst
```

Les floods ICMP et DNS suivent le meme principe sur leur protocole : un volume massif de requetes ICMP ou DNS depuis un hote vers la cible. Le point commun de tous les floods directs, c'est un hote, un volume énorme, une cible. Statistics puis Conversations le fait ressortir en deux clics, en triant par nombre de paquets.

## La réflexion et l'amplification

L'autre famille est plus retorse. L'attaquant usurpe l'IP source de la victime, envoie ses requetes à des tiers, et ce sont eux qui répondent, tous vers la victime. Le résultat : la cible reçoit une avalanche de réponses qu'elle n'a jamais demandées. Quand la réponse est plus grosse que la requete, on parle d'amplification.

L'attaque SMURF applique ça à ICMP : des pings envoyés à de nombreux hotes avec l'IP source de la victime, et toutes les réponses ICMP convergent vers elle. On isole les réponses et on regarde la convergence.

```
icmp.type == 0
```

Puis Statistics puis Endpoints pour voir l'hote vers lequel tout le trafic remonte.

L'amplification DNS exploite le ratio entre une petite requete et une grosse réponse. Une requete de type ANY, émise avec l'IP source de la victime, déclenche une réponse DNS volumineuse expédiée vers cette victime. Un resolveur ouvert mal configuré devient ainsi un canon pointé sur un tiers.

L'indice qui ne trompe jamais pour cette famille : un hote qui reçoit un flot de réponses sans avoir émis les requetes correspondantes. C'est l'anomalie de fond de toute attaque par réflexion.

## En un coup d'oeil

| Famille | Principe | Indice clé |
| --- | --- | --- |
| SYN flood | Saturer la table de connexions | SYN en masse vers un port unique |
| LAND | Paquet d'un hote vers lui-meme | `ip.src == ip.dst` |
| Flood ICMP / DNS | Noyer par le volume | Volume massif depuis un hote |
| SMURF | Réflexion ICMP | Réponses ICMP convergeant vers une victime |
| Amplification DNS | Réflexion DNS amplifiée | Grosses réponses DNS vers une cible qui n'a rien demandé |

## Le réflexe analyste

Comme souvent en analyse réseau, on ne commence pas par un filtre mais par les statistiques. Conversations désigne l'hote bavard d'un flood direct, Endpoints révèle la convergence d'une attaque par réflexion. La forme du trafic nomme le coupable avant meme qu'on pose un filtre. C'est seulement ensuite qu'on affine, pour confirmer la variante et documenter l'incident.

## Contre-mesures

Le filtrage anti-usurpation en entrée de réseau (ne laisser sortir aucun paquet dont l'IP source n'appartient pas au réseau) coupe la racine des attaques par réflexion. La limitation de débit absorbe les floods, désactiver les réponses ICMP en broadcast neutralise SMURF, et durcir ou fermer les resolveurs DNS ouverts retire à l'attaquant ses amplificateurs.

## Pour s'entrainer

Ce vecteur se comprend mieux en le reproduisant qu'en le lisant. Dans un lab isolé, générer un flood maitrisé avec un générateur de paquets entre deux machines virtuelles, puis observer la signature dans Statistics, ancre durablement la différence entre un flood direct et une réflexion. L'important n'est pas l'attaque elle-meme, banale, mais l'oeil qu'on entraine à lire sa forme dans la capture.
