---
title: "Détecter les scans de ports et leurs évasions dans Wireshark"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "port-scanning", "nmap", "détection"]
summary: "Le scan de ports est la première manoeuvre de presque toute intrusion. Reconnaître ses signatures dans Wireshark, et surtout repérer les déguisements (fragmentation, TTL bas, leurre), c'est attraper l'attaquant avant l'exploitation."
draft: false
---

Avant d'exploiter quoi que ce soit, un attaquant regarde. Le scan de ports est sa première manoeuvre, celle qui lui dit quelles portes existent et lesquelles sont ouvertes. C'est aussi une excellente occasion de le détecter tot, à condition de reconnaître ses signatures et de ne pas se laisser berner par les techniques qui servent à les masquer. Cet article prolonge la série analyse réseau en montant dans la pile, après les attaques ARP et Wi-Fi, vers les couches IP et TCP.

## Le handshake normal comme référence

Tout repose sur une comparaison simple. Une connexion TCP légitime suit toujours le meme rythme : `SYN`, puis `SYN/ACK`, puis `ACK`. C'est la poignée de main en trois temps. Tout écart à ce schéma est, par construction, anormal. Les scanners vivent précisément dans ces écarts, parce qu'ils n'ont pas besoin d'établir une vraie connexion pour savoir si un port répond.

## Les types de scans et leurs signatures

Chaque variante de scan joue avec les flags TCP pour interroger un port sans aller au bout du handshake. La réponse, ou l'absence de réponse, révèle l'état du port.

| Scan | Flags envoyés | Port ouvert | Port fermé | Indice |
| --- | --- | --- | --- | --- |
| SYN | SYN | SYN/ACK puis RST de l'attaquant | RST | Flood de SYN depuis un hote |
| NULL | aucun | Pas de réponse | RST | Paquets TCP sans aucun flag |
| FIN | FIN | Pas de réponse | RST | FIN hors connexion établie |
| Xmas | FIN + PSH + URG | Pas de réponse | RST | Tous ces flags allumés ensemble |
| ACK | ACK | Pas de réponse ou RST | RST | Flood d'ACK sans SYN préalable |

Le SYN scan est le plus courant : l'attaquant envoie un SYN, reçoit un SYN/ACK si le port est ouvert, puis coupe avec un RST sans jamais finir la connexion. Les scans NULL, FIN et Xmas exploitent une subtilité de la pile TCP, un port fermé répond RST quand un port ouvert ignore le paquet, ce qui permet de cartographier en restant discret. Le ACK scan, lui, sert surtout à sonder les règles d'un pare-feu.

Au-delà des signatures individuelles, deux indices généraux trahissent un scan : un meme hote qui envoie le meme flag en masse vers de nombreux ports, et des combinaisons de flags incohérentes avec l'état réel de la connexion. Le pattern à graver est « un hote vers beaucoup de ports », ou « un hote vers beaucoup d'hotes ».

## Évasion par fragmentation

Un attaquant sait que ses paquets seront inspectés, alors il les découpe. La fragmentation IP est légitime au départ, un gros paquet se scinde selon le MTU et se réassemble à destination. Détournée, elle sert à passer sous le nez d'un IDS ou d'un pare-feu qui n'inspecte pas les fragments réassemblés. Un MTU minuscule, de l'ordre de 10 à 20 octets, multiplie les fragments au point que certains contrôles renoncent à tout reconstituer.

Les indices à chercher sont un grand nombre de fragments IP venant d'un meme hote, combinés au pattern de scan habituel, un hote qui sonde de nombreux ports avec des RST en retour sur les ports fermés. Réflexe Wireshark indispensable ici : s'assurer que le réassemblage est actif, dans Preferences puis Protocols puis IPv4, sinon l'analyse passe à coté du contenu reconstruit.

## Évasion par TTL bas

Autre ruse, fixer un TTL volontairement très bas. Chaque routeur décrémente le TTL de un, et quand il atteint zéro le paquet est détruit. En calant le TTL juste assez bas, l'attaquant fait mourir ses paquets après le pare-feu ou l'IDS mais avant qu'ils ne déclenchent une alerte, tout en atteignant parfois sa cible. Les routeurs qui suppriment ces paquets renvoient un message ICMP Time Exceeded vers la source.

Les indices se lisent à trois endroits : un TTL anormalement bas dans l'en-tete IPv4, des messages ICMP Time Exceeded en retour qui signalent des paquets expirés en chemin, et malgré tout des SYN/ACK revenant de ports ouverts, preuve que le scan a partiellement fonctionné. Le filtre est direct, et le champ se vérifie dans l'onglet IPv4 du paquet.

```text
ip.ttl < 10
```

La parade consiste à configurer le pare-feu pour rejeter les paquets dont le TTL passe sous un seuil raisonnable, fixé selon la topologie.

## Évasion par leurre

La technique du decoy noie le vrai scan dans une foule de fausses sources. L'attaquant émet des paquets avec des IP sources factices pour cacher la sienne. Mais il se trahit sur un détail : les RST renvoyés par les ports fermés reviennent vers sa vraie adresse, puisque c'est elle qui doit recevoir les réponses pour exploiter le scan. On cherche donc une fragmentation ou un scan venant d'IP factices, dont les réponses convergent malgré tout vers une seule IP réelle. Plus généralement, une connexion initiée par un hote mais poursuivie par un autre est un signal de leurre.

Côté défense, trois mesures se cumulent : réassembler les paquets avant inspection, repérer ces connexions à deux émetteurs, et filtrer en entrée tout paquet dont l'IP source appartient pourtant au sous-réseau interne.

## Partir des statistiques

Comme souvent en analyse réseau, le plus rapide n'est pas de filtrer à l'aveugle mais d'ouvrir Statistics puis Conversations. Un hote qui ouvre des centaines de conversations vers autant de ports différents saute aux yeux dès qu'on trie par nombre de paquets. On confirme ensuite avec les filtres de flags. Cette habitude évite de chercher une aiguille dans la botte alors que la forme du trafic désigne déjà le coupable.

## Aide-mémoire des filtres de flags

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN seuls, signature de SYN scan
tcp.flags == 0x000                          # NULL scan, aucun flag
tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1   # Xmas scan
tcp.flags.reset == 1                        # RST, réponses des ports fermés
tcp.flags.syn == 1 && tcp.flags.ack == 1    # SYN/ACK, ports ouverts
```

## Pour s'entrainer

Le Sherlock Packet Puzzle de Hack The Box : il faut y reconstituer une intrusion à partir d'une seule capture, et l'enquête commence justement par identifier le scan initial qui a repéré le port du serveur web avant l'exploitation. L'exercice fait pratiquer exactement ce raisonnement, partir d'une activité de reconnaissance dans le pcap pour remonter au point d'entrée.