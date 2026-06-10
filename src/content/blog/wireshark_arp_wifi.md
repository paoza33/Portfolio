---
title: "Repérer les attaques ARP et Wi-Fi dans Wireshark"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "arp", "802.11", "détection"]
summary: "Les couches basses sont un angle mort de la supervision réseau. Pourtant un MitM ARP ou une déauthentification Wi-Fi se lisent clairement dans Wireshark, à condition de savoir quel filtre poser et quel indice chercher."
draft: false
---

La plupart des règles de détection vivent dans les couches hautes : HTTP, DNS, TLS. Les couches basses, elles, passent souvent sous le radar. C'est dommage, parce qu'un attaquant qui s'installe en homme du milieu au niveau 2 ouvre la porte à toute l'exfiltration qui suivra plus haut. Cet article se concentre sur deux familles, les attaques ARP et les attaques Wi-Fi 802.11, et sur la façon de les repérer dans Wireshark. D'autres vecteurs feront l'objet d'articles séparés.

## ARP, un protocole sans défense

ARP sert à retrouver l'adresse MAC associée à une IP sur le réseau local. Le fonctionnement est minimal : une requete en broadcast demande « qui a cette IP », une réponse en unicast annonce « c'est moi, voici mon MAC », et le résultat est mis en cache. Le problème tient en une phrase : ARP n'authentifie rien. N'importe qui peut répondre n'importe quoi, et le cache de la victime le croira. C'est tout ce dont un attaquant a besoin.

## ARP spoofing : le MitM de couche 2

L'attaquant envoie de faux messages ARP pour corrompre les caches. Il dit à la victime que le routeur a son MAC, il dit au routeur que la victime a son MAC, et désormais tout le trafic transite par lui. S'il relaie, c'est un homme du milieu discret, souvent combiné à du DNS spoofing ou du SSL stripping. S'il ne relaie pas, c'est un déni de service.

Côté Wireshark, on entre par les opcodes ARP et on cherche les incohérences :

```text
arp.opcode == 2                                     # toutes les réponses ARP
arp.duplicate-address-detected && arp.opcode == 2   # doublons d'adresse confirmés
```

Les indices qui trahissent un empoisonnement :

- une meme IP associée à deux MAC différents dans les échanges,
- un hote qui émet en boucle des réponses ARP non sollicitées (gratuitous ARP),
- des connexions TCP qui tombent à répétition, signe que l'attaquant capte le trafic sans le relayer,
- un MAC suspect qui portait une autre IP plus tot dans la capture.

Pour cibler l'activité d'un MAC précis une fois repéré :

```text
(arp.opcode) && ((eth.src == AA:AA:AA:AA:AA:AA) || (eth.dst == AA:AA:AA:AA:AA:AA))
```

Et pour vérifier le cache local de la machine analysée :

```bash
arp -a
```

## ARP scanning : la reconnaissance avant l'attaque

Avant d'empoisonner, l'attaquant cartographie. ARP se prete très bien à la reconnaissance : on envoie des requetes en masse pour lister les hotes actifs. La signature est nette, et un simple `arp.opcode` suffit à la faire ressortir :

- des requetes broadcast vers des IP séquentielles, .1 puis .2 puis .3,
- des requetes vers des hotes inexistants qui ne répondront jamais,
- un volume de trafic ARP anormalement élevé depuis un seul hote.

Un hote qui interroge tout le sous-réseau en séquence n'explore pas, il scanne. Les machines qui répondent lui donnent sa liste de cibles. C'est le comportement typique d'un outil comme Nmap en phase de découverte.

## ARP en déni de service

Une fois la liste des hotes obtenue, le poisoning peut servir à couper le réseau plutot qu'à l'écouter. L'attaquant empoisonne le cache du routeur et celui des clients avec de faux MAC pour les IP actives, et le trafic se retrouve aiguillé dans le vide. L'indice caractéristique est l'IP du routeur qui apparait dupliquée sur plusieurs machines clientes en meme temps.

La réponse tient en deux temps. D'abord tracer la machine émettrice pour la localiser physiquement, en gardant en tete qu'elle est peut-etre elle-meme compromise et pilotée à distance. Ensuite contenir, en isolant la zone touchée au niveau du switch ou du routeur pour stopper l'attaque à la source. Les attaques de couche 2 sont silencieuses, mais les détecter coupe l'herbe sous le pied de toute exfiltration ultérieure.

## Passer au Wi-Fi : le monitor mode

Le 802.11 demande un préalable. Pour voir les trames Wi-Fi brutes, et notamment les trames de gestion, il faut une interface en monitor mode, l'équivalent sans fil du mode promiscuous, qui capture tout ce qui circule sans filtrer ce qui n'est pas destiné à la carte.

```bash
sudo airmon-ng start wlan0
# ou manuellement
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
iwconfig    # doit afficher Mode:Monitor
```

On peut ensuite cibler la capture sur un point d'accès précis, par son canal et son BSSID, avec airodump-ng.

## La déauthentification : DoS et vol de handshake

L'attaque Wi-Fi la plus courante usurpe le MAC du point d'accès légitime pour envoyer de fausses trames de déauthentification. La victime est éjectée, se reconnecte, et l'attaquant en profite soit pour faire du déni de service en boucle, soit pour capturer le handshake WPA lors de la reconnexion afin de le casser hors ligne, soit pour forcer la victime à rejoindre un faux point d'accès.

Pour lire ça dans Wireshark, on raisonne en types et sous-types de trames 802.11. Les trames de gestion sont de type 0, et la déauthentification est le sous-type 12 :

```text
wlan.fc.type == 0 && wlan.fc.type_subtype == 12
```

Cela affiche toutes les déconnexions, légitimes comme malveillantes. Pour confirmer une attaque, on regarde le reason code. Les outils offensifs classiques comme aireplay-ng et mdk4 utilisent par défaut le code 7 :

```text
(wlan.bssid == F8:14:FE:4D:E6:F1) && (wlan.fc.type == 0) && (wlan.fc.type_subtype == 12) && (wlan.fixed.reason_code == 7)
```

L'indice principal reste le volume : un grand nombre de trames de déauth dirigées vers un seul client en peu de temps ne laisse aucun doute. Attention toutefois, un attaquant averti peut faire tourner les reason codes (1, 2, 3, puis 7) pour échapper aux règles d'un WIDS. Dans ce cas, c'est la rotation séquentielle elle-meme qui devient l'indice.

Petit rappel des sous-types de gestion utiles :

| type | type_subtype | Trame |
| --- | --- | --- |
| 0 | 8 | Beacon |
| 0 | 11 | Authentication |
| 0 | 0 | Association request |
| 0 | 1 | Association response |
| 0 | 12 | Deauthentication |

## L'evil-twin, suite logique de la déauth

La déauthentification sert souvent à pousser les victimes vers un faux point d'accès. Un evil-twin reprend l'ESSID du réseau légitime mais avec un BSSID différent. Le signal d'alerte est donc deux points d'accès annonçant le meme nom de réseau avec des MAC différents, et souvent des niveaux de chiffrement qui ne collent pas, l'un en WPA2, l'autre ouvert.

On compare les beacon frames des deux points d'accès :

```text
(wlan.fc.type == 0) && (wlan.fc.type_subtype == 8)    # beacons
```

La différence se voit dans les informations RSN du beacon : le point d'accès légitime annonce un RSN complet (WPA2, AES, PSK), tandis qu'un evil-twin basique n'en a pas du tout puisqu'il est ouvert. Si l'attaquant copie aussi le chiffrement, on cherche ailleurs, dans les champs vendor-specific souvent absents du faux point d'accès, ou dans le canal et les débits annoncés. Et l'indice qui confirme une victime piégée, c'est un client qui émet des requetes ARP alors qu'il est associé au faux point d'accès. On note alors son MAC et son nom d'hote pour la réponse à incident.

## Contre-mesures, en résumé

Au niveau 2, deux leviers : les entrées ARP statiques, qui empechent la réécriture du cache mais coutent cher en maintenance, et le port security sur le switch, qui n'autorise que les appareils connus par port. Côté Wi-Fi, activer la protection des trames de gestion (IEEE 802.11w) authentifie les trames de déauth et coupe l'attaque à la racine, et WPA3-SAE est plus résistant par conception. Dans tous les cas, adapter les règles du WIDS/WIPS au volume et aux patterns décrits plus haut.

## Aide-mémoire des filtres

```text
# ARP
arp.opcode == 1                                    # requêtes
arp.opcode == 2                                    # réponses
arp.duplicate-address-detected && arp.opcode == 2  # doublon d'adresse

# 802.11
wlan.bssid == AA:AA:AA:AA:AA:AA
wlan.fc.type == 0 && wlan.fc.type_subtype == 8     # beacons
wlan.fc.type == 0 && wlan.fc.type_subtype == 12    # déauthentification
wlan.fixed.reason_code == 7                         # signature aireplay-ng / mdk4
```

## Pour s'entrainer

La détection de poisoning sur les couches basses se travaille bien sur le Sherlock Noxious de Hack The Box, qui fait analyser un empoisonnement LLMNR dans une capture, au niveau débutant. Le mécanisme est cousin de l'ARP poisoning, une réponse de résolution de nom forgée pour se faire passer pour quelqu'un d'autre, et l'approche Wireshark est la meme : repérer l'incohérence, puis remonter à la machine qui ment. Un bon candidat pour un futur write-up Blue.