---
title: "Wireshark, TShark et la boîte à outils de l'analyste réseau"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "tshark", "tcpdump", "networkminer"]
summary: "Quatre outils pour lire le trafic réseau, et surtout savoir lequel sortir à quel moment. De la capture propre au tri par statistiques, jusqu'à l'extraction d'artefacts, l'approche d'un analyste plutôt qu'une liste de commandes."
draft: false
---

Ouvrir un pcap de plusieurs dizaines de milliers de paquets et scroller paquet par paquet, c'est la meilleure façon de perdre une heure pour rien. L'analyse réseau efficace tient moins à connaître toutes les options qu'à savoir quel outil sortir, dans quel ordre, et par où entrer dans la capture. Cet article regroupe les quatre outils que j'utilise (Wireshark, TShark, tcpdump, NetworkMiner) et la logique qui décide lequel employer.

## Quatre outils, quatre usages

Ils se recoupent en partie, mais chacun a un terrain de prédilection.

| Outil | Type | Quand le sortir |
| --- | --- | --- |
| Wireshark | GUI | Analyse interactive, exploration fine, suivi de flux, inspection d'un paquet précis |
| TShark | CLI | Capture sur un serveur sans interface, automatisation, extraction de champs en masse, statistiques scriptables |
| tcpdump | CLI | Capture rapide et légère sur n'importe quelle machine Unix, là où Wireshark n'est pas installé |
| NetworkMiner | GUI forensic | Vue centrée sur les hotes, extraction automatique de fichiers, images et identifiants |

La règle mentale : on capture souvent en CLI (tcpdump ou TShark sur la cible), on analyse en GUI (Wireshark), et on extrait les artefacts avec NetworkMiner quand l'objectif est de reconstruire ce qui a transité plutot que d'inspecter les paquets.

## Capturer proprement

Avant de filtrer, il faut une capture exploitable. Le premier réflexe est de lister les interfaces disponibles, parce que capturer sur la mauvaise donne un fichier vide.

```text
tshark -D                # liste les interfaces
tshark -i eth0 -w capture.pcapng     # capture sur eth0 vers un fichier
tshark -i eth0 -c 100    # s'arrête après 100 paquets
tshark -i eth0 -a duration:60   # s'arrête après 60 secondes
```

Sur un serveur ou une machine sans interface graphique, tcpdump fait le même travail en plus léger :

```text
tcpdump -i eth0 -w capture.pcap        # écrit la capture
tcpdump -i eth0 host 192.168.1.10      # ne capture que ce qui touche cet hote
tcpdump -i eth0 port 53                 # ne capture que le DNS
```

Le point important ici, ce sont les **filtres de capture** (syntaxe BPF). Ils décident de ce qui entre dans le fichier, et tout ce qui est exclu à la capture est perdu pour toujours. On les garde donc larges quand on enquête, pour ne pas amputer la preuve.

| Filtre de capture (BPF) | Effet |
| --- | --- |
| `host 192.168.1.10` | Tout le trafic de cet hote |
| `net 192.168.1.0/24` | Tout un sous-réseau |
| `port 80` | Un port précis |
| `tcp port 443` | Un protocole et un port |
| `src host 10.0.0.5` | Seulement la source |

## Filtrer pour analyser

Une fois le pcap ouvert dans Wireshark, on bascule sur les **filtres d'affichage**, qui sont une syntaxe différente des filtres de capture et ne suppriment rien : ils masquent temporairement, donc on peut affiner et revenir en arrière sans perdre de données. Confondre les deux est l'erreur classique du débutant. Filtre de capture pour décider quoi enregistrer, filtre d'affichage pour décider quoi regarder.

| Filtre d'affichage | Usage |
| --- | --- |
| `ip.addr == 192.168.1.10` | Trafic vers ou depuis cet hote |
| `http` | Tout le HTTP (non chiffré, donc lisible) |
| `http.request.method == "POST"` | Les requetes POST, souvent là où ça se passe |
| `dns` | Les requetes DNS, utiles pour repérer un tunneling |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Les SYN seuls, signature d'un scan de ports |
| `tcp.port == 4444` | Un port suspect (ici un classique de reverse shell) |
| `frame contains "password"` | Recherche d'une chaine dans les paquets |

## Lire un pcap vite : commencer par les statistiques

Le réflexe qui fait gagner le plus de temps n'est pas un filtre, c'est le menu Statistics de Wireshark. Plutot que de plonger dans les paquets, on prend d'abord la forme générale du trafic.

La **hiérarchie des protocoles** (Statistics, Protocol Hierarchy) montre la répartition par protocole. Un volume DNS anormalement élevé saute aux yeux, et c'est souvent le premier indice d'un tunneling ou d'une exfiltration.

Les **conversations** et **endpoints** (Statistics, Conversations) classent le trafic par couple d'hotes et par volume. L'attaquant ou la machine la plus bavarde ressort immédiatement en triant par octets ou par paquets.

L'**Expert Information** (Statistics, Expert Information) remonte les anomalies repérées par Wireshark, retransmissions, resets, erreurs, ce qui oriente vers les zones intéressantes.

En CLI, TShark expose les memes statistiques, ce qui permet de les scripter :

```text
tshark -r capture.pcap -z io,phs -q          # hiérarchie des protocoles
tshark -r capture.pcap -z conv,tcp -q        # conversations TCP
tshark -r capture.pcap -z endpoints,ip -q    # endpoints IP
```

## TShark pour extraire en masse

Là où TShark devient irremplaçable, c'est pour sortir un champ précis sur l'ensemble d'une capture, par exemple lister tous les noms de domaine interrogés afin de repérer ceux qui n'ont rien à faire là :

```text
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
```

Le `-Y` applique un filtre d'affichage, `-T fields` demande une sortie en champs bruts, et `-e` choisit le champ. On enchaine ensuite avec les outils Unix habituels (sort, uniq, grep) pour traiter le résultat. C'est cette combinaison qui transforme une capture en données analysables.

## NetworkMiner : reconstruire plutot qu'inspecter

NetworkMiner répond à une autre question. Wireshark montre les paquets, NetworkMiner montre ce qu'ils transportaient. Il adopte une vue centrée sur les hotes et reconstruit automatiquement les artefacts d'une capture : fichiers transférés, images, identifiants en clair, sessions. Quand l'objectif est de répondre à « quel fichier a été téléchargé » ou « quelles credentials ont circulé », il fait en deux clics ce qui prendrait plusieurs manipulations dans Wireshark. À noter, il préfère le format pcap au pcapng, une conversion préalable est parfois nécessaire.

## Quelques réflexes d'analyste

Au fil des captures, ce sont surtout des habitudes qui font la différence. Suivre un flux complet avec Follow TCP Stream reconstitue une conversation entière, requete et réponse, bien plus parlant que les paquets isolés. L'option Export Objects (File, Export Objects, HTTP) sort directement les fichiers transférés en HTTP, ce qui permet de récupérer un binaire pour l'analyser ensuite. Et désactiver la résolution de noms évite que Wireshark génère lui-meme du trafic DNS et brouille l'analyse.

## Pour s'entrainer

La théorie ne remplace pas un vrai pcap. Les Sherlocks réseau de Hack The Box sont un excellent terrain : Noxious fait analyser un poisoning LLMNR au niveau débutant, Litter porte sur de l'exfiltration par tunneling DNS, Compromised reconstitue une infection Pikabot, et Meerkat combine justement Wireshark, NetworkMiner et un IDS sur une meme capture. De bons candidats à transformer en write-ups Blue par la suite, dans la continuité de cet article.