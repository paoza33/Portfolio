---
title: "Détecter le tunneling et l'exfiltration dans Wireshark"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "tunneling", "exfiltration", "c2", "dns"]
summary: "ICMP et DNS sont rarement bloqués en sortie, ce qui en fait des canaux d'exfiltration et de C2 idéaux. Le fil rouge pour les démasquer : un champ censé être minuscule qui transporte soudain beaucoup de données."
draft: false
---

Quand un attaquant veut faire sortir des données sans déclencher d'alerte, il n'ouvre pas un nouveau port que le pare-feu bloquerait. Il se sert d'un protocole déjà autorisé et y cache sa charge. C'est le principe du tunneling : encapsuler des données à exfiltrer dans du trafic qui a le droit de circuler, ICMP, DNS, parfois Telnet ou UDP. ICMP et DNS sont particulièrement prisés parce qu'ils sont presque toujours permis en sortie. La bonne nouvelle pour le défenseur, c'est qu'un fil rouge unique permet de les repérer tous : un champ prévu pour transporter peu de données se met soudain à en transporter beaucoup, souvent encodées. Cet article clot la montée dans la pile entamée avec les attaques ARP, Wi-Fi et les scans.

## ICMP tunneling

Un paquet ICMP possède un champ data, normalement rempli de bourrage sans intérêt. L'attaquant y glisse ses données, et le trafic se fond dans les pings légitimes. Pour le repérer, on affiche l'ICMP puis on regarde la taille et le contenu de ce champ.

```text
icmp
```

Les indices qui doivent alerter :

- un champ data anormalement grand, de l'ordre de plusieurs milliers d'octets là où un ping normal en transporte une cinquantaine,
- de la fragmentation sur du trafic ICMP, signe d'un gros volume découpé,
- du contenu lisible directement dans le champ data, identifiants ou texte clair,
- des données manifestement encodées, en base64 par exemple.

Quand on tombe sur de l'encodage, on le sort de Wireshark et on le décode :

```bash
echo 'VGhpcyBpcyBhIHRlc3Q=' | base64 -d
```

Côté défense, la mesure radicale est de bloquer ICMP s'il n'est pas nécessaire. Sinon, on inspecte le champ data en profondeur et on alerte au-delà d'un seuil de taille raisonnable, autour de 48 octets.

## Ne pas confondre tunnel et flood

Avant d'aller plus loin, une distinction qui évite les fausses pistes. Sur ICMP, trois comportements n'ont rien à voir même s'ils manipulent le même protocole.

| | Flooding | Tunneling | SMURF |
| --- | --- | --- | --- |
| Objectif | Déni de service | Exfiltration ou C2 | Déni de service distribué |
| Principe | Noyer la cible sous les pings | Cacher des données dans le champ data | Pings à IP source usurpée vers plein d'hotes |
| Indice clé | Volume massif depuis un hote | Champ data trop grand, encodé | Masse de réponses convergeant vers une victime |
| Discrétion | Faible | Élevée | Moyenne |

Autrement dit, un flood est bruyant et vise la disponibilité, un tunnel est discret et vise la confidentialité. Crier au tunnel devant un simple flood fait perdre du temps, l'indice qui tranche est la taille et l'encodage du champ data, pas le volume.

## DNS tunneling, le canal préféré du C2

Le DNS applique exactement la même logique, et c'est de loin le tunnel le plus répandu pour le command and control. Les données sont cachées dans les champs des requetes, le plus souvent dans des enregistrements TXT ou dans des sous-domaines fabriqués. On part du trafic DNS :

```text
dns
```

Les indices d'un tunnel DNS :

- de nombreux enregistrements TXT venant d'un seul hote,
- un champ TXT long, encodé ou illisible,
- des requetes vers des sous-domaines bizarres et changeants,
- les données visibles dans le hex dump en bas de Wireshark.

Le décodage suit le même réflexe, parfois en plusieurs couches :

```bash
echo '<valeur>' | base64 -d
echo '<valeur>' | base64 -d | base64 -d    # encodage multiple
```

Ce canal sert à l'exfiltration discrète, au C2 de botnets et de malwares, et au contournement de pare-feu puisque le DNS est presque toujours autorisé en sortie. À surveiller aussi, les algorithmes de génération de domaines (DGA), qui produisent à la volée des noms de domaine changeants pour le C2, et les requetes vers des URI de type cloudflare-ipfs.com/ipfs/, utilisées par des acteurs avancés pour héberger des fichiers malveillants sur un réseau P2P difficile à bloquer.

Là encore, ne pas confondre. Un flood DNS sature un serveur, une amplification se sert d'une requete ANY à source usurpée pour matraquer une victime tierce, et un tunnel se contente de faire sortir des données en silence. C'est le troisième qui doit retenir l'attention en chasse à l'exfiltration.

## Telnet et UDP, des canaux qu'on oublie

Telnet est en clair, donc tout son contenu se lit directement dans Wireshark. Légitime sur de vieux systèmes, il devient suspect dans trois cas : sur le port 23 vers des hotes inconnus, sur un port non standard comme 9999, ou en IPv6 sur un réseau censé être uniquement IPv4. Le réflexe est de suivre le flux pour lire l'échange.

```text
((ipv6.src_host == fe80::1234) or (ipv6.dst_host == fe80::1234)) and telnet
```

UDP mérite aussi un oeil. Sans connexion donc sans poignée de main, il est rapide et moins surveillé, ce qui le rend attractif pour l'exfiltration. On inspecte son contenu avec Follow UDP Stream. Attention toutefois à ne pas confondre avec le trafic UDP légitime courant : DNS, DHCP, SNMP, TFTP, streaming et jeux en ligne en génèrent beaucoup.

## Le réflexe commun

Quel que soit le protocole, la démarche est la même. On suit le flux complet avec Follow Stream pour reconstituer l'échange, on inspecte le hex dump quand le contenu n'est pas lisible tel quel, et on décode ce qui ressemble à du base64. Surtout, on garde en tete le fil rouge : un protocole qui transporte beaucoup plus de données qu'il ne le devrait est l'anomalie à traquer. Côté prévention, des seuils de taille sur ICMP et DNS, et une inspection en profondeur des champs concernés, font tomber la plupart de ces tunnels.

## Aide-mémoire des canaux

| Protocole | Où se cache la donnée | Filtre de départ |
| --- | --- | --- |
| ICMP | Champ data | `icmp` |
| DNS | Enregistrements TXT, sous-domaines | `dns` |
| Telnet | Flux en clair, port ou version inhabituels | `telnet` |
| UDP | Flux applicatif hors usage légitime | `udp` |

## Pour s'entrainer

Le Sherlock Litter de Hack The Box est taillé pour ce sujet : il fait analyser une exfiltration par tunneling DNS dans une capture, avec du décodage à la clé. Le Sherlock Compromised va dans le même sens, une infection dont le malware établit un tunnel DNS pour son C2. Deux bons terrains pour pratiquer le réflexe décrit ici, et deux candidats à transformer en write-ups Blue dans la continuité de cette série.