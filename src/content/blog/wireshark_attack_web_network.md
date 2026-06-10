---
title: "Repérer les attaques web dans une capture réseau"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "http", "xss", "tls", "détection"]
summary: "Les attaques web se chassent d'habitude dans les logs applicatifs, mais elles laissent des traces nettes au niveau réseau quand le trafic est en clair. Et même en HTTPS, le handshake suffit parfois à trahir l'attaque."
draft: false
---

On traque d'ordinaire les attaques web dans les logs du serveur. Pourtant elles laissent aussi des traces au niveau réseau, et parfois plus parlantes. Tant que le trafic est en HTTP, donc en clair, une capture montre tout : les requetes, les réponses, les charges injectées. Le chiffrement TLS change la donne en masquant le contenu, mais le handshake reste lisible et trahit certaines manoeuvres. Cet article, qui prolonge la série analyse réseau vers la couche applicative, montre comment repérer trois attaques web dans une capture : l'énumération HTTP, l'injection de code, et la renégociation SSL.

## Énumération et fuzzing HTTP

Avant d'exploiter une application, un attaquant cartographie ses chemins. Il envoie des requetes en masse pour deviner les répertoires et fichiers présents. En clair, ça se voit immédiatement. On part du trafic HTTP, et on peut se limiter aux requetes pour éliminer le bruit des réponses :

```text
http.request
http.request and ((ip.src_host == 192.168.10.5) or (ip.dst_host == 192.168.10.5))
```

Les indices d'un fuzzing de répertoires :

- une rafale de réponses 404, signe de requetes vers des fichiers qui n'existent pas,
- des requetes en succession très rapide depuis la meme IP,
- des chemins révélateurs tentés à la chaine, comme `/.git/HEAD`, `/.bash_history` ou `/.config`.

D'autres formes de fuzzing visent les paramètres plutot que les chemins. Une suite de requetes faisant varier une valeur numérique, `?id=1`, `?id=2`, `?id=3`, cherche une référence directe non sécurisée (IDOR). La modification d'un champ JSON, par exemple un `return=max` qui devient `return=min`, relève de la meme logique d'exploration. Pour reconstituer un échange complet, le clic droit puis Follow HTTP Stream reste l'outil de base.

Quand on dispose aussi des logs serveur, on recoupe :

```bash
cat access.log | grep "192.168.10.5"
```

Côté attaquant, deux techniques d'évasion existent, étaler les requetes dans le temps pour passer sous les seuils d'alerte, et les distribuer depuis plusieurs IP sources. Côté défense, retourner les bons codes HTTP n'aide pas le scanner, et une fois l'IP repérée on la bloque au niveau du WAF.

## Injection de code et XSS

L'injection consiste à glisser du code dans un champ de saisie, commentaire ou formulaire, pour qu'il s'exécute ailleurs. En XSS, le code injecté est du JavaScript exécuté par le navigateur des autres visiteurs, ce qui permet de voler cookies, jetons et sessions. Vu du réseau, la signature principale est claire : de nombreuses requetes HTTP partent vers un serveur inconnu, souvent avec un cookie ou un jeton glissé en paramètre. C'est la donnée volée qui transite vers l'infrastructure de l'attaquant.

```text
http
```

Les familles de charges à reconnaitre, sans entrer dans leur fabrication : un script qui lit le cookie de session et l'envoie vers une URL externe controlée par l'attaquant, ou, en injection serveur, un fragment PHP qui exécute une commande système passée en paramètre. Dans les deux cas, Follow HTTP Stream révèle le contenu, parfois encodé sur les cas plus avancés. La parade tient à l'assainissement systématique des entrées utilisateur et au principe de ne jamais interpréter une saisie comme du code. En réponse à incident, on retire la charge injectée sans délai, quitte à couper le service le temps du correctif.

## Le mur du chiffrement et la renégociation SSL

En HTTPS, le contenu disparait derrière TLS. On ne lit plus les requetes ni les charges, on raisonne sur les métadonnées et sur le handshake, qui lui reste en clair. C'est justement là qu'une attaque par renégociation SSL se repère.

Le principe : l'attaquant envoie plusieurs Client Hello pour forcer une renégociation du handshake, dans l'espoir d'obtenir une suite cryptographique plus faible, d'exploiter une faiblesse, ou simplement d'épuiser les ressources du serveur, car une renégociation coute cher. On affiche les messages de handshake, et on peut isoler les Client Hello :

```text
ssl.record.content_type == 22                              # messages de handshake
ssl.record.content_type == 22 && ssl.handshake.type == 1   # uniquement les Client Hello
```

Les indices : plusieurs Client Hello venant du meme client en peu de temps, et des messages de handshake dans le mauvais ordre, par exemple un Client Hello reçu alors qu'un handshake était déjà terminé. À garder en tete dans la meme famille, Heartbleed (CVE-2014-0160), qui exploitait le mécanisme de heartbeat de TLS.

## Le réflexe analyste

Tout se joue sur la frontière clair contre chiffré. En HTTP, Follow HTTP Stream est roi, on lit l'attaque directement et on recoupe avec les logs serveur quand on les a. En HTTPS, le contenu est hors de portée, alors on travaille sur ce qui reste visible, le rythme des requetes, les volumes, et surtout les anomalies du handshake. Savoir ce que le chiffrement laisse voir, et ce qu'il cache, évite de chercher en vain une charge qu'on ne lira jamais.

## Aide-mémoire des filtres

```text
# HTTP
http.request                       # uniquement les requêtes
http.response.code == 404          # réponses 404, rafale = fuzzing
http.request.method == "POST"      # souvent là où se logent les injections

# TLS
ssl.record.content_type == 22                            # handshake
ssl.record.content_type == 22 && ssl.handshake.type == 1 # Client Hello
```

## Pour s'entrainer

Le Sherlock Meerkat de Hack The Box est un excellent terrain : il fait enqueter sur une attaque web vue du réseau, du credential stuffing à l'exploitation d'une CVE applicative, en combinant Wireshark, NetworkMiner et un IDS sur une meme capture. C'est exactement le type d'analyse décrite ici, et un bon candidat pour un futur write-up Blue dans la continuité de la série.