---
title: "Couper ou détourner une connexion TCP : RST forgé et hijacking"
date: 2026-06-10
side: "blue"
tags: ["analyse-réseau", "wireshark", "tcp", "hijacking", "détection"]
summary: "TCP fait confiance à l'IP source et aux numéros de séquence. Deux attaques exploitent cette confiance : le RST forgé qui coupe une connexion, le hijacking qui la vole. Les deux se lisent dans Wireshark, à condition de ne pas se fier à l'IP seule."
draft: false
---

TCP repose sur deux hypothèses de confiance : que l'IP source d'un paquet est bien celle qu'elle prétend être, et que les numéros de séquence suivent un ordre prévisible. Deux attaques exploitent précisément cette confiance. Le RST forgé coupe brutalement une connexion active, le hijacking en prend le controle. Cet article clot la partie TCP de la série analyse réseau, après les scans et le tunneling, en montrant comment repérer ces deux manipulations dans une capture.

## Le RST forgé, pour couper une connexion

Une connexion TCP se termine normalement par un échange propre. Un attaquant peut la couper de force en injectant un paquet RST fabriqué. Le mécanisme est simple : il usurpe l'IP source de la victime, met le flag RST, et vise le port que la victime utilise à cet instant. La pile TCP, voyant un RST apparemment légitime, ferme la connexion.

L'indice principal est un volume anormal de RST dirigés vers un meme port. Mais l'IP source étant usurpée, elle ne suffit pas à conclure. La vérification se fait au niveau du MAC : on compare l'adresse MAC qui émet ces RST avec celle enregistrée pour cette IP dans l'inventaire réseau. Un MAC différent trahit l'injection. Et si l'attaquant a aussi usurpé son MAC, on cherche alors des retransmissions, exactement comme pour un empoisonnement ARP.
```
tcp.flags.reset == 1
```

## Le hijacking, pour voler la connexion

Le détournement de session va plus loin que la coupure : l'attaquant ne casse pas la connexion, il s'y substitue. La manoeuvre est plus avancée. Il surveille passivement la connexion cible, prédit les numéros de séquence pour injecter ses paquets au bon endroit dans le flux, usurpe l'IP source de la victime, et bloque ou retarde les ACK de la vraie machine pour l'empecher de répondre et de rétablir l'ordre.

Ce blocage des ACK explique pourquoi le hijacking s'appuie presque toujours sur un empoisonnement ARP en couche 2 : pour intercepter et retenir les ACK, il faut déjà etre en homme du milieu. Autrement dit, détecter le hijacking et détecter l'ARP poisoning sont liés, et l'article sur les attaques ARP donne déjà la moitié des indices.

## RST contre hijacking, en un coup d'oeil

| | RST forgé | Hijacking |
| --- | --- | --- |
| Objectif | Couper la connexion | En prendre le controle |
| Technique clé | Injection de RST usurpé | Prédiction des numéros de séquence |
| Souvent combiné avec | Usurpation IP ou MAC | Empoisonnement ARP |
| Difficulté | Simple | Avancée |

## Le réflexe commun

La leçon des deux attaques tient en une phrase : ne jamais se fier à l'IP source seule. Un paquet qui prétend appartenir à une connexion mais arrive d'un MAC inattendu trahit une injection, qu'il s'agisse d'un RST ou d'un paquet de hijacking. On recoupe donc systématiquement IP et MAC, on surveille les incohérences dans les numéros de séquence et le flux d'ACK, et on garde en tete que le hijacking propre passe par un MitM ARP. Côté prévention, le chiffrement de bout en bout (TLS, SSH) rend le détournement de contenu beaucoup plus difficile, et les protections anti-spoofing comme la détection ARP vue précédemment coupent la racine de ces attaques.

## Pour s'entrainer

Je n'ai pas encore fait d'exercice en dehors de celui présenter dans le cours hack the box. Sinon on peut monter un MitM ARP avec un outil comme bettercap entre deux machines virtuelles, puis observer dans sa propre capture les RST injectés et leur effet sur les numéros de séquence. On peut également utiliser cette méthode d'entraînement pour faire de l'empoisonnement ARP comme cet article est comme une continuité (le hijacking s'appuie dessus).
