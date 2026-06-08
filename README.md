# Portfolio - [Site](https://portfolio-mkadri.vercel.app/).

Portfolio cybersécurité construit avec [Astro](https://astro.build).

Ce README est exclusivement des rappels pour moi-même, aucun intérêt pour les autres.

---

## 1. Lancer le site localement

```bash
# une seule fois, pour installer les dependances
npm install

# lance le site en local (rechargement automatique)
npm run dev
```

Ouvrir à l'adresse affichee dans le terminal (en general
`http://localhost:4321`). Le site se met à jour tout seul à chaque modification.

Pour vérifier la version finale telle qu'elle sera publiée :

```bash
npm run build      # fabrique le site dans le dossier dist/
npm run preview    # le sert comme en production
```

---

## 2. Modifier mes informations

Tout ce qui est infos personnel dans le site se modifie à un seul endroit :

**`src/consts.ts`** - nom, titre, pitch, liens, email,
le chemin du CV, et mes certifications (avec leur statut).

Pour le CV : deposer mon PDF dans `public/cv/`, puis verifier que son nom
correspond a la valeur `cv` dans `src/consts.ts`. Pour masquer le bouton CV tant
que le fichier n'est pas prêt: `cv: ''` (vide).

---

## 3. Ajouter un projet ou un article

Tout le contenu vivant est en markdown. Pas besoin de toucher au code.

### Un projet

Créé un fichier dans `src/content/projets/`, par exemple `mon-projet.md` :

```md
---
title: "Nom du projet"
date: 2026-06-08
side: "blue"
tags: ["Splunk", "DFIR"]
summary: "Une phrase d'accroche affichée dans la carte."
draft: false           # true = cache l'entrée sans la supprimer
---

Ici le contenu complet en markdown.
```

Pour un projet qui pointe vers un lien externe (repo, write-up, PDF) au lieu
d'une page interne, ajouter dans le frontmatter :

```md
externalUrl: "https://github.com/paoza33/mon-repo"
```

### Un article / une note

Même principe, dans `src/content/blog/`. Pour signaler une mise a jour,
ajouter une ligne `updated: 2026-06-20` : le site affichera "mis a jour le...".

### Une requete SPL vitrine

La page des requetes se modifie dans **`src/data/spl.ts`** (un tableau à
completer). Les 150+ requêtes complètes restent sur GitHub, le bouton de la
page pointe vers le dépôt indiqué par `SPL_REPO` dans `src/consts.ts`.

### Les images

Dépose-les dans `public/images/`, puis dans le markdown :

```md
![Texte alternatif](/images/mon-image.png)
```

> Attention au frontmatter : `side` doit valoir exactement `"blue"` ou `"red"`,
> et la date doit être au format `AAAA-MM-JJ`. Une erreur ici fait échouer la
> construction avec un message explicite. Copier un fichier temoin existant pour
> partir sur une base correcte.

---

## 4. MAJ (GitHub + Vercel)

Le cycle de mise à jour est simple : ajouter ou modifier un
fichier markdown, puis :

```bash
git add .
git commit -m "Ajout d'un projet"
git push
```

Vercel reconstruit et republie automatiquement en une minute ou deux.

> Penser à mettre à jour le champ `site` dans `astro.config.mjs` avec l'URL
> finale que Vercel attribue.

---

## Structure du projet

```
src/
  consts.ts              -> infos (nom, liens, certifs)
  data/spl.ts            -> requetes SPL vitrines
  content/
    projets/             -> fichier .md par projet
    blog/                -> fichier .md par article/note
    config.ts            -> schéma des métadonnees (ne pas casser)
  components/            -> briques visuelles (hero, cartes, bascule...)
  pages/                 -> pages du site (accueil, spl, details)
  layouts/               -> gabarit commun
  styles/global.css      -> thème (couleurs, polices)
public/
  cv/                    -> deposer le CV ici
  images/                -> deposer les images ici
  favicon.svg
```
