# Portfolio — Mehdi Kadri (Paoza)

Portfolio cybersecurite construit avec [Astro](https://astro.build).
Theme sombre, accent vert terminal, bascule Blue Team / Red Team, blog et notes
filtrables, page dediee aux requetes SPL.

---

## 1. Lancer le site sur ta machine

Tu as besoin de [Node.js](https://nodejs.org) version 18 ou plus.

```bash
# une seule fois, pour installer les dependances
npm install

# lance le site en local (rechargement automatique)
npm run dev
```

Ouvre ensuite l'adresse affichee dans le terminal (en general
`http://localhost:4321`). Le site se met a jour tout seul a chaque modification.

Pour verifier la version finale telle qu'elle sera publiee :

```bash
npm run build      # fabrique le site dans le dossier dist/
npm run preview    # le sert comme en production
```

---

## 2. Modifier tes informations

Tout ce qui est "grave" dans le site se modifie a un seul endroit :

**`src/consts.ts`** — ton nom, ton titre, ton pitch, tes liens, ton email,
le chemin de ton CV, et tes certifications (avec leur statut).

Pour le CV : depose ton PDF dans `public/cv/`, puis verifie que son nom
correspond a la valeur `cv` dans `src/consts.ts`. Pense a retirer adresse
postale et telephone de la version publique. Pour masquer le bouton CV tant
que le fichier n'est pas pret, mets `cv: ''` (vide).

---

## 3. Ajouter un projet ou un article

Tout le contenu vivant est en markdown. Pas besoin de toucher au code.

### Un projet

Cree un fichier dans `src/content/projets/`, par exemple `mon-projet.md` :

```md
---
title: "Nom du projet"
date: 2026-06-08
side: "blue"          # "blue" (defensif) ou "red" (offensif)
tags: ["Splunk", "DFIR"]
summary: "Une phrase d'accroche affichee dans la carte."
draft: false           # true = cache l'entree sans la supprimer
---

Ici le contenu complet en markdown.
```

Pour un projet qui pointe vers un lien externe (repo, write-up, PDF) au lieu
d'une page interne, ajoute dans le frontmatter :

```md
externalUrl: "https://github.com/paoza33/mon-repo"
```

### Un article / une note

Meme principe, dans `src/content/blog/`. Pour signaler une mise a jour,
ajoute une ligne `updated: 2026-06-20` : le site affichera "mis a jour le...".

### Une requete SPL vitrine

La page des requetes se modifie dans **`src/data/spl.ts`** (un tableau a
completer). Tes 150+ requetes completes restent sur GitHub, le bouton de la
page pointe vers le depot indique par `SPL_REPO` dans `src/consts.ts`.

### Les images

Depose-les dans `public/images/`, puis dans le markdown :

```md
![Texte alternatif](/images/mon-image.png)
```

> Attention au frontmatter : `side` doit valoir exactement `"blue"` ou `"red"`,
> et la date doit etre au format `AAAA-MM-JJ`. Une erreur ici fait echouer la
> construction avec un message explicite. Copie un fichier temoin existant pour
> partir sur une base correcte.

---

## 4. Mettre en ligne (GitHub + Vercel)

Une seule fois :

1. Cree un nouveau depot sur GitHub (par exemple `portfolio`).
2. Depuis ce dossier :

```bash
git init
git add .
git commit -m "Premiere version du portfolio"
git branch -M main
git remote add origin https://github.com/paoza33/portfolio.git
git push -u origin main
```

3. Va sur [vercel.com](https://vercel.com), connecte ton compte GitHub,
   importe le depot `portfolio`. Vercel detecte Astro tout seul, aucune
   configuration n'est necessaire. Valide : ton site est en ligne.

Ensuite, le cycle de mise a jour est simple : tu ajoutes ou modifies un
fichier markdown, puis :

```bash
git add .
git commit -m "Ajout d'un projet"
git push
```

Vercel reconstruit et republie automatiquement en une minute ou deux.

> Pense a mettre a jour le champ `site` dans `astro.config.mjs` avec l'URL
> finale que Vercel t'attribue.

---

## Structure du projet

```
src/
  consts.ts              -> TES infos (nom, liens, certifs)
  data/spl.ts            -> tes requetes SPL vitrines
  content/
    projets/             -> un fichier .md par projet
    blog/                -> un fichier .md par article/note
    config.ts            -> schema des metadonnees (ne pas casser)
  components/            -> briques visuelles (hero, cartes, bascule...)
  pages/                 -> pages du site (accueil, spl, details)
  layouts/               -> gabarit commun
  styles/global.css      -> theme (couleurs, polices)
public/
  cv/                    -> depose ton CV ici
  images/                -> depose tes images ici
  favicon.svg
```
