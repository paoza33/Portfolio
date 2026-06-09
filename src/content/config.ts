import { defineCollection, z } from 'astro:content';

// Schema commun aux projets et aux articles.
// Le "side" range l'entree du cote Blue ou Red pour la bascule.
const baseSchema = z.object({
  title: z.string(),
  date: z.coerce.date(),
  // date de derniere mise a jour (optionnel) -> affiche "mis a jour le..."
  updated: z.coerce.date().optional(),
  side: z.enum(['blue', 'red']),
  tags: z.array(z.string()).default([]),
  summary: z.string(),
  // pour un projet qui pointe vers un lien externe (repo, write-up, PDF)
  // plutot que vers une page de detail interne. Laisse vide pour une page interne.
  externalUrl: z.string().url().optional(),
  // mettre a true pour cacher une entree sans la supprimer
  draft: z.boolean().default(false),
});

const projets = defineCollection({
  type: 'content',
  schema: baseSchema,
});

const blog = defineCollection({
  type: 'content',
  schema: baseSchema,
});

const writeups = defineCollection({
  type: 'content',
  schema: baseSchema,
});

export const collections = { projets, blog, writeups };