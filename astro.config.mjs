import { defineConfig } from 'astro/config';

// https://astro.build
export default defineConfig({
  // Remplace par ton URL finale une fois deployee (ex: https://mehdikadri.vercel.app)
  site: 'https://exemple.vercel.app',
  build: {
    format: 'directory',
  },
});
