// =============================================================
//  CONFIGURATION DU SITE
//  C'est le SEUL fichier à modifier pour mon identite, les
//  liens et les certifications. Pas besoin de toucher au reste.
// =============================================================

export const SITE = {
  // Affiche dans l'onglet du navigateur et le pied de page
  title: 'Mehdi Kadri (Paoza)',
  description: 'Portfolio cybersecurite : analyste SOC & pentester',
};

export const IDENTITE = {
  prenom: 'Mehdi',
  nom: 'Kadri',
  pseudo: 'Paoza',
  // Titre affiche sous le nom dans le hero
  titre: 'Analyste SOC & Pentester',
  // Le pitch : mon paragraphe de presentation.
  // Tu peux le modifier librement ici.
  pitch: `Ancien développeur gameplay, je me suis reconverti vers la cybersécurité, domaine qui m'a toujours attiré. Je me forme aujourd'hui sur la détection, l'investigation numérique et la simulation de tests d'intrusion. Mon objectif est de construire une approche Blue Team et Red Team complémentaire, pour mieux comprendre et anticiper les menaces réelles. Je vise un premier poste d'analyste SOC ou administrateur système, où mon approche offensive et défensive peut faire la différence au quotidien.`,
};

// Les liens du hero. Mettre à jour les URL si besoin.
// Pour cacher un lien, mettre en commentaire ou supprimer la ligne.
export const LIENS = {
  github: 'https://github.com/paoza33',
  linkedin: 'https://www.linkedin.com/in/mehdikadri/',
  hackthebox: 'https://profile.hackthebox.com/profile/019cc3d9-6b6d-72ce-b62e-84c7ed31a48e',
  // Adresse utilisee par le bouton "Me contacter" (mailto, jamais affichee en clair)
  email: 'mehdi.kadripro@outlook.fr',
  // Le CV : depose ton fichier dans public/cv/ et mets son nom ici.
  // Laisse '' (vide) pour masquer le bouton CV tant que le fichier n'est pas pret.
  cv: '/cv/CV-Mehdi-Kadri.pdf',
};

// Lien vers le depot GitHub qui contient tes 150+ requetes SPL
export const SPL_REPO = 'https://github.com/paoza33/Cyber/blob/main/blue_team/splunk/spl_queries.md';

// Mes certifications.
// statut : 'obtenu' | 'en-cours' | 'planifie'
export const CERTIFS = [
  {
    sigle: 'CJCA',
    nom: 'Certified Junior Cybersecurity Associate (HTB)',
    statut: 'obtenu',
    preuve: '/images/cjca.png',
  },
  {
    sigle: 'AIS',
    nom: 'Administrateur d\'Infrastructures Securisees (RNCP 37680)',
    statut: 'en-cours',
    note: 'en cours de validation',
  },
  {
    sigle: 'CDSA',
    nom: 'Certified Defensive Security Analyst (HTB)',
    statut: 'planifie',
  },
  {
    sigle: 'CPTS',
    nom: 'Certified Penetration Testing Specialist (HTB)',
    statut: 'planifie',
  },
];
