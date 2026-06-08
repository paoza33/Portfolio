// =============================================================
//  REQUETES SPL VITRINES
//  Edite ce fichier pour ajouter/retirer une requete mise en avant.
//  Chaque entree : un nom, une categorie, un ou des tags MITRE,
//  la requete elle-meme, et une explication.
//  (Tes 150+ requetes completes restent sur GitHub, lien plus bas.)
// =============================================================

export interface RequeteSPL {
  nom: string;
  categorie: 'Detection' | 'Investigation' | 'Threat Hunting' | 'Correlation';
  mitre?: string[]; // ex: ['T1059.001']
  description: string; // ce que la requete detecte / le raisonnement
  requete: string; // la requete SPL
}

export const REQUETES: RequeteSPL[] = [
  {
    nom: 'PowerShell encode (commande obfusquee)',
    categorie: 'Detection',
    mitre: ['T1059.001', 'T1027'],
    description:
      "Repere les executions PowerShell avec l'argument -EncodedCommand, frequemment utilise pour masquer une charge malveillante. On agrege par hote et utilisateur pour distinguer un usage isole d'une activite anormale a grande echelle.",
    requete: `index=wineventlog EventCode=4688
| search NewProcessName="*powershell.exe"
| regex CommandLine="(?i)-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+/=]{20,}"
| stats count values(CommandLine) as commandes by host, SubjectUserName
| sort - count`,
  },
  {
    nom: 'Force brute sur authentification (4625)',
    categorie: 'Detection',
    mitre: ['T1110'],
    description:
      "Detecte les rafales d'echecs d'authentification Windows (EventCode 4625) depuis une meme source. Le seuil de 10 tentatives sur une fenetre courte limite les faux positifs lies aux erreurs de saisie.",
    requete: `index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count as echecs values(TargetUserName) as comptes_vises by _time, IpAddress
| where echecs > 10
| sort - echecs`,
  },
  {
    nom: 'Creation de tache planifiee suspecte',
    categorie: 'Threat Hunting',
    mitre: ['T1053.005'],
    description:
      "Les taches planifiees sont un mecanisme de persistance courant. Cette recherche isole les creations de taches (4698) et met en avant celles dont l'auteur n'est pas un compte de service connu.",
    requete: `index=wineventlog EventCode=4698
| rex field=Message "Author:\\s+(?<auteur>[^\\r\\n]+)"
| search NOT auteur IN ("SYSTEM", "NT AUTHORITY*")
| table _time, host, SubjectUserName, auteur, TaskName
| sort - _time`,
  },
  {
    nom: 'Exfiltration potentielle (volume sortant anormal)',
    categorie: 'Correlation',
    mitre: ['T1048'],
    description:
      "Compare le volume sortant par hote a sa moyenne historique pour faire ressortir les pics inhabituels, signe possible d'exfiltration. Approche basee sur l'ecart a la ligne de base plutot que sur un seuil fixe.",
    requete: `index=firewall action=allowed direction=outbound
| stats sum(bytes_out) as total_out by src_ip, date_hour
| eventstats avg(total_out) as moyenne, stdev(total_out) as ecart by src_ip
| where total_out > (moyenne + 3 * ecart)
| sort - total_out`,
  },
  {
    nom: 'Effacement du journal de securite (1102)',
    categorie: 'Investigation',
    mitre: ['T1070.001'],
    description:
      "L'effacement du journal de securite est un indicateur fort d'anti-forensique. Cette recherche remonte chaque occurrence avec le compte responsable, a correler avec l'activite precedant l'effacement.",
    requete: `index=wineventlog EventCode=1102
| table _time, host, SubjectUserName, SubjectDomainName
| sort - _time`,
  },
];
