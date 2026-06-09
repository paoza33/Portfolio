// =============================================================
//  REQUETES SPL VITRINES
//  Selection extraite de ma bibliotheque (repo GitHub). Chaque
//  requete est reprise telle quelle, avec son mapping MITRE ATT&CK.
//  Pour ajouter/retirer une entree : edite ce tableau.
// =============================================================

export interface RequeteSPL {
  nom: string;
  categorie: 'Detection' | 'Investigation' | 'Threat Hunting' | 'Correlation';
  mitre?: string[];
  description: string;
  requete: string;
}

export const REQUETES: RequeteSPL[] = [
  {
    nom: "Failed logons - brute force / password spraying (par IP source)",
    categorie: "Detection",
    mitre: ["T1110.003", "T1110.001"],
    description:
      "détecter une IP source qui tente beaucoup de comptes différents (signe spraying) ou un compte qui voit beaucoup d'échecs (brute force).",
    requete: `index=main source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason`,
  },
  {
    nom: "Kerberoasting - TGS sans logon explicite suivant (méthode `stats`)",
    categorie: "Detection",
    mitre: ["T1558.003"],
    description:
      "un TGS pour un service sans 4648 dans la fenêtre suivante = pas d'accès légitime au service après le ticket → roasting probable.",
    requete: `index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time
| search username!=*$
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")`,
  },
  {
    nom: "Pass-the-Hash - détection renforcée (LogonType 9 + accès LSASS)",
    categorie: "Correlation",
    mitre: ["T1550.002", "T1003.001"],
    description:
      "élimine les `runas /netonly` légitimes en exigeant un accès LSASS (Sysmon EID 10) dans la même minute.",
    requete: `index=main (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\\\Windows\\\\system32\\\\lsass.exe" SourceImage!="C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\platform\\\\*\\\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count`,
  },
  {
    nom: "Pass-the-Ticket / Golden Ticket - TGS sans TGT préalable",
    categorie: "Correlation",
    mitre: ["T1550.003", "T1558.001"],
    description:
      "un TGS (4769) sans 4768 préalable dans la fenêtre = ticket forgé/volé injecté.",
    requete: `index=main source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\\:\\:ffff\\:)?(?<src_ip_4>[0-9\\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category`,
  },
  {
    nom: "DCSync - détection minimale (Access_Mask 0x100)",
    categorie: "Detection",
    mitre: ["T1003.006"],
    description:
      "4662 sur DS avec accès \"Replicating Directory Changes\" + non-compte machine.",
    requete: `index=main EventCode=4662 Access_Mask=0x100 Account_Name!=*$`,
  },
  {
    nom: "DCShadow - ajout de SPN Global Catalog (4742)",
    categorie: "Detection",
    mitre: ["T1207"],
    description:
      "ajout d'un SPN `XX/MACHINE.corp.local` (global catalog) à un compte machine = enregistrement comme faux DC.",
    requete: `index=main EventCode=4742
| rex field=Message "(?P<gcspn>XX\\/[a-zA-Z0-9\\.\\-\\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*`,
  },
  {
    nom: "Recon AD natif - multi-commands depuis même parent (Sysmon EID 1)",
    categorie: "Threat Hunting",
    mitre: ["T1087.002"],
    description:
      "un même parent qui lance plus de 3 commandes de recon (whoami/net/nltest/ipconfig...) = signal fort de recon manuelle / scripts d'attaquant.",
    requete: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3`,
  },
  {
    nom: "Zerologon (CVE-2020-1472) - flood Netlogon RPC",
    categorie: "Detection",
    mitre: ["T1210"],
    description:
      ">100 reqs/min sur endpoint `netlogon` avec ≥2 opérations distinctes.",
    requete: `index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation=="NetrServerReqChallenge" OR operation=="NetrServerAuthenticate3" OR operation=="NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100`,
  },
  {
    nom: "PowerShell - recherche dans le contenu des scripts (4104)",
    categorie: "Detection",
    mitre: ["T1059.001"],
    description:
      "Script Block Logging logue le **contenu** des scripts PowerShell.",
    requete: `index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*<motif>*"
| table _time, ComputerName, EventCode, Message`,
  },
  {
    nom: "PowerShell encodé (CommandLine > 1000 chars)",
    categorie: "Detection",
    mitre: ["T1059.001", "T1027"],
    description:
      "heuristique simple = CommandLine PowerShell anormalement longue → Base64/obfuscation.",
    requete: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\\\powershell.exe" OR Image="*\\\\powershell_ise.exe"
| eval cmd_len = len(CommandLine)
| where cmd_len > 1000
| table _time, host, User, ParentImage, Image, CommandLine, cmd_len
| sort - cmd_len`,
  },
  {
    nom: "Scheduled task creation",
    categorie: "Detection",
    mitre: ["T1053.005"],
    description:
      ".",
    requete: `index=main source="WinEventLog:Security" EventCode IN (4698,4700,4701,4702)
| table _time, host, SubjectUserName, TaskName, TaskContent
| sort - _time`,
  },
  {
    nom: "Service installation (7045)",
    categorie: "Detection",
    mitre: ["T1543.003"],
    description:
      ".",
    requete: `index=main source="WinEventLog:System" EventCode=7045
| table _time, host, ServiceName, ImagePath, ServiceType, StartType
| sort - _time`,
  },
  {
    nom: "Registry Run keys (Sysmon EID 13)",
    categorie: "Detection",
    mitre: ["T1547.001"],
    description:
      ".",
    requete: `index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
TargetObject IN ("*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*",
                 "*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\*",
                 "*\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\*")
| table _time, host, User, Image, TargetObject, Details`,
  },
  {
    nom: "DNS queries (Sysmon EID 22) - Responder / LLMNR poisoning",
    categorie: "Detection",
    mitre: ["T1557.001"],
    description:
      "un nom DNS inexistant qui résout = Responder actif sur le LAN.",
    requete: `index=main EventCode=22
| table _time, Computer, user, Image, QueryName, QueryResults`,
  },
  {
    nom: "Event log clearing (1102)",
    categorie: "Detection",
    mitre: ["T1070.001"],
    description:
      ".",
    requete: `index=main source="WinEventLog:Security" EventCode=1102
| table _time, host, SubjectUserName, SubjectLogonId`,
  },
  {
    nom: "Process injection - détection avancée (CallTrace UNKNOWN)",
    categorie: "Threat Hunting",
    mitre: ["T1055"],
    description:
      "CallTrace contenant `UNKNOWN` = appel depuis mémoire allouée (shellcode/reflective DLL). Filtrer les faux positifs .NET.",
    requete: `index="main" CallTrace="*UNKNOWN*"
  SourceImage!="*Microsoft.NET*"
  CallTrace!=*ni.dll*
  CallTrace!=*clr.dll*
  CallTrace!=*wow64*
  SourceImage!="C:\\\\Windows\\\\Explorer.EXE"
| where SourceImage!=TargetImage
| stats count by SourceImage, TargetImage, CallTrace`,
  },
  {
    nom: "LSASS access (Sysmon EID 10) - credential dumping",
    categorie: "Detection",
    mitre: ["T1003.001"],
    description:
      "tout process accédant à `lsass.exe` est suspect. Filtrer Defender.",
    requete: `index=main EventCode=10 lsass
| stats count by SourceImage`,
  },
  {
    nom: "Exfiltration DNS - sous-domaines anormalement longs",
    categorie: "Detection",
    mitre: ["T1048.003"],
    description:
      "DNS tunneling = champ TXT / sous-domaines très longs depuis un même hôte.",
    requete: `index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day`,
  },
];