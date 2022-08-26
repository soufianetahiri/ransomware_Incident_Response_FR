# Ransomware Réponse à Incident

La démarche se base sur [NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) .
Une checklist (simple) est mise à dispo par  [rapid7](https://ss-usa.s3.amazonaws.com/c/308484380/media/19406140aa9beaad829072190465848/Ransomware%20Incident%20Checklist.pdf)

# Détecter l'attaque

L'étape de détection est celle où vous découvrez la présence du ransomware ou celle d'une compagne de ciblage en cours. Que la notification provienne d'un système/du SOC, d'un employé ou d'un message apparu sur votre écran vous demandant de payer pour décrypter vos fichiers, les premières mesures que l'organisation devrait prendre consistent à identifier le principal responsable du traitement de l'incident (l'équipe sécurité ?) et à documenter autant d'informations que possible sur l'incident.

Globalement la détection se fait suite à:

1.  Alertes EDR
2.  Remontées collaborateurs
3.  Modification inhabituelle de fichiers sur des shares / localement
4.  Consommation inhabituelles de ressources (CPU/Memoire)
5.  Alertes FW/réseaux (Navigation inhabituelle, TOR, I2P, communications C2 connus ou inconnues)
6.  Emails / Fichiers joints suspects remontés par les collaborateurs
7.  …

# Communiquer
Établissez à l'avance un protocole pour les communications "out-of-band"
![image2021-12-7_16-0-37.png](https://i.ibb.co/BstGNgM/image2021-12-7-16-0-37.png2)
(source : https://www.ssi.gouv.fr/guide/crise-dorigine-cyber-les-cles-dune-gestion-operationnelle-et-strategique/) 
# Analyser la menace

La phase d'analyse consiste à faire tout ce qui est en votre pouvoir pour identifier la portée, les origines et les modèles d'occurrence du ransomware. En d'autres termes, quelle est sa gravité, d'où vient-il et à quelle vitesse se propage-t-il ? Déterminez quels fichiers ont été cryptés et s'il existe une clé de décryptage connue.

## Identification de l'acteur / Ransomware

1.  Déterminez le type de ransomware (c.-à-d., quelle est la famille, la variante ([ref](https://www.gdatasoftware.com/blog/2019/06/31666-ransomware-identification-for-the-judicious-analyst)) ).
    1.  Trouvez un maximum de messages associés. Vérifiez :
        1.  les interfaces utilisateur graphiques du logiciel malveillant lui-même (ex: Jigsaw)
        2.  les fichiers texte ou html, parfois ouverts automatiquement après le cryptage
        3.  les fichiers image, souvent utilisés comme fond d'écran sur les systèmes infectés
        4.  pop-up après avoir essayé d'ouvrir un fichier crypté (ex: CrypVault)
        5.  messages vocaux (ex  [Cerber](https://www.bleepingcomputer.com/news/security/the-cerber-ransomware-not-only-encrypts-your-data-but-also-speaks-to-you/))
    2.  Analysez les messages à la recherche d'indices sur le type de ransomware :
        1.  le nom du ransomware
        2.  langue, structure, phrases, illustrations
        3.  adresse mail de l'acteur
        4.  format de l'identifiant de l'utilisateur
        5.  détails de la demande de rançon (par exemple, monnaie numérique, cartes-cadeaux)
        6.  adresse de paiement en cas de monnaie numérique
        7.  page d'assistance / chat
    3.  Analysez les fichiers affectés et/ou nouveaux. Vérifiez :
        1.  le schéma de renommage des fichiers cryptés, y compris l'extension (par exemple, .crypt, .cry, .locked) et le nom de base.
        2.  fichiers corrompus OU fichier cryptés
        3.  les types et les emplacements des fichiers ciblés
        4.  l'utilisateur/le groupe propriétaire des fichiers affectés
        5.  icône des fichiers cryptés
        6.  existence de listes de fichiers, de fichiers clés ou d'autres fichiers de données
    4.  Analysez les types de logiciels ou de systèmes affectés. Certaines variantes de ransomware n'affectent que certains outils (par exemple, les bases de données) ou certaines plateformes (par exemple, les produits NAS).
    5.  Chargez les indicateurs dans des services de catégorisation automatisés tels que  [Crypto Sheriff](https://www.nomoreransom.org/crypto-sheriff.php),  [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)  ou autres.

## Détermination du scope de l'incident

1.  Quels sont les systèmes concernés ?
    1.  Rechercher des indicateurs concrets de compromission (IOCs) tels que des fichiers/hashs, des processus, des connexions réseau, etc. Utiliser S1 par exemple voici quelques requêtes utiles: [https://github.com/soufianetahiri/sentinelone-queries/tree/main/queries/windows](https://github.com/soufianetahiri/sentinelone-queries/tree/main/queries/windows)) , endpoint telemetry, les journaux système, etc.
    2.  Vérifier la similitude (utilisateurs, groupes, données, outils, configuration, état des correctifs similaires) : vérifier les IAM, les outils de gestion des permissions, les services d'annuaire, etc.
    3.  Trouver le système de commande et de contrôle (C2) externe, s'il est présent, et trouver les autres systèmes qui s'y connectent : vérifier les journaux du pare-feu ou de l'IDS, les journaux du système/EDR, les journaux DNS, les journaux du flux net ou du routeur, etc.
    4.  Quelles sont les données affectées ? (par exemple, les types de fichiers ou le groupe, le logiciel affecté).
    5.  Trouver des changements anormaux dans les métadonnées des fichiers, comme des changements massifs dans les heures de création ou de modification. Vérifier les outils de recherche de métadonnées de fichiers
    6.  Trouver des changements dans des fichiers de données normalement stables ou critiques. Vérifier les outils de surveillance de l'intégrité des fichiers (Varonis?)

Il est important de déterminer le moyen de propagation utilisé par l'acteur, il existe globalement 3 moyens de propagations (ces exemples sont tirés du mode opératoire du groupe MazeRansomware):

1.  Propagation manuelle après avoir pénétré l'environnement (obtention de privilèges admin / compromission de collaborateurs / Insider...):
    
    1.  Exécuter manuellement les crypteurs sur les systèmes ciblés.
        
    2.  Déployer des crypteurs dans l'environnement à l'aide de fichiers batch/powershell (monter les partages C$, copier le crypteur et l'exécuter avec l'outil Microsoft PsExec).
        
    3.  Déployer des crypteurs avec des GPOs.
        
    4.  Déployer des crypteurs avec les outils de déploiement de logiciels existants utilisés par l'organisation.
        
2.  Propagation automatisée
    1.  Extraction de mots de passe/ tokens à partir du disque ou de la mémoire.
    2.  Relations de confiance entre les systèmes - et utilisation de méthodes telles que Windows Management Instrumentation (WMI), SMB ou PsExec pour se connecter et déployer les payloads.
    3.  Exploitation des système non à jours (par exemple, EternalBlue : ms17-010).
3.  Méthode hybride

## Évaluer l'impact (pour prioriser et motiver les troupes)

1.  Évaluer l'impact fonctionnel : impact sur l'activité / production / logistique / Prise de commande...
    1.  Combien d'argent est perdu ou en danger ?
    2.  Combien d'activités (et lesquelles) sont dégradées ou en danger ?
2.  Évaluer l'impact sur les informations : impact sur la confidentialité, l'intégrité et la disponibilité des données.
    1.  Quel est le degré de criticité des données / de l'activité ?
    2.  Les données sont-elles sensibles ? (par exemple, les secrets commerciaux)
    3.  Quel est le statut réglementaire des données (RGPD/CNIL) ?

## Trouver le vecteur d'infection

Vérifiez les tactiques saisies dans  [la tactique d'accès initial](https://attack.mitre.org/tactics/TA0001/)  de  [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0040/)  . Les spécificités et les sources de données communes incluent :

-   pièce jointe d'un courriel : vérifiez les journaux des courriels, les dispositifs et services de sécurité des courriels, les outils de découverte électronique, etc.
-   protocole de bureau à distance (RDP) non sécurisé : vérifier les résultats des analyses de vulnérabilité, les configurations des pare-feu, etc.
-   auto-propagation (ver ou virus) (vérifier la télémétrie/EDR de l'hôte, les journaux système, forensics etc.)
-   infection via des disques amovibles (ver ou virus)
-   transmission par d'autres logiciels malveillants ou outils d'attaque : élargir l'enquête pour inclure d'autres outils d'attaque ou logiciels malveillants.

# Contenir la menace

Cette étape consiste à stopper le ransomware dans son élan. Les éléments clés d'une stratégie de maitrise d'un ransomware sont probablement l'isolement des systèmes compromis, la sécurisation des données de sauvegarde, la réinitialisation des mots de passe et la suppression ou la désactivation de l'exécution des processus malveillants connus.

Les quarantaines (logiques, physiques, ou les deux) empêchent la propagation à partir des systèmes infectés et empêchent la propagation aux systèmes et données critiques. Les quarantaines doivent être complètes : elles doivent inclure l'accès au cloud/SaaS, l'SSO, l'accès aux systèmes tels que les ERPs/SAP/WH ou d'autres outils commerciaux, etc...

-   Mettre en quarantaine les systèmes infectés
-   Mettre en quarantaine les utilisateurs et les groupes affectés.
-   Mettez en quarantaine les partages de fichiers (pas seulement les partages infectés connus ; protégez également les partages non infectés).
-   Mettez en quarantaine les bases de données partagées (pas seulement les serveurs infectés connus ; protégez également les bases de données non infectées).
-   Mettez en quarantaine les sauvegardes, si elles ne sont pas déjà sécurisées.
-   Bloquer les domaines et les adresses de commande et de contrôle identifiées
-   Confirmez que la protection (AV/EDR/FW...) est à jour et activée sur tous les systèmes.
-   Confirmer que les correctifs sont déployés sur tous les systèmes (en donnant la priorité aux systèmes ciblés , systèmes d'exploitation, ciblés logiciels ciblés, etc.).
-   Déployer des signatures personnalisées dans les outils de protection en fonction des IOCs découverts
-   Segmentation des endpoints- Durcissement - FW
-   Durcissement de RDP
-   Suspendre les shares (ex • ADMIN$• C$• D$• IPC$)
-   Restreindre / Désactiver les accès admis aux partages
-   Désactiver les protocoles légacy (ex: SMBv1)
-   Restreindre / Désactiver l'utilisation de WinRM/PowerShell
-   Arrêter les mouvements latéraux en désactivant les accès distants des comptes locaux ([https://techcommunity.microsoft.com/t5/microsoft-security-baselines/blocking-remote-use-of-local-accounts/ba-p/701042](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/blocking-remote-use-of-local-accounts/ba-p/701042))
-   Réduire l'exposition des comptes privilégiés et des comptes de service - Restrictions de connexion des comptes privilégiés - Restrictions de connexion des comptes de service - Groupe de sécurité des utilisateurs protégés.
-   Appliquer Cleartext Password Protections (si c e n'est pas déjà le cas) [https://www.sikich.com/insight/easy-wins-for-active-directory-part-3/](https://www.sikich.com/insight/easy-wins-for-active-directory-part-3/)

Une bonne base de stratégie est détaillée ici [https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/wp-ransomware-protection-and-containment-strategies.pdf](https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/wp-ransomware-protection-and-containment-strategies.pdf)

  

# Éradiquer la menace

L'étape d'éradication consiste à supprimer toutes les traces du ransomware. Faites preuve d'une grande prudence, car tout résidu pourrait réinfecter les systèmes. Dans le cadre de l'éradication, vous devez non seulement vous concentrer sur la suppression du logiciel malveillant, mais aussi sur le blocage des domaines et adresses IP malveillants connus afin de réduire la probabilité que la même attaque se reproduise.

1.  Finalisez une chronologie rigoureuse de l'incident avec le plus de détails possible, notamment:
    1.  Qui a accédé aux systèmes, et quels comptes ont été modifiés, accédés ou créés.
    2.  Quelles modifications ont été apportées aux systèmes par les attaquants ?
    3.  Quel code, malveillant ou autre, a été installé ou utilisé par les attaquants ?
    4.  Quelles données ont été affectées, consultées ou exfiltrées par les attaquants ?
2.  Quand l'attaque a-t-elle eu lieu et pendant combien de temps les attaquants ont-ils accédé aux systèmes ? Quand la méthode utilisée par les attaquants a-t-elle été rendue publique (si elle l'a été) ?
    1.  Où se trouvaient les systèmes affectés, et quels autres systèmes partageaient le même environnement ?
    2.  D'où les attaquants ont-ils accédé aux systèmes, et par où ont-ils pénétré dans le réseau et les systèmes ?
    3.  Pourquoi les systèmes ont-ils été attaqués ? S'agissait-il d'une attaque ciblée ou simplement d'une attaque aléatoire sur un système vulnérable ?
    4.  Pourquoi l'antivirus ou d'autres outils n'ont-ils pas détecté ou arrêté l'attaque ?
    5.  Comment les attaquants ont-ils accédé au système ? Ont-ils utilisé une mauvaise configuration, une vulnérabilité connue ou une 0 day, ou s'agit-il d'actions délibérées d'un collaborateur malveillant ?

Une fois on a répondu à un maximum de questions:

-   Supprimez les logiciels malveillants des systèmes affectés.
-   Reconstruire les systèmes affectés à partir de supports connus.
-   Restaurer à partir de sauvegardes connues.
-   Confirmer que la protection des endpoints (AV, NGAV, EDR, etc.) est à jour et activée sur tous les systèmes.
-   Confirmer que les correctifs sont déployés sur tous les systèmes (en donnant la priorité aux systèmes ciblés, aux systèmes d'exploitation, aux logiciels, etc.)
-   Déployer des signatures personnalisées dans les outils de protection (EDR/FW/IDS...) en fonction des IOCs découverts.
-   Bloquer les IPs identifiées
-   Surveillez la réinfection : envisagez d'augmenter la priorité des alarmes/alertes liées à cet incident.

  

# Rétablir l'activité

Les périmètres de compromission identifiés et les parties prenantes informées, les équipes de gestion de crise doivent agir pour revenir à une situation normale.
Des actions de sécurisation et des mesures de durcissement globales sont mises en place pour isoler l’attaquant si celui-ci parvient à maintenir son accès à certaines parties du SI.
Une surveillance des systèmes est mise en place, en particulier ceux identifiés comme précédemment compromis par l’investigation.
Une priorisation (P0 – P1 – P2 – P3) des applications et des systèmes à reconstruire est réalisée (en fonction de la criticité) et validée.

  

# Références:

-   [https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf](https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf)
-   [https://board.flexibleir.com/b/LQMuLgPYlEoMglqtV/1](https://board.flexibleir.com/b/LQMuLgPYlEoMglqtV/1)
-   [https://ss-usa.s3.amazonaws.com/c/308484380/media/19406140aa9beaad829072190465848/Ransomware%20Incident%20Checklist.pdf](https://ss-usa.s3.amazonaws.com/c/308484380/media/19406140aa9beaad829072190465848/Ransomware%20Incident%20Checklist.pdf)
-   [https://www.cisa.gov/stopransomware](https://www.cisa.gov/stopransomware)
-   [https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-insightidr-ransomware-playbook.pdf](https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-insightidr-ransomware-playbook.pdf)
-   [https://isea.utoronto.ca/policies-procedures/guidelines-2/short-incident-response-playbook-for-ransomware/](https://isea.utoronto.ca/policies-procedures/guidelines-2/short-incident-response-playbook-for-ransomware/)
-   [https://docs.microsoft.com/en-us/security/compass/incident-response-overview](https://docs.microsoft.com/en-us/security/compass/incident-response-overview)
