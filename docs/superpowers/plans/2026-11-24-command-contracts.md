# Contrats des commandes et laboratoire local

Objectif : corriger les limites identifiées par la vérification du 24 novembre,
conserver les commandes existantes et produire des preuves exécutables.

Architecture : le catalogue déclare les capacités ; la racine valide les options
avant l'action, route les sorties et publie les fichiers atomiquement. Les
handlers propagent les erreurs. Les modules réseau partagent le parsing et des
API avec contexte. Les fixtures locales prouvent les échanges protocolaires,
sans prétendre certifier un environnement AD ou cloud réel.

- [x] Contrat des options : tests CLI de fichier, remplacement, format refusé,
  erreurs d'écriture, silence informatif et absence d'action si option invalide.
- [x] Handlers : supprimer les exits internes et erreurs imprimées avec succès ;
  JSON structuré pour keygen et sorties capturables dans les commandes.
- [x] Réseau : parser commun, délais bornés, contexte, tests ports ouverts/fermés
  et annulation sur loopback pour scan, ports et recon.
- [x] Protocoles : remplacer les tests SMB permissifs par des fixtures strictes,
  corriger les affirmations de succès non justifiées et tester le bind LDAP.
- [x] Produit : documenter les capacités et le parcours audit/compare/CI ; ajouter
  un diagnostic local doctor sans recherche de secrets ni sondes externes.
- [x] Vérification : tests avec race, vet, lint disponible ou installé dans un
  dossier temporaire, compilation des plateformes et catalogue régénéré.

Contraintes : préserver les modifications existantes ; aucune opération sur des
cibles externes, aucun secret réel requis, pas de publication ou de commit demandé.
Les options non implémentées sont refusées explicitement avant toute action.
