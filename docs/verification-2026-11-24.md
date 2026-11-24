# Vérification des commandes — 24 novembre 2026

> Historique du premier passage. Les corrections et validations suivantes sont
> consignées dans [le bilan des correctifs](corrections-2026-11-24.md). Les limites
> listées ci-dessous décrivent l’état antérieur à ces correctifs.

La vérification a été effectuée sur macOS ARM64. Le projet compile et la suite
locale passe après les corrections ci-dessous. Cela ne constitue pas une
validation fonctionnelle complète des intégrations AD, SMB, Kubernetes ou cloud.

## Résultats

| Contrôle | Résultat |
|---|---|
| Aide publique | 214 entrées du catalogue : aide non vide, code 0, stderr vide |
| Tests Go, sous-tests inclus | 1 192 réussis avec `-race -count=1` |
| Paquets testés | 67 réussis ; un paquet sans tests |
| Couverture des instructions | 68,3 % ; le binaire lancé par les tests CLI est compilé sans instrumentation |
| Analyse statique | `go vet ./...` réussi |
| Compilation | Linux amd64/arm64, Windows amd64, macOS amd64/arm64 |
| Catalogue généré | Régénération réussie ; bloc du catalogue inchangé |
| Scripts | Syntaxe shell et JavaScript vérifiée ; installation réelle non exécutée |

Les tests publics supplémentaires vérifient les valeurs attendues des encodages,
hachages et chiffrements classiques, 16 parcours JSON hors ligne, la génération
de mots de passe via les deux formes de commande, les erreurs d'entrée, un aller-
retour de chiffrement de fichier, la préservation des fichiers en simulation et
les six méthodes HTTP contre un serveur local. Les tests existants couvrent
également les rapports, comparaisons, seuils de sévérité, DNS et TLS sur fixtures.
Les exécutables compilés pour d'autres systèmes n'ont pas été exécutés ici.

## Corrections effectuées

- `pwgen` génère maintenant des mots de passe directement, conformément au README.
  `pwgen generate` reste disponible. Longueur et nombre invalides produisent une
  erreur sur stderr et le code 1 ; les scripts reçoivent du JSON valide et ne
  voient plus de demande de copie dans le presse-papiers. La demande de copie
  reste disponible dans un vrai terminal en sortie texte.
- `files ... --dry-run` ne lance plus l'action. Un test reproduisait auparavant
  la création d'un fichier chiffré et d'une archive, puis la suppression de
  l'entrée par `shred`, malgré le drapeau de simulation.
- Un mot de passe d'archive était ignoré : une archive ZIP non protégée était
  créée. Compression et extraction rejettent maintenant cette option non prise
  en charge. `--armor`, également ignoré, renvoie une erreur explicite.
- `cipher freq`, `cookie analyze` et `cookie sensitive` respectent maintenant
  `--output=json`.
- Les exemples incorrects de README.md et CLAUDE.md ont été corrigés : formats
  d'encodage, sélection d'algorithme de hachage, longueur de hexdump, minimum de
  strings, compression avec sortie explicite et commandes todo/ports.
- L'aide précise que les fichiers de clés concernent RSA, que les chiffrements
  symétriques utilisent une passphrase, que `--overwrite` permet le remplacement
  de la sortie et que la syntaxe du sel est `--salt=false`.

## Limites encore observées

Le catalogue déclare 16 entrées stables, 181 expérimentales et 17 informatives,
y compris les commandes de groupe. Un code 0 sur l'aide ne valide pas l'action.
Les commandes informatives peuvent être utiles pour préparer une opération,
mais elles ne réalisent pas nécessairement cette opération.

Deux écarts de contrat ont été reproduits sur le binaire et restent à traiter :

- `raxuiscli --output=json keygen aes` réussit mais produit du texte.
- `raxuiscli --output=json --output-file result.json hash hello --algo sha256`
  réussit mais ne crée pas le fichier demandé.

Le support des options globales dépend donc encore de la commande. Le contrat
complet de rapport est surtout implémenté par `audit`, `demo` et `compare`.
D'autres commandes utilisent encore `fmt.Print` ou `os.Exit` directement : cela
complique la capture des sorties et l'harmonisation des erreurs.

Les tests SMB existants ne constituent pas une preuve de fonctionnement contre
un vrai serveur : certains se contentent d'un message de journal même en cas
d'erreur. Les scénarios AD/cloud nécessitent également des environnements de
test dédiés. Le lint golangci-lint complet n'a pas été exécuté, son binaire
n'étant pas installé ; `go vet` a été exécuté.

## Améliorations proposées, par priorité

1. **Fiabiliser le contrat de chaque commande.** Déclarer les capacités JSON,
   HTML, fichier, quiet et fail-on dans le catalogue. Refuser explicitement une
   option non prise en charge avant l'action. Généraliser `RunE`, les sorties
   capturables et la propagation des erreurs d'écriture. Tester les résultats
   et les fichiers créés par le binaire, au-delà de son aide.
2. **Mettre en avant le parcours audit → rapport → comparaison → CI.** C'est
   déjà le parcours stable et cohérent du projet. Présenter des cas concrets
   avant/après avec correction conseillée et niveau de sévérité ; rendre les
   helpers informatifs facilement identifiables dès les exemples.
3. **Ajouter un laboratoire reproductible.** Utiliser des services locaux
   éphémères pour les scénarios HTTP/TLS/DNS et des environnements dédiés pour
   LDAP/SMB/Kubernetes. Remplacer les tests qui journalisent un échec sans
   assertion par des scénarios déterministes ou des tests d'intégration
   explicitement séparés. Vérifier aussi le succès attendu et l'annulation.
4. **Rationaliser `scan`, `ports` et `recon`.** Partager parsing, délais,
   concurrence, annulation et résultats structurés pour éviter les comportements
   divergents. Tester d'abord les ports ouverts/fermés sur loopback.
5. **Ajouter un diagnostic d'environnement.** Une commande `doctor` pourrait
   signaler les outils nécessaires, capacités réseau et dépendances disponibles,
   puis proposer la commande compatible avec la machine actuelle.

Les propositions ci-dessus ne sont pas implémentées par cette vérification.

## Reproduction

```sh
go test -race -count=1 ./...
go vet ./...
make build-all
go generate ./internal/shared/catalog/...
git diff --check
```
