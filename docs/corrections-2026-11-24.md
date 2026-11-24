# Correctifs du bilan — 24 novembre 2026

Les limites de contrat et les défauts reproductibles du premier bilan ont été
traités. Le parcours local documenté fonctionne. Les fonctionnalités sans
implémentation effective renvoient une erreur explicite ; elles ne sont pas
présentées comme des opérations réalisées.

## Résultat vérifié

| Contrôle | Résultat |
|---|---|
| Suite complète, cache désactivé, détecteur de concurrence | 1 298 tests et sous-tests réussis, aucun échec |
| Couverture des instructions | 72,3 % ; les sous-processus CLI ne sont pas instrumentés |
| Catalogue public et aide | 215 entrées ; 92 déclarent un support JSON complet |
| Version Go déclarée par le projet | Suite également réussie avec Go 1.26.8 |
| Analyse statique | `go vet ./...` réussi |
| Lint de la CI | golangci-lint v2.13.2 : zéro problème, avec Go 1.26.8 |
| Laboratoire local | Onze paquets réussis avec race detector et cache désactivé |
| Compilation | Linux amd64/arm64, Windows amd64, macOS amd64/arm64 |
| Parcours documenté | doctor, démo JSON sauvegardée, comparaison et rapport HTML réussis sur le binaire |

Les exécutables Linux, Windows et macOS Intel ont été compilés, sans être
exécutés sur ces systèmes ici. Le lint a été lancé avec la version Go du projet :
l'outil de lint épinglé ne décode pas les données d'export du Go 1.27.4 installé
sur la machine. Aucun contournement ou exclusion de règle n'a été ajouté.

## Contrat des commandes

- Le catalogue déclare JSON, HTML, fichier, quiet en texte, fail-on et verbose.
  Ces capacités sont affichées dans l'aide et dans ROADMAP.md. JSON accepte
  également quiet. Une option non prise en charge est rejetée avant l'action.
- Les sorties génériques vers un fichier réutilisent la publication atomique des
  rapports. Le fichier est préparé avant l'action, publié seulement après succès
  et protégé du remplacement sans force. Les fichiers de rapport natifs gardent
  leur gestion des audits partiels et du code de politique 2.
- Les écritures interrompues ou partielles font échouer la commande, même si un
  ancien callback ignore l'erreur. Les sorties texte utilisent un écrivain
  capturable ; no-color et les sorties non interactives retirent les séquences
  ANSI, même lorsqu'elles sont réparties entre plusieurs écritures.
- Les handlers remontent leurs erreurs et ne terminent plus le processus avec
  os.Exit. Les erreurs de données, d'entrée ou de transport ne deviennent plus
  automatiquement des succès. Les sorties JSON sont complétées notamment pour
  keygen, cipher, cookie, todo et version. La racine en JSON expose le catalogue.
- Le collecteur fuzz ne perd plus les résultats restés dans le canal à la fin.

Les collisions avec les options globales ont été supprimées : les manifests de
checksum utilisent `--manifest-output`, les sorties de credentials `--out`, et
l'exception à la garde de verrouillage spray `--override-lockout-guard`.
L'option globale `--force` reste liée aux remplacements de fichiers ; elle reste
également utilisable pour la confirmation de shred. Les options non implémentées
`--armor` et mots de passe d'archives renvoient une erreur.

## Réseau et intégrations

scan, ports et recon partagent maintenant un parsing strict des ports, la
normalisation des hôtes, des délais bornés et des sondes avec contexte. Les
interfaces exportées précédentes restent disponibles. Les corrections couvrent
IPv6, les sondes et résultats en double, la mutation des cibles fournies, les
délais de lecture ignorés et l'annulation. Une plage inversée est refusée.

Le laboratoire lance les vrais clients contre des services loopback éphémères.
Les tests SMB lisent les trames complètes, vérifient les réponses negotiate et
les bits de signature à leur bon emplacement. Les listes prédéfinies de partages
et la fausse affirmation d'authentification anonyme ont été supprimées. Les
recherches LDAP non implémentées ne retournent plus une liste vide avec succès ;
le bind LDAP réellement effectué est testé sur le fil.

Kubernetes distingue les refus RBAC attendus des problèmes d'authentification,
de serveur, de réponse et de transport. Les sondes partagent le certificat CA du
cluster, refusent les redirections et bornent les réponses. Une page HTML en
HTTP 200 ne prouve plus un accès anonyme à l'API. Les résultats partiels restent
disponibles dans les API internes qui renvoient aussi l'erreur.

## Utilisation

```sh
raxuiscli doctor
raxuiscli demo web --output=json --output-file demo.json
raxuiscli compare demo.json demo.json --output=json
raxuiscli demo web --output=html --output-file demo.html
make lab
```

Le README met en avant le parcours audit → rapport → comparaison → CI et précise
le rôle des commandes informatives. doctor inspecte uniquement l'environnement
local et les outils présents : il ne les exécute pas et ne confond pas leur
installation avec la disponibilité de leur service.

## Limites de validation

Le moteur Docker n'était pas disponible. Le laboratoire ne revendique donc pas
une certification de compatibilité avec un véritable AD, serveur SMB, cluster
Kubernetes ou compte cloud. L'énumération des partages SMB, l'authentification
anonyme SMB et la recherche d'utilisateurs LDAP restent explicitement non
implémentées. Transformer ces fonctions en clients de protocole complets serait
un développement supplémentaire, distinct de la suppression des faux succès.

Les fixtures et leur portée sont décrites dans [le laboratoire](../lab/README.md).
Aucun environnement réel, compte ou secret de production n'a été utilisé pour
ces contrôles.

## Correction du premier run GitHub

Le [run CI du commit e6827ff](https://github.com/Raxuis/RaxuisCLI/actions/runs/45349913745)
a réussi les tests sur Linux, macOS et Windows, le lint et les compilations.
Son job govulncheck a toutefois détecté 14 vulnérabilités atteignables avec le
compilateur Go 1.26.8 et la dépendance x/net v0.56.0. Ce contrôle n'avait pas été
inclus dans la vérification locale initiale.

La version minimale de Go est portée à 1.26.11 et x/net à v0.60.0. Ces versions
intègrent les correctifs requis, notamment [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859)
pour la bibliothèque standard et [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)
pour HTTP/2. Les workflows de CI et de release sélectionnent Go depuis go.mod.

`make vulncheck` exécute désormais le même scanner govulncheck v1.10.0 en local
et en CI. Aucune alerte n'est ignorée et le contrôle reste bloquant. Les résultats
Go 1.26.8 du tableau initial décrivent le contrôle effectué avant cette mise à
jour de sécurité.

Vérification du correctif avec Go 1.26.11 : govulncheck v1.10.0 réussit avec
zéro vulnérabilité atteignable et zéro dans les packages importés ; trois
alertes concernent des modules requis dont les symboles affectés ne sont pas
appelés. Vet, les tests avec race detector, le lint et les cinq compilations
réussissent également sur cette version de Go.
