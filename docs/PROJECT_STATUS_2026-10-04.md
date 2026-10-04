# État du projet — 4 octobre 2026

Le dépôt est public et distribue la version v0.5.0. La revue a porté sur le checkout local a41d2b9 et donne la priorité aux audits web, DNS et TLS, conformément au choix de l’auteur. Les modifications préexistantes de README.md et CLAUDE.md sont conservées. Les corrections restent locales, sans publication ni nouvelle release.

## Inventaire et portée de la vérification

Le catalogue contient 213 chemins de commandes, groupes et aides inclus : 15 `stable`, 17 `informational`, 181 `experimental`. Ces étiquettes décrivent la maturité déclarée ; elles ne signifient pas que 181 commandes sont cassées. L’aide de chacun des 213 chemins est exécutée par le nouveau test du binaire.

La suite couvre les packages métier, les rapports, les commandes d’audit et l’interface guidée. Des tests du binaire ajoutent des contrôles des erreurs utilisateur et des codes de sortie. La démonstration HTTPS locale vérifie un rapport JSON lisible et le code 2 de `--fail-on=high`. Les cas DNS/AXFR et TLS utilisent des services locaux ou des collecteurs injectés : aucun scan de système tiers n’a été réalisé.

Cela ne constitue pas une validation en environnement réel de chaque fonction cloud, Kubernetes, Active Directory ou réseau. La compilation multiplateforme ne remplace pas l’exécution sur chaque système.

## Corrections livrées

| Parcours | Défaut constaté | Comportement corrigé |
|---|---|---|
| Audit DNS | Erreurs DNS ignorées ; absence SPF/DMARC inventée | Rapport partiel, erreurs conservées, politique inconnue sans faux constat d’absence |
| Audit DNS | Cibles URL, IP ou domaines invalides acceptés | Validation avant les requêtes et normalisation IDNA |
| Audit DNS | Recherche des politiques par sous-chaînes | Mécanismes SPF et tag DMARC `p` analysés séparément ; prise en charge de `all`, `redirect=` et des enregistrements multiples |
| AXFR | `NOERROR` seul présenté comme transfert autorisé | Lecture complète des trames TCP et validation des SOA d’ouverture et de fermeture ; limites de collecte |
| AXFR | Échecs de collecte silencieux | Refus explicite distingué d’un transfert incomplet ou indisponible, qui rend le rapport partiel |
| Audit TLS | Contexte d’annulation ignoré | Connexions et négociations interrompues ; Ctrl+C transmis au contexte du CLI |
| Audit TLS | IPv6 et ports invalides mal interprétés | Analyse correcte des hôtes IPv6 et validation des ports |
| Audit TLS | Collecte de certificat limitée aux protocoles modernes | Collecte possible à partir de TLS 1.0 ; collecte échouée signalée comme partielle |
| Audit TLS | Confiance de la chaîne non vérifiée | Vérification X.509 avec les intermédiaires et les autorités système ; diagnostic `cert-untrusted` et prise en charge Ed25519 |
| Audit web | Absence d’un en-tête déprécié signalée | Retrait de l’alerte d’absence `X-XSS-Protection` et mise à jour de l’exemple JSON |
| Commandes locales/web | Erreurs imprimées avec succès du processus | Propagation des erreurs HTTP, JWT, keygen, cookies, fuzz et todo vers Cobra |
| Génération de clés | Longueur négative : panic ; paramètres invalides remplacés silencieusement | Erreur explicite pour longueur négative, taille AES et courbe ECDSA invalides |
| JWT | Erreurs de lecture de wordlist ou de sortie ignorées | Propagation des erreurs de lecture et de sortie structurée |
| Todo | Texte de plusieurs mots tronqué ; numéros affichés différents des IDs | Arguments réunis et vrais IDs affichés ; aide alignée sur les opérations disponibles |
| LM | Valeur de remplacement retournée pour tout mot de passe | Calcul DES réel pour les mots de passe ASCII, vérifié avec le vecteur Microsoft ; marqueur désactivé pour les entrées non prises en charge |

## Chaîne de compilation et sécurité

La dernière CI de `main` était [verte le 19 septembre](https://github.com/Raxuis/RaxuisCLI/actions/runs/35433591286). La [CI Dependabot du 1er octobre](https://github.com/Raxuis/RaxuisCLI/actions/runs/36814855342) échouait dans `govulncheck` avec 27 vulnérabilités atteignables de la bibliothèque standard : le workflow utilisait Go 1.26.0. Ce résultat décrit cette exécution et son compilateur, pas nécessairement tous les binaires déjà publiés.

La version minimale passe à Go 1.26.8, ce qui met aussi à jour le compilateur sélectionné par la CI et les releases via `go-version-file`. `golang.org/x/net` passe à v0.56.0 pour corriger [GO-2026-5942](https://pkg.go.dev/vuln/GO-2026-5942), pertinent pour le décodage DNS ; la résolution des modules met également `x/crypto` à v0.53.0. Le guide contributeur est aligné.

Sources des comportements corrigés : [SPF, RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html), [AXFR, RFC 5936](https://www.rfc-editor.org/rfc/rfc5936.html), [statut de X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection), [vecteur LM de Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a724e8df-2b0a-4a36-aef4-2d2b56fd3db7), [versions officielles Go](https://go.dev/dl/).

## Limites encore visibles

- LDAP : `EnumerateUsers` établit une connexion et peut binder, mais n’envoie pas de recherche LDAP. Une liste vide n’est donc pas une preuve qu’aucun utilisateur n’existe.
- Les aides Kerberos, poison et certains tunnels génèrent volontairement des commandes ou scripts ; elles n’exécutent pas toutes les opérations annoncées par leur famille.
- Le support interne `.kirbi` reste un parseur simplifié. Le helper interne NTLMv2 n’est pas une implémentation complète des échanges du protocole.
- Plusieurs commandes historiques utilisent encore `os.Exit` et n’appliquent pas uniformément les options globales de rapport (`--output-file`, HTML, `--quiet`, `--fail-on`). Les contrats les plus cohérents sont ceux de `audit`, `compare` et `demo`.
- DNS : la posture email ne couvre pas une évaluation récursive SPF, les limites de recherches SPF, la découverte DKIM, DNSSEC ou l’héritage organisationnel DMARC. Un enregistrement TXT absent et un domaine inexistant peuvent être présentés de la même manière par le résolveur Go.
- TLS : les suites 1.3 ne sont pas individuellement sélectionnables avec la bibliothèque standard ; la suite négociée est observée. Ce n’est pas un inventaire exhaustif de toutes les suites possibles, ni une mesure indépendante de type SSL Labs.
- Web : l’audit évalue surtout la présence d’en-têtes et les certificats ; il ne prouve pas la qualité complète d’une CSP ni l’absence de vulnérabilités applicatives.
- Les animations de démonstration sont des captures historiques et peuvent encore montrer l’ancienne alerte X-XSS-Protection.

## Priorités proposées

1. Étendre les tests du binaire aux rapports JSON/HTML, aux comparaisons et aux erreurs pour chaque parcours stable, avec les mêmes contrôles sur Linux, macOS et Windows.
2. Ajouter DNSSEC et CAA, puis un contrôle récursif SPF avec budget de requêtes et une découverte DKIM par sélecteurs fournis par l’utilisateur.
3. Étendre l’audit web à la qualité de CSP, à `frame-ancestors`, aux redirections et aux attributs de cookies, avec un niveau de confiance et des preuves précises.
4. Ajouter un parcours `audit all` produisant un rapport consolidé web/DNS/TLS, réutilisant les collecteurs et les limites existants.
5. Uniformiser la validation des entrées, les sorties structurées et les codes de sortie des commandes expérimentales avant de les promouvoir en `stable`.

## Vérifications finales

- `go test ./...` : succès, avec le nouveau test du binaire et l’aide des 213 chemins.
- `GOTOOLCHAIN=go1.26.8 go vet ./...` : succès.
- `GOTOOLCHAIN=go1.26.8 go test -race ./...` : succès sur la version minimale déclarée.
- `golangci-lint v2.13.2 run ./...` : 0 problème.
- `GOTOOLCHAIN=go1.26.8 go run golang.org/x/vuln/cmd/govulncheck@latest ./...` : 0 vulnérabilité atteignable ; l’outil signale aussi des vulnérabilités dans des packages/modules dont les symboles concernés ne sont pas appelés.
- `make build-all` : succès pour Linux amd64/arm64, Windows amd64 et macOS amd64/arm64, avec Go 1.27.1 installé localement.
- `make build` : binaire local actualisé dans `bin/raxuiscli`.
- Exemple de rapport JSON valide et `git diff --check` sans erreur.

Ces résultats portent sur les modifications locales. Une CI distante et les tests natifs Linux/Windows devront être confirmés après publication des changements.
