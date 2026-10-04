# Proposition — audit consolidé web, DNS et TLS

## Objectif

Ajouter `raxuiscli audit all <http-or-https-url>` pour réunir les trois audits existants dans un rapport comparable. Le commit de référence est `9e83e11`. Proposition validée par l’auteur le 4 octobre 2026.

## Approches examinées

1. Rapport unique dans le schéma v1 existant : réutilise JSON, HTML, texte, `compare` et `--fail-on`. Approche retenue.
2. Trois fichiers séparés : peu de code, mais pas de rapport consolidé ni de comparaison globale.
3. Nouveau schéma contenant trois sous-rapports : conserve toute leur structure, mais impose de modifier les lecteurs et les rendus. Hors périmètre pour cette itération.

## Interface

- Cible : URL HTTP/HTTPS absolue, validée avant toute opération réseau, avec les mêmes règles que `audit web`.
- Web : conserve l’URL et les options existantes (en-têtes, cookie, user-agent, insecure, redirections et taille maximale du corps).
- DNS : utilise le nom d’hôte de l’URL. Pour une adresse IP, le volet DNS est explicitement ignoré et décrit par une observation.
- TLS : utilise le nom d’hôte et le port HTTPS de la cible ; pour HTTP, le volet TLS est explicitement ignoré. Aucun test implicite du port 443 d’une URL HTTP.
- AXFR : ignoré par défaut ; `--axfr` permet de l’activer explicitement.
- `--timeout` : durée maximale globale, défaut 60 secondes. Les appels réseau DNS et TLS ont une limite de 10 secondes par connexion/requête et respectent aussi le contexte global.
- Les trois collectes sont séquentielles, afin de rendre l’exécution et les erreurs prévisibles. Aucune nouvelle dépendance.

## Architecture

- `internal/audit/combined` : valide la cible, détermine les volets applicables, appelle les services existants et agrège leurs résultats. Collecteurs injectables pour les tests.
- `cmd/audit/all.go` : expose les options et applique les mécanismes existants de rendu, fichier de sortie, remplacement et seuil de sévérité.
- La normalisation des URL utilisée par `audit web` est rendue accessible à l’orchestrateur, sans dupliquer ses règles.
- Le catalogue des commandes et la documentation générée sont mis à jour. Aucune modification du parcours TUI dans cette itération.

## Contrat du rapport

- `audit.kind` vaut `all` ; `audit.target` conserve l’URL normalisée.
- Les identités, ressources et preuves des constats individuels sont conservées. Les constats portant sur un domaine et sur un hôte:port restent distincts.
- Les observations conservent leurs clés déjà préfixées `http`, `dns` et `tls`. Le statut de chaque volet est ajouté sous `combined.web.status`, `combined.dns.status` et `combined.tls.status`.
- Les volets ignorés ont le statut `skipped` et une raison explicite.
- Un échec de collecte ne supprime pas les résultats des autres volets. Le rapport global est `partial` dès qu’un volet applicable échoue ; sinon il est `complete`.
- Annulation : le rapport conserve les résultats déjà obtenus et indique les volets non terminés comme partiels. Aucune nouvelle collecte réseau ne démarre après annulation.
- Codes de sortie : 0 pour un rapport complet sous le seuil ; 1 pour erreur d’entrée, de sortie ou rapport partiel ; 2 pour un seuil atteint dans un rapport complet.
- Deux rapports `all` sont comparables avec la commande actuelle `compare`. Aucun changement de schéma.

## Validation

Tests de cible invalide avant les collectes, URL avec port HTTPS personnalisé, HTTP sans TLS, IP sans DNS, AXFR désactivé par défaut, propagation des options, conservation des résultats après échec et expiration du délai global. Vérifier également la lecture du JSON, le rendu HTML, la comparaison et les codes 0/1/2. Utiliser des collecteurs injectés et des serveurs locaux.

Exécuter les tests concernés, la suite avec détection de courses, le lint, puis vérifier le catalogue généré. DNSSEC, CAA, DKIM, analyse approfondie de CSP et promotion des commandes expérimentales sont des itérations ultérieures.
