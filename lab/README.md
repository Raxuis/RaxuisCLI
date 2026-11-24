# Laboratoire local de protocoles

Depuis la racine du dépôt :

```sh
./scripts/lab/run.sh
```

Prérequis : la version Go indiquée dans `go.mod`, son compilateur C pour le
race detector, les dépendances Go en cache (ou un accès réseau pour les
récupérer), et le droit d'ouvrir des sockets loopback. Les scénarios n'utilisent
ni identifiants réels, ni services externes, ni ports privilégiés. Les tests
créent leurs services sur des ports éphémères et les ferment à la fin. Une erreur
fait échouer le script ; aucun échec réseau n'est transformé en simple journal.
Le script désactive le cache des résultats et limite chaque paquet à deux minutes.

| Périmètre | Preuve fournie par les fixtures |
|---|---|
| HTTP | Requêtes, en-têtes, corps, redirections, limites de lecture, erreurs et annulation de contexte contre des serveurs locaux |
| TLS | Serveur TLS de test, récupération de certificat et erreurs de connexion ; les certificats sont temporaires/de test |
| DNS | Réponses d'un serveur UDP loopback ; analyse des politiques sur réponses injectées |
| TCP | Ports loopback ouverts/fermés, bannières, IPv6, délais, déduplication et annulation |
| Kubernetes | API locale : listes JSON, refus RBAC, authentification, erreurs serveur, réponses invalides et connexion refusée |
| LDAP | Vrai client TCP, requête BER simple bind vérifiée octet par octet ; succès, refus, réponse malformée, déconnexion et bind anonyme |
| SMB | Vrai client TCP, requête negotiate contrôlée ; réponse SMB2 locale, trois modes de signature, trames fragmentées, refus et troncature |

Les assertions vérifient les résultats des fonctions de production, pas seulement
la disponibilité d'un serveur. Pour examiner un protocole séparément :

```sh
go test -race -count=1 -v ./internal/redteam/smb
go test -race -count=1 -v ./internal/redteam/ldap
```

## Portée et limites

Ce laboratoire est une suite de fixtures de protocoles. Il ne certifie pas la
compatibilité avec Active Directory, Samba, Windows, Kubernetes ou les clouds.
La négociation SMB ne prouve pas une authentification anonyme : `CheckNullSession`
renvoie une erreur explicite tant que session setup n'est pas implémenté.
`EnumerateShares` et `EnumerateUsers` renvoient également une erreur explicite,
car ils n'effectuent pas les échanges RPC/search nécessaires. Aucune liste de
partages inventée ou liste vide présentée comme un succès d'énumération.

Le bind LDAP simple est testé ; les recherches, Kerberos, NTLM, autorisations
SMB, ACL et configurations AD réelles ne le sont pas. Les fixtures ne valident
pas non plus une politique de confiance TLS de production.

Docker est facultatif et n'est pas utilisé par ce script. Sur la machine de
vérification du 24 novembre 2026, le client Docker était installé mais son daemon
n'était pas disponible ; aucune validation de conteneur AD/SMB n'est revendiquée.
Avant toute annonce de compatibilité réelle, ajouter un environnement isolé
avec versions de serveurs fixées, comptes de test, scénarios positifs/négatifs et
nettoyage vérifié, puis publier les commandes et résultats observés.
