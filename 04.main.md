+++
title = "CryptKVS : description générale"
template = "project/page.html"
weight = 3

[extra]
week = 1
revision = "2022.02.09 / 1"
+++


## Plan de ce document

1. Contexte
2. Buts
3. Description générale
4. Principales étapes

## Contexte

Le but premier de ce projet est de vous faire développer un large programme en C sur une thématique « système ».  

La gestion des données confidentielles dans le cloud est un des enjeux majeurs de notre époque.  Il suffit de lire les journaux pour comprendre les enjeux liés aux pertes de données massives lorsqu'elles sont gérées de manière centralisée, que ce soit dans des serveurs locaux ou dans le cloud.

La gestion des mots de passe est un bon exemple.  Le site [haveibeenpwned](https://haveibeenpwned.com/) regroupe un ensemble de données volées dans plus de 500 sites web, pour un total de 11 milliards de comptes.  Votre email en fait peut-être partie, du reste.

Idéalement, les données confidentielles ne sont jamais disponibles dans un site centralisé.  Les systèmes de communication avec encryptage de bout-en-bout (« _end-to-end encryption_ ») garantissent que les serveurs qui servent de relais ne peuvent pas décrypter le contenu des messages. Les applications mobiles [SIGNAL](https://en.wikipedia.org/wiki/Signal_(software)) et WhatsApp en sont deux exemples très connus ; elles utilisent toutes les deux des variantes du même protocole cryptographique.

SIGNAL est particulièrement reconnue pour son respect maximal de la vie privée.  L'objectif de la fondation qui l'opère est d'offrir un service de déploiement mondial (plus de 40 millions d'utilisateurs actifs) tout en minimisant les informations collectées par leurs serveurs (voir [Wikipedia](https://en.wikipedia.org/wiki/Signal_(software))).

SIGNAL a introduit une nouvelle fonctionnalité qui permet à un utilisateur de copier la liste de ses contacts dans le cloud.  Cette fonctionnalité est utile si vous devez changer de téléphone. La liste est protégée par un PIN à 6 chiffres.  Si vous êtes utilisateur/utilisatrice de l'application mobile, elle vous demande de rentrer régulièrement le PIN afin d'être sûr de ne pas l'oublier.

La technologie sous-jacente s'appelle « _secure value recovery_ » ; elle est décrite ici: [https://signal.org/blog/secure-value-recovery/](https://signal.org/blog/secure-value-recovery/).   Cette solution utilise un nombre de technologies avancées de divers domaines tels que la cryptographie, le hardware (les enclaves SGX) et a même nécessité une modification de compilateur.


## Buts

Durant ce projet, vous allez construire une version simplifiée de « _secure value recovery_ » qui encrypte les données dans une base de données partagée : un « _(en)crypted key-value store_ » (d'où le nom du projet : « CryptKVS »).

**NOTE DE SECURITE IMPORTANTE :**  par raison de simplification, la solution que vous implémenterez n'est pas résistante aux attaques de type « force brute », comme nous l'expliquons plus bas.  Dans le domaine de la sécurité, toute simplification ou changement a des effets de bords qui doivent être analysés en détail. Ceci n'est pas l'objectif de ce cours.

L'objectif pédagogique principal est de vous donner un aperçu des outils et technique de construction de programmation orientée système, y compris les librairies cryptographiques basiques, mais il ne s'agit pas d'un cours de sécurité informatique. **[fin de note]**


Durant les premières semaines, il s'agira d'abord d'implémenter les fonctions de base du système, à savoir :

* lister les informations (métadonnées, liste des données) ;
* décrypter une valeur lorsqu'on connait la clef et le mot de passe ;
* créer une clef et associer une valeur correspondante.

Dans cette première phase, les fonctions seront exposées via un utilitaire en ligne de commande. Durant les dernières semaines du semestre, vous construirez un véritable serveur web qui exposera la même fonctionnalité en séparant les fonctions client et les fonctions serveur.


Durant ce projet, vous allez pouvoir mettre en pratique et découvrir :

* la programmation en C dans le cadre d'un projet de taille moyenne ;
* les outils de debugging présentés durant les 3 premières semaines (`gdb`, `asan`, etc.) ;  l'accent sera mis sur la gestion correcte de la mémoire (allocation, déallocation, bounds checking) ;
* la gestions de fichiers avec la librarie POSIX ;
* la librairie cryptographique `openssl` ;
* la programmation client-serveur en C utilisant `libcurl`(côté client) et `libmongoose` côté serveur. ;
* le protocole `https` et la gestion des certificats SSL.


Durant les 10 semaines de ce projet, vous allez devoir implémenter, graduellement morceau par morceau les composants clés mentionnés ci-dessus et décrits plus bas, puis détaillés dans les sujets hebdomadaires.

Vous allez aussi devoir développer des tests complémentaires utiles pour observer et analyser le fonctionnement du système. Ces tests seront développés sous forme d'exécutables indépendants du cœur principal.

Afin de faciliter au mieux l'organisation de votre travail (dans le groupe et dans le temps), nous vous conseillons de consulter [la page de barème du cours](/projet/bareme.html) (et la lire en entier !!).


## Description générale

Nous décrivons ici de façon générale les principaux concepts et structures de données que ce projet nécessitera. Leurs détails d'implémentation seront précisés plus tard lorsque nécessaire dans chaque sujet hebdomadaire correspondant.


Considérons le problème de stocker un secret dans le cloud. Chaque secret a :

* une clef unique (`key`), par exemple le nom de l'utilisateur, son numéro de téléphone, etc.  
    Dans notre solution, il s'agit d'un string de 32 caractères au maximum (`'\0'` non compris) ;  c'est le seul élément visible en clair dans la base de données ;

* un mot de passe, connu uniquement de l'utilisateur ;  la combinaison de la clef et du mot de passe forment la base d'une double chaîne cryptographique utilisée pour :

    1. vérifier que le mot de passe est correct et
    2. encrypter et décrypter le contenu ;

* le secret lui-même (c.-à-d. la valeur). L'objectif principal est d'en protéger le contenu, afin que seul le client puisse le récupérer.

La solution s’inspire du protocole SIGNAL « _secure value recovery_ », qui est décrit comme suit (expliqué ci-dessous) :

```
stretched_key = Argon2(passphrase=user_passphrase, output_length=32)

auth_key    = HMAC-SHA256(key=stretched_key, "Auth Key")
c1          = HMAC-SHA256(key=stretched_key, "Master Key Encryption")
c2          = Secure-Random(output_length=32)

master_key      = HMAC-SHA256(key=c1, c2)
```

Evidemment, cette notation nécessite quelques explications :

* `user_passphrase` est la concaténation de la clef (`key`) et du mot de passe (`password`) ;  dans le protocole original, la concaténation est ensuite « étirée » sur 32 octets par la fonction cryptographique `Argon2` ;  cette opération a lieu sur le client ;  par simplification, nous nous contentons de faire la concaténation (sans `Argon2`) ;

* le client génère ensuite `auth_key` et `c1`, en utilisant `stretched_key` pour signer de manière numérique deux « documents » ; ces « documents » sont des constantes ayant ici respectivement pour contenu `"Auth key"` et `"Master Key Encryption"` ;  
    le contenu n'est pas important -- puisque ce sont des constantes du protocole ;  l'important est que ce sont deux documents _différents_, ce qui rend impossible à un adversaire de lier un résultat avec l'autre.

* le serveur génère la valeur `c2` de manière aléatoire (32 octets) ; il stocke dans une table `key`, `auth_key` and `c2` ;

* lorsque le client souhaite lire ou écrire une valeur, le client soumet `auth_key` comme authentification ; le serveur répond avec `c2` ;

* seul le client peut générer `master_key`, qui est ensuite utilisée par le client comme clef symétrique pour encrypter (écriture) ou décrypter (lecture) la valeur.


Ce protocole a un certain nombre de propriétés intéressantes, disponible dans la solution de SIGNAL (et pas dans le projet):

* l'entropie offerte par `c2` dans `master_key` implique qu’un attaquant avec des moyens illimités ne pourrait pas décoder les valeurs secrètes sauf s’il a accès à `c2` ;    
    les secrets peuvent donc être stockés dans le cloud (p.ex. sur disque) pour autant que `c2` est protégé, ce qui est le cas avec l'utilisation des enclaves SGX ;  dans notre projet, pour simplifier tout est stocké dans le même fichier ;

* dans la version déployée par SIGNAL, le service limite le nombre d'essais de comparaison de `auth_key`, ce qui évite une attaque par force brute.


## Étapes de développement du projet

* Semaine 4 (cette semaine, donc !) : la commande « stats » : opération en lecture pour accéder au format sur disque de la base de données.

* Semaine 5 : command « get » :  implement the logic to compute the various keys and decode a secret stored in the provided file.  exercises the openssl library functions, etc.

* Semaine 6 : command « set » : requires fseek, fwrite, to append the new value and update an existing entry.

* **Premier rendu :** correspond au travail des semaines 4 à 6 ; à rendre en fin de semaine 7 ;

* Semaine 7 : command « new » : create a new key.  This is where we introduce open hashing instead of linear scan.  Move away from fixed-sized tables to a dynamic approach where the table size is set in the header.

* Semaine 9 : refactoring of the CLI to be table-driven; also preparation for client-server programming; (students will likely not be asked to implement "create-kvs" to create a table)

* **Second rendu :** correspond au travail des semaines 4 à 9 ; à rendre en fin de semaine 10 ;

* Semaine 10 : command "stat"/network and "get"/network : instructors provide the running server (shared by all).   HTTP client programming.  Requires mongoose.

* Semaine 11 : command "httpd" : students connect to their own webserver.   Students implement  "stat"/network "get"/network.

* Semaine 12 : command "set"/network and "new"/network. (client-side and server side).  For simplicity, "set" is implemented using "GET" rather than "POST" (small secrets only); les étudiants plus avancées peuvent par contre bien sûr implémenter un « POST ».

* **Rendu final :** correspond au travail des semaines 4 à 14 ; à rendre en fin de semestre.
