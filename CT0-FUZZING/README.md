### Petit serveur web permettant de travailler l'énumeration web  
par défaut seule une page s'affiche grâce à l'adresse IP de la machine hôte.
Il existe 3 domaines différents, 2 noms d'hôtes différents pour deux d'entre eux (1 seul pour le troisième)
3 fichiers à découvrir dans les répertoires. Tous les noms sont disponibles dans les listes seclists.
Le Top Level Domain utilisé est : .lab.

```bash
git clone https://github.com/itform-fr/Etude-OWASP.git
docker-compose -f Etude-OWASP/CT0-FUZZING/fuzz.yaml up -d
```
