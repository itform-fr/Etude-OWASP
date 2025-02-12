### Petit serveur web permettant de travailler l'énumeration web  
Par défaut seule une page s'affiche grâce à l'adresse IP de la machine hôte.  
Il existe :  
 - 3 domaines différents
 - 2 noms d'hôtes différents pour deux d'entre eux (1 seul pour le troisième)
 - 3 fichiers à découvrir dans les répertoires.

Tous les noms sont disponibles dans les listes seclists.  
Le Top Level Domain utilisé est : .lab.  

```bash
apt update && apt install -y docker.io docker-compose git  
git clone https://github.com/itform-fr/Etude-OWASP.git
docker-compose -f Etude-OWASP/CT0-FUZZING/fuzz.yaml up -d
```
Si vous souhaiter utiliser les outils directement sur la machine hébergeant les conteneurs (pour une debian)
```bash
apt install ffuf wfuzz
mkdir -p /usr/share/wordlists/
pushd /usr/share/wordlists/
git clone https://github.com/danielmiessler/SecLists.git
popd
```
Pour arrêter la machine:
```bash
docker-compose -f Etude-OWASP/CT0-FUZZING/fuzz.yaml down
```
