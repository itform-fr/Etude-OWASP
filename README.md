Site Web possédant plusieurs vulnérabilitées à trouver.
Attention il ne s'agit pas d'un CTF, il s'agit de détecter des vulnérabilitées vues dans le cadre de l'OWASP. Il existe de multiples possiblité pour obtenir les privilèges administrateurs sur le site.

Vous disposez d'un compte sur le site(login/mdp): 
lisa/poseidon

pour lancer le site vous pouvez effectuer ces commandes suivantes, le site sera ensuite sur le port 80 de la machine sur laquelle vous avez effectué les commandes.

Attention à ne pas rendre cette machine accessible sur votre réseau (puisqu'elle pourra être assez facilement compromise)!

Installation sur une machine debian:
apt install docker.io docker-compose git
git clone https://github.com/itform-fr/OWASP-CT1.git
docker-compose -f OWASP-CT1/vuln-site.yaml up -d

Pour arrêter la machine:
docker-compose -f OWASP-CT1/vuln-site.yaml down
