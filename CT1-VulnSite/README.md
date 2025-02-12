## Site Web possédant plusieurs vulnérabilitées à trouver.
Attention il ne s'agit pas d'un CTF, il s'agit de détecter des vulnérabilitées vues dans le cadre de l'OWASP. Il existe de multiples possiblité pour obtenir les privilèges administrateurs sur le site. L'objectif est d'en trouver le plus possible tout en catégorisant les différentes vulnérabilitées et en expliquer les enjeux pour le système d'information.

Vous disposez d'un compte sur le site (login/mdp):  
>**lisa/poseidon**


Pour lancer le site vous pouvez effectuer ces commandes suivantes, le site sera ensuite accessible sur le port 80 de la machine sur laquelle vous avez effectué les commandes.

Attention à ne pas rendre cette machine accessible sur votre réseau (puisqu'elle pourrat être assez facilement compromise)!

Installation sur une machine debian:  
```bash
apt update && apt install -y docker.io docker-compose git
git clone https://github.com/itform-fr/OWASP-CT1.git
docker-compose -f OWASP-CT1/vuln_site.yaml up -d
```

Pour arrêter la machine:
```bash
docker-compose -f OWASP-CT1/vuln-site.yaml down
```
