# 🛠️ Le Fuzzing

Le **Fuzzing** est une technique utilisée pour trouver des failles dans un logiciel en envoyant de multiples informations variées permettant de déceler une mauvaise interprétation des données entrées et ainsi générer un plantage du logiciel.

Traditionnellement, il est utilisé pour trouver des failles logicielles entraînant des vulnérabilités telles que **buffer overflow** et autres abus de gestion de la mémoire. Le terme est également employé dans différents domaines, notamment pour l’**énumération web** et la découverte de vulnérabilités dans une application web.

## 🌐 Fuzzing Web

Dans le cas du **web**, le principe reste similaire mais cible un objectif plus précis. Il sert principalement à découvrir :

- 📂 Des **répertoires et fichiers** accessibles via l’application web (**énumération**)
- 🔍 Des zones sensibles de l’application exposées à différents types d’**injections**
- 🛑 Des débordements mémoires (**buffer overflow, use after free**, etc.)

## 🛠️ Outils pour le Fuzzing Web

Nous allons utiliser quelques outils permettant la reconnaissance d’une application web lors d’une phase d’**énumération**. Pour cela, nous utiliserons des listes de noms qui seront passées en paramètre à nos outils de fuzzing pour découvrir certaines parties cachées d’une application.

📌 **Liste utilisée** : [SecLists](https://github.com/danielmiessler/SecLists)

Sur une machine **Kali Linux** ou toute autre dédiée à la sécurité, nous pouvons installer le paquet **seclists** :

```bash
apt install seclists
```

## 🚀 Déploiement d’un Environnement de Test

Nous allons utiliser un **conteneur Docker** pour déployer une application possédant plusieurs noms et ainsi permettre la découverte des outils.

### 🖥️ Installation (sur une machine Debian)

```bash
apt update && apt install -y docker.io docker-compose git  
git clone https://github.com/itform-fr/Etude-OWASP.git
docker-compose -f Etude-OWASP/CT0-FUZZING/fuzz.yaml up -d
```

### 🕵️ Vérification de l’accès à l’application

Depuis la même machine ou une autre sur le réseau, on peut afficher la page par défaut du site avec :

```bash
curl http://192.168.1.109
```

💡 **Sortie attendue :**
```html
<html><body><h1>It works!</h1></body></html>
```

## 🔍 Découverte des Sous-Domaines

### 📌 Avec **wfuzz**

```bash
wfuzz -u http://192.168.1.109 -H 'Host: FUZZ.lab' \
      -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

🚨 **Problème** : Cette commande retourne beaucoup de **faux positifs**.

✅ **Solution** : Filtrer les résultats pour ne pas afficher la page par défaut (ex. en excluant une taille spécifique) :

```bash
wfuzz -u http://192.168.189.109 -H 'Host: FUZZ.lab' \
      -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh 45
```

### 📌 Avec **ffuf**

```bash
ffuf -u http://192.168.189.109 -H 'Host: FUZZ.lab' \
     -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --fw 2
```

**Explication** :
- `--fw 2` → Exclut les réponses ayant **2 mots** (correspondant aux faux positifs)

## 🔎 Accès au Contenu des Sites

Pour voir le contenu d’un site découvert, nous utilisons **curl** avec un header spécifique :

```bash
curl -H 'Host: goodluck.lab' http://192.168.1.109
```

💡 **Astuce** : Ajouter le domaine et l’IP dans le fichier `/etc/hosts` pour éviter d’utiliser l’option `-H` à chaque requête.

## 📂 Recherche de Fichiers Sensibles

Nous utilisons des listes de **noms de fichiers** (avec ou sans extensions) pour trouver du contenu intéressant :

```bash
ffuf -u http://192.168.189.109/FUZZ.txt -H 'Host: dev.goodluck.lab' \
     -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt --fw 2
```

Une fois un fichier trouvé, nous pouvons récupérer son contenu avec **curl** ou un navigateur web.

---

🎯 **Objectif de l’exercice :**
- 🔍 Trouver **2 fichiers** et **3 noms d’hôtes** pour les autres sites.

Bonne exploration ! 🚀
