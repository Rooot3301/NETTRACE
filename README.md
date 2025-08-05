# NetTrace - Outil OSINT d'analyse de domaines

NetTrace est un outil complet d'OSINT (Open Source Intelligence) pour l'analyse de domaines, développé en Python pur sans dépendance à des APIs payantes.

## 🚀 Fonctionnalités

- **WHOIS Lookup** : Informations sur le registrar, dates de création/expiration, propriétaire
- **Résolution DNS** : Enregistrements A, AAAA, MX, TXT, NS, CNAME
- **Extraction de sous-domaines** : Via crt.sh, subfinder, amass
- **Lien VirusTotal** : Génération automatique du lien d'analyse
- **Score de confiance** : Calcul intelligent basé sur plusieurs critères
- **Export** : Sauvegarde en JSON ou TXT

## 📦 Installation

1. Cloner ou télécharger les fichiers
2. Installer les dépendances :

```bash
pip install -r requirements.txt
```

3. (Optionnel) Installer des outils externes pour plus de sous-domaines :
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
go install -v github.com/OWASP/Amass/v3/...@master
```

## 🎯 Usage

### Analyse basique
```bash
python nettrace.py --domain google.com
```

### Avec export JSON
```bash
python nettrace.py --domain example.com --output rapport.json
```

### Avec export TXT
```bash
python nettrace.py --domain test.com --format txt --output rapport.txt
```

### Mode verbeux
```bash
python nettrace.py --domain site.com --verbose
```

## 📊 Score de confiance

Le score est calculé sur 100 points selon ces critères :

- **Ancienneté du domaine** (30 pts max)
  - 10+ ans : 30 pts
  - 3-10 ans : 20 pts  
  - 1-3 ans : 10 pts
  - <1 an : 0 pts

- **Enregistrements DNS** (25 pts max)
  - A, MX, NS requis : 8 pts chacun
  - AAAA, TXT optionnels : 4 pts chacun

- **Sous-domaines** (20 pts max)
  - 50+ : 20 pts
  - 20-49 : 15 pts
  - 5-19 : 10 pts
  - 1-4 : 5 pts

- **Informations WHOIS** (15 pts max)
  - Registrar visible : 5 pts
  - Propriétaire visible : 5 pts
  - Statut visible : 5 pts

- **Stabilité** (10 pts max)

## 🛠️ Structure du projet

```
nettrace/
├── nettrace.py      # Script principal
├── utils.py         # Fonctions utilitaires
├── requirements.txt # Dépendances Python
└── README.md       # Documentation
```

## ❓ Dépannage

### Module manquant
```bash
pip install python-whois dnspython requests colorama python-dateutil
```

### Pas de sous-domaines trouvés
- Vérifiez votre connexion internet
- Installez subfinder/amass pour plus de résultats
- Certains domaines n'ont pas de certificats publics

### Erreur WHOIS
- Certains TLD ne sont pas supportés par python-whois
- Vérifiez que le domaine existe

## 🔒 Confidentialité

NetTrace respecte la vie privée :
- Aucune donnée envoyée à des tiers (sauf requêtes publiques)
- Pas de tracking ou de logs externes
- Sources d'information publiques uniquement

## 📝 Licence

Outil éducatif - Usage responsable requis
Ne pas utiliser pour des activités malveillantes

## 🤝 Contribution

Les contributions sont les bienvenues ! 
Respectez les bonnes pratiques et testez vos modifications.