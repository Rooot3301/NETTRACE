# 🔍 NetTrace - Outil OSINT d'analyse de domaines

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OSINT](https://img.shields.io/badge/OSINT-Tool-red.svg)](https://github.com)

**NetTrace** est un outil complet d'OSINT (Open Source Intelligence) pour l'analyse de domaines, développé en Python pur sans dépendance à des APIs payantes. Il permet d'effectuer une reconnaissance passive approfondie sur n'importe quel domaine.

![NetTrace Demo](https://via.placeholder.com/800x400/1a1a1a/00ff00?text=NetTrace+OSINT+Tool)

## 🚀 Fonctionnalités

### 🔎 Analyse complète
- **WHOIS Lookup** : Informations sur le registrar, dates de création/expiration, propriétaire
- **Résolution DNS** : Enregistrements A, AAAA, MX, TXT, NS, CNAME
- **Extraction de sous-domaines** : Via crt.sh, subfinder, amass (passif uniquement)
- **Lien VirusTotal** : Génération automatique du lien d'analyse
- **Score de confiance** : Calcul intelligent basé sur plusieurs critères (0-100)

### 📊 Fonctionnalités avancées
- **Export multi-format** : Sauvegarde en JSON ou TXT
- **Interface colorée** : Affichage clair avec codes couleur
- **Mode verbeux** : Débogage détaillé des opérations
- **Gestion d'erreurs** : Fallbacks intelligents en cas d'échec
- **Architecture modulaire** : Code propre et extensible

## 📦 Installation

### Prérequis
- Python 3.7 ou supérieur
- pip (gestionnaire de paquets Python)

### Installation rapide
```bash
# Cloner le repository
git clone https://github.com/votre-username/nettrace.git
cd nettrace

# Installer les dépendances
pip install -r requirements.txt
```

### Installation des outils externes (optionnel)
Pour maximiser la découverte de sous-domaines :

```bash
# Subfinder (Go requis)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass (Go requis)
go install -v github.com/OWASP/Amass/v3/...@master
```

## 🎯 Usage

### Commandes de base

```bash
# Mode interactif (recommandé)
python nettrace.py --interactive

# Analyse simple
python nettrace.py --domain google.com

# Avec export JSON
python nettrace.py --domain example.com --output rapport.json

# Avec export TXT
python nettrace.py --domain test.com --format txt --output rapport.txt

# Mode verbeux pour débogage
python nettrace.py --domain site.com --verbose
```

### Options disponibles

| Option | Description | Exemple |
|--------|-------------|---------|
| `--domain, -d` | Domaine à analyser (requis) | `-d google.com` |
| `--output, -o` | Fichier de sortie | `-o rapport.json` |
| `--format, -f` | Format d'export (json/txt) | `-f txt` |
| `--verbose, -v` | Mode verbeux | `-v` |
| `--interactive, -i` | Mode interactif avec menu | `-i` |

### Exemples d'usage

```bash
# Mode interactif complet
python nettrace.py -i

# Analyse complète avec export
python nettrace.py -d facebook.com -o facebook_analysis.json -v

# Analyse rapide sans export
python nettrace.py -d github.com

# Export en format texte
python nettrace.py -d stackoverflow.com -f txt -o report.txt
```

## 🎮 Mode interactif

NetTrace propose un mode interactif avec menu pour une utilisation plus conviviale :

```
╔══════════════════════════════════════════════════════════╗
║                    🔍 NETTRACE MENU                     ║
╠══════════════════════════════════════════════════════════╣
║  1. 🎯 Analyser un domaine                               ║
║  2. 📊 Analyser avec rapport automatique                ║
║  3. 📁 Analyser plusieurs domaines (batch)              ║
║  4. ⚙️  Configuration et outils                         ║
║  5. 📖 Aide et exemples                                 ║
║  6. 🚪 Quitter                                          ║
╚══════════════════════════════════════════════════════════╝
```

### Fonctionnalités du menu

- **Analyse simple** : Analyse rapide d'un domaine
- **Rapport automatique** : Génération automatique de fichiers de rapport avec timestamp
- **Analyse en lot** : Traitement de plusieurs domaines (saisie manuelle ou fichier)
- **Configuration** : Vérification des dépendances et outils installés
- **Aide intégrée** : Exemples et documentation directement dans l'outil

## 📊 Score de confiance

NetTrace calcule un score de confiance sur 100 points basé sur :

### Critères de scoring

| Critère | Points max | Description |
|---------|------------|-------------|
| **Ancienneté du domaine** | 30 pts | 10+ ans (30), 3-10 ans (20), 1-3 ans (10), <1 an (0) |
| **Enregistrements DNS** | 25 pts | A/MX/NS requis (8 pts chacun), AAAA/TXT optionnels (4 pts) |
| **Sous-domaines** | 20 pts | 50+ (20), 20-49 (15), 5-19 (10), 1-4 (5) |
| **Informations WHOIS** | 15 pts | Registrar (5), Propriétaire (5), Statut (5) |
| **Stabilité** | 10 pts | Score basé sur la cohérence des données |

### Interprétation des scores

- **80-100** : 🟢 **ÉLEVÉ** - Domaine établi et fiable
- **60-79** : 🟡 **MOYEN** - Domaine standard avec quelques lacunes
- **0-59** : 🔴 **FAIBLE** - Domaine récent ou suspect

## 🛠️ Structure du projet

```
nettrace/
├── nettrace.py          # Script principal
├── utils.py             # Fonctions utilitaires et classes
├── requirements.txt     # Dépendances Python
├── README.md           # Documentation
└── examples/           # Exemples de rapports
    ├── google.json
    └── example.txt
```

## 📋 Exemple de sortie

```
🔍 NETTRACE - OUTIL OSINT D'ANALYSE DE DOMAINES
By: Assistant IA | Version: 1.0

🎯 Analyse du domaine: google.com
============================================================

📋 WHOIS LOOKUP
────────────────
🏢 Registrar: MarkMonitor Inc.
📅 Date de création: 1997-09-15 04:00:00
⏰ Date d'expiration: 2028-09-14 04:00:00
👤 Propriétaire: Google LLC
📊 Statut: clientDeleteProhibited

📋 RÉSOLUTION DNS
──────────────────
🔍 A: 142.250.185.78
🔍 AAAA: 2a00:1450:4007:80c::200e
🔍 MX: 10 smtp.google.com
🔍 TXT: v=spf1 include:_spf.google.com ~all
🔍 NS: ns1.google.com, ns2.google.com

🎯 Score de confiance: 95/100 (ÉLEVÉ)
```

## ❓ Dépannage

### Problèmes courants

**Module manquant**
```bash
pip install python-whois dnspython requests colorama python-dateutil
```

**Pas de sous-domaines trouvés**
- Vérifiez votre connexion internet
- Installez subfinder/amass pour plus de résultats
- Certains domaines n'ont pas de certificats SSL publics

**Erreur WHOIS**
- Certains TLD ne sont pas supportés par python-whois
- Vérifiez que le domaine existe et est valide

**Timeout sur les sous-domaines**
- Utilisez le mode verbeux (`-v`) pour voir les détails
- Certains outils externes peuvent être lents

## 🔒 Éthique et légalité

### Usage responsable
- ✅ Reconnaissance passive uniquement
- ✅ Sources d'information publiques
- ✅ Respect des robots.txt et rate limits
- ❌ Pas de scan actif ou intrusif
- ❌ Pas d'exploitation de vulnérabilités

### Confidentialité
NetTrace respecte la vie privée :
- Aucune donnée envoyée à des tiers (sauf requêtes publiques légitimes)
- Pas de tracking ou de logs externes
- Toutes les analyses sont locales

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. **Fork** le projet
2. Créez une **branche** pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. **Committez** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une **Pull Request**

### Guidelines de contribution
- Respectez le style de code existant
- Ajoutez des tests pour les nouvelles fonctionnalités
- Mettez à jour la documentation si nécessaire
- Testez vos modifications sur plusieurs domaines

## 📝 Changelog

### v1.0.0 (2025-01-XX)
- 🎉 Version initiale
- ✅ WHOIS lookup complet
- ✅ Résolution DNS multi-enregistrements
- ✅ Extraction de sous-domaines via crt.sh
- ✅ Support subfinder/amass
- ✅ Score de confiance intelligent
- ✅ Export JSON/TXT
- ✅ Interface CLI colorée

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- [python-whois](https://github.com/richardpenman/whois) pour les requêtes WHOIS
- [dnspython](https://github.com/rthalley/dnspython) pour la résolution DNS
- [crt.sh](https://crt.sh/) pour les certificats SSL publics
- [ProjectDiscovery](https://github.com/projectdiscovery) pour subfinder
- [OWASP Amass](https://github.com/OWASP/Amass) pour la reconnaissance passive

## 📞 Support

- 🐛 **Issues** : [GitHub Issues](https://github.com/votre-username/nettrace/issues)
- 💬 **Discussions** : [GitHub Discussions](https://github.com/votre-username/nettrace/discussions)
- 📧 **Email** : contact@root3301.fr

---

<div align="center">

**⭐ Si ce projet vous aide, n'hésitez pas à lui donner une étoile ! ⭐**

Made with ❤️ by [Root3301](https://github.com/Rooot3301)

</div>
