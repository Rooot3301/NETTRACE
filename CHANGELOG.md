# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-XX

### Ajouté
- 🎉 Version initiale de NetTrace
- ✅ Analyse WHOIS complète avec informations détaillées
- ✅ Résolution DNS multi-enregistrements (A, AAAA, MX, TXT, NS, CNAME)
- ✅ Extraction de sous-domaines via Certificate Transparency (crt.sh)
- ✅ Support des outils externes (subfinder, amass)
- ✅ Détection avancée des technologies web (frameworks, serveurs, CDN, CMS)
- ✅ Analyse de sécurité complète (headers, SSL, redirections)
- ✅ Géolocalisation et analyse d'infrastructure
- ✅ Système de réputation multi-sources (VirusTotal, listes malware, PhishTank)
- ✅ Scores intelligents (confiance, sécurité, réputation) sur 100 points
- ✅ Système de cache intelligent avec TTL différencié
- ✅ Export multi-formats (JSON, HTML, CSV, XML, TXT)
- ✅ Analyse en lot avec gestion d'erreurs
- ✅ Système de monitoring et d'alertes
- ✅ Interface CLI colorée et intuitive
- ✅ Mode interactif avec menu avancé
- ✅ Rapports HTML magnifiques avec design moderne
- ✅ Architecture modulaire et extensible
- ✅ Gestion robuste des erreurs et timeouts
- ✅ Documentation complète avec exemples

### Fonctionnalités techniques
- Cache intelligent avec TTL configurable par type de données
- Système de scoring basé sur des critères pondérés
- Détection de plus de 50 technologies web différentes
- Support IPv4 et IPv6 avec géolocalisation
- Analyse de latence depuis plusieurs points
- Vérification de réputation via sources publiques
- Export HTML responsive avec design glassmorphism
- Interface en ligne de commande complète
- Mode batch pour traitement en masse
- Système de monitoring avec historique des changements

### Sécurité
- Utilisation exclusive de sources publiques (OSINT)
- Respect des rate limits et robots.txt
- Pas de scan actif ou intrusif
- Gestion sécurisée des API keys optionnelles
- Validation stricte des entrées utilisateur

### Performance
- Cache intelligent pour éviter les requêtes répétitives
- Requêtes parallèles pour optimiser les temps de réponse
- Gestion des timeouts et retry automatique
- Limitation du nombre de requêtes simultanées

## [Unreleased]

### Prévu
- [ ] Interface web avec dashboard
- [ ] API REST pour intégrations
- [ ] Base de données pour historique long terme
- [ ] Notifications Slack/Discord/Teams
- [ ] Analyse de vulnérabilités avancée
- [ ] Intégration Shodan (avec API key)
- [ ] Support de nouveaux formats d'export
- [ ] Mode stealth avec proxies
- [ ] Analyse de performance web
- [ ] Détection de phishing avancée