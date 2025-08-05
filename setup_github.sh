#!/bin/bash

# Script de configuration pour GitHub
# Usage: ./setup_github.sh [nom-du-repo]

set -e

REPO_NAME=${1:-nettrace}
GITHUB_USERNAME=${2:-"votre-username"}

echo "🚀 Configuration de NetTrace pour GitHub"
echo "========================================"

# Vérifier si git est installé
if ! command -v git &> /dev/null; then
    echo "❌ Git n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

# Initialiser le repository git si nécessaire
if [ ! -d ".git" ]; then
    echo "📁 Initialisation du repository Git..."
    git init
    git branch -M main
fi

# Ajouter tous les fichiers
echo "📋 Ajout des fichiers..."
git add .

# Premier commit
echo "💾 Premier commit..."
git commit -m "🎉 Initial commit - NetTrace v1.0

✨ Fonctionnalités principales:
- Analyse WHOIS complète
- Résolution DNS multi-enregistrements  
- Extraction de sous-domaines via Certificate Transparency
- Détection des technologies web (50+ technologies)
- Analyse de sécurité avancée (headers, SSL, redirections)
- Géolocalisation et analyse d'infrastructure
- Système de réputation multi-sources
- Scores intelligents (confiance, sécurité, réputation)
- Cache intelligent avec TTL différencié
- Export multi-formats (JSON, HTML, CSV, XML)
- Interface CLI colorée et mode interactif
- Rapports HTML magnifiques avec design moderne
- Architecture modulaire et extensible

🛡️ 100% légal - Sources publiques uniquement (OSINT)
📊 Scoring intelligent basé sur des critères pondérés
🎨 Interface moderne avec design glassmorphism
⚡ Performance optimisée avec cache et requêtes parallèles"

# Instructions pour GitHub
echo ""
echo "🌟 Prochaines étapes pour GitHub:"
echo "================================="
echo ""
echo "1. Créez un nouveau repository sur GitHub:"
echo "   https://github.com/new"
echo "   Nom: $REPO_NAME"
echo "   Description: 🔍 Outil OSINT d'analyse de domaines - Analyse complète, sécurité, réputation, technologies web"
echo ""
echo "2. Ajoutez le remote et poussez:"
echo "   git remote add origin https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
echo "   git push -u origin main"
echo ""
echo "3. Configurez les topics GitHub (optionnel):"
echo "   osint, cybersecurity, domain-analysis, python, security-tools, reconnaissance"
echo ""
echo "4. Activez GitHub Pages pour la documentation:"
echo "   Settings > Pages > Source: Deploy from a branch > main"
echo ""
echo "✅ Repository prêt pour GitHub!"
echo ""
echo "📋 Fichiers créés:"
echo "   - .gitignore (ignore cache, logs, config locale)"
echo "   - LICENSE (MIT License)"
echo "   - CHANGELOG.md (historique des versions)"
echo "   - CONTRIBUTING.md (guide de contribution)"
echo "   - setup_github.sh (ce script)"
echo ""
echo "🎯 Pour pousser maintenant:"
echo "   git remote add origin https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
echo "   git push -u origin main"