# Guide de Contribution

Merci de votre intérêt pour contribuer à NetTrace ! Ce guide vous aidera à contribuer efficacement au projet.

## 🚀 Comment contribuer

### 1. Fork et Clone
```bash
# Fork le repository sur GitHub
# Puis clonez votre fork
git clone https://github.com/VOTRE-USERNAME/nettrace.git
cd nettrace
```

### 2. Installation pour développement
```bash
# Installer les dépendances
pip install -r requirements.txt

# Installer les outils de développement (optionnel)
pip install black flake8 pytest
```

### 3. Créer une branche
```bash
git checkout -b feature/ma-nouvelle-fonctionnalite
# ou
git checkout -b fix/correction-bug
```

## 📋 Types de contributions

### 🐛 Corrections de bugs
- Décrivez le bug dans l'issue
- Incluez les étapes pour reproduire
- Proposez une solution avec tests

### ✨ Nouvelles fonctionnalités
- Discutez d'abord dans une issue
- Respectez l'architecture existante
- Ajoutez de la documentation

### 📚 Documentation
- Améliorations du README
- Commentaires de code
- Exemples d'utilisation

### 🔧 Améliorations techniques
- Optimisations de performance
- Refactoring de code
- Amélioration de la sécurité

## 🏗️ Structure du projet

```
nettrace/
├── config/          # Configuration globale
├── core/           # Modules centraux (cache, display)
├── analyzers/      # Modules d'analyse spécialisés
├── exporters/      # Générateurs de rapports
├── examples/       # Exemples et configurations
├── cache/          # Cache (ignoré par git)
├── reports/        # Rapports générés (ignoré par git)
├── logs/           # Logs système (ignoré par git)
├── nettrace.py     # Script principal
├── utils.py        # Classes et fonctions utilitaires
└── requirements.txt # Dépendances Python
```

## 📝 Standards de code

### Style Python
- Suivre PEP 8
- Utiliser des noms descriptifs
- Commenter le code complexe
- Docstrings pour toutes les fonctions publiques

### Exemple de docstring
```python
def analyze_domain(domain: str, verbose: bool = False) -> Dict:
    """
    Analyse un domaine et retourne les résultats.
    
    Args:
        domain: Le domaine à analyser (ex: 'google.com')
        verbose: Mode verbeux pour plus de détails
        
    Returns:
        Dict contenant les résultats d'analyse
        
    Raises:
        ValueError: Si le domaine est invalide
    """
```

### Gestion d'erreurs
```python
try:
    # Code qui peut échouer
    result = risky_operation()
except SpecificException as e:
    # Gestion spécifique
    logger.error(f"Erreur spécifique: {str(e)}")
    return None
except Exception as e:
    # Gestion générale
    logger.error(f"Erreur inattendue: {str(e)}")
    raise
```

## 🧪 Tests

### Lancer les tests
```bash
# Tests unitaires (quand disponibles)
python -m pytest tests/

# Test manuel
python nettrace.py -d google.com -v
```

### Tester vos modifications
- Testez sur plusieurs domaines différents
- Vérifiez les cas d'erreur
- Testez les exports dans tous les formats
- Vérifiez le mode verbeux

## 📤 Soumettre une Pull Request

### 1. Préparer votre PR
```bash
# S'assurer que le code fonctionne
python nettrace.py -d example.com

# Vérifier le style (optionnel)
black nettrace.py utils.py
flake8 --max-line-length=100 *.py

# Commit avec message descriptif
git add .
git commit -m "feat: ajouter analyse de performance web"
```

### 2. Pousser et créer la PR
```bash
git push origin feature/ma-nouvelle-fonctionnalite
```

Puis créez la Pull Request sur GitHub avec :
- **Titre descriptif**
- **Description détaillée** des changements
- **Tests effectués**
- **Screenshots** si applicable

### 3. Template de PR
```markdown
## Description
Brève description des changements apportés.

## Type de changement
- [ ] Correction de bug
- [ ] Nouvelle fonctionnalité
- [ ] Amélioration de performance
- [ ] Documentation

## Tests effectués
- [ ] Tests sur domaines multiples
- [ ] Vérification des exports
- [ ] Tests des cas d'erreur

## Checklist
- [ ] Le code suit les standards du projet
- [ ] Les tests passent
- [ ] La documentation est mise à jour
- [ ] Pas de régression introduite
```

## 🎯 Priorités de développement

### Haute priorité
- Corrections de bugs critiques
- Amélioration de la stabilité
- Optimisation des performances

### Moyenne priorité
- Nouvelles sources de données
- Améliorations de l'interface
- Nouveaux formats d'export

### Basse priorité
- Fonctionnalités expérimentales
- Intégrations avancées
- Interface graphique

## 🔒 Sécurité

### Principes à respecter
- **Pas de scan actif** ou intrusif
- **Sources publiques uniquement**
- **Respect des rate limits**
- **Validation des entrées**
- **Gestion sécurisée des secrets**

### Signaler une vulnérabilité
Envoyez un email privé plutôt qu'une issue publique pour les problèmes de sécurité.

## 💬 Communication

### Où discuter
- **Issues GitHub** : Bugs et fonctionnalités
- **Discussions GitHub** : Questions générales
- **Pull Requests** : Revue de code

### Ton et respect
- Soyez respectueux et constructifs
- Aidez les nouveaux contributeurs
- Partagez vos connaissances

## 🏆 Reconnaissance

Tous les contributeurs seront mentionnés dans :
- Le fichier AUTHORS
- Les notes de version
- La documentation

## 📞 Besoin d'aide ?

- Consultez la documentation
- Regardez les issues existantes
- Posez des questions dans les discussions
- Contactez les mainteneurs

Merci de contribuer à NetTrace ! 🎉