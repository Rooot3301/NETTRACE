#!/usr/bin/env python3
"""
NetTrace - Production-ready OSINT domain analysis tool
Author: Root3301
Version: 1.0.1

Complete OSINT analysis tool for domains without paid APIs
Production-ready with comprehensive error handling and optimization
"""

import argparse
import json
import sys
import time
import logging
import signal
from datetime import datetime
from pathlib import Path

# Configuration du logging avant les imports
from config.settings import LOG_LEVEL, LOG_FORMAT, LOG_FILE, LOGS_DIR

# Créer le dossier logs
LOGS_DIR.mkdir(exist_ok=True)

# Configuration logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Imports après configuration logging
from utils import DomainAnalyzer, show_interactive_menu, validate_domain
from core.display import (print_banner, print_section, print_success, 
                         print_error, print_warning, print_info)
from config.settings import REPORTS_DIR
from core.cache import cache

# Gestionnaire de signaux pour arrêt propre
def signal_handler(signum, frame):
    """Gestionnaire pour arrêt propre du programme"""
    print_warning("\n⚠️  Arrêt demandé par l'utilisateur...")
    logger.info("Programme arrêté par signal utilisateur")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def run_analysis(domain, output=None, format_type='json', verbose=False, analysis_type='complete'):
    """Lance l'analyse pour un domaine donné avec gestion d'erreurs robuste"""
    start_time = time.time()
    
    # Validation du domaine
    domain = domain.lower().strip()
    if not validate_domain(domain):
        print_error("❌ Domaine invalide. Veuillez spécifier un domaine valide (ex: google.com)")
        logger.error(f"Domaine invalide fourni: {domain}")
        return False
    
    logger.info(f"Début analyse {analysis_type} pour {domain}")
    print_info(f"🎯 Analyse du domaine: {domain}")
    print_info(f"📋 Type d'analyse: {analysis_type}")
    print_info("=" * 60)
    
    try:
        # Initialisation de l'analyseur
        analyzer = DomainAnalyzer(domain, verbose=verbose)
        
        # Exécution de l'analyse selon le type
        if analysis_type == 'quick':
            results = analyzer.run_quick_analysis()
        elif analysis_type == 'standard':
            results = analyzer.run_standard_analysis()
        else:
            results = analyzer.run_full_analysis()
        
        if not results:
            print_error("❌ Aucun résultat obtenu")
            return False
        
        # Affichage des résultats
        analyzer.display_results(results)
        
        # Export si demandé
        if output:
            success = analyzer.export_results(results, output, format_type)
            if not success:
                logger.error(f"Échec export vers {output}")
                return False
        
        # Statistiques de performance
        execution_time = time.time() - start_time
        logger.info(f"Analyse {analysis_type} terminée en {execution_time:.2f}s")
        
        print_info("\n" + "=" * 60)
        print_success(f"🎉 Analyse terminée avec succès! ({execution_time:.1f}s)")
        return True
        
    except KeyboardInterrupt:
        print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
        logger.warning(f"Analyse interrompue pour {domain}")
        return False
    except ValueError as e:
        print_error(f"❌ Erreur de validation: {str(e)}")
        logger.error(f"Erreur validation {domain}: {str(e)}")
        return False
    except Exception as e:
        print_error(f"❌ Erreur lors de l'analyse: {str(e)}")
        logger.error(f"Erreur analyse {domain}: {str(e)}", exc_info=True)
        if verbose:
            import traceback
            traceback.print_exc()
        return False

def main():
    """Point d'entrée principal avec gestion d'erreurs complète"""
    try:
        logger.info("Démarrage NetTrace")
        main_execution()
    except Exception as e:
        logger.critical(f"Erreur critique: {str(e)}", exc_info=True)
        print_error(f"❌ Erreur critique: {str(e)}")
        sys.exit(1)
    finally:
        logger.info("Arrêt NetTrace")

def main_execution():
    """Exécution principale du programme"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="NetTrace - Outil OSINT d'analyse de domaines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'usage:
  python nettrace.py --domain google.com
  python nettrace.py --domain example.com --output report.json
  python nettrace.py --domain test.com --format txt --output report.txt
  python nettrace.py --interactive
  python nettrace.py --batch-file domains.txt --format html
        """
    )
    
    parser.add_argument(
        '--domain', '-d', 
        help='Domaine à analyser (ex: google.com)'
    )
    
    parser.add_argument(
        '--output', '-o', 
        help='Fichier de sortie pour sauvegarder le rapport'
    )
    
    parser.add_argument(
        '--format', '-f', 
        choices=['json', 'txt', 'html', 'csv', 'xml'], 
        default='json',
        help='Format de sortie (json, txt, html, csv, xml - défaut: json)'
    )
    
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Mode verbeux'
    )
    
    parser.add_argument(
        '--interactive', '-i', 
        action='store_true',
        help='Mode interactif avec menu'
    )
    
    parser.add_argument(
        '--clear-cache', 
        action='store_true',
        help='Vider le cache avant l\'analyse'
    )
    
    parser.add_argument(
        '--batch-file', 
        help='Fichier contenant une liste de domaines à analyser'
    )
    
    parser.add_argument(
        '--analysis-type',
        choices=['quick', 'standard', 'complete'],
        default='complete',
        help='Type d\'analyse (quick, standard, complete - défaut: complete)'
    )
    
    parser.add_argument(
        '--optimize-cache',
        action='store_true',
        help='Optimiser le cache en supprimant les éléments expirés'
    )
    
    args = parser.parse_args()
    
    # Optimisation du cache si demandée
    if args.optimize_cache:
        print_info("🔧 Optimisation du cache...")
        stats = cache.optimize()
        print_success(f"✅ Cache optimisé: {stats['disk_files_removed']} fichiers supprimés")
        if not args.domain and not args.interactive and not args.batch_file:
            return
    
    # Vider le cache si demandé
    if args.clear_cache:
        cache.clear()
        print_success("✅ Cache vidé")
        logger.info("Cache vidé par l'utilisateur")
    
    # Mode batch
    if args.batch_file:
        success = run_batch_analysis(
            args.batch_file, 
            args.format, 
            args.verbose, 
            args.analysis_type
        )
        sys.exit(0 if success else 1)
    
    # Mode interactif par défaut si aucun domaine spécifié
    if args.interactive or not args.domain:
        show_interactive_menu()
    else:
        # Mode direct
        success = run_analysis(
            args.domain, 
            args.output, 
            args.format, 
            args.verbose, 
            args.analysis_type
        )
        sys.exit(0 if success else 1)

def run_batch_analysis(batch_file: str, format_type: str = 'json', 
                      verbose: bool = False, analysis_type: str = 'standard') -> bool:
    """Lance l'analyse en lot depuis un fichier avec gestion d'erreurs robuste"""
    logger.info(f"Début analyse batch: {batch_file}")
    
    try:
        batch_path = Path(batch_file)
        if not batch_path.exists():
            print_error(f"❌ Fichier '{batch_file}' introuvable")
            return False
        
        with open(batch_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Validation des domaines
        valid_domains = []
        for domain in domains:
            if validate_domain(domain):
                valid_domains.append(domain.lower())
            else:
                print_warning(f"⚠️  Domaine invalide ignoré: {domain}")
        
        domains = valid_domains
        
        if not domains:
            print_error("❌ Aucun domaine trouvé dans le fichier")
            return False
        
        print_info(f"🚀 Analyse {analysis_type} en lot de {len(domains)} domaine(s)...")
        logger.info(f"Analyse batch: {len(domains)} domaines valides")
        
        success_count = 0
        all_results = []
        start_time = time.time()
        
        for i, domain in enumerate(domains, 1):
            print_info(f"\n[{i}/{len(domains)}] Analyse de: {domain}")
            
            try:
                # Générer un nom de fichier unique
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"batch_{analysis_type}_{domain.replace('.', '_')}_{timestamp}.{format_type}"
                
                success = run_analysis(domain, filename, format_type, verbose, analysis_type)
                if success:
                    success_count += 1
                else:
                    errors.append(f"{domain}: Échec de l'analyse")
                
                # Pause entre analyses
                if i < len(domains):
                    time.sleep(1)  # Réduit pour la production
                    
            except KeyboardInterrupt:
                print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
                logger.warning("Analyse batch interrompue")
                break
            except Exception as e:
                error_msg = f"{domain}: {str(e)}"
                errors.append(error_msg)
                logger.error(f"Erreur batch {domain}: {str(e)}")
                print_error(f"❌ Erreur pour {domain}: {str(e)}")
        
        # Statistiques finales
        execution_time = time.time() - start_time
        print_info(f"\n📊 Résultats: {success_count}/{len(domains)} analyses réussies")
        print_info(f"⏱️  Temps total: {execution_time:.1f}s")
        
        if errors:
            print_warning(f"⚠️  {len(errors)} erreurs rencontrées:")
            for error in errors[:5]:  # Afficher les 5 premières erreurs
                print_warning(f"   • {error}")
            if len(errors) > 5:
                print_warning(f"   ... et {len(errors) - 5} autres erreurs")
        
        logger.info(f"Analyse batch terminée: {success_count}/{len(domains)} succès")
        return success_count > 0
        
    except FileNotFoundError:
        print_error(f"❌ Fichier '{batch_file}' introuvable")
        logger.error(f"Fichier batch introuvable: {batch_file}")
        return False
    except PermissionError:
        print_error(f"❌ Permissions insuffisantes pour lire '{batch_file}'")
        logger.error(f"Permissions insuffisantes: {batch_file}")
        return False
    except Exception as e:
        print_error(f"❌ Erreur lors de l'analyse en lot: {str(e)}")
        logger.error(f"Erreur analyse batch: {str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    main()