#!/usr/bin/env python3
"""
NetTrace - Outil OSINT d'analyse de domaines
Auteur: Assistant IA
Version: 1.0

Outil complet d'analyse OSINT pour domaines sans APIs payantes
"""

import argparse
import json
import sys
import time
from datetime import datetime
from utils import (DomainAnalyzer, print_banner, print_section, print_success, 
                   print_error, print_warning, print_info, show_interactive_menu)
from config.settings import REPORTS_DIR
from core.cache import cache

def run_analysis(domain, output=None, format_type='json', verbose=False):
    """Lance l'analyse pour un domaine donné"""
    # Validation du domaine
    domain = domain.lower().strip()
    if not domain or '.' not in domain:
        print_error("❌ Domaine invalide. Veuillez spécifier un domaine valide (ex: google.com)")
        return False
    
    print_info(f"🎯 Analyse du domaine: {domain}")
    print_info("=" * 60)
    
    # Initialisation de l'analyseur
    analyzer = DomainAnalyzer(domain, verbose=verbose)
    
    try:
        # Exécution de l'analyse complète
        results = analyzer.run_full_analysis()
        
        # Affichage des résultats
        analyzer.display_results(results)
        
        # Export si demandé
        if output:
            success = analyzer.export_results(results, output, format_type)
            if not success:
                return False
        
        print_info("\n" + "=" * 60)
        print_success("🎉 Analyse terminée avec succès!")
        return True
        
    except KeyboardInterrupt:
        print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
        return False
    except Exception as e:
        print_error(f"❌ Erreur lors de l'analyse: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False

def main():
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
    
    args = parser.parse_args()
    
    # Vider le cache si demandé
    if args.clear_cache:
        cache.clear()
        print_success("✅ Cache vidé")
    
    # Mode batch
    if args.batch_file:
        success = run_batch_analysis(args.batch_file, args.format, args.verbose)
        sys.exit(0 if success else 1)
    
    # Mode interactif par défaut si aucun domaine spécifié
    if args.interactive or not args.domain:
        show_interactive_menu()
    else:
        # Mode direct
        success = run_analysis(args.domain, args.output, args.format, args.verbose)
        sys.exit(0 if success else 1)

def run_batch_analysis(batch_file: str, format_type: str = 'json', verbose: bool = False) -> bool:
    """Lance l'analyse en lot depuis un fichier"""
    try:
        with open(batch_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not domains:
            print_error("❌ Aucun domaine trouvé dans le fichier")
            return False
        
        print_info(f"🚀 Analyse en lot de {len(domains)} domaine(s)...")
        
        success_count = 0
        all_results = []
        
        for i, domain in enumerate(domains, 1):
            print_info(f"\n[{i}/{len(domains)}] Analyse de: {domain}")
            
            try:
                # Générer un nom de fichier unique
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"batch_{domain.replace('.', '_')}_{timestamp}.{format_type}"
                
                success = run_analysis(domain, filename, format_type, verbose)
                if success:
                    success_count += 1
                
                # Pause entre analyses
                if i < len(domains):
                    time.sleep(2)
                    
            except KeyboardInterrupt:
                print_warning("\n⚠️  Analyse interrompue par l'utilisateur")
                break
        
        print_info(f"\n📊 Résultats: {success_count}/{len(domains)} analyses réussies")
        return success_count > 0
        
    except FileNotFoundError:
        print_error(f"❌ Fichier '{batch_file}' introuvable")
        return False
    except Exception as e:
        print_error(f"❌ Erreur lors de l'analyse en lot: {str(e)}")
        return False

if __name__ == "__main__":
    main()