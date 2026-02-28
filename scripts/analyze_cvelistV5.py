#!/usr/bin/env python3
"""
Nexus Automation Framework - CVEProject/cvelistV5 Analysis
Analyzes the official CVE repository for quality and content
"""

import os
import json
from pathlib import Path

def analyze_cve_quality(directory):
    """Analyze CVE data quality"""
    quality_stats = {
        'total_files': 0,
        'valid_json': 0,
        'with_cvss': 0,
        'with_description': 0,
        'with_references': 0,
        'sample_cves': []
    }
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json') and 'CVE-' in file:
                file_path = Path(root) / file
                quality_stats['total_files'] += 1
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        quality_stats['valid_json'] += 1
                        
                        # Check for CVSS
                        if 'metrics' in str(data) or 'cvss' in str(data).lower():
                            quality_stats['with_cvss'] += 1
                        
                        # Check for description
                        if 'description' in str(data) or 'descriptions' in str(data):
                            quality_stats['with_description'] += 1
                        
                        # Check for references
                        if 'references' in str(data) or 'reference' in str(data):
                            quality_stats['with_references'] += 1
                        
                        # Sample CVEs (first 5)
                        if len(quality_stats['sample_cves']) < 5:
                            cve_id = file.replace('.json', '')
                            quality_stats['sample_cves'].append(cve_id)
                
                except Exception as e:
                    continue
                
                # Stop after analyzing 1000 files for speed
                if quality_stats['total_files'] >= 1000:
                    break
    
    return quality_stats

def count_cve_files(directory):
    """Count CVE files by year"""
    cve_count = 0
    year_stats = {}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                file_path = Path(root) / file
                try:
                    # Extract year from path or filename
                    if 'cves' in root:
                        year_dir = Path(root).name
                        if year_dir.isdigit():
                            year = int(year_dir)
                        else:
                            # Try to extract from filename
                            if 'CVE-' in file:
                                year = int(file.split('-')[1])
                            else:
                                continue
                        
                        # Count CVEs in this file
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Count CVE occurrences (rough estimate)
                            cve_in_file = content.count('CVE-')
                            cve_count += cve_in_file
                            
                            if year not in year_stats:
                                year_stats[year] = 0
                            year_stats[year] += cve_in_file
                except Exception as e:
                    continue
    
    return cve_count, year_stats

def main():
    cve_dir = Path('cve-cvelistV5')
    if not cve_dir.exists():
        print('❌ Répertoire cve-cvelistV5 non trouvé')
        return
    
    print('📊 ANALYSE COMPLÈTE CVEProject/cvelistV5')
    print('=' * 60)
    
    # Count CVEs
    total_cves, yearly_stats = count_cve_files(cve_dir)
    
    print(f'Total estimé de CVEs: {total_cves:,}')
    print()
    
    print('📅 Distribution par année:')
    for year in sorted(yearly_stats.keys(), reverse=True)[:10]:  # Top 10 years
        print(f'  {year}: {yearly_stats[year]:,} CVEs')
    
    if len(yearly_stats) > 10:
        print(f'  ... et {len(yearly_stats) - 10} autres années')
    
    print()
    print('📈 Statistiques générales:')
    print(f'  Années couvertes: {len(yearly_stats)}')
    print(f'  Moyenne par année: {total_cves // len(yearly_stats):,}')
    print(f'  Année la plus active: {max(yearly_stats, key=yearly_stats.get)} ({yearly_stats[max(yearly_stats, key=yearly_stats.get)]:,})')
    print(f'  Plage d\'années: {min(yearly_stats)} - {max(yearly_stats)}')
    
    # Quality analysis
    print()
    print('🔍 Analyse de qualité:')
    quality = analyze_cve_quality(cve_dir)
    print(f'  Fichiers analysés: {quality["total_files"]:,}')
    print(f'  JSON valides: {quality["valid_json"]:,} ({quality["valid_json"]/quality["total_files"]*100:.1f}%)')
    print(f'  Avec CVSS: {quality["with_cvss"]:,} ({quality["with_cvss"]/quality["valid_json"]*100:.1f}%)')
    print(f'  Avec description: {quality["with_description"]:,} ({quality["with_description"]/quality["valid_json"]*100:.1f}%)')
    print(f'  Avec références: {quality["with_references"]:,} ({quality["with_references"]/quality["valid_json"]*100:.1f}%)')
    
    print()
    print('🎯 Comparaison avec votre base actuelle:')
    print(f'  Votre base knowledge.db: 120,008 CVEs')
    print(f'  CVEProject/cvelistV5: {total_cves:,} CVEs')
    print(f'  Potentiel d\'amélioration: {total_cves - 120008:,} CVEs supplémentaires')
    print(f'  Couverture potentielle: {(total_cves / 120008 * 100 - 100):.1f}% d\'amélioration')
    
    # Sample CVEs
    print()
    print('📋 Exemples de CVEs dans cvelistV5:')
    for cve in quality['sample_cves']:
        print(f'  - {cve}')
    
    # Detailed example
    sample_file = None
    for root, dirs, files in os.walk(cve_dir):
        for file in files:
            if file.endswith('.json') and 'CVE-2024' in file:
                sample_file = Path(root) / file
                break
        if sample_file:
            break
    
    if sample_file:
        print()
        print(f'🔬 DÉTAIL D\'EXEMPLE: {sample_file.name}')
        try:
            with open(sample_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f'  Keys: {list(data.keys())}')
                if 'containers' in data:
                    print(f'  Containers: {list(data["containers"].keys())}')
                if 'cveMetadata' in data:
                    metadata = data['cveMetadata']
                    print(f'  CVE ID: {metadata.get("cveId", "N/A")}')
                    print(f'  State: {metadata.get("state", "N/A")}')
                    print(f'  Assigner: {metadata.get("assignerOrgId", "N/A")}')
        except Exception as e:
            print(f'  Erreur lecture: {e}')

if __name__ == "__main__":
    main()
