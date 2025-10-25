"""Test pattern analyzer"""
from app.database import get_db
from app.models import Vulnerability
from app.services.behavior.pattern_analyzer import PatternAnalyzer

print('=' * 60)
print('PATTERN ANALYZER TEST')
print('=' * 60)

with get_db() as db:
    vulns = db.query(Vulnerability).all()
    print(f'\nAnalyzing {len(vulns)} vulnerabilities...')
    
    analyzer = PatternAnalyzer(db)
    results = analyzer.analyze_patterns(vulns)
    
    print(f'\nPatterns Found: {len(results["patterns_found"])}')
    for pattern in results['patterns_found']:
        print(f'\n  {pattern["name"]}')
        print(f'  Category: {pattern["category"]}')
        print(f'  Severity: {pattern["severity"]}')
        print(f'  Occurrences: {pattern["occurrences"]}')
        print(f'  Affected files: {len(pattern["affected_files"])}')
    
    print(f'\nHotspots Found: {len(results["hotspots"])}')
    for hotspot in results['hotspots']:
        print(f'\n  {hotspot["path"]}')
        print(f'  Vulnerabilities: {hotspot["vulnerability_count"]}')
    
    print(f'\nClusters Found: {len(results["clusters"])}')
    for cluster in results['clusters']:
        print(f'\n  {cluster["name"]} ({cluster["count"]} items)')
    
    print(f'\nRecommendations: {len(results["recommendations"])}')
    for i, rec in enumerate(results['recommendations'][:3], 1):
        print(f'\n  {i}. [{rec["priority"]}] {rec["title"]}')

print('\nPattern analysis complete!')
