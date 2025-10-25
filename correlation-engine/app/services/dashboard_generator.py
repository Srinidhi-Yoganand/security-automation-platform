"""
Security Dashboard Generator

Generates an HTML dashboard from correlation report data with Phase 2 behavior analysis.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from app.database import get_db
from app.models import Vulnerability, Scan, VulnerabilityState
from app.services.behavior.pattern_analyzer import PatternAnalyzer
from sqlalchemy import func


class DashboardGenerator:
    """Generate interactive HTML security dashboard with behavior analysis"""
    
    def __init__(self, include_behavior_analysis: bool = False):
        """
        Initialize dashboard generator.
        
        Args:
            include_behavior_analysis: Whether to include Phase 2 behavior analysis data
        """
        self.include_behavior_analysis = include_behavior_analysis
    
    def _get_behavior_data(self) -> Optional[Dict[str, Any]]:
        """Fetch Phase 2 behavior analysis data from database"""
        if not self.include_behavior_analysis:
            return None
        
        try:
            with get_db() as db:
                # Get metrics
                total_vulns = db.query(Vulnerability).count()
                total_scans = db.query(Scan).count()
                
                if total_vulns == 0:
                    return None
                
                # State distribution
                state_counts = {}
                for state in VulnerabilityState:
                    count = db.query(Vulnerability).filter(
                        Vulnerability.state == state
                    ).count()
                    state_counts[state.value] = count
                
                # Severity distribution
                severity_counts = db.query(
                    Vulnerability.severity,
                    func.count(Vulnerability.id)
                ).group_by(Vulnerability.severity).all()
                severity_dict = {sev: count for sev, count in severity_counts}
                
                # Risk metrics
                vulns = db.query(Vulnerability).all()
                avg_risk = sum(v.risk_score for v in vulns) / len(vulns) if vulns else 0
                high_risk_count = sum(1 for v in vulns if v.risk_score >= 7.0)
                
                # Pattern analysis
                analyzer = PatternAnalyzer(db)
                pattern_results = analyzer.analyze_patterns()
                
                # Trend data (last 10 scans)
                scans = db.query(Scan).order_by(Scan.timestamp.desc()).limit(10).all()
                scans.reverse()  # Oldest first for charts
                
                trend_data = []
                for scan in scans:
                    scan_vulns = db.query(Vulnerability).filter(
                        Vulnerability.scan_id == scan.id
                    ).all()
                    
                    trend_data.append({
                        'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M'),
                        'total': len(scan_vulns),
                        'critical': sum(1 for v in scan_vulns if v.severity == 'critical'),
                        'high': sum(1 for v in scan_vulns if v.severity == 'high'),
                        'medium': sum(1 for v in scan_vulns if v.severity == 'medium'),
                        'low': sum(1 for v in scan_vulns if v.severity == 'low')
                    })
                
                # Top risk vulnerabilities
                top_risks = db.query(Vulnerability).filter(
                    Vulnerability.state != VulnerabilityState.FIXED
                ).order_by(Vulnerability.risk_score.desc()).limit(10).all()
                
                return {
                    'total_scans': total_scans,
                    'total_vulnerabilities': total_vulns,
                    'state_counts': state_counts,
                    'severity_counts': severity_dict,
                    'average_risk_score': round(avg_risk, 2),
                    'high_risk_count': high_risk_count,
                    'patterns': pattern_results,
                    'trends': trend_data,
                    'top_risks': [
                        {
                            'id': v.id,
                            'type': v.type,
                            'severity': v.severity,
                            'risk_score': v.risk_score,
                            'file_path': v.file_path,
                            'line_number': v.line_number,
                            'state': v.state.value,
                            'age_days': v.age_days
                        }
                        for v in top_risks
                    ]
                }
        except Exception as e:
            print(f"Warning: Could not fetch behavior data: {e}")
            return None
    
    def generate(self, report_data: Dict[str, Any]) -> str:
        """
        Generate HTML dashboard from correlation report.
        
        Args:
            report_data: Dictionary containing correlation results
            
        Returns:
            HTML string
        """
        total = report_data.get('total_findings', 0)
        correlated = report_data.get('correlated_count', 0)
        critical = report_data.get('critical', 0)
        high = report_data.get('high', 0)
        medium = report_data.get('medium', 0)
        low = report_data.get('low', 0)
        findings = report_data.get('findings', [])
        
        # Get Phase 2 behavior data if enabled
        behavior_data = self._get_behavior_data()
        
        # Generate findings table rows
        findings_html = ""
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_class = {
                'critical': 'bg-purple-100 text-purple-800',
                'high': 'bg-red-100 text-red-800',
                'medium': 'bg-yellow-100 text-yellow-800',
                'low': 'bg-blue-100 text-blue-800'
            }.get(severity, 'bg-gray-100 text-gray-800')
            
            sources = ', '.join(finding.get('sources', []))
            confirmed = '✓' if finding.get('data_flow_confirmed') else '○'
            
            # Generate unique ID for this finding
            finding_id = finding.get('id', hash(str(finding.get('file', '')) + str(finding.get('line', ''))))
            
            findings_html += f"""
                <tr class="border-b hover:bg-gray-50">
                    <td class="px-4 py-3">{finding.get('type', 'Unknown')}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-1 rounded text-sm {severity_class}">
                            {severity.upper()}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-sm">{finding.get('file', 'N/A')}</td>
                    <td class="px-4 py-3">{finding.get('line', '0')}</td>
                    <td class="px-4 py-3 text-sm">{sources}</td>
                    <td class="px-4 py-3 text-center">{int(finding.get('confidence', 0) * 100)}%</td>
                    <td class="px-4 py-3 text-center text-lg">{confirmed}</td>
                    <td class="px-4 py-3">
                        <button onclick="generatePatch({finding_id})" 
                                class="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded text-sm transition-colors"
                                id="patch-btn-{finding_id}">
                            🤖 Generate Patch
                        </button>
                        <div id="patch-result-{finding_id}" class="mt-2 hidden"></div>
                    </td>
                </tr>
            """
        
        # Generate complete HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Correlation Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h1 class="text-3xl font-bold text-gray-800 mb-2">Security Correlation Dashboard</h1>
            <p class="text-gray-600">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Total Findings</div>
                <div class="text-3xl font-bold text-gray-800">{total}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Correlated</div>
                <div class="text-3xl font-bold text-blue-600">{correlated}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Critical + High</div>
                <div class="text-3xl font-bold text-red-600">{critical + high}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Correlation Rate</div>
                <div class="text-3xl font-bold text-green-600">
                    {int((correlated / total * 100) if total > 0 else 0)}%
                </div>
            </div>
        </div>

        <!-- Severity Breakdown -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-bold mb-4">Severity Distribution</h2>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-bold mb-4">Severity Breakdown</h2>
                <div class="space-y-3">
                    <div class="flex justify-between items-center">
                        <span class="text-purple-600 font-semibold">Critical</span>
                        <span class="text-2xl font-bold">{critical}</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-red-600 font-semibold">High</span>
                        <span class="text-2xl font-bold">{high}</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-yellow-600 font-semibold">Medium</span>
                        <span class="text-2xl font-bold">{medium}</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-blue-600 font-semibold">Low</span>
                        <span class="text-2xl font-bold">{low}</span>
                    </div>
                </div>
            </div>
        </div>

        {self._generate_behavior_analysis_html(behavior_data)}

        <!-- Findings Table -->
        <div class="bg-white rounded-lg shadow overflow-hidden">
            <div class="px-6 py-4 border-b">
                <h2 class="text-xl font-bold">Correlated Findings</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">File</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Line</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Sources</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Confidence</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Data Flow</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white">
                        {findings_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Severity Chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{critical}, {high}, {medium}, {low}],
                    backgroundColor: ['#9333ea', '#dc2626', '#eab308', '#3b82f6']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true
            }}
        }});
        
        {self._generate_behavior_charts_js(behavior_data)}
        
        // Patch Generation Functions
        async function generatePatch(findingId) {{
            const btn = document.getElementById(`patch-btn-${{findingId}}`);
            const resultDiv = document.getElementById(`patch-result-${{findingId}}`);
            
            btn.disabled = true;
            btn.innerHTML = '⏳ Generating...';
            btn.classList.add('opacity-50');
            
            try {{
                const response = await fetch('/api/patches/generate', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ vulnerability_id: findingId }})
                }});
                
                if (!response.ok) throw new Error('Patch generation failed');
                
                const data = await response.json();
                
                btn.innerHTML = '✅ Patch Generated';
                btn.classList.remove('bg-green-500', 'hover:bg-green-600');
                btn.classList.add('bg-blue-500');
                
                // Show patch in collapsible section
                resultDiv.innerHTML = `
                    <div class="bg-gray-50 border border-gray-200 rounded p-3 mt-2">
                        <button onclick="togglePatch(${{findingId}})" class="w-full text-left font-semibold text-sm text-blue-600 hover:text-blue-800">
                            📝 View Patch (Confidence: ${{data.confidence}})
                        </button>
                        <div id="patch-details-${{findingId}}" class="hidden mt-2 space-y-2">
                            <div>
                                <p class="text-xs text-gray-600 font-semibold mb-1">Original Code:</p>
                                <pre class="bg-red-50 p-2 rounded text-xs overflow-x-auto"><code>${{escapeHtml(data.original_code)}}</code></pre>
                            </div>
                            <div>
                                <p class="text-xs text-gray-600 font-semibold mb-1">Fixed Code:</p>
                                <pre class="bg-green-50 p-2 rounded text-xs overflow-x-auto"><code>${{escapeHtml(data.fixed_code)}}</code></pre>
                            </div>
                            <div>
                                <p class="text-xs text-gray-600 font-semibold mb-1">Explanation:</p>
                                <p class="text-xs text-gray-700">${{data.explanation}}</p>
                            </div>
                            <button onclick="applyPatch(${{findingId}})" class="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1 rounded text-xs">
                                Apply Patch
                            </button>
                        </div>
                    </div>
                `;
                resultDiv.classList.remove('hidden');
                
            }} catch (error) {{
                btn.innerHTML = '❌ Error';
                btn.classList.add('bg-red-500');
                resultDiv.innerHTML = `<p class="text-xs text-red-600 mt-2">Error: ${{error.message}}</p>`;
                resultDiv.classList.remove('hidden');
            }}
        }}
        
        function togglePatch(findingId) {{
            const details = document.getElementById(`patch-details-${{findingId}}`);
            details.classList.toggle('hidden');
        }}
        
        async function applyPatch(findingId) {{
            if (!confirm('Apply this patch? This will modify the source code.')) return;
            
            try {{
                const response = await fetch(`/api/patches/${{findingId}}/apply`, {{
                    method: 'POST'
                }});
                
                if (!response.ok) throw new Error('Failed to apply patch');
                
                alert('✅ Patch applied successfully!');
                location.reload();
            }} catch (error) {{
                alert(`❌ Error: ${{error.message}}`);
            }}
        }}
        
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
    </script>
</body>
</html>
        """
        
        return html
    
    def _generate_behavior_analysis_html(self, behavior_data: Optional[Dict[str, Any]]) -> str:
        """Generate HTML for Phase 2 behavior analysis section"""
        if not behavior_data:
            return ""
        
        state_counts = behavior_data['state_counts']
        patterns = behavior_data['patterns']
        top_risks = behavior_data['top_risks']
        
        # Generate pattern cards
        pattern_cards = ""
        for pattern in patterns.get('patterns_found', [])[:6]:  # Top 6 patterns
            count = pattern.get('occurrences', pattern.get('count', 0))
            pattern_cards += f"""
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="font-semibold text-gray-800">{pattern['name']}</h3>
                        <span class="px-2 py-1 bg-red-100 text-red-800 rounded text-sm">{count}</span>
                    </div>
                    <p class="text-sm text-gray-600 mb-2">{pattern['description']}</p>
                    <p class="text-xs text-gray-500">{pattern['remediation'][:100]}...</p>
                </div>
            """
        
        # Generate top risk table
        risk_rows = ""
        for risk in top_risks[:10]:
            risk_color = 'purple' if risk['risk_score'] >= 8.5 else 'red' if risk['risk_score'] >= 7 else 'yellow' if risk['risk_score'] >= 4 else 'blue'
            risk_rows += f"""
                <tr class="border-b hover:bg-gray-50">
                    <td class="px-4 py-3 font-medium">{risk['type']}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-1 bg-{risk_color}-100 text-{risk_color}-800 rounded text-sm">
                            {risk['risk_score']}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-sm">{risk['file_path']}</td>
                    <td class="px-4 py-3">{risk['line_number']}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">
                            {risk['state']}
                        </span>
                    </td>
                    <td class="px-4 py-3">{risk['age_days']}d</td>
                </tr>
            """
        
        # Generate hotspot cards
        hotspot_cards = ""
        for hotspot in patterns.get('hotspots', [])[:3]:  # Top 3 hotspots
            hotspot_type = hotspot.get('type', 'file')
            hotspot_path = hotspot.get('path', hotspot.get('directory', 'Unknown'))
            vuln_count = hotspot.get('vulnerability_count', 0)
            risk_score = hotspot.get('total_risk_score', 0)
            
            hotspot_cards += f"""
                <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs text-red-600 uppercase font-semibold">{hotspot_type} Hotspot</span>
                        <span class="px-2 py-1 bg-red-600 text-white rounded text-sm">{vuln_count}</span>
                    </div>
                    <p class="text-sm font-mono text-gray-800 mb-1">{hotspot_path}</p>
                    <p class="text-xs text-gray-600">Combined Risk: {risk_score:.1f}</p>
                </div>
            """
        
        return f"""
        <!-- Phase 2: Behavior Analysis -->
        <div class="bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg shadow-lg p-6 mb-6 text-white">
            <h2 class="text-2xl font-bold mb-2">🔍 Security Behavior Analysis (Phase 2)</h2>
            <p class="text-blue-100">Lifecycle tracking, risk scoring, and pattern detection</p>
        </div>
        
        <!-- Phase 2 Metrics -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Total Scans</div>
                <div class="text-3xl font-bold text-gray-800">{behavior_data['total_scans']}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Tracked Vulnerabilities</div>
                <div class="text-3xl font-bold text-blue-600">{behavior_data['total_vulnerabilities']}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">High Risk (7.0+)</div>
                <div class="text-3xl font-bold text-red-600">{behavior_data['high_risk_count']}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-600 mb-1">Avg Risk Score</div>
                <div class="text-3xl font-bold text-purple-600">{behavior_data['average_risk_score']}</div>
            </div>
        </div>
        
        <!-- Trends and State Distribution -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-bold mb-4">Vulnerability Trends</h2>
                <canvas id="trendChart"></canvas>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-bold mb-4">Lifecycle State Distribution</h2>
                <canvas id="stateChart"></canvas>
            </div>
        </div>
        
        <!-- Security Patterns -->
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <h2 class="text-xl font-bold mb-4">🎯 Detected Security Patterns</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {pattern_cards}
            </div>
        </div>
        
        <!-- Hotspots -->
        {f'''
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <h2 class="text-xl font-bold mb-4">🔥 Security Hotspots</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                {hotspot_cards}
            </div>
        </div>
        ''' if hotspot_cards else ''}
        
        <!-- Top Risk Vulnerabilities -->
        <div class="bg-white rounded-lg shadow overflow-hidden mb-6">
            <div class="px-6 py-4 border-b">
                <h2 class="text-xl font-bold">⚠️ Top Risk Vulnerabilities</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk Score</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">File</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Line</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">State</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white">
                        {risk_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def _generate_behavior_charts_js(self, behavior_data: Optional[Dict[str, Any]]) -> str:
        """Generate JavaScript for Phase 2 charts"""
        if not behavior_data:
            return ""
        
        trends = behavior_data['trends']
        state_counts = behavior_data['state_counts']
        
        # Prepare trend data
        timestamps = [t['timestamp'] for t in trends]
        critical_data = [t['critical'] for t in trends]
        high_data = [t['high'] for t in trends]
        medium_data = [t['medium'] for t in trends]
        low_data = [t['low'] for t in trends]
        
        # Prepare state data
        state_labels = list(state_counts.keys())
        state_values = list(state_counts.values())
        state_colors = {
            'new': '#10b981',
            'existing': '#f59e0b',
            'fixed': '#3b82f6',
            'regressed': '#ef4444',
            'ignored': '#6b7280'
        }
        colors = [state_colors.get(label, '#gray') for label in state_labels]
        
        return f"""
        // Trend Chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        new Chart(trendCtx, {{
            type: 'line',
            data: {{
                labels: {timestamps},
                datasets: [
                    {{
                        label: 'Critical',
                        data: {critical_data},
                        borderColor: '#9333ea',
                        backgroundColor: 'rgba(147, 51, 234, 0.1)',
                        tension: 0.4
                    }},
                    {{
                        label: 'High',
                        data: {high_data},
                        borderColor: '#dc2626',
                        backgroundColor: 'rgba(220, 38, 38, 0.1)',
                        tension: 0.4
                    }},
                    {{
                        label: 'Medium',
                        data: {medium_data},
                        borderColor: '#eab308',
                        backgroundColor: 'rgba(234, 179, 8, 0.1)',
                        tension: 0.4
                    }},
                    {{
                        label: 'Low',
                        data: {low_data},
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        
        // State Chart
        const stateCtx = document.getElementById('stateChart').getContext('2d');
        new Chart(stateCtx, {{
            type: 'pie',
            data: {{
                labels: {state_labels},
                datasets: [{{
                    data: {state_values},
                    backgroundColor: {colors}
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
        """
