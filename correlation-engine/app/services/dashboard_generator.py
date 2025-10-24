"""
Security Dashboard Generator

Generates an HTML dashboard from correlation report data.
"""

from typing import Dict, Any
from datetime import datetime


class DashboardGenerator:
    """Generate interactive HTML security dashboard"""
    
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
    </script>
</body>
</html>
        """
        
        return html
