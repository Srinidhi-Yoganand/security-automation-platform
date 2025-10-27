"""
Unit tests for Semantic Analyzer
Tests CodeQL integration, SARIF parsing, and CPG building
"""

import unittest
import json
import tempfile
from pathlib import Path
from correlation-engine.app.core.semantic_analyzer_complete import (
    SemanticAnalyzer,
    DataFlowPath,
    CodeLocation,
    SecurityContext,
    CPGNode,
    analyze_java_project
)


class TestCodeLocation(unittest.TestCase):
    """Test CodeLocation dataclass"""
    
    def test_code_location_creation(self):
        loc = CodeLocation(
            file_path="test.java",
            start_line=10,
            end_line=10,
            start_column=5,
            end_column=20
        )
        self.assertEqual(str(loc), "test.java:10:5")
    
    def test_code_location_to_dict(self):
        loc = CodeLocation("test.java", 10, 10, 5, 20)
        d = loc.to_dict()
        self.assertEqual(d['file_path'], "test.java")
        self.assertEqual(d['start_line'], 10)


class TestDataFlowPath(unittest.TestCase):
    """Test DataFlowPath dataclass"""
    
    def test_data_flow_path_creation(self):
        source_loc = CodeLocation("test.java", 5, 5)
        sink_loc = CodeLocation("test.java", 15, 15)
        
        path = DataFlowPath(
            source="userId parameter",
            sink="findById call",
            source_location=source_loc,
            sink_location=sink_loc,
            vulnerability_type="IDOR",
            confidence=0.9
        )
        
        self.assertEqual(path.vulnerability_type, "IDOR")
        self.assertEqual(path.confidence, 0.9)
    
    def test_data_flow_path_to_dict(self):
        source_loc = CodeLocation("test.java", 5, 5)
        sink_loc = CodeLocation("test.java", 15, 15)
        
        path = DataFlowPath(
            source="input",
            sink="output",
            source_location=source_loc,
            sink_location=sink_loc
        )
        
        d = path.to_dict()
        self.assertIn('source', d)
        self.assertIn('sink', d)
        self.assertIn('source_location', d)


class TestSecurityContext(unittest.TestCase):
    """Test SecurityContext extraction"""
    
    def test_security_context_creation(self):
        context = SecurityContext(
            file_path="test.java",
            line_number=10,
            authentication_present=True,
            authorization_present=False,
            framework="spring"
        )
        
        self.assertTrue(context.authentication_present)
        self.assertFalse(context.authorization_present)
        self.assertEqual(context.framework, "spring")


class TestSemanticAnalyzer(unittest.TestCase):
    """Test SemanticAnalyzer functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_project = Path(__file__).parent.parent.parent.parent / "test-vuln-app"
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        analyzer = SemanticAnalyzer(str(self.test_project))
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.project_root, self.test_project)
    
    def test_cache_key_generation(self):
        """Test cache key generation"""
        analyzer = SemanticAnalyzer(str(self.test_project))
        
        # Create a temp file
        test_file = Path(self.temp_dir) / "test.java"
        test_file.write_text("class Test {}")
        
        key1 = analyzer._get_cache_key(str(test_file))
        key2 = analyzer._get_cache_key(str(test_file))
        
        # Same content should generate same key
        self.assertEqual(key1, key2)
        
        # Different content should generate different key
        test_file.write_text("class Test2 {}")
        key3 = analyzer._get_cache_key(str(test_file))
        self.assertNotEqual(key1, key3)
    
    def test_parse_sarif_location(self):
        """Test SARIF location parsing"""
        analyzer = SemanticAnalyzer(str(self.test_project))
        
        physical_location = {
            'artifactLocation': {'uri': 'test.java'},
            'region': {
                'startLine': 10,
                'endLine': 10,
                'startColumn': 5,
                'endColumn': 20
            }
        }
        
        loc = analyzer._parse_location(physical_location)
        self.assertIsNotNone(loc)
        self.assertEqual(loc.file_path, 'test.java')
        self.assertEqual(loc.start_line, 10)
        self.assertEqual(loc.start_column, 5)
    
    def test_vulnerability_type_detection(self):
        """Test vulnerability type detection from rule ID"""
        analyzer = SemanticAnalyzer(str(self.test_project))
        
        vuln_type = analyzer._get_vulnerability_type(
            'java/idor-vulnerability-enhanced',
            'IDOR detected'
        )
        self.assertEqual(vuln_type, 'IDOR')
        
        vuln_type = analyzer._get_vulnerability_type(
            'java/missing-authorization',
            'Missing auth'
        )
        self.assertEqual(vuln_type, 'Missing Authorization')
    
    def test_security_context_extraction(self):
        """Test security context extraction from source file"""
        analyzer = SemanticAnalyzer(str(self.test_project))
        
        # Test with actual test file
        test_file = self.test_project / "src" / "main" / "java" / "com" / "thesis" / "vuln" / "UserController.java"
        
        if test_file.exists():
            context = analyzer.extract_security_context(str(test_file), 30)
            self.assertIsNotNone(context)
            self.assertEqual(context.file_path, str(test_file))


class TestSARIFParsing(unittest.TestCase):
    """Test SARIF parsing functionality"""
    
    def test_parse_minimal_sarif(self):
        """Test parsing a minimal SARIF file"""
        sarif_data = {
            'version': '2.1.0',
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'runs': [
                {
                    'tool': {'driver': {'name': 'CodeQL'}},
                    'results': [
                        {
                            'ruleId': 'java/idor-vulnerability-enhanced',
                            'level': 'error',
                            'message': {'text': 'IDOR vulnerability detected'},
                            'locations': [
                                {
                                    'physicalLocation': {
                                        'artifactLocation': {'uri': 'test.java'},
                                        'region': {
                                            'startLine': 15,
                                            'endLine': 15,
                                            'startColumn': 5,
                                            'endColumn': 20
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        # Save to temp file
        temp_dir = tempfile.mkdtemp()
        sarif_file = Path(temp_dir) / "test.sarif"
        with open(sarif_file, 'w') as f:
            json.dump(sarif_data, f)
        
        # Parse
        analyzer = SemanticAnalyzer(temp_dir)
        paths = analyzer.parse_sarif_results(str(sarif_file))
        
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].vulnerability_type, 'IDOR')
        self.assertEqual(paths[0].severity, 'error')


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_project = Path(__file__).parent.parent.parent.parent / "test-vuln-app"
    
    def test_full_analysis_workflow(self):
        """Test complete analysis workflow (if test project exists)"""
        if not self.test_project.exists():
            self.skipTest("Test project not found")
        
        analyzer = SemanticAnalyzer(str(self.test_project.parent))
        
        # Check if CodeQL is available
        if not analyzer.codeql_path.exists():
            self.skipTest("CodeQL not installed")
        
        # Test database creation (quick check)
        # Full tests would require actual Maven build


if __name__ == '__main__':
    unittest.main()
