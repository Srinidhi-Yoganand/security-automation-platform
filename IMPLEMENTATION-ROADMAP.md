# 🚀 Thesis Implementation Roadmap
## Hybrid Semantic Analysis + Symbolic Execution System

**Last Updated:** October 27, 2025  
**Status:** 🟢 Ready to Begin Implementation

---

## 📊 Current State Assessment

### ✅ What We Already Have

1. **Infrastructure (80% Complete)**
   - ✅ Docker-based deployment
   - ✅ FastAPI REST API
   - ✅ Multi-tool SAST integration (Semgrep, CodeQL)
   - ✅ Correlation engine for cross-tool validation
   - ✅ LLM integration (Ollama/DeepSeek, OpenAI, Gemini)
   - ✅ Basic patch generation
   - ✅ Dashboard generation
   - ✅ Git integration
   - ✅ Testing framework

2. **New Components (Just Added)**
   - ✅ `semantic_analyzer.py` - CPG builder skeleton
   - ✅ `symbolic_executor.py` - Symbolic execution engine skeleton
   - ✅ Setup scripts for CodeQL
   - ✅ Z3 solver dependency added

### 🎯 What We Need to Build

1. **Phase 1:** CodeQL Integration & CPG Building
2. **Phase 2:** Symbolic Execution Implementation
3. **Phase 3:** Enhanced LLM Patching with Rich Context
4. **Phase 4:** Integration & End-to-End Testing
5. **Phase 5:** Evaluation & Thesis Writing

---

## 📅 Implementation Phases

### **PHASE 1: CodeQL Integration & Semantic Analysis (Week 1-2)**

**Goal:** Get CodeQL working and build real CPGs from Java code

#### Tasks:

##### 1.1 Setup CodeQL Environment ⏱️ 2 hours
- [ ] Run `setup-codeql.sh` to install CodeQL
- [ ] Test CodeQL on a sample Java project
- [ ] Verify queries work
- [ ] Document any Windows-specific issues

**Test:**
```bash
./setup-codeql.sh
./create-codeql-db.sh ./sample-vuln-app
./run-codeql-queries.sh ./codeql-databases/sample-vuln-app-codeql-db
```

**Success Criteria:**
- ✅ CodeQL database created without errors
- ✅ Queries run and produce JSON output
- ✅ At least 1 vulnerability detected

##### 1.2 Enhance CodeQL Queries ⏱️ 4 hours
- [ ] Write comprehensive IDOR detection query
- [ ] Write missing authorization query
- [ ] Write data flow tracking query
- [ ] Add support for Spring annotations
- [ ] Test on known vulnerable code

**Files to Create:**
- `codeql-queries/idor-detection.ql` (✅ exists, needs enhancement)
- `codeql-queries/auth-bypass-detection.ql` (✅ exists, needs enhancement)
- `codeql-queries/data-flow-advanced.ql` (new)

**Test:**
```bash
cd correlation-engine
python -c "from app.core.semantic_analyzer import SemanticAnalyzer; \
           a = SemanticAnalyzer('./test-data'); \
           print('Import successful')"
```

##### 1.3 Complete Semantic Analyzer ⏱️ 8 hours
- [ ] Implement full CodeQL integration
- [ ] Parse CodeQL output into DataFlowPath objects
- [ ] Extract security context from code
- [ ] Build CPG representation
- [ ] Add caching for performance

**Files to Update:**
- `correlation-engine/app/core/semantic_analyzer.py`

**Test Script:**
```python
# test_semantic_analyzer.py
from app.core.semantic_analyzer import SemanticAnalyzer

# Test on vulnerable app
analyzer = SemanticAnalyzer("./vulnerable-app")
db = analyzer.create_codeql_database()
flows = analyzer.find_taint_flows(db)

print(f"Found {len(flows)} data flows")
for flow in flows:
    print(f"- {flow.vulnerability_type}: {flow.source} → {flow.sink}")
    
assert len(flows) > 0, "Should find at least one vulnerability"
print("✅ Semantic analyzer test passed")
```

##### 1.4 Integration with Existing System ⏱️ 4 hours
- [ ] Add semantic analysis to correlation engine
- [ ] Update API endpoints to use semantic analysis
- [ ] Enhance vulnerability model with CPG data
- [ ] Update database schema if needed

**Files to Update:**
- `correlation-engine/app/core/correlator.py`
- `correlation-engine/app/main.py`
- `correlation-engine/app/models/__init__.py`

**Test:**
```bash
# Start the server
cd correlation-engine
python run_server.py

# In another terminal
curl -X POST http://localhost:8000/api/scan/semantic \
  -H "Content-Type: application/json" \
  -d '{"path": "./vulnerable-app"}'
```

**Deliverables:**
- ✅ Working CodeQL integration
- ✅ CPG generation from Java code
- ✅ Data flow analysis
- ✅ Integration tests passing

**Checkpoint:** Can we generate CPGs and find data flows?

---

### **PHASE 2: Symbolic Execution Implementation (Week 3-4)**

**Goal:** Implement symbolic execution to prove vulnerabilities are exploitable

#### Tasks:

##### 2.1 Z3 Solver Setup & Testing ⏱️ 2 hours
- [ ] Install Z3 solver
- [ ] Test basic Z3 operations
- [ ] Create helper functions for common patterns
- [ ] Document Z3 usage

**Test Script:**
```python
# test_z3_setup.py
from z3 import *

# Test basic constraint solving
userId = Int('userId')
currentUserId = Int('currentUserId')

s = Solver()
s.add(userId > 0)
s.add(currentUserId > 0)
s.add(userId != currentUserId)

if s.check() == sat:
    m = s.model()
    print(f"✅ Z3 working: userId={m[userId]}, currentUserId={m[currentUserId]}")
else:
    print("❌ Z3 not working correctly")
```

##### 2.2 IDOR Detection Implementation ⏱️ 6 hours
- [ ] Complete `_analyze_idor()` method
- [ ] Add constraint generation from data flows
- [ ] Implement exploit proof generation
- [ ] Test with known IDOR vulnerabilities

**Files to Update:**
- `correlation-engine/app/core/symbolic_executor.py`

**Test Cases:**
```python
# test_idor_detection.py
from app.core.symbolic_executor import SymbolicExecutor
from app.core.semantic_analyzer import DataFlowPath, SecurityContext

# Test 1: Vulnerable IDOR (no authorization)
def test_idor_vulnerable():
    flow = create_test_flow_idor_vulnerable()
    context = create_test_context_no_auth()
    
    executor = SymbolicExecutor()
    proof = executor.analyze_authorization_gap(flow, context)
    
    assert proof is not None, "Should detect IDOR"
    assert proof.exploitable == True
    assert proof.confidence > 0.9
    print("✅ Test 1 passed: IDOR detected")

# Test 2: Secure code (has authorization)
def test_idor_secure():
    flow = create_test_flow_idor_vulnerable()
    context = create_test_context_with_auth()
    
    executor = SymbolicExecutor()
    proof = executor.analyze_authorization_gap(flow, context)
    
    assert proof is None or proof.exploitable == False
    print("✅ Test 2 passed: Secure code not flagged")

if __name__ == "__main__":
    test_idor_vulnerable()
    test_idor_secure()
```

##### 2.3 Missing Authentication Detection ⏱️ 4 hours
- [ ] Implement `_analyze_missing_auth()` method
- [ ] Detect endpoints without authentication
- [ ] Generate exploit proofs
- [ ] Test with unauthenticated endpoints

**Test:**
```python
# test_missing_auth.py
def test_missing_authentication():
    flow = create_test_flow_sensitive_operation()
    context = create_test_context_no_auth_annotation()
    
    executor = SymbolicExecutor()
    proof = executor.analyze_authorization_gap(flow, context)
    
    assert proof.vulnerability_type == VulnerabilityType.MISSING_AUTHENTICATION
    print("✅ Missing authentication detected")
```

##### 2.4 Exploit Test Generation ⏱️ 3 hours
- [ ] Complete `generate_exploit_test()` method
- [ ] Generate JUnit tests for vulnerabilities
- [ ] Make tests runnable
- [ ] Add to output

**Files to Update:**
- `correlation-engine/app/core/symbolic_executor.py`

##### 2.5 Integration with Semantic Analyzer ⏱️ 4 hours
- [ ] Connect symbolic executor to semantic analyzer
- [ ] Create hybrid analysis pipeline
- [ ] Add to correlation engine
- [ ] Test end-to-end flow

**New File:**
```python
# correlation-engine/app/core/hybrid_analyzer.py
class HybridAnalyzer:
    """Combines semantic analysis + symbolic execution"""
    
    def __init__(self):
        self.semantic_analyzer = SemanticAnalyzer()
        self.symbolic_executor = SymbolicExecutor()
    
    def analyze(self, codebase_path):
        # 1. Semantic analysis
        flows = self.semantic_analyzer.find_taint_flows()
        
        # 2. Symbolic execution on suspicious flows
        proofs = []
        for flow in flows:
            if flow.is_potentially_vulnerable():
                context = self.semantic_analyzer.extract_security_context(
                    flow.sink_location[0],
                    flow.sink_location[1]
                )
                proof = self.symbolic_executor.analyze_authorization_gap(
                    flow, context
                )
                if proof:
                    proofs.append(proof)
        
        return proofs
```

**Test:**
```bash
cd correlation-engine
python test_hybrid_analyzer.py
```

**Deliverables:**
- ✅ Working symbolic execution for IDOR
- ✅ Missing authentication detection
- ✅ Exploit proof generation
- ✅ Integration tests passing

**Checkpoint:** Can we prove vulnerabilities are exploitable?

---

### **PHASE 3: Enhanced LLM Patching (Week 5)**

**Goal:** Generate high-quality patches using rich context

#### Tasks:

##### 3.1 Context Builder ⏱️ 4 hours
- [ ] Extract full context for patches
- [ ] Include CPG data flow
- [ ] Include symbolic execution proof
- [ ] Include framework APIs

**New File:**
```python
# correlation-engine/app/services/patcher/context_builder.py
class PatchContextBuilder:
    def build_rich_context(self, vulnerability, flow, proof, security_context):
        """Build comprehensive context for LLM"""
        return {
            "vulnerability": vulnerability,
            "data_flow": self.format_data_flow(flow),
            "exploit_proof": proof.to_dict(),
            "security_apis": security_context.available_apis,
            "similar_fixes": self.fetch_similar_cve_fixes(vulnerability.type),
            "code_context": self.extract_surrounding_code(vulnerability)
        }
```

##### 3.2 Enhanced Prompt Engineering ⏱️ 6 hours
- [ ] Create detailed prompt templates
- [ ] Add data flow visualization
- [ ] Add exploit proof explanation
- [ ] Add security API documentation

**Files to Create:**
- `correlation-engine/app/services/patcher/prompt_templates.py`

**Test:**
```python
# test_prompt_generation.py
builder = PatchContextBuilder()
context = builder.build_rich_context(vuln, flow, proof, sec_context)

prompt = generate_patch_prompt(context)

# Should include:
assert "Data Flow Path:" in prompt
assert "Symbolic Execution Proof:" in prompt
assert "Available Security APIs:" in prompt
assert "Similar CVE Fixes:" in prompt

print("✅ Prompt generation test passed")
```

##### 3.3 Semantic Patch Generator ⏱️ 6 hours
- [ ] Implement `SemanticPatchGenerator` class
- [ ] Use rich context in prompts
- [ ] Generate patches with explanations
- [ ] Add confidence scoring

**File to Create:**
- `correlation-engine/app/services/patcher/semantic_patch_generator.py`

##### 3.4 CVE Database Integration ⏱️ 4 hours
- [ ] Fetch similar CVE fixes
- [ ] Parse patch patterns
- [ ] Include in LLM context
- [ ] Cache for performance

**File to Create:**
- `correlation-engine/app/services/patcher/cve_database.py`

**Test:**
```python
# test_cve_database.py
db = CVEDatabase()
similar = db.find_similar_fixes("idor", "spring", "java")

assert len(similar) > 0
print(f"✅ Found {len(similar)} similar CVE fixes")
```

##### 3.5 Patch Validation ⏱️ 4 hours
- [ ] Re-run symbolic execution on patches
- [ ] Verify exploit is fixed
- [ ] Check syntax correctness
- [ ] Measure patch quality

**Test:**
```python
# test_patch_validation.py
# 1. Generate patch
patch = generator.generate_patch(vuln, flow, proof, context)

# 2. Apply patch (in memory)
patched_code = apply_patch_to_code(original_code, patch)

# 3. Re-run symbolic execution
new_proof = executor.analyze(patched_code)

# 4. Verify fix
assert new_proof is None or not new_proof.exploitable
print("✅ Patch validated: exploit fixed")
```

**Deliverables:**
- ✅ Context-rich prompt generation
- ✅ Enhanced patch quality
- ✅ CVE database integration
- ✅ Patch validation

**Checkpoint:** Are generated patches better than before?

---

### **PHASE 4: Integration & End-to-End Testing (Week 6)**

**Goal:** Complete system integration and comprehensive testing

#### Tasks:

##### 4.1 Full Pipeline Integration ⏱️ 6 hours
- [ ] Connect all components
- [ ] Create end-to-end workflow
- [ ] Add error handling
- [ ] Optimize performance

**Workflow:**
```
Input: Java Application
  ↓
[1] Semantic Analysis (CodeQL)
  ↓
[2] Identify suspicious flows
  ↓
[3] Symbolic Execution (prove exploitability)
  ↓
[4] Generate rich context
  ↓
[5] LLM patch generation
  ↓
[6] Patch validation
  ↓
Output: Validated patches with proofs
```

##### 4.2 API Endpoints ⏱️ 4 hours
- [ ] Add `/api/scan/hybrid` endpoint
- [ ] Add `/api/analyze/symbolic` endpoint
- [ ] Add `/api/patches/semantic` endpoint
- [ ] Update documentation

**New Endpoints:**
```python
# app/main.py

@app.post("/api/scan/hybrid")
async def hybrid_scan(request: HybridScanRequest):
    """
    Perform hybrid semantic + symbolic analysis
    Returns vulnerabilities with exploit proofs
    """
    analyzer = HybridAnalyzer()
    results = analyzer.analyze(request.codebase_path)
    return {"vulnerabilities": results}

@app.post("/api/patches/semantic")
async def generate_semantic_patch(request: SemanticPatchRequest):
    """
    Generate context-rich patches using symbolic execution proofs
    """
    generator = SemanticPatchGenerator()
    patch = generator.generate(request.vulnerability_id)
    return {"patch": patch}
```

##### 4.3 Dashboard Enhancement ⏱️ 3 hours
- [ ] Add CPG visualization
- [ ] Show exploit proofs
- [ ] Display data flow paths
- [ ] Add confidence scores

##### 4.4 Test Suite Creation ⏱️ 8 hours
- [ ] Unit tests for each component
- [ ] Integration tests
- [ ] End-to-end tests
- [ ] Performance tests

**Test Files:**
```
correlation-engine/tests/
  test_semantic_analyzer.py
  test_symbolic_executor.py
  test_hybrid_analyzer.py
  test_semantic_patch_generator.py
  test_end_to_end.py
```

##### 4.5 Documentation ⏱️ 4 hours
- [ ] Update README with new features
- [ ] Document API endpoints
- [ ] Add usage examples
- [ ] Create troubleshooting guide

**Deliverables:**
- ✅ Fully integrated system
- ✅ Comprehensive test suite
- ✅ Updated documentation
- ✅ Working demo

**Checkpoint:** Does everything work together?

---

### **PHASE 5: Evaluation & Thesis Writing (Week 7-8)**

**Goal:** Evaluate system performance and write thesis

#### Tasks:

##### 5.1 Dataset Collection ⏱️ 6 hours
- [ ] Collect 50-100 vulnerable Java apps
- [ ] Include known IDORs and auth issues
- [ ] Annotate ground truth
- [ ] Split train/test sets

**Sources:**
1. OWASP Benchmark
2. GitHub Security Advisories
3. SecuriBench Micro
4. Custom test cases

##### 5.2 Quantitative Evaluation ⏱️ 8 hours
- [ ] Run system on full dataset
- [ ] Measure discovery rate (TP, FP, FN)
- [ ] Measure patch quality
- [ ] Compare with baselines

**Metrics:**
```python
# evaluation/metrics.py
def calculate_metrics(results, ground_truth):
    tp = true_positives(results, ground_truth)
    fp = false_positives(results, ground_truth)
    fn = false_negatives(results, ground_truth)
    
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1 = 2 * (precision * recall) / (precision + recall)
    
    return {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "discovery_rate": recall,
        "false_positive_rate": fp / (fp + tp)
    }
```

##### 5.3 Qualitative Analysis ⏱️ 6 hours
- [ ] Select 5-10 case studies
- [ ] Detailed analysis of each
- [ ] Create visualizations
- [ ] Document failure cases

##### 5.4 Comparison with Baselines ⏱️ 4 hours
- [ ] Compare with Semgrep alone
- [ ] Compare with CodeQL alone
- [ ] Compare with simple correlation
- [ ] Statistical significance tests

##### 5.5 Thesis Writing ⏱️ 40 hours
- [ ] Chapter 1: Introduction
- [ ] Chapter 2: Background & Related Work
- [ ] Chapter 3: Methodology
- [ ] Chapter 4: Implementation
- [ ] Chapter 5: Evaluation
- [ ] Chapter 6: Discussion
- [ ] Chapter 7: Conclusion

**Deliverables:**
- ✅ Complete evaluation results
- ✅ Statistical analysis
- ✅ Thesis document (100 pages)
- ✅ Research paper draft

---

## 🎯 Success Criteria

### Phase 1 Success:
- [ ] CodeQL database created successfully
- [ ] At least 5 data flows detected
- [ ] CPG generated and queryable

### Phase 2 Success:
- [ ] IDOR vulnerabilities detected with 90%+ accuracy
- [ ] Exploit proofs generated automatically
- [ ] False positive rate < 15%

### Phase 3 Success:
- [ ] Patches compile and run
- [ ] Patches fix the vulnerability
- [ ] Patch quality improved by 40%+

### Phase 4 Success:
- [ ] All tests passing
- [ ] End-to-end demo works
- [ ] Performance acceptable (< 5 min per project)

### Phase 5 Success:
- [ ] Evaluation complete on 50+ projects
- [ ] Thesis draft complete
- [ ] Results show significant improvement over baselines

---

## 📊 Testing Strategy

### Continuous Testing Approach:

After each task:
1. **Unit Test** - Test the specific function/class
2. **Integration Test** - Test with other components
3. **Smoke Test** - Quick end-to-end check
4. **Regression Test** - Ensure old features still work

### Test-Driven Development:

For each new feature:
```python
# 1. Write the test first
def test_new_feature():
    result = new_feature()
    assert result.is_correct()

# 2. Implement the feature
def new_feature():
    # implementation
    pass

# 3. Run test
pytest test_new_feature.py

# 4. Refactor if needed
```

---

## 🚀 Let's Start Implementation!

### **TODAY: Phase 1, Task 1.1 - CodeQL Setup**

**Next Steps:**
1. Run the CodeQL setup script
2. Test on sample-vuln-app
3. Verify it works
4. Move to next task

**Command to run:**
```bash
cd /c/Users/srini/Documents/College/security-automation-platform
chmod +x setup-codeql.sh
./setup-codeql.sh
```

---

## 📞 Questions Before We Start?

- [ ] Do you have sufficient disk space (~10GB for CodeQL)?
- [ ] Is your network connection stable (for downloads)?
- [ ] Are you ready to commit 2-3 hours today?

**Ready to begin? Let's build something novel! 🎓🚀**
