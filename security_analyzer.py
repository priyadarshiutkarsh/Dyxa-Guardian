# security_analyzer.py
import ast
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, ClassVar
from datetime import datetime
from radon.complexity import cc_visit
import pyjsparser
import javalang
import pycparser

logger = logging.getLogger(__name__)

@dataclass
class SecurityIssue:
    severity: str
    description: str
    line_number: int
    suggestion: str
    code_snippet: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    risk_score: float = 0.0
    affected_components: List[str] = field(default_factory=list)
    remediation_complexity: str = "Medium"
    issue_type: str = "Security"
    detailed_description: str = field(default="")
    references: List[str] = field(default_factory=list)

    SEVERITY_SCORES: ClassVar[Dict[str, float]] = {
        "Critical": 10.0,
        "High": 8.0,
        "Medium": 5.0,
        "Low": 2.0,
        "Info": 1.0,
    }

    SECURITY_MAPPINGS: ClassVar[Dict[str, Dict[str, str]]] = {
        "eval": {"cwe_id": "CWE-94", "owasp_category": "A1:2017-Injection"},
        "SQL Injection": {"cwe_id": "CWE-89", "owasp_category": "A1:2017-Injection"},
        "Sensitive Data": {"cwe_id": "CWE-200", "owasp_category": "A3:2017-Sensitive Data Exposure"}
    }

    def __post_init__(self):
        if self.severity not in self.SEVERITY_SCORES:
            raise ValueError(f"Invalid severity: {self.severity}. Must be one of {list(self.SEVERITY_SCORES.keys())}")
        self.risk_score = self.SEVERITY_SCORES.get(self.severity, 5.0)
        self._auto_populate_security_metadata()
        self.detailed_description = self._get_detailed_description()
        self.references = self._get_references()

    def _auto_populate_security_metadata(self):
        for key, mapping in self.SECURITY_MAPPINGS.items():
            if key in self.description:
                self.cwe_id = self.cwe_id or mapping["cwe_id"]
                self.owasp_category = self.owasp_category or mapping["owasp_category"]
                break

    def _get_detailed_description(self) -> str:
        if self.cwe_id == "CWE-94":
            return "The use of `eval()` can lead to code injection vulnerabilities. Avoid using `eval()` with untrusted input."
        elif self.cwe_id == "CWE-89":
            return "SQL Injection occurs when untrusted input is included in SQL queries. Use parameterized queries to prevent this."
        elif self.cwe_id == "CWE-200":
            return "Sensitive data exposure occurs when sensitive information is not properly protected. Ensure encryption and secure storage."
        return "No detailed description available."

    def _get_references(self) -> List[str]:
        if self.cwe_id == "CWE-94":
            return ["https://cwe.mitre.org/data/definitions/94.html", "https://owasp.org/www-community/attacks/Code_Injection"]
        elif self.cwe_id == "CWE-89":
            return ["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-community/attacks/SQL_Injection"]
        elif self.cwe_id == "CWE-200":
            return ["https://cwe.mitre.org/data/definitions/200.html", "https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure"]
        return []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "description": self.description,
            "line_number": self.line_number,
            "suggestion": self.suggestion,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "affected_components": self.affected_components,
            "remediation_complexity": self.remediation_complexity,
            "issue_type": self.issue_type,
            "detailed_description": self.detailed_description,
            "references": self.references
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityIssue':
        return cls(**data)

class CodeMetrics:
    def __init__(self, code: str):
        self.code = code
        self.loc = len(code.splitlines())
        self.complexity = self._calculate_complexity()
        self.vulnerability_density = 0

    def _calculate_complexity(self) -> int:
        try:
            blocks = cc_visit(self.code)
            return sum(block.complexity for block in blocks)
        except SyntaxError:
            logger.warning("Invalid syntax in code")
            return 1
        except Exception as e:
            logger.error(f"Error calculating complexity: {e}")
            return 1

class CodeSecurityAnalyzer:
    def __init__(self):
        self.vulnerability_history = []
        self.metrics_history = []

    SECURITY_MAPPINGS = {
        "dangerous_functions": {
            "eval": {"cwe_id": "CWE-94", "owasp_category": "A1:2017-Injection", "description": "Code Injection via eval()"},
            "exec": {"cwe_id": "CWE-95", "owasp_category": "A1:2017-Injection", "description": "Code Injection via exec()"},
            "os.system": {"cwe_id": "CWE-78", "owasp_category": "A1:2017-Injection", "description": "OS Command Injection"},
            "subprocess.call": {"cwe_id": "CWE-78", "owasp_category": "A1:2017-Injection", "description": "Command Injection Risk"},
            "pickle.loads": {"cwe_id": "CWE-502", "owasp_category": "A8:2017-Insecure Deserialization", "description": "Unsafe Deserialization"}
        },
        # Add more mappings as needed
    }

    async def analyze_code_snippet(self, code: str, language: str = "python") -> List[SecurityIssue]:
        issues = []
        try:
            logger.info(f"Analyzing code snippet in {language}...")
            if language == "python":
                try:
                    tree = ast.parse(code)
                    logger.info("Python code parsed successfully.")
                except SyntaxError as e:
                    logger.error(f"Syntax error in code: {e}")
                    return issues

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        await self._check_dangerous_calls(node, issues, code)
                        await self._check_sql_injection(node, issues, code)
                        await self._check_insecure_deserialization(node, issues, code)
                        await self._check_insecure_file_handling(node, issues, code)
                        await self._check_insecure_cryptography(node, issues, code)
                        await self._check_xss(node, issues, code)
                        await self._check_insecure_random(node, issues, code)
                        await self._check_insecure_http_headers(node, issues, code)
                        await self._check_csrf(node, issues, code)
                        await self._check_ssrf(node, issues, code)
                        await self._check_xxe(node, issues, code)
                    elif isinstance(node, ast.Assign):
                        await self._check_sensitive_data(node, issues, code)
                        await self._check_insecure_authentication(node, issues, code)
                    elif isinstance(node, ast.Expr):
                        await self._check_security_misconfigurations(node, issues, code)
                    elif isinstance(node, ast.Import):
                        await self._check_insecure_imports(node, issues, code)

                # Store issues for trend analysis
                self.vulnerability_history.append(issues)

                logger.info(f"Found {len(issues)} issues.")
                return issues
            elif language == "javascript":
                tree = pyjsparser.parse(code)
                logger.info("JavaScript code parsed successfully.")
                await self._check_javascript_xss(tree, issues, code)
            elif language == "java":
                tree = javalang.parse.parse(code)
                logger.info("Java code parsed successfully.")
                await self._check_java_insecure_deserialization(tree, issues, code)
            elif language == "cpp":
                parser = pycparser.CParser()
                tree = parser.parse(code)
                logger.info("C++ code parsed successfully.")
                await self._check_cpp_insecure_memory_handling(tree, issues, code)

            return issues
        except Exception as e:
            logger.error(f"Error in code snippet analysis: {e}", exc_info=True)
            return issues

    async def _check_dangerous_calls(self, node, issues, code):
        """Check for dangerous function calls like eval, exec, etc."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                if node.func.attr == "system":
                    logger.info("Found OS Command Injection")
                    issues.append(SecurityIssue(
                        severity="Critical",
                        description="OS Command Injection",
                        line_number=node.lineno,
                        suggestion="Avoid using os.system with untrusted input.",
                        code_snippet=self._get_code_snippet(code, "os.system"),
                        cwe_id="CWE-78",
                        owasp_category="A1:2017-Injection"
                    ))
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.SECURITY_MAPPINGS["dangerous_functions"]:
                metadata = self.SECURITY_MAPPINGS["dangerous_functions"][func_name]
                logger.info(f"Found dangerous function call: {func_name}")
                issues.append(SecurityIssue(
                    severity="Critical",
                    description=metadata["description"],
                    line_number=node.lineno,
                    suggestion=f"Avoid using {func_name} with untrusted input.",
                    code_snippet=self._get_code_snippet(code, func_name),
                    cwe_id=metadata["cwe_id"],
                    owasp_category=metadata["owasp_category"]
                ))

    async def _check_sql_injection(self, node, issues, code):
        """Check for SQL Injection vulnerabilities."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            # Check if the first argument is a string with concatenation
            if isinstance(node.args[0], ast.Str) and "+" in node.args[0].s:
                logger.info("Found potential SQL Injection")
                issues.append(SecurityIssue(
                    severity="High",
                    description="Potential SQL Injection",
                    line_number=node.lineno,
                    suggestion="Use parameterized queries to prevent SQL Injection.",
                    code_snippet=self._get_code_snippet(code, "execute"),
                    cwe_id="CWE-89",
                    owasp_category="A1:2017-Injection"
                ))
            # Check if the first argument is a BinOp (e.g., "SELECT * FROM users WHERE id = " + user_input)
            elif isinstance(node.args[0], ast.BinOp) and isinstance(node.args[0].op, ast.Add):
                logger.info("Found potential SQL Injection")
                issues.append(SecurityIssue(
                    severity="High",
                    description="Potential SQL Injection",
                    line_number=node.lineno,
                    suggestion="Use parameterized queries to prevent SQL Injection.",
                    code_snippet=self._get_code_snippet(code, "execute"),
                    cwe_id="CWE-89",
                    owasp_category="A1:2017-Injection"
                ))

    async def _check_sensitive_data(self, node, issues, code):
        """Check for hardcoded sensitive data like passwords, secrets, etc."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ["password", "secret", "token"]:
                    logger.info(f"Found hardcoded {target.id}")
                    issues.append(SecurityIssue(
                        severity="Medium",
                        description=f"Hardcoded {target.id} detected.",
                        line_number=node.lineno,
                        suggestion=f"Avoid hardcoding {target.id} in the code.",
                        code_snippet=self._get_code_snippet(code, target.id),
                        cwe_id="CWE-259",
                        owasp_category="A3:2017-Sensitive Data Exposure"
                    ))

    async def _check_insecure_deserialization(self, node, issues, code):
        """Check for insecure deserialization vulnerabilities."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                logger.info("Found insecure deserialization")
                issues.append(SecurityIssue(
                    severity="Critical",
                    description="Insecure deserialization detected.",
                    line_number=node.lineno,
                    suggestion="Avoid deserializing untrusted data.",
                    code_snippet=self._get_code_snippet(code, "pickle.loads"),
                    cwe_id="CWE-502",
                    owasp_category="A8:2017-Insecure Deserialization"
                ))

    async def _check_insecure_file_handling(self, node, issues, code):
        """Check for insecure file handling vulnerabilities."""
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            logger.info("Found insecure file handling")
            issues.append(SecurityIssue(
                severity="Medium",
                description="Insecure file handling detected.",
                line_number=node.lineno,
                suggestion="Ensure proper file handling and access controls.",
                code_snippet=self._get_code_snippet(code, "open"),
                cwe_id="CWE-22",
                owasp_category="A5:2017-Broken Access Control"
            ))

    async def _check_insecure_cryptography(self, node, issues, code):
        """Check for insecure cryptography usage."""
        if isinstance(node.func, ast.Name) and node.func.id in ["md5", "sha1"]:
            logger.info(f"Found use of weak cryptographic algorithm: {node.func.id}")
            issues.append(SecurityIssue(
                severity="Medium",
                description=f"Use of weak cryptographic algorithm ({node.func.id}).",
                line_number=node.lineno,
                suggestion="Use stronger cryptographic algorithms like SHA-256.",
                code_snippet=self._get_code_snippet(code, node.func.id),
                cwe_id="CWE-328",
                owasp_category="A3:2017-Sensitive Data Exposure"
            ))

    async def _check_xss(self, node, issues, code):
        """Check for XSS vulnerabilities in Python code."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "render_template_string":
                # Check if any argument is user input (e.g., from request.args or request.form)
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in ["user_input", "request.args", "request.form"]:
                        logger.info("Found potential XSS vulnerability")
                        issues.append(SecurityIssue(
                            severity="High",
                            description="Potential XSS vulnerability",
                            line_number=node.lineno,
                            suggestion="Sanitize user input before rendering templates.",
                            code_snippet=self._get_code_snippet(code, "render_template_string"),
                            cwe_id="CWE-79",
                            owasp_category="A7:2017-Cross-Site Scripting (XSS)"
                        ))

    async def _check_javascript_xss(self, tree, issues, code):
        """Check for XSS vulnerabilities in JavaScript code."""
        for node in tree.body:
            if node.type == "ExpressionStatement" and node.expression.type == "CallExpression":
                if node.expression.callee.property and node.expression.callee.property.name in ["innerHTML", "document.write"]:
                    logger.info("Found potential XSS vulnerability in JavaScript")
                    issues.append(SecurityIssue(
                        severity="High",
                        description="Potential XSS vulnerability",
                        line_number=node.loc.start.line,
                        suggestion="Avoid using innerHTML or document.write with untrusted input.",
                        code_snippet=self._get_code_snippet(code, node.expression.callee.property.name),
                        cwe_id="CWE-79",
                        owasp_category="A7:2017-Cross-Site Scripting (XSS)"
                    ))

    async def _check_java_insecure_deserialization(self, tree, issues, code):
        """Check for insecure deserialization in Java code."""
        for node in tree.types:
            if node.name == "ObjectInputStream":
                logger.info("Found insecure deserialization in Java")
                issues.append(SecurityIssue(
                    severity="Critical",
                    description="Insecure deserialization detected",
                    line_number=node.position.line,
                    suggestion="Avoid deserializing untrusted data.",
                    code_snippet=self._get_code_snippet(code, "ObjectInputStream"),
                    cwe_id="CWE-502",
                    owasp_category="A8:2017-Insecure Deserialization"
                ))

    async def _check_cpp_insecure_memory_handling(self, tree, issues, code):
        """Check for insecure memory handling in C++ code."""
        for node in tree.ext:
            if node.type == "Decl" and node.name == "strcpy":
                logger.info("Found insecure memory handling in C++")
                issues.append(SecurityIssue(
                    severity="High",
                    description="Insecure memory handling detected",
                    line_number=node.coord.line,
                    suggestion="Use safer alternatives like strncpy.",
                    code_snippet=self._get_code_snippet(code, "strcpy"),
                    cwe_id="CWE-120",
                    owasp_category="A9:2017-Using Components with Known Vulnerabilities"
                ))

    async def _check_insecure_random(self, node, issues, code):
        """Check for insecure random number generation."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "random":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
                logger.info("Found insecure random number generation")
                issues.append(SecurityIssue(
                    severity="Medium",
                    description="Insecure random number generation detected.",
                    line_number=node.lineno,
                    suggestion="Use `secrets` module for cryptographic randomness.",
                    code_snippet=self._get_code_snippet(code, "random.random"),
                    cwe_id="CWE-330",
                    owasp_category="A6:2017-Security Misconfiguration"
                ))

    async def _check_insecure_http_headers(self, node, issues, code):
        """Check for insecure HTTP headers."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "set_header":
            if isinstance(node.args[0], ast.Str) and node.args[0].s.lower() in ["x-frame-options", "content-security-policy"]:
                logger.info("Found insecure HTTP header configuration")
                issues.append(SecurityIssue(
                    severity="Medium",
                    description="Insecure HTTP header configuration detected.",
                    line_number=node.lineno,
                    suggestion="Ensure proper HTTP headers are set to prevent attacks like clickjacking.",
                    code_snippet=self._get_code_snippet(code, "set_header"),
                    cwe_id="CWE-693",
                    owasp_category="A6:2017-Security Misconfiguration"
                ))

    async def _check_csrf(self, node, issues, code):
        """Check for missing CSRF tokens in POST requests."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "post" and not self._has_csrf_token(node):
                issues.append(SecurityIssue(
                    severity="High",
                    description="Missing CSRF token in POST request.",
                    line_number=node.lineno,
                    suggestion="Add CSRF token to prevent CSRF attacks.",
                    code_snippet=self._get_code_snippet(code, "post"),
                    cwe_id="CWE-352",
                    owasp_category="A1:2017-Injection"
                ))

    async def _check_ssrf(self, node, issues, code):
        """Check for SSRF vulnerabilities."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get" and isinstance(node.func.value, ast.Name) and node.func.value.id == "requests":
                if isinstance(node.args[0], ast.Name):
                    issues.append(SecurityIssue(
                        severity="High",
                        description="Potential SSRF vulnerability detected.",
                        line_number=node.lineno,
                        suggestion="Validate and sanitize user input used in HTTP requests.",
                        code_snippet=self._get_code_snippet(code, "requests.get"),
                        cwe_id="CWE-918",
                        owasp_category="A10:2017-Server-Side Request Forgery (SSRF)"
                    ))

    async def _check_xxe(self, node, issues, code):
        """Check for XXE vulnerabilities."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "parse" and isinstance(node.func.value, ast.Name) and node.func.value.id == "lxml":
                issues.append(SecurityIssue(
                    severity="High",
                    description="Potential XXE vulnerability detected.",
                    line_number=node.lineno,
                    suggestion="Disable external entity parsing in XML parsers.",
                    code_snippet=self._get_code_snippet(code, "lxml.parse"),
                    cwe_id="CWE-611",
                    owasp_category="A4:2017-XML External Entities (XXE)"
                ))

    async def _check_insecure_authentication(self, node, issues, code):
        """Check for hardcoded credentials."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ["password", "api_key"]:
                    issues.append(SecurityIssue(
                        severity="High",
                        description=f"Hardcoded {target.id} detected.",
                        line_number=node.lineno,
                        suggestion="Avoid hardcoding credentials in the code.",
                        code_snippet=self._get_code_snippet(code, target.id),
                        cwe_id="CWE-259",
                        owasp_category="A3:2017-Sensitive Data Exposure"
                    ))

    async def _check_security_misconfigurations(self, node, issues, code):
        """Check for security misconfigurations."""
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name) and node.targets[0].id == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value == True:
                    issues.append(SecurityIssue(
                        severity="Medium",
                        description="Debug mode is enabled.",
                        line_number=node.lineno,
                        suggestion="Disable debug mode in production.",
                        code_snippet=self._get_code_snippet(code, "DEBUG"),
                        cwe_id="CWE-215",
                        owasp_category="A6:2017-Security Misconfiguration"
                    ))

    def _get_code_snippet(self, code: str, pattern: str) -> str:
        """Get the code snippet where the pattern appears."""
        for line in code.splitlines():
            if pattern in line:
                return line.strip()
        return ""

    def _has_csrf_token(self, node) -> bool:
        """Check if a CSRF token is present in the node."""
        # Placeholder logic for checking CSRF token
        return False
