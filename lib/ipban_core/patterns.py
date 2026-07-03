"""
Attack pattern definitions for IP Ban Hammer.

Contains regex patterns for detecting various attack types:
- SQL Injection
- XSS Attack
- Path Traversal
- Command Injection
- Scanner Detection
- Sensitive File Probe
- Webshell
- Vulnerability Probe
- Protocol Attack
- Proxy Attack
- AI API Probe
"""

import re

ATTACK_PATTERNS = {
    'SQL Injection': [
        r"(?i)(union\s+(all\s+)?select\s+)",
        r"(?i)(select\s+.+\s+from\s+)",
        r"(?i)(insert\s+into\s+.+\s+values)",
        r"(?i)(update\s+.+\s+set)",
        r"(?i)(delete\s+from)",
        r"(?i)(drop\s+(table|database))",
        r"(?i)(exec\s*\()",
        r"(?i)(execute\s*\()",
        r"(?i)(;\s*--)",
        r"(?i)(benchmark\s*\()",
        r"(?i)(sleep\s*\()",
    ],
    'XSS Attack': [
        r"(?i)(javascript\s*:)",
        r"""(?i)(on(?:error|load|click|mouseover|focus|blur|submit|change|keydown|keyup|mouseenter|mouseleave|input|dblclick|contextmenu|drag|drop|wheel|touchstart|touchend|pointerover|pointerenter|pointerdown|pointerup|pointerleave|pointerout|beforeinput|compositionstart|compositionend|cut|copy|paste)\s*=\s*['\"]?\s*(?:javascript|vbscript|data\s*:))""",
        r"(?i)(<script[^>]*>)",
        r"(?i)(<iframe[^>]*>)",
    ],
    'Path Traversal': [
        r"(\.\.\/|\.\.\\)",
        r"(%2e%2e%2f|%2e%2e\/)",
        r"(\/etc\/passwd)",
        r"(\/etc\/shadow)",
    ],
    'Command Injection': [
        r"(?i)(;\s*cat\s+)",
        r"(?i)(\|\s*cat\s+)",
        r"(?i)(;\s*wget\s+)",
        r"(?i)(;\s*curl\s+)",
        r"(?i)(\|\s*bash)",
        r"(?i)(`.*`)",
    ],
    'Scanner': [
        r"(?i)(zgrab)",
        r"(?i)(nikto)",
        r"(?i)(sqlmap)",
        r"(?i)(masscan)",
        r"(?i)(nmap)",
        r"(?i)(acunetix)",
        r"(?i)(nessus)",
    ],
    'Sensitive File Probe': [
        r"(?i)(\/\.(git|svn|env|htaccess))",
        r"(?i)(\/(backup|bak)\s*$)",
        r"(?i)(\.(sql|dump|tar|gz)$)",
        r"(?i)(\/phpmyadmin)",
        r"(?i)(\/adminer\.php)",
    ],
    'Webshell': [
        r"(?i)(\/(cmd|shell|backdoor|c99|r57|webshell)\.(php|asp))",
        r"(?i)(eval\s*\()",
        r"(?i)(base64_decode\s*\()",
        r"(?i)(system\s*\()",
        r"(?i)(shell_exec\s*\()",
    ],
    'Vulnerability Probe': [
        r"(?i)(\/autodiscover\/)",
        r"(?i)(\/owa\/)",
        r"(?i)(\/ecp\/)",
        r"(?i)(\/cgi-bin\/)",
        r"(?i)(\/thinkphp\/)",
        r"(?i)(\/?s=index\/\think\\app\/invokefunction)",
        r"(?i)(\/?s=index\/\think\\Container\/invokefunction)",
        r"(?i)(\/?s=index\/\think\\template\/driver\/file\/write)",
        r"(?i)(jndi:)",
        r"(?i)(ldap:)",
        r"(?i)(rmi:)",
    ],
    'Protocol Attack': [
        r"(\\x[0-9a-f]{2})",
        r"(CONNECT\s+)",
    ],
    'Proxy Attack': [
        r"(?i)(GET\s+http:\/\/)",
        r"(?i)(POST\s+http:\/\/)",
        r"(?i)(CONNECT\s+\d+\.\d+\.\d+\.\d+:\d+)",
    ],
    'AI API Probe': [
        r"(?i)(/v1/models(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/chat/completions(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/completions(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/embeddings(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/audio/(transcriptions|translations|speech)(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/images/generations(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/files(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/fine[-_]tune)",
        r"(?i)(/v1/moderations(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/assistants(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/threads(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/runs(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/messages(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/vector_stores(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/batches(?:[/\s\x22\x27]|$))",
        r"(?i)(/v1/usage(?:[/\s\x22\x27]|$))",
        r"(?i)(/api/v1/(models|chat/completions|embeddings)(?:[/\s\x22\x27]|$))",
        r"(?i)(/openai/v1/(models|chat/completions)(?:[/\s\x22\x27]|$))",
        r"(?i)(/(llm|ai)/v1/models(?:[/\s\x22\x27]|$))",
        r"(?i)(/(gpt|chatgpt|chatapi)/v1/models(?:[/\s\x22\x27]|$))",
        r"(?i)(/(stream|proxy)/v1/chat/completions(?:[/\s\x22\x27]|$))",
    ],
}

COMPILED_PATTERNS = {}
for attack_type, patterns in ATTACK_PATTERNS.items():
    COMPILED_PATTERNS[attack_type] = [re.compile(p) for p in patterns]


def get_compiled_patterns():
    """Return compiled regex patterns for all attack types."""
    return COMPILED_PATTERNS


def detect_attack(line):
    """
    Detect if a log line contains an attack pattern.
    
    Args:
        line: Log line string to analyze
        
    Returns:
        Attack type string if detected, None otherwise
    """
    for attack_type, patterns in COMPILED_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(line):
                return attack_type
    return None
