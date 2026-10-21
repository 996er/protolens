"""Local, dependency-free HTML views for gcov snapshots."""
from __future__ import annotations

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading


def write_view(root: Path, *, snapshot: Path | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "style.css").write_text(STYLE, encoding="utf-8")
    (root / "app.js").write_text(SCRIPT, encoding="utf-8")
    destination = snapshot or root
    destination.mkdir(parents=True, exist_ok=True)
    base = "../.." if snapshot else "."
    (destination / "index.html").write_text(HTML.replace("$BASE", base).replace(
        "$DATA", "coverage.json" if snapshot else "latest.json"), encoding="utf-8")


class CoverageHTTPServer:
    def __init__(self, root: Path, host: str, port: int) -> None:
        served_root = root.resolve()

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def end_headers(self):
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                super().end_headers()

            def send_head(self):
                # Resolve symlinks too; only the generated public directory is served.
                try:
                    Path(self.translate_path(self.path)).resolve().relative_to(served_root)
                except ValueError:
                    self.send_error(403)
                    return
                return super().send_head()

        self.server = ThreadingHTTPServer((host, port), partial(Handler, directory=str(served_root)))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ProtoLens 源码覆盖率</title>
<link rel="stylesheet" href="$BASE/style.css"><body data-base="$BASE" data-report="$DATA">
<header><span>PROTOLENS / GCOV</span><h1>源码覆盖率</h1><p id="status">等待覆盖率数据…</p></header>
<main><section id="metrics" class="metrics"></section><section><h2>覆盖率变化</h2>
<svg id="trend" viewBox="0 0 900 150" role="img" aria-label="累计行与分支覆盖率曲线"></svg>
<p class="muted">蓝色：行覆盖率 · 紫色：分支覆盖率。每个点对应一个队列用例。</p></section>
<section><h2>文件与未覆盖区域</h2><input id="filter" placeholder="搜索源码路径">
<div class="columns"><div id="files"></div><div id="detail">选择文件查看行执行次数和分支。</div></div></section>
<section><h2>用例快照</h2><p class="muted">每个 HTML 快照保存该用例完成后的累计覆盖；增量按独立用例重放计算。</p>
<div class="scroll"><table><thead><tr><th>Queue 用例</th><th>结果</th><th>行覆盖</th><th>分支覆盖</th>
<th>新增行 / 分支</th><th>报告</th></tr></thead><tbody id="history"></tbody></table></div></section>
</main><script src="$BASE/app.js"></script></body></html>"""

STYLE = """*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:#18283b;font:15px system-ui,sans-serif}
header{background:#152b43;color:white;padding:32px max(24px,calc((100vw - 1250px)/2))}header span{font-size:12px;letter-spacing:3px;color:#7ed5df}
h1{font-size:32px;margin:14px 0}main{max-width:1300px;margin:auto;padding:24px}section{background:white;padding:24px;margin-bottom:20px;border:1px solid #e0e6ed;border-radius:12px}
h2{font-size:18px;margin-top:0}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:24px}.metric strong{font-size:28px;display:block;margin:10px 0;color:#1762b4}.muted{color:#617083;font-size:13px}
input{padding:10px;border:1px solid #ccd6e0;border-radius:6px;width:100%;margin-bottom:15px}.columns{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,2fr);gap:12px}#files{max-height:550px;overflow:auto}button{display:block;width:100%;text-align:left;background:#f5f8fc;border:0;border-bottom:1px solid #dde5ee;padding:12px;cursor:pointer;overflow-wrap:anywhere}
button:hover{background:#e7f1ff}.scroll,#detail{overflow:auto}#detail{max-height:550px}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:9px;text-align:left;border-bottom:1px solid #e3e9ef;vertical-align:top}a{color:#1762b4}.code{font-family:ui-monospace,monospace;white-space:pre}.hit{background:#e7f5ec}.miss{background:#ffe9e8}.partial{background:#fff2cc}svg{width:100%;max-height:170px}code{overflow-wrap:anywhere}@media(max-width:700px){.metrics{grid-template-columns:1fr 1fr}.columns{grid-template-columns:1fr}main{padding:12px}}
"""

SCRIPT = r"""const base=document.body.dataset.base, report=document.body.dataset.report;
let current=null,sources={},selected=null;
const el=(tag,text,cls)=>{const x=document.createElement(tag);if(text!==undefined)x.textContent=text;if(cls)x.className=cls;return x};
async function json(url){const r=await fetch(url,{cache:'no-store'});if(!r.ok)throw Error(`${r.status} ${url}`);return r.json()}
function files(){if(!current)return;const box=document.querySelector('#files');box.replaceChildren();const query=document.querySelector('#filter').value.toLowerCase();
for(const [name,f] of Object.entries(current.files||{}).filter(([n])=>n.toLowerCase().includes(query))){const b=el('button',`${name}\n${f.summary.lines.hit}/${f.summary.lines.total} 行 · ${f.summary.branches.hit}/${f.summary.branches.total} 分支`);b.onclick=()=>detail(name);box.append(b)}}
function detail(name){selected=name;const f=current.files[name],box=document.querySelector('#detail');box.replaceChildren(el('h3',name));const t=el('table');
const src=sources[name]||[];for(let i=1;i<=Math.max(src.length,...Object.keys(f.lines).map(Number),0);i++){
const row=el('tr'),count=f.lines[i],branches=Object.values(f.branches).filter(b=>b.line===i),hits=branches.filter(b=>b.count>0).length;
row.className=count===undefined?'':count===0?'miss':branches.length&&hits<branches.length?'partial':'hit';
row.append(el('td',String(i)),el('td',count===undefined?'':String(count)),el('td',branches.length?`${hits}/${branches.length} 分支`:''),el('td',src[i-1]||'','code'));t.append(row)}box.append(t)}
function render(data,history,state){if(report!=='latest.json'){history=history.filter(h=>h.sequence<=data.sequence);state={status:'历史快照',pending:0}}current=data;document.querySelector('#status').textContent=`${state.status||'ready'} · 已收集 ${history.length} 个用例 · 待收集 ${state.pending||0} · 失败 ${history.filter(h=>h.status!=='collected').length} · ${state.error||data.completed_at||''}`;
const metrics=document.querySelector('#metrics');metrics.replaceChildren();for(const [key,title] of [['lines','行覆盖率'],['branches','分支覆盖率'],['functions','函数覆盖率']]){const v=data.summary?.[key]||{hit:0,total:0,percent:0};const box=el('div',undefined,'metric');box.append(el('span',title),el('strong',`${v.percent.toFixed(2)}%`),el('span',`${v.hit} / ${v.total}`,'muted'));metrics.append(box)}const box=el('div',undefined,'metric');box.append(el('span','最近用例新增'),el('strong',`+${data.delta?.lines||0} 行`),el('span',`+${data.delta?.branches||0} 分支`,'muted'));metrics.append(box);
const chart=document.querySelector('#trend');chart.replaceChildren();for(const [key,color] of [['lines','#1762b4'],['branches','#8b5bc1']]){const p=document.createElementNS('http://www.w3.org/2000/svg','polyline');p.setAttribute('fill','none');p.setAttribute('stroke',color);p.setAttribute('stroke-width','3');p.setAttribute('points',history.map((h,i)=>`${10+i*880/Math.max(1,history.length-1)},${140-(h.summary?.[key]?.percent||0)*1.3}`).join(' '));chart.append(p)}
const body=document.querySelector('#history');body.replaceChildren();for(const h of [...history].reverse()){const r=el('tr');r.append(el('td',h.seed_file),el('td',h.error||h.status),el('td',`${h.summary?.lines?.percent||0}%`),el('td',`${h.summary?.branches?.percent||0}%`),el('td',`${h.delta?.lines||0} / ${h.delta?.branches||0}`));const cell=el('td'),a=el('a','HTML');a.href=`${base}/${h.report}`;cell.append(a);r.append(cell);body.append(r)}files();if(selected&&data.files?.[selected])detail(selected)}
async function refresh(){try{const [data,history,state]=await Promise.all([json(report),json(`${base}/history.json`),json(`${base}/status.json`)]);if(!Object.keys(sources).length)sources=await json(`${base}/sources.json`);render(data,history,state)}catch(e){document.querySelector('#status').textContent=`等待报告或读取失败：${e.message}`}}
document.querySelector('#filter').oninput=files;refresh();if(report==='latest.json')setInterval(refresh,3000);
"""
