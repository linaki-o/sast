"""Self contained HTML dashboard renderer.

The generated page embeds its own CSS and JavaScript so that it can be
copied around, archived or opened from a file system without any network
access.  Jinja2 is used when it is available; otherwise the very same
document is produced by a small pure Python builder.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from sast import __version__
from sast.core.models import AnalysisResult, Severity
from sast.report import relative_uri, resolve_output_dir, sanitize_anchor
from sast.report.json_report import SEVERITY_ORDER, build_summary, collect_rules

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

DASHBOARD_TEMPLATE = "dashboard.html.j2"

VIOLATION_TEMPLATE = "violation.html.j2"

THEMES = ("dark", "light")

_FILTER_SCRIPT = """
(function () {
  var rows = [];
  var all = document.querySelectorAll('tr.vrow');
  for (var i = 0; i < all.length; i++) {
    rows.push(all[i]);
  }
  var severity = document.getElementById('filter-severity');
  var category = document.getElementById('filter-category');
  var rule = document.getElementById('filter-rule');
  var search = document.getElementById('filter-search');
  var counter = document.getElementById('visible-count');

  function detailOf(row) {
    var id = row.getAttribute('data-detail');
    return id ? document.getElementById(id) : null;
  }

  function apply() {
    var sev = severity ? severity.value : '';
    var cat = category ? category.value : '';
    var rul = rule ? rule.value : '';
    var query = search ? search.value.toLowerCase() : '';
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var visible = true;
      if (sev && row.getAttribute('data-severity') !== sev) { visible = false; }
      if (visible && cat && row.getAttribute('data-category') !== cat) { visible = false; }
      if (visible && rul && row.getAttribute('data-rule') !== rul) { visible = false; }
      if (visible && query) {
        var haystack = row.getAttribute('data-text') || '';
        if (haystack.indexOf(query) === -1) { visible = false; }
      }
      var detail = detailOf(row);
      if (visible) {
        row.style.display = '';
        if (detail) { detail.style.display = ''; }
        shown = shown + 1;
      } else {
        row.style.display = 'none';
        if (detail) { detail.style.display = 'none'; }
      }
    }
    if (counter) { counter.textContent = String(shown); }
  }

  var toggles = document.querySelectorAll('button.vtoggle');
  for (var j = 0; j < toggles.length; j++) {
    toggles[j].addEventListener('click', function () {
      var target = document.getElementById(this.getAttribute('data-target'));
      if (!target) { return; }
      if (target.getAttribute('data-open') === '1') {
        target.style.display = 'none';
        target.setAttribute('data-open', '0');
      } else {
        target.style.display = 'table-row';
        target.setAttribute('data-open', '1');
      }
    });
  }

  var expand = document.getElementById('expand-all');
  var collapse = document.getElementById('collapse-all');
  if (expand) {
    expand.addEventListener('click', function () {
      var details = document.querySelectorAll('tr.vdetail');
      for (var k = 0; k < details.length; k++) {
        details[k].style.display = 'table-row';
        details[k].setAttribute('data-open', '1');
      }
    });
  }
  if (collapse) {
    collapse.addEventListener('click', function () {
      var details = document.querySelectorAll('tr.vdetail');
      for (var k = 0; k < details.length; k++) {
        details[k].style.display = 'none';
        details[k].setAttribute('data-open', '0');
      }
    });
  }

  if (severity) { severity.addEventListener('change', apply); }
  if (category) { category.addEventListener('change', apply); }
  if (rule) { rule.addEventListener('change', apply); }
  if (search) { search.addEventListener('input', apply); }

  apply();
})();
"""

_FALLBACK_CSS = """
* { box-sizing: border-box; }
body { margin: 0; padding: 0 0 48px; background: var(--bg); color: var(--text);
  font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif; font-size: 14px; }
a { color: var(--accent); text-decoration: none; }
.topbar { display: flex; align-items: center; gap: 24px; padding: 20px 28px;
  background: var(--panel); border-bottom: 1px solid var(--border); }
.topbar h1 { margin: 0; font-size: 20px; }
.brand .logo { color: var(--accent); font-weight: 700; letter-spacing: 1px; }
.meta { color: var(--muted); font-size: 12px; }
.score { margin-left: auto; text-align: center; }
.score-value { font-size: 28px; font-weight: 700; }
.score-label { color: var(--muted); font-size: 12px; }
.verdict { padding: 6px 16px; border-radius: 999px; font-weight: 700; }
.verdict.ok { background: rgba(60, 200, 120, 0.18); color: #3cc878; }
.verdict.bad { background: rgba(255, 77, 106, 0.18); color: #ff4d6a; }
main { max-width: 1400px; margin: 0 auto; padding: 0 20px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 18px 22px; margin: 20px 0; }
.panel h2 { margin: 0 0 14px; font-size: 17px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; }
.card { flex: 1 1 140px; padding: 14px; border-radius: 10px; background: var(--bg-soft);
  border-left: 4px solid var(--muted); }
.card-count { font-size: 26px; font-weight: 700; }
.card-label { color: var(--muted); font-size: 12px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }
select, input { background: var(--bg-soft); color: var(--text); border: 1px solid var(--border);
  border-radius: 6px; padding: 5px 8px; }
button.link { background: none; border: none; color: var(--accent); cursor: pointer; }
table.vtable { width: 100%; border-collapse: collapse; }
table.vtable th, table.vtable td { padding: 7px 8px; border-bottom: 1px solid var(--border);
  text-align: left; vertical-align: top; }
table.vtable th { color: var(--muted); font-weight: 600; font-size: 12px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px;
  font-weight: 700; text-transform: uppercase; }
.sev-critical { background: rgba(255, 77, 106, 0.18); color: #ff4d6a; }
.sev-high { background: rgba(255, 138, 61, 0.18); color: #ff8a3d; }
.sev-medium { background: rgba(255, 209, 102, 0.18); color: #ffd166; }
.sev-low { background: rgba(76, 201, 240, 0.18); color: #4cc9f0; }
.sev-info { background: rgba(139, 149, 165, 0.18); color: #9aa4b2; }
pre.snippet { margin: 0; padding: 8px; background: var(--bg-soft); border-radius: 6px;
  overflow-x: auto; font-family: Consolas, monospace; font-size: 12px; }
.vdetail td { background: var(--bg-soft); }
.detail { display: flex; flex-wrap: wrap; gap: 18px; }
.detail > div { flex: 1 1 180px; }
.detail h4 { margin: 0 0 6px; font-size: 12px; color: var(--muted); }
.bars .bar-row { display: flex; align-items: center; gap: 10px; margin: 6px 0; }
.bar-label { flex: 0 0 190px; font-size: 12px; }
.bar { flex: 1; height: 12px; background: var(--bg-soft); border-radius: 999px; overflow: hidden; }
.bar-fill { height: 100%; background: var(--accent); }
.bar-value { flex: 0 0 40px; text-align: right; font-size: 12px; color: var(--muted); }
.file-group h3 { margin: 16px 0 8px; font-size: 14px; }
.pill { margin-left: 8px; padding: 1px 8px; border-radius: 999px; background: var(--bg-soft);
  color: var(--muted); font-size: 11px; }
.sub { color: var(--muted); font-size: 12px; }
"""

_FALLBACK_THEME = """
html[data-theme="dark"] {
  --bg: #0f1117; --bg-soft: #161a23; --panel: #1b202b; --border: #262d3b;
  --text: #e6e9ef; --muted: #97a0b0; --accent: #4c8dff;
}
html[data-theme="light"] {
  --bg: #f5f7fb; --bg-soft: #eef1f7; --panel: #ffffff; --border: #dde3ee;
  --text: #1d2330; --muted: #5d6675; --accent: #2563eb;
}
"""


def _percentage(count: int, total: int) -> float:
    """Percentage of *count* within *total*, rounded to one decimal."""
    if not total:
        return 0.0
    return round(count * 100.0 / total, 1)


def _project_name(result: AnalysisResult, project: Any | None) -> str:
    """Resolve the name shown in the dashboard header."""
    name = getattr(project, "name", "") if project is not None else ""
    if name:
        return str(name)
    return result.project or "CodeShield"


def _anchor_map(paths: list[str]) -> dict[str, str]:
    """Build unique HTML anchors for *paths*."""
    anchors: dict[str, str] = {}
    used: set[str] = set()
    for path in paths:
        anchor = "file-" + sanitize_anchor(path)
        candidate = anchor
        suffix = 2
        while candidate in used:
            candidate = f"{anchor}-{suffix}"
            suffix += 1
        used.add(candidate)
        anchors[path] = candidate
    return anchors


def _violation_payload(
    violation: Any,
    anchor: str,
    anchors: dict[str, str],
) -> dict[str, Any]:
    """Build the template payload of a single violation."""
    file_path = relative_uri(violation.location.file)
    search_parts = [
        violation.rule_id,
        violation.rule_name,
        violation.severity.value,
        violation.category,
        file_path,
        violation.function,
        violation.message,
    ]
    return {
        "id": violation.fingerprint,
        "row_id": "v-" + violation.fingerprint,
        "detail_id": "d-" + violation.fingerprint,
        "severity": violation.severity.value,
        "severity_label": violation.severity.label,
        "rule_id": violation.rule_id,
        "rule_name": violation.rule_name,
        "category": violation.category,
        "language": violation.language,
        "function": violation.function,
        "message": violation.message,
        "snippet": violation.snippet,
        "recommendation": violation.recommendation,
        "cwe": [str(item) for item in violation.cwe],
        "owasp": list(violation.owasp),
        "standards": list(violation.standards),
        "trace": [
            {
                "file": relative_uri(step.file),
                "line": step.line,
                "column": step.column,
                "anchor": anchors.get(step.file),
            }
            for step in violation.trace
        ],
        "file": file_path,
        "line": violation.location.line,
        "column": violation.location.column,
        "location": f"{file_path}:{violation.location.line}:{violation.location.column}",
        "anchor": anchor,
        "search_text": " ".join(part for part in search_parts if part).lower(),
    }


def build_context(
    result: AnalysisResult,
    project: Any | None = None,
    theme: str = "dark",
) -> dict[str, Any]:
    """Build the template context describing *result*."""
    summary = build_summary(result)
    total = summary["total_findings"]
    counts = summary["by_severity"]

    severity_cards = []
    for name in SEVERITY_ORDER:
        count = counts.get(name, 0)
        severity_cards.append(
            {
                "severity": name,
                "label": Severity.parse(name).label,
                "count": count,
                "pct": _percentage(count, total),
            }
        )

    categories = [
        {"name": name, "count": count, "pct": _percentage(count, total)}
        for name, count in summary["by_category"].items()
    ]

    rule_names = {entry["rule_id"]: entry["name"] for entry in collect_rules(result)}
    rules = [
        {
            "rule_id": rule_id,
            "name": rule_names.get(rule_id, rule_id),
            "count": count,
            "pct": _percentage(count, total),
        }
        for rule_id, count in summary["by_rule"].items()
    ]

    grouped: dict[str, list[Any]] = {}
    for violation in result.sorted_violations():
        grouped.setdefault(violation.location.file, []).append(violation)

    anchors = _anchor_map(list(grouped))
    violations = [
        _violation_payload(violation, anchors[violation.location.file], anchors)
        for violation in result.sorted_violations()
    ]

    by_id = {violation["id"]: violation for violation in violations}
    file_groups = []
    for path, items in grouped.items():
        file_groups.append(
            {
                "path": relative_uri(path),
                "anchor": anchors[path],
                "count": len(items),
                "violations": [by_id[item.fingerprint] for item in items],
            }
        )

    metrics = []
    for item in result.file_metrics:
        anchor = anchors.get(item.path)
        metrics.append(
            {
                "path": relative_uri(item.path),
                "anchor": anchor,
                "linked": anchor is not None,
                "language": item.language,
                "lines_total": item.lines_total,
                "lines_code": item.lines_code,
                "lines_comment": item.lines_comment,
                "lines_blank": item.lines_blank,
                "functions": item.functions,
                "classes": item.classes,
                "cyclomatic_complexity": item.cyclomatic_complexity,
                "max_nesting": item.max_nesting,
                "parameters": item.parameters,
                "globals": item.globals,
                "comment_ratio": f"{item.comment_ratio * 100:.1f}%",
                "duplicate_blocks": item.duplicate_blocks,
            }
        )

    theme_name = str(theme or "dark").strip().lower()
    if theme_name not in THEMES:
        theme_name = "dark"

    return {
        "project": _project_name(result, project),
        "version": result.tool_version or __version__,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "theme": theme_name,
        "health_score": summary["health_score"],
        "risk_score": summary["risk_score"],
        "passed": bool(result.passed),
        "status": "PASS" if result.passed else "FAIL",
        "total": total,
        "counts": counts,
        "severity_cards": severity_cards,
        "categories": categories,
        "rules": rules,
        "violations": violations,
        "file_groups": file_groups,
        "metrics": metrics,
        "files_scanned": result.files_scanned,
        "lines_scanned": result.lines_scanned,
        "duration": round(result.duration_seconds, 3),
        "warnings": list(result.warnings),
        "filter_script": _FILTER_SCRIPT,
        "violation_template": VIOLATION_TEMPLATE,
    }


def _render_fallback(context: dict[str, Any]) -> str:
    """Build the dashboard without Jinja2."""
    esc = html.escape
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append(f'<html lang="zh-CN" data-theme="{esc(context["theme"])}">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f'<title>CodeShield 报告 - {esc(context["project"])}</title>')
    parts.append("<style>")
    parts.append(_FALLBACK_THEME)
    parts.append(_FALLBACK_CSS)
    parts.append("</style>")
    parts.append("</head>")
    parts.append("<body>")

    parts.append('<header class="topbar">')
    parts.append(
        f'<div class="brand"><span class="logo">CodeShield</span>'
        f'<h1>{esc(context["project"])}</h1>'
        f'<span class="meta">生成时间 {esc(context["generated_at"])} · 版本 {esc(context["version"])}</span></div>'
    )
    parts.append(
        f'<div class="score"><div class="score-value">{context["health_score"]}</div>'
        f'<div class="score-label">健康分</div></div>'
    )
    verdict_class = "ok" if context["passed"] else "bad"
    parts.append(f'<div class="verdict {verdict_class}">{esc(context["status"])}</div>')
    parts.append("</header>")

    parts.append("<main>")
    parts.append('<section class="panel"><h2>风险概览</h2><div class="cards">')
    for card in context["severity_cards"]:
        parts.append(
            f'<div class="card sev-{esc(card["severity"])}">'
            f'<div class="card-count">{card["count"]}</div>'
            f'<div class="card-label">{esc(card["severity"])} · {esc(card["label"])}</div></div>'
        )
    parts.append("</div>")
    parts.append(
        f'<p class="meta">扫描文件 {context["files_scanned"]} · 扫描行数 {context["lines_scanned"]} · '
        f'耗时 {context["duration"]}s · 风险分 {context["risk_score"]}</p></section>'
    )

    parts.append('<section class="panel" id="violations"><h2>违规明细</h2>')
    parts.append('<div class="toolbar">')
    parts.append('<label>严重级别 <select id="filter-severity"><option value="">全部</option>')
    for card in context["severity_cards"]:
        parts.append(f'<option value="{esc(card["severity"])}">{esc(card["severity"])} ({card["count"]})</option>')
    parts.append("</select></label>")
    parts.append('<label>类别 <select id="filter-category"><option value="">全部</option>')
    for item in context["categories"]:
        parts.append(f'<option value="{esc(item["name"])}">{esc(item["name"])} ({item["count"]})</option>')
    parts.append("</select></label>")
    parts.append('<label>规则 <select id="filter-rule"><option value="">全部</option>')
    for item in context["rules"]:
        parts.append(f'<option value="{esc(item["rule_id"])}">{esc(item["rule_id"])} ({item["count"]})</option>')
    parts.append("</select></label>")
    parts.append('<label>搜索 <input id="filter-search" type="search" placeholder="规则、函数、文件、消息"></label>')
    parts.append(f'<span class="counter">显示 <b id="visible-count">{context["total"]}</b> / {context["total"]}</span>')
    parts.append('<button id="expand-all" class="link" type="button">展开全部</button>')
    parts.append('<button id="collapse-all" class="link" type="button">折叠全部</button>')
    parts.append("</div>")
    parts.append('<table class="vtable"><thead><tr><th>级别</th><th>规则</th><th>位置</th><th>函数</th>'
                 "<th>消息</th><th>代码片段</th><th></th></tr></thead><tbody>")
    for violation in context["violations"]:
        parts.append(_fallback_rows(violation))
    parts.append("</tbody></table>")
    if not context["violations"]:
        parts.append('<p class="meta">没有发现问题，项目通过质量门禁。</p>')
    parts.append("</section>")

    parts.append('<section class="panel" id="breakdown"><h2>类别与规则分布</h2><div class="bars">')
    parts.append("<h3>按类别</h3>")
    for item in context["categories"]:
        parts.append(
            f'<div class="bar-row"><span class="bar-label">{esc(item["name"])}</span>'
            f'<div class="bar"><div class="bar-fill" style="width: {item["pct"]}%"></div></div>'
            f'<span class="bar-value">{item["count"]}</span></div>'
        )
    parts.append("<h3>按规则</h3>")
    for item in context["rules"]:
        parts.append(
            f'<div class="bar-row"><span class="bar-label">{esc(item["rule_id"])}</span>'
            f'<div class="bar"><div class="bar-fill" style="width: {item["pct"]}%"></div></div>'
            f'<span class="bar-value">{item["count"]}</span></div>'
        )
    parts.append("</div></section>")

    parts.append('<section class="panel" id="files"><h2>按文件分组</h2>')
    for group in context["file_groups"]:
        parts.append(f'<article class="file-group" id="{esc(group["anchor"])}">')
        parts.append(
            f'<h3><a href="#{esc(group["anchor"])}">{esc(group["path"])}</a>'
            f'<span class="pill">{group["count"]}</span></h3>'
        )
        parts.append('<table class="vtable"><thead><tr><th>级别</th><th>规则</th><th>位置</th>'
                     "<th>消息</th></tr></thead><tbody>")
        for violation in group["violations"]:
            parts.append(
                f'<tr><td><span class="badge sev-{esc(violation["severity"])}">'
                f'{esc(violation["severity"])}</span></td>'
                f'<td>{esc(violation["rule_id"])} · {esc(violation["rule_name"])}</td>'
                f'<td>{esc(violation["location"])}</td>'
                f'<td>{esc(violation["message"])}</td></tr>'
            )
        parts.append("</tbody></table></article>")
    parts.append("</section>")

    parts.append('<section class="panel" id="metrics"><h2>文件指标</h2>')
    parts.append('<table class="vtable"><thead><tr><th>文件</th><th>语言</th><th>总行数</th><th>代码</th>'
                 "<th>注释</th><th>空行</th><th>函数</th><th>类</th><th>圈复杂度</th><th>最大嵌套</th>"
                 "<th>参数</th><th>全局</th><th>注释率</th></tr></thead><tbody>")
    for item in context["metrics"]:
        name = esc(item["path"])
        if item["linked"]:
            name = f'<a href="#{esc(item["anchor"])}">{name}</a>'
        parts.append(
            f'<tr><td>{name}</td><td>{esc(item["language"])}</td><td>{item["lines_total"]}</td>'
            f'<td>{item["lines_code"]}</td><td>{item["lines_comment"]}</td><td>{item["lines_blank"]}</td>'
            f'<td>{item["functions"]}</td><td>{item["classes"]}</td>'
            f'<td>{item["cyclomatic_complexity"]}</td><td>{item["max_nesting"]}</td>'
            f'<td>{item["parameters"]}</td><td>{item["globals"]}</td><td>{esc(item["comment_ratio"])}</td></tr>'
        )
    parts.append("</tbody></table></section>")
    parts.append("</main>")
    parts.append("<script>")
    parts.append(context["filter_script"])
    parts.append("</script>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _fallback_rows(violation: dict[str, Any]) -> str:
    """Build the table rows of a single violation without Jinja2."""
    esc = html.escape
    snippet = (
        f'<pre class="snippet">{esc(violation["snippet"])}</pre>'
        if violation["snippet"]
        else '<span class="sub">—</span>'
    )
    trace = ""
    if violation["trace"]:
        steps = "".join(
            f'<li>{esc(step["file"])}:{step["line"]}:{step["column"]}</li>' for step in violation["trace"]
        )
        trace = f'<ol class="trace">{steps}</ol>'
    else:
        trace = '<p class="sub">无</p>'
    cwe = "".join(f"<li>{esc(item)}</li>" for item in violation["cwe"]) or "<li>—</li>"
    owasp = "".join(f"<li>{esc(item)}</li>" for item in violation["owasp"]) or "<li>—</li>"
    standards = "".join(f"<li>{esc(item)}</li>" for item in violation["standards"]) or "<li>—</li>"
    return (
        f'<tr class="vrow" id="{esc(violation["row_id"])}" data-severity="{esc(violation["severity"])}" '
        f'data-category="{esc(violation["category"])}" data-rule="{esc(violation["rule_id"])}" '
        f'data-detail="{esc(violation["detail_id"])}" data-text="{esc(violation["search_text"])}">'
        f'<td><span class="badge sev-{esc(violation["severity"])}">{esc(violation["severity"])}</span>'
        f'<span class="sub"> {esc(violation["severity_label"])}</span></td>'
        f'<td><b>{esc(violation["rule_id"])}</b><br><span class="sub">{esc(violation["rule_name"])}</span></td>'
        f'<td><a href="#{esc(violation["anchor"])}">{esc(violation["location"])}</a>'
        f'<br><span class="sub">{esc(violation["category"])}</span></td>'
        f'<td>{esc(violation["function"])}</td>'
        f'<td>{esc(violation["message"])}</td>'
        f'<td>{snippet}</td>'
        f'<td><button class="vtoggle" type="button" data-target="{esc(violation["detail_id"])}">详情</button></td>'
        f'</tr>'
        f'<tr class="vdetail" id="{esc(violation["detail_id"])}" data-open="0" style="display:none">'
        f'<td colspan="7"><div class="detail">'
        f'<div><h4>CWE</h4><ul>{cwe}</ul></div>'
        f'<div><h4>OWASP</h4><ul>{owasp}</ul></div>'
        f'<div><h4>标准</h4><ul>{standards}</ul></div>'
        f'<div><h4>修复建议</h4><p>{esc(violation["recommendation"])}</p></div>'
        f'<div><h4>数据流</h4>{trace}</div>'
        f'</div></td></tr>'
    )


def render_document(context: dict[str, Any]) -> str:
    """Render the dashboard for *context* into a HTML document."""
    jinja2 = None
    try:
        import jinja2 as _jinja2
    except ImportError:
        _jinja2 = None
    jinja2 = _jinja2
    if jinja2 is None:
        return _render_fallback(context)
    try:
        environment = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        template = environment.get_template(DASHBOARD_TEMPLATE)
        return template.render(**context)
    except (jinja2.TemplateError, OSError):
        return _render_fallback(context)


def render_html(
    result: AnalysisResult,
    output_dir: str | Path | None = None,
    *,
    project: Any | None = None,
    theme: str = "dark",
) -> Path:
    """Write ``index.html`` for *result* and return the written path."""
    context = build_context(result, project=project, theme=theme)
    document = render_document(context)
    path = resolve_output_dir(output_dir) / "index.html"
    path.write_text(document, encoding="utf-8")
    return path
