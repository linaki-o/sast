"""Rendering of the traceability matrix.

Three representations are offered: a CSV table for spreadsheets and CI
artifacts, a self contained HTML dashboard and a JSON document.  The HTML
page embeds its own style sheet and script, so it works from a file system
without any network access.
"""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any, Iterable

from sast.traceability.matrix import TraceabilityMatrix

__all__ = ["to_csv", "to_html", "to_json", "write_reports"]

CSV_HEADER = [
    "requirement_id",
    "title",
    "priority",
    "status",
    "category",
    "state",
    "test_count",
    "test_names",
    "code_locations",
    "finding_count",
    "finding_severities",
]

_STYLE = """
:root {
  --bg: #0f172a;
  --panel: #172033;
  --panel-alt: #1e293b;
  --border: #2b3a52;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --covered: #22c55e;
  --implemented: #f59e0b;
  --uncovered: #ef4444;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 0 0 48px;
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}
header.page {
  padding: 24px 32px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--panel);
}
header.page h1 { margin: 0 0 4px; font-size: 22px; letter-spacing: .3px; }
header.page p { margin: 0; color: var(--muted); font-size: 13px; }
main { padding: 24px 32px; }
.cards { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; }
.card {
  min-width: 170px;
  padding: 14px 18px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--panel);
}
.card .value { font-size: 26px; font-weight: 600; }
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; }
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
}
.toolbar input, .toolbar select {
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--panel-alt);
  color: var(--text);
  font-size: 13px;
}
.toolbar input { min-width: 260px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }
th {
  position: sticky;
  top: 0;
  background: var(--panel-alt);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .4px;
  color: var(--muted);
}
tbody tr:hover { background: rgba(56, 189, 248, .06); }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid transparent;
}
.badge.covered { color: var(--covered); border-color: var(--covered); }
.badge.implemented { color: var(--implemented); border-color: var(--implemented); }
.badge.uncovered { color: var(--uncovered); border-color: var(--uncovered); }
.prio { font-size: 12px; text-transform: uppercase; color: var(--muted); }
.prio.high { color: #f87171; }
.prio.medium { color: #fbbf24; }
.prio.low { color: #60a5fa; }
button.toggle {
  width: 24px;
  height: 24px;
  margin-right: 6px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--panel-alt);
  color: var(--text);
  cursor: pointer;
}
tr.detail td { background: var(--panel); }
tr.detail[hidden] { display: none; }
.detail-grid { display: grid; grid-template-columns: 140px 1fr; gap: 6px 16px; }
.detail-grid h4 { margin: 0; color: var(--muted); font-size: 12px; text-transform: uppercase; }
.detail-grid ul { margin: 0; padding-left: 18px; }
.muted { color: var(--muted); }
.sev { font-size: 12px; padding: 1px 8px; border-radius: 4px; border: 1px solid var(--border); }
footer { padding: 0 32px; color: var(--muted); font-size: 12px; }
"""

_SCRIPT = """
(function () {
  var rows = [];
  var all = document.querySelectorAll('tr.req-row');
  for (var i = 0; i < all.length; i++) { rows.push(all[i]); }
  var search = document.getElementById('filter-search');
  var state = document.getElementById('filter-state');
  var priority = document.getElementById('filter-priority');
  var counter = document.getElementById('visible-count');

  function apply() {
    var query = search ? search.value.toLowerCase() : '';
    var wantedState = state ? state.value : '';
    var wantedPriority = priority ? priority.value : '';
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var visible = true;
      if (wantedState && row.getAttribute('data-state') !== wantedState) { visible = false; }
      if (visible && wantedPriority && row.getAttribute('data-priority') !== wantedPriority) { visible = false; }
      if (visible && query) {
        var haystack = row.getAttribute('data-text') || '';
        if (haystack.indexOf(query) === -1) { visible = false; }
      }
      var detail = document.getElementById(row.getAttribute('data-detail'));
      if (visible) {
        row.style.display = '';
        shown = shown + 1;
      } else {
        row.style.display = 'none';
        if (detail) { detail.style.display = 'none'; }
      }
    }
    if (counter) { counter.textContent = String(shown); }
  }

  var toggles = document.querySelectorAll('button.toggle');
  for (var j = 0; j < toggles.length; j++) {
    toggles[j].addEventListener('click', function () {
      var detail = document.getElementById(this.getAttribute('data-target'));
      if (!detail) { return; }
      var open = detail.getAttribute('data-open') === '1';
      detail.setAttribute('data-open', open ? '0' : '1');
      detail.style.display = open ? 'none' : 'table-row';
      this.textContent = open ? '+' : '-';
    });
  }

  var expand = document.getElementById('expand-all');
  if (expand) {
    expand.addEventListener('click', function () {
      for (var k = 0; k < toggles.length; k++) {
        var detail = document.getElementById(toggles[k].getAttribute('data-target'));
        if (detail) {
          detail.setAttribute('data-open', '1');
          detail.style.display = 'table-row';
          toggles[k].textContent = '-';
        }
      }
    });
  }

  var collapse = document.getElementById('collapse-all');
  if (collapse) {
    collapse.addEventListener('click', function () {
      for (var k = 0; k < toggles.length; k++) {
        var detail = document.getElementById(toggles[k].getAttribute('data-target'));
        if (detail) {
          detail.setAttribute('data-open', '0');
          detail.style.display = 'none';
          toggles[k].textContent = '+';
        }
      }
    });
  }

  if (search) { search.addEventListener('input', apply); }
  if (state) { state.addEventListener('change', apply); }
  if (priority) { priority.addEventListener('change', apply); }
  apply();
})();
"""


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _test_names(matrix: TraceabilityMatrix, requirement_id: str) -> list[str]:
    names: list[str] = []
    for link in matrix.links_for(requirement_id, "test"):
        name = link.target_name or link.target_id
        if name and name not in names:
            names.append(name)
    return names


def _finding_severities(matrix: TraceabilityMatrix, requirement_id: str) -> list[str]:
    severities: list[str] = []
    for link in matrix.links_for(requirement_id, "finding"):
        value = link.severity or "unknown"
        if value not in severities:
            severities.append(value)
    return severities


def to_csv(matrix: TraceabilityMatrix) -> str:
    """Render the matrix as a CSV document."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    for requirement, cell in matrix.rows():
        writer.writerow(
            [
                requirement.id,
                requirement.title,
                requirement.priority,
                requirement.status,
                requirement.category,
                cell.coverage_state,
                len(cell.tests),
                "; ".join(_test_names(matrix, requirement.id)),
                "; ".join(cell.code_locations),
                len(cell.findings),
                "; ".join(_finding_severities(matrix, requirement.id)),
            ]
        )
    return buffer.getvalue()


def to_json(matrix: TraceabilityMatrix) -> str:
    """Render the matrix as a JSON document."""
    return json.dumps(matrix.to_dict(), indent=2, ensure_ascii=False)


def _card(value: Any, label: str) -> str:
    return (
        '<div class="card"><div class="value">{value}</div>'
        '<div class="label">{label}</div></div>'
    ).format(value=_escape(value), label=_escape(label))


def _list_items(items: Iterable[str]) -> str:
    entries = list(items)
    if not entries:
        return '<span class="muted">none</span>'
    return "<ul>{body}</ul>".format(
        body="".join("<li>{}</li>".format(_escape(entry)) for entry in entries)
    )


def to_html(matrix: TraceabilityMatrix, *, analysis: Any = None) -> str:
    """Render the matrix as a self contained HTML page."""
    rows = matrix.rows()
    total = len(rows)
    covered = sum(1 for _, cell in rows if cell.covered)
    uncovered = total - covered
    uncovered_percentage = (uncovered * 100.0 / total) if total else 0.0
    orphans = matrix.orphan_tests(sorted(matrix.known_test_ids))
    finding_links = [link for link in matrix.links if link.target_kind == "finding"]
    if analysis is not None:
        finding_count = len(getattr(analysis, "violations", []) or [])
    else:
        finding_count = len(finding_links)

    project_name = ""
    if analysis is not None:
        project_name = str(getattr(analysis, "project", "") or "")

    body_rows: list[str] = []
    for index, (requirement, cell) in enumerate(rows, start=1):
        detail_id = f"detail-{index}"
        tests = _test_names(matrix, requirement.id)
        haystack = " ".join(
            [
                requirement.id,
                requirement.title,
                requirement.description,
                requirement.category,
                requirement.priority,
                requirement.status,
                " ".join(requirement.tags),
                " ".join(tests),
            ]
        ).lower()
        test_items = [
            "{} ({})".format(link.target_name or link.target_id, link.target_id)
            for link in matrix.links_for(requirement.id, "test")
        ]
        code_items = list(cell.code_locations)
        finding_items = [
            "{} [{}] {} {}".format(
                link.target_name or link.target_id,
                link.severity or "unknown",
                link.comment,
                link.location or "",
            ).strip()
            for link in matrix.links_for(requirement.id, "finding")
        ]
        detail = (
            '<tr class="detail" id="{detail_id}" data-open="0" hidden>'
            "<td colspan=\"7\"><div class=\"detail-grid\">"
            "<h4>Tests</h4><div>{tests}</div>"
            "<h4>Code locations</h4><div>{code}</div>"
            "<h4>Findings</h4><div>{findings}</div>"
            "<h4>Tags</h4><div>{tags}</div>"
            "<h4>Description</h4><div>{description}</div>"
            "</div></td></tr>"
        ).format(
            detail_id=detail_id,
            tests=_list_items(test_items),
            code=_list_items(code_items),
            findings=_list_items(finding_items),
            tags=_list_items(requirement.tags),
            description=_escape(requirement.description) or '<span class="muted">none</span>',
        )
        body_rows.append(
            '<tr class="req-row" data-state="{state}" data-priority="{priority}" '
            'data-detail="{detail_id}" data-text="{haystack}">'
            '<td><button class="toggle" data-target="{detail_id}" type="button">+</button>'
            "<strong>{rid}</strong></td>"
            "<td>{title}</td>"
            '<td class="prio {priority}">{priority}</td>'
            "<td>{status}</td>"
            "<td>{category}</td>"
            '<td><span class="badge {state}">{state}</span></td>'
            '<td class="num">{test_count}</td>'
            "</tr>".format(
                state=_escape(cell.coverage_state),
                priority=_escape(requirement.priority),
                detail_id=detail_id,
                haystack=_escape(haystack),
                rid=_escape(requirement.id),
                title=_escape(requirement.title),
                status=_escape(requirement.status),
                category=_escape(requirement.category),
                test_count=len(cell.tests),
            )
        )
        body_rows.append(detail)

    if not body_rows:
        body_rows.append(
            '<tr><td colspan="7" class="muted">No requirements loaded</td></tr>'
        )

    priorities = sorted({requirement.priority for requirement, _ in rows})
    priority_options = "".join(
        '<option value="{value}">{value}</option>'.format(value=_escape(value))
        for value in priorities
    )

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeShield traceability matrix</title>
<style>{style}</style>
</head>
<body>
<header class="page">
<h1>Requirements traceability matrix</h1>
<p>{subtitle}</p>
</header>
<main>
<div class="cards">
{cards}
</div>
<div class="toolbar">
<input id="filter-search" type="search" placeholder="Search requirements, tests and tags">
<select id="filter-state">
<option value="">all states</option>
<option value="covered">covered</option>
<option value="implemented">implemented</option>
<option value="uncovered">uncovered</option>
</select>
<select id="filter-priority">
<option value="">all priorities</option>
{priority_options}
</select>
<button id="expand-all" class="toggle" type="button">+</button>
<button id="collapse-all" class="toggle" type="button">-</button>
<span class="muted"><span id="visible-count">{total}</span> of {total} requirements shown</span>
</div>
<table>
<thead>
<tr>
<th>Requirement</th>
<th>Title</th>
<th>Priority</th>
<th>Status</th>
<th>Category</th>
<th>Coverage</th>
<th>Tests</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</main>
<footer>Generated by CodeShield</footer>
<script>{script}</script>
</body>
</html>
""".format(
        style=_STYLE,
        script=_SCRIPT,
        subtitle=_escape(
            project_name
            or "Requirements linked to tests, code locations and findings"
        ),
        cards="".join(
            [
                _card(total, "requirements"),
                _card(covered, "covered"),
                _card(uncovered, "uncovered"),
                _card(f"{uncovered_percentage:.1f}%", "uncovered share"),
                _card(len(orphans), "orphan tests"),
                _card(finding_count, "findings"),
            ]
        ),
        priority_options=priority_options,
        total=total,
        rows="".join(body_rows),
    )


def write_reports(
    matrix: TraceabilityMatrix,
    output_dir: str | Path,
    *,
    analysis: Any = None,
) -> list[Path]:
    """Write the CSV, HTML and JSON reports into *output_dir*."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    csv_path = directory / "traceability.csv"
    csv_path.write_text(to_csv(matrix), encoding="utf-8")
    written.append(csv_path)

    html_path = directory / "traceability.html"
    html_path.write_text(to_html(matrix, analysis=analysis), encoding="utf-8")
    written.append(html_path)

    json_path = directory / "traceability.json"
    json_path.write_text(to_json(matrix), encoding="utf-8")
    written.append(json_path)

    return written
