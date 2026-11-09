(function () {
  "use strict";

  var SEVERITIES = ["critical", "high", "medium", "low", "info"];
  var SEVERITY_LABELS = {
    critical: "严重",
    high: "高危",
    medium: "中危",
    low: "低危",
    info: "提示"
  };

  var state = {
    runId: "",
    violations: [],
    sortKey: "severity",
    sortDir: "asc",
    results: null
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function readBootstrap() {
    var node = byId("bootstrap");
    if (!node) {
      return {};
    }
    try {
      return JSON.parse(node.textContent || "{}");
    } catch (error) {
      return {};
    }
  }

  function fetchJSON(url, options) {
    return fetch(url, options || {}).then(function (response) {
      return response.text().then(function (text) {
        var payload = null;
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (error) {
            payload = null;
          }
        }
        if (!response.ok) {
          var detail = payload && (payload.detail || payload.message);
          var failure = new Error(detail || "HTTP " + response.status);
          failure.status = response.status;
          throw failure;
        }
        return payload;
      });
    });
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function showSpinner(label) {
    var spinner = byId("spinner");
    if (!spinner) {
      return;
    }
    spinner.classList.remove("hidden");
    var text = spinner.querySelector(".spinner-label");
    if (text) {
      text.textContent = label || "处理中…";
    }
  }

  function hideSpinner() {
    var spinner = byId("spinner");
    if (spinner) {
      spinner.classList.add("hidden");
    }
  }

  var toastTimer = null;

  function toast(message, ok) {
    var node = byId("toast");
    if (!node) {
      return;
    }
    node.textContent = String(message);
    node.classList.remove("hidden");
    node.classList.toggle("ok", Boolean(ok));
    if (toastTimer) {
      window.clearTimeout(toastTimer);
    }
    toastTimer = window.setTimeout(function () {
      node.classList.add("hidden");
    }, 6000);
  }

  function severityOrder(value) {
    var index = SEVERITIES.indexOf(String(value || "").toLowerCase());
    return index < 0 ? SEVERITIES.length : index;
  }

  function formatTime(value) {
    if (!value) {
      return "—";
    }
    var date = new Date(value);
    if (isNaN(date.getTime())) {
      return String(value);
    }
    return date.toLocaleString();
  }

  function renderKpis(summary) {
    var counts = (summary && summary.counts) || {};
    var set = function (id, value) {
      var node = byId(id);
      if (node) {
        node.textContent = String(value);
      }
    };
    set("kpi-total", summary ? summary.violations : 0);
    set("kpi-critical", counts.critical || 0);
    set("kpi-high", counts.high || 0);
    set("kpi-medium", counts.medium || 0);
    set("kpi-health", summary ? summary.health_score : 0);
    set("kpi-files", summary ? summary.files_scanned : 0);
    var verdict = byId("verdict");
    if (verdict) {
      var passed = summary ? summary.passed : true;
      verdict.textContent = passed ? "PASS" : "FAIL";
      verdict.classList.toggle("ok", Boolean(passed));
      verdict.classList.toggle("bad", !passed);
    }
    var score = byId("health-score");
    if (score && summary) {
      score.textContent = String(summary.health_score);
    }
  }

  function renderSeverityBar(counts) {
    var bar = byId("sevbar");
    var legend = byId("sevlegend");
    if (!bar) {
      return;
    }
    clear(bar);
    var total = 0;
    SEVERITIES.forEach(function (name) {
      total += (counts && counts[name]) || 0;
    });
    SEVERITIES.forEach(function (name) {
      var count = (counts && counts[name]) || 0;
      var segment = element("span", "seg-" + name);
      segment.style.width = total ? (count * 100 / total).toFixed(2) + "%" : "0%";
      segment.title = name + ": " + count;
      bar.appendChild(segment);
    });
    if (!legend) {
      return;
    }
    clear(legend);
    SEVERITIES.forEach(function (name) {
      var item = element("span", "legend-" + name);
      var dot = element("i");
      dot.style.background = "var(--" + name + ")";
      item.appendChild(dot);
      item.appendChild(document.createTextNode(name + " · " + ((counts && counts[name]) || 0)));
      legend.appendChild(item);
    });
  }

  function renderCategories(byCategory) {
    var container = byId("category-list");
    if (!container) {
      return;
    }
    clear(container);
    var entries = Object.keys(byCategory || {}).map(function (name) {
      return { name: name, count: byCategory[name] };
    });
    if (!entries.length) {
      container.appendChild(element("p", "empty", "暂无数据"));
      return;
    }
    var max = entries.reduce(function (acc, item) {
      return Math.max(acc, item.count);
    }, 0);
    entries.forEach(function (item) {
      var row = element("div", "bar-row");
      row.appendChild(element("span", "bar-label", item.name));
      var track = element("div", "bar");
      var fill = element("div", "bar-fill");
      fill.style.width = max ? (item.count * 100 / max).toFixed(2) + "%" : "0%";
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(element("span", "bar-value", item.count));
      container.appendChild(row);
    });
  }

  function fillSelect(selectId, values, keep) {
    var select = byId(selectId);
    if (!select) {
      return;
    }
    var previous = keep ? select.value : "";
    clear(select);
    var all = element("option", null, "全部");
    all.value = "";
    select.appendChild(all);
    values.forEach(function (item) {
      var option = element("option", null, item.label);
      option.value = item.value;
      select.appendChild(option);
    });
    if (previous) {
      select.value = previous;
    }
  }

  function violationSortKey(violation, key) {
    var location = violation.location || {};
    if (key === "severity") {
      return severityOrder(violation.severity);
    }
    if (key === "line") {
      return location.line || 0;
    }
    if (key === "file") {
      return String(location.file || "");
    }
    if (key === "rule_id") {
      return String(violation.rule_id || "");
    }
    return String(violation.message || "");
  }

  function sortViolations(items) {
    var key = state.sortKey;
    var direction = state.sortDir === "asc" ? 1 : -1;
    var copy = items.slice();
    copy.sort(function (left, right) {
      var a = violationSortKey(left, key);
      var b = violationSortKey(right, key);
      if (a < b) {
        return -1 * direction;
      }
      if (a > b) {
        return 1 * direction;
      }
      return 0;
    });
    return copy;
  }

  function detailCell(violation) {
    var cell = document.createElement("td");
    cell.colSpan = 6;
    var wrapper = element("div", "detail");

    var block = function (title, body) {
      var box = element("div");
      box.appendChild(element("h4", null, title));
      box.appendChild(body);
      return box;
    };

    var list = function (values, empty) {
      if (!values || !values.length) {
        return element("p", "sub", empty || "—");
      }
      var node = document.createElement("ul");
      values.forEach(function (value) {
        node.appendChild(element("li", null, value));
      });
      return node;
    };

    wrapper.appendChild(block("消息", element("p", null, violation.message || "—")));
    wrapper.appendChild(block("修复建议", element("p", null, violation.recommendation || "—")));
    wrapper.appendChild(block("CWE", list((violation.cwe || []).map(String))));
    wrapper.appendChild(block("OWASP", list(violation.owasp || [])));
    wrapper.appendChild(block("标准", list(violation.standards || [])));

    var snippet = element("pre", "snippet", violation.snippet || "");
    wrapper.appendChild(block("代码片段", snippet));

    var trace = violation.trace || [];
    var traceBox = element("div");
    if (trace.length) {
      var ordered = document.createElement("ol");
      trace.forEach(function (step) {
        ordered.appendChild(element("li", null, (step.file || "") + ":" + (step.line || 0) + ":" + (step.column || 0)));
      });
      traceBox.appendChild(ordered);
    } else {
      traceBox.appendChild(element("p", "sub", "无"));
    }
    wrapper.appendChild(block("数据流", traceBox));

    cell.appendChild(wrapper);
    return cell;
  }

  function renderViolations(items) {
    var body = byId("findings-body");
    if (!body) {
      return;
    }
    clear(body);
    var counter = byId("visible-count");
    var totalCounter = byId("total-count");
    if (totalCounter) {
      totalCounter.textContent = String(items.length);
    }
    if (counter) {
      counter.textContent = String(items.length);
    }
    if (!items.length) {
      var empty = element("tr");
      var cell = element("td", "empty", "没有匹配的问题");
      cell.colSpan = 6;
      empty.appendChild(cell);
      body.appendChild(empty);
      return;
    }
    sortViolations(items).forEach(function (violation) {
      var location = violation.location || {};
      var row = document.createElement("tr");
      row.className = "vrow";
      row.setAttribute("data-severity", violation.severity || "");
      row.setAttribute("data-category", violation.category || "");
      row.setAttribute("data-rule", violation.rule_id || "");
      row.setAttribute("data-fingerprint", violation.fingerprint || "");

      var severityCell = document.createElement("td");
      var badge = element("span", "badge sev-" + (violation.severity || "info"), violation.severity || "");
      severityCell.appendChild(badge);
      severityCell.appendChild(element("span", "sub", " " + (SEVERITY_LABELS[violation.severity] || "")));
      row.appendChild(severityCell);

      var ruleCell = document.createElement("td");
      ruleCell.appendChild(element("b", null, violation.rule_id || ""));
      ruleCell.appendChild(element("br"));
      ruleCell.appendChild(element("span", "sub", violation.rule_name || ""));
      row.appendChild(ruleCell);

      var fileCell = document.createElement("td");
      fileCell.appendChild(element("span", null, location.file || ""));
      fileCell.appendChild(element("br"));
      fileCell.appendChild(element("span", "sub", violation.category || ""));
      row.appendChild(fileCell);

      var lineCell = element("td", "num", location.line || 0);
      row.appendChild(lineCell);

      var messageCell = document.createElement("td");
      messageCell.appendChild(element("span", null, violation.message || ""));
      row.appendChild(messageCell);

      var actionCell = document.createElement("td");
      var toggle = element("button", "btn ghost vtoggle", "详情");
      toggle.type = "button";
      actionCell.appendChild(toggle);
      row.appendChild(actionCell);

      var detailRow = document.createElement("tr");
      detailRow.className = "vdetail";
      detailRow.style.display = "none";
      detailRow.appendChild(detailCell(violation));

      body.appendChild(row);
      body.appendChild(detailRow);
    });
  }

  function updateSortIndicators() {
    var headers = document.querySelectorAll("table.vtable thead th[data-sort]");
    for (var index = 0; index < headers.length; index += 1) {
      var header = headers[index];
      var arrow = header.querySelector(".arrow");
      if (!arrow) {
        arrow = element("span", "arrow");
        header.appendChild(arrow);
      }
      arrow.textContent = header.getAttribute("data-sort") === state.sortKey
        ? (state.sortDir === "asc" ? "▲" : "▼")
        : "";
    }
  }

  function loadViolations() {
    if (!state.runId) {
      renderViolations([]);
      return Promise.resolve();
    }
    var params = [];
    var severity = byId("filter-severity");
    var category = byId("filter-category");
    var rule = byId("filter-rule");
    var search = byId("filter-search");
    if (severity && severity.value) {
      params.push("severity=" + encodeURIComponent(severity.value));
    }
    if (category && category.value) {
      params.push("category=" + encodeURIComponent(category.value));
    }
    if (rule && rule.value) {
      params.push("rule=" + encodeURIComponent(rule.value));
    }
    if (search && search.value.trim()) {
      params.push("q=" + encodeURIComponent(search.value.trim()));
    }
    var url = "/api/results/" + encodeURIComponent(state.runId) + "/violations";
    if (params.length) {
      url += "?" + params.join("&");
    }
    return fetchJSON(url).then(function (payload) {
      state.violations = (payload && payload.violations) || [];
      renderViolations(state.violations);
    }).catch(function (error) {
      toast("加载问题列表失败: " + error.message);
    });
  }

  function loadResult(runId) {
    state.runId = runId || "";
    if (!state.runId) {
      renderKpis(null);
      renderSeverityBar({});
      renderCategories({});
      renderViolations([]);
      return Promise.resolve();
    }
    return fetchJSON("/api/results/" + encodeURIComponent(state.runId)).then(function (payload) {
      state.results = payload;
      renderKpis({
        counts: payload.counts,
        violations: (payload.violations || []).length,
        health_score: Math.max(0, 100 - Math.floor((payload.risk_score || 0) / 2)),
        files_scanned: payload.files_scanned,
        passed: payload.passed
      });
      renderSeverityBar(payload.counts || {});
      renderCategories(payload.by_category || {});
      var categories = Object.keys(payload.by_category || {});
      var rules = Object.keys(payload.by_rule || {});
      fillSelect("filter-category", categories.map(function (name) {
        return { value: name, label: name };
      }));
      fillSelect("filter-rule", rules.map(function (name) {
        return { value: name, label: name };
      }));
      return loadViolations();
    }).catch(function (error) {
      toast("加载运行结果失败: " + error.message);
    });
  }

  function renderRunList(runs) {
    var container = byId("run-list");
    if (!container) {
      return;
    }
    clear(container);
    if (!runs || !runs.length) {
      container.appendChild(element("li", "empty", "尚无运行记录"));
      return;
    }
    runs.slice().reverse().forEach(function (run) {
      var item = document.createElement("li");
      var title = element("div", "run-title");
      var link = document.createElement("a");
      link.href = "/runs/" + run.id;
      link.textContent = run.kind + " · " + run.project;
      title.appendChild(link);
      var pill = element("span", "pill", run.violations !== undefined ? (run.violations + " 项") : (run.total_tests !== undefined ? (run.total_tests + " 个用例") : "—"));
      title.appendChild(pill);
      item.appendChild(title);
      var meta = element("div", "run-meta", formatTime(run.created_at) + " · " + (run.duration_s || 0).toFixed(2) + "s");
      item.appendChild(meta);
      container.appendChild(item);
    });
  }

  function loadRuns() {
    return fetchJSON("/api/runs").then(function (payload) {
      renderRunList(payload.runs || []);
      var latest = byId("latest-run");
      if (latest) {
        latest.value = payload.runs && payload.runs.length ? payload.runs[payload.runs.length - 1].id : "";
      }
    }).catch(function (error) {
      toast("加载运行历史失败: " + error.message);
    });
  }

  function renderRules(rules) {
    var container = byId("rule-groups");
    if (!container) {
      return;
    }
    clear(container);
    var groups = {};
    rules.forEach(function (rule) {
      var key = rule.category || "other";
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(rule);
    });
    var names = Object.keys(groups).sort();
    var counter = byId("rule-count");
    if (counter) {
      counter.textContent = rules.length + " 条规则";
    }
    names.forEach(function (name) {
      var group = element("div", "rule-group");
      group.appendChild(element("h3", null, name + " (" + groups[name].length + ")"));
      var list = document.createElement("ul");
      groups[name].forEach(function (rule) {
        var item = document.createElement("li");
        item.appendChild(element("span", "rule-id", rule.rule_id));
        item.appendChild(element("span", "rule-name", rule.name));
        var badge = element("span", "badge sev-" + rule.severity, rule.severity);
        item.appendChild(badge);
        list.appendChild(item);
      });
      group.appendChild(list);
      container.appendChild(group);
    });
  }

  function loadRules() {
    return fetchJSON("/api/rules").then(function (payload) {
      renderRules(payload.rules || []);
    }).catch(function (error) {
      toast("加载规则目录失败: " + error.message);
    });
  }

  function runAnalysis() {
    var button = byId("btn-analyze");
    if (button) {
      button.disabled = true;
    }
    showSpinner("正在分析…");
    return fetchJSON("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ formats: ["html", "json"], baseline: false })
    }).then(function (payload) {
      hideSpinner();
      if (button) {
        button.disabled = false;
      }
      state.runId = payload.run ? payload.run.id : "";
      toast("分析完成，发现 " + ((payload.result && payload.result.violations) || []).length + " 个问题", true);
      return loadRuns().then(function () {
        return loadResult(state.runId);
      });
    }).catch(function (error) {
      hideSpinner();
      if (button) {
        button.disabled = false;
      }
      toast("分析失败: " + error.message);
    });
  }

  function runTests() {
    var button = byId("btn-test");
    if (button) {
      button.disabled = true;
    }
    showSpinner("正在运行测试…");
    return fetchJSON("/api/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    }).then(function (payload) {
      hideSpinner();
      if (button) {
        button.disabled = false;
      }
      var tests = payload.tests || {};
      toast("测试完成: " + (tests.total || 0) + " 个用例，失败 " + (tests.failed || 0) + " 个", !(tests.failed || 0));
      renderTests(payload);
      return loadRuns();
    }).catch(function (error) {
      hideSpinner();
      if (button) {
        button.disabled = false;
      }
      toast("测试失败: " + error.message);
    });
  }

  function renderTests(payload) {
    var panel = byId("test-summary");
    if (!panel) {
      return;
    }
    clear(panel);
    var tests = payload.tests || {};
    var coverage = tests.coverage || {};
    var grid = element("div", "kv");
    var entry = function (label, value) {
      var box = element("div");
      box.appendChild(element("span", null, label));
      box.appendChild(document.createTextNode(String(value)));
      grid.appendChild(box);
    };
    entry("用例总数", tests.total || 0);
    entry("失败", tests.failed || 0);
    entry("通过率", (tests.pass_rate !== undefined ? tests.pass_rate : 0) + "%");
    entry("语句覆盖", (coverage.statement_coverage !== undefined ? coverage.statement_coverage : 0) + "%");
    entry("分支覆盖", (coverage.branch_coverage !== undefined ? coverage.branch_coverage : 0) + "%");
    entry("条件覆盖", (coverage.condition_coverage !== undefined ? coverage.condition_coverage : 0) + "%");
    entry("MC/DC", (coverage.mc_dc_coverage !== undefined ? coverage.mc_dc_coverage : 0) + "%");
    panel.appendChild(grid);

    var results = tests.results || [];
    if (results.length) {
      var table = document.createElement("table");
      table.className = "vtable";
      var head = document.createElement("thead");
      var headRow = document.createElement("tr");
      ["用例", "结果", "耗时(ms)", "信息"].forEach(function (title) {
        var cell = element("th", "static", title);
        headRow.appendChild(cell);
      });
      head.appendChild(headRow);
      table.appendChild(head);
      var tbody = document.createElement("tbody");
      results.forEach(function (item) {
        var row = document.createElement("tr");
        var name = element("td", null, item.name || item.test_id);
        row.appendChild(name);
        var status = element("td");
        status.appendChild(element("span", "badge " + (item.passed ? "sev-low" : "sev-critical"), item.passed ? "pass" : "fail"));
        row.appendChild(status);
        row.appendChild(element("td", "num", item.duration_ms !== undefined ? item.duration_ms : 0));
        row.appendChild(element("td", null, item.message || ""));
        tbody.appendChild(row);
      });
      table.appendChild(tbody);
      panel.appendChild(table);
    }
  }

  function bindFilters() {
    ["filter-severity", "filter-category", "filter-rule"].forEach(function (id) {
      var node = byId(id);
      if (node) {
        node.addEventListener("change", function () {
          loadViolations();
        });
      }
    });
    var search = byId("filter-search");
    if (search) {
      var timer = null;
      search.addEventListener("input", function () {
        if (timer) {
          window.clearTimeout(timer);
        }
        timer = window.setTimeout(function () {
          loadViolations();
        }, 250);
      });
    }
  }

  function bindSorting() {
    var headers = document.querySelectorAll("table.vtable thead th[data-sort]");
    for (var index = 0; index < headers.length; index += 1) {
      (function (header) {
        header.addEventListener("click", function () {
          var key = header.getAttribute("data-sort");
          if (state.sortKey === key) {
            state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
          } else {
            state.sortKey = key;
            state.sortDir = key === "severity" ? "asc" : "asc";
          }
          renderViolations(state.violations);
          updateSortIndicators();
        });
      })(headers[index]);
    }
  }

  function bindToggles() {
    document.addEventListener("click", function (event) {
      var target = event.target;
      if (!target || !target.classList) {
        return;
      }
      if (target.classList.contains("vtoggle")) {
        var row = target.closest("tr.vrow");
        if (!row) {
          return;
        }
        var detail = row.nextElementSibling;
        if (!detail) {
          return;
        }
        var open = detail.style.display !== "none";
        detail.style.display = open ? "none" : "table-row";
        target.textContent = open ? "详情" : "收起";
      }
    });
  }

  function bindExpandAll() {
    var expand = byId("expand-all");
    if (expand) {
      expand.addEventListener("click", function () {
        var details = document.querySelectorAll("tr.vdetail");
        for (var index = 0; index < details.length; index += 1) {
          details[index].style.display = "table-row";
        }
      });
    }
    var collapse = byId("collapse-all");
    if (collapse) {
      collapse.addEventListener("click", function () {
        var details = document.querySelectorAll("tr.vdetail");
        for (var index = 0; index < details.length; index += 1) {
          details[index].style.display = "none";
        }
      });
    }
  }

  function bindButtons() {
    var analyze = byId("btn-analyze");
    if (analyze) {
      analyze.addEventListener("click", function () {
        runAnalysis();
      });
    }
    var tests = byId("btn-test");
    if (tests) {
      tests.addEventListener("click", function () {
        runTests();
      });
    }
    var refresh = byId("btn-refresh");
    if (refresh) {
      refresh.addEventListener("click", function () {
        loadRuns();
        loadRules();
        loadResult(state.runId);
      });
    }
  }

  function boot() {
    var data = readBootstrap();
    bindFilters();
    bindSorting();
    bindToggles();
    bindExpandAll();
    bindButtons();
    updateSortIndicators();

    if (data.rules && data.rules.length) {
      renderRules(data.rules);
    }
    if (data.runs && data.runs.length) {
      renderRunList(data.runs);
    }
    var latest = data.run_id || data.latest_run || "";
    if (latest) {
      loadResult(latest);
    } else {
      loadResult("");
    }
    loadRules();
    loadRuns();
  }

  window.CodeShield = {
    fetchJSON: fetchJSON,
    toast: toast,
    showSpinner: showSpinner,
    hideSpinner: hideSpinner,
    loadResult: loadResult,
    loadRuns: loadRuns,
    loadRules: loadRules,
    loadViolations: loadViolations,
    runAnalysis: runAnalysis,
    runTests: runTests,
    state: state
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
