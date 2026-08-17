import { horizontalBars } from "../charts.js";
import { escapeHtml, formatAddress, formatBytes, formatNumber, formatPercent } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function functionRows(items) {
  return items.map((item) => `
    <tr>
      <td><strong class="mono">${escapeHtml(item.name)}</strong><br><small>${item.source_lines?.length ? escapeHtml(item.source_lines[0]) : ""}</small></td>
      <td class="mono">${formatAddress(item.address)}</td>
      <td class="number">${formatBytes(item.size)}</td>
      <td class="number">${formatNumber(item.instruction_count)}</td>
      <td class="number">${formatNumber(item.estimated_complexity)}</td>
      <td class="number">${formatNumber(item.call_count)}</td>
      <td class="number">${formatNumber(item.callers?.length || 0)}</td>
      <td class="number">${formatPercent(item.compressed_percent)}</td>
      <td><span class="badge ${item.is_leaf ? "green" : "blue"}">${item.is_leaf ? "叶函数" : "调用函数"}</span></td>
    </tr>`).join("");
}

export function render(context) {
  const analysis = context.state.analysis;
  if (!analysis) return `${pageHeader("函数画像", "查看函数规模、指令量、复杂度和调用关系。")}${emptyState("没有分析数据", "请先选择一个固件版本。")}`;
  const profiles = analysis.function_profiles || [];
  const summary = analysis.metadata?.function_summary || {};
  const instructionByFunction = Object.fromEntries(profiles.slice(0, 12).map((item) => [item.name, item.instruction_count]));
  return `
    ${pageHeader("函数画像", `${formatNumber(profiles.length)} 个函数 · ${formatNumber(summary.call_edge_count)} 条调用关系`)}
    <section class="metric-grid">
      <div class="metric-card"><span class="label">函数数量</span><strong>${formatNumber(summary.function_count)}</strong><small>${formatNumber(summary.leaf_function_count)} 个叶函数</small></div>
      <div class="metric-card"><span class="label">调用关系</span><strong>${formatNumber(summary.call_edge_count)}</strong><small>${formatNumber(summary.non_leaf_function_count)} 个非叶函数</small></div>
      <div class="metric-card"><span class="label">最大复杂度</span><strong>${formatNumber(summary.maximum_complexity)}</strong><small>分支路径估算</small></div>
      <div class="metric-card"><span class="label">平均复杂度</span><strong>${Number(summary.average_complexity || 0).toFixed(2)}</strong><small>每个函数</small></div>
      <div class="metric-card"><span class="label">最大指令量</span><strong>${formatNumber(summary.maximum_instruction_count)}</strong><small>单个函数</small></div>
    </section>
    <section class="panel"><header class="panel-header"><h2>主要函数指令量</h2><span>前12项</span></header><div class="panel-body">${horizontalBars(instructionByFunction, { total: analysis.instruction_profile.total, limit: 12 })}</div></section>
    <div style="height:16px"></div>
    <div class="toolbar">
      <input id="function-search" class="search-input" type="search" placeholder="搜索函数、调用方或被调用方">
      <select id="function-kind" class="filter-select"><option value="">全部函数</option><option value="leaf">叶函数</option><option value="caller">含调用函数</option></select>
      <select id="function-sort" class="filter-select"><option value="instructions">按指令量</option><option value="size">按大小</option><option value="complexity">按复杂度</option><option value="calls">按调用数</option></select>
      <span class="spacer"></span><span id="function-count">${profiles.length} 项</span>
    </div>
    <div class="data-table-wrap"><table class="data-table"><thead><tr><th>函数</th><th>地址</th><th>大小</th><th>指令数</th><th>复杂度</th><th>调用</th><th>调用方</th><th>压缩率</th><th>类型</th></tr></thead><tbody id="function-body">${functionRows(profiles)}</tbody></table></div>`;
}

export function bind(context, root) {
  const profiles = context.state.analysis?.function_profiles || [];
  const search = root.querySelector("#function-search");
  if (!search) return;
  const kind = root.querySelector("#function-kind");
  const sort = root.querySelector("#function-sort");
  const body = root.querySelector("#function-body");
  const count = root.querySelector("#function-count");
  const sorters = {
    instructions: (a, b) => b.instruction_count - a.instruction_count,
    size: (a, b) => b.size - a.size,
    complexity: (a, b) => b.estimated_complexity - a.estimated_complexity,
    calls: (a, b) => b.call_count - a.call_count,
  };
  const update = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = profiles.filter((item) => {
      const callText = `${item.name} ${(item.callers || []).join(" ")} ${(item.callees || []).join(" ")}`.toLowerCase();
      const kindMatch = !kind.value || (kind.value === "leaf" ? item.is_leaf : !item.is_leaf);
      return (!query || callText.includes(query)) && kindMatch;
    }).sort(sorters[sort.value]);
    body.innerHTML = functionRows(filtered);
    count.textContent = `${filtered.length} 项`;
  };
  search.addEventListener("input", update);
  kind.addEventListener("change", update);
  sort.addEventListener("change", update);
}

