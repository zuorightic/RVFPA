import { horizontalBars } from "../charts.js";
import { escapeHtml, formatAddress, formatNumber, formatPercent } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function instructionRows(records) {
  return records.map((item) => `
    <tr>
      <td class="mono">${formatAddress(item.address)}</td>
      <td class="mono">${escapeHtml(item.raw)}</td>
      <td><strong class="mono">${escapeHtml(item.mnemonic)}</strong></td>
      <td class="mono">${escapeHtml(item.operands)}</td>
      <td><span class="badge blue">${escapeHtml(item.category)}</span></td>
      <td><span class="badge green">${escapeHtml(item.extension)}</span></td>
      <td>${escapeHtml(item.function_name)}</td>
    </tr>`).join("");
}

export function render(context) {
  const analysis = context.state.analysis;
  if (!analysis) return `${pageHeader("指令画像", "统计RISC-V指令类别、扩展和函数分布。")}${emptyState("没有分析数据", "请先选择一个固件版本。")}`;
  const profile = analysis.instruction_profile;
  const system = analysis.metadata?.system_usage || {};
  const records = profile.records || [];
  return `
    ${pageHeader("指令画像", `${formatNumber(profile.total)} 条指令 · 压缩率 ${formatPercent(profile.compressed_percent)}`)}
    <section class="content-grid">
      <section class="panel"><header class="panel-header"><h2>指令类别</h2><span>${Object.keys(profile.categories || {}).length} 类</span></header><div class="panel-body">${horizontalBars(profile.categories, { total: profile.total, limit: 14 })}</div></section>
      <section class="panel"><header class="panel-header"><h2>扩展使用</h2><span>${Object.keys(profile.extensions || {}).length} 项</span></header><div class="panel-body">${horizontalBars(profile.extensions, { total: profile.total, limit: 14 })}</div></section>
    </section>
    <div style="height:16px"></div>
    <section class="content-grid">
      <section class="panel"><header class="panel-header"><h2>CSR访问</h2><span>${formatNumber(system.csr_instruction_count || 0)} 条</span></header><div class="panel-body">${horizontalBars(system.csr_counts || {}, { total: system.csr_instruction_count || 0, limit: 12 })}</div></section>
      <section class="panel"><header class="panel-header"><h2>系统与同步指令</h2><span>${formatNumber(Object.keys(system.trap_counts || {}).length + Object.keys(system.fence_counts || {}).length)} 类</span></header><div class="panel-body">${horizontalBars({ ...(system.trap_counts || {}), ...(system.fence_counts || {}), ...(system.atomic_counts || {}) }, { total: profile.total, limit: 12 })}</div></section>
    </section>
    <div style="height:16px"></div>
    <div class="toolbar">
      <input id="instruction-search" class="search-input" type="search" placeholder="搜索助记符、操作数或函数">
      <select id="instruction-category" class="filter-select"><option value="">全部类别</option>${Object.keys(profile.categories || {}).map((item) => `<option>${escapeHtml(item)}</option>`).join("")}</select>
      <select id="instruction-extension" class="filter-select"><option value="">全部扩展</option>${Object.keys(profile.extensions || {}).map((item) => `<option>${escapeHtml(item)}</option>`).join("")}</select>
      <span class="spacer"></span><span id="instruction-count">${records.length} 项</span>
    </div>
    <div class="data-table-wrap"><table class="data-table">
      <thead><tr><th>地址</th><th>机器码</th><th>助记符</th><th>操作数</th><th>类别</th><th>扩展</th><th>函数</th></tr></thead>
      <tbody id="instruction-body">${instructionRows(records)}</tbody>
    </table></div>`;
}

export function bind(context, root) {
  const records = context.state.analysis?.instruction_profile?.records || [];
  const search = root.querySelector("#instruction-search");
  if (!search) return;
  const category = root.querySelector("#instruction-category");
  const extension = root.querySelector("#instruction-extension");
  const body = root.querySelector("#instruction-body");
  const count = root.querySelector("#instruction-count");
  const update = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = records.filter((item) => {
      const text = `${item.mnemonic} ${item.operands} ${item.function_name}`.toLowerCase();
      return (!query || text.includes(query)) && (!category.value || item.category === category.value) && (!extension.value || item.extension === extension.value);
    });
    body.innerHTML = instructionRows(filtered);
    count.textContent = `${filtered.length} 项`;
  };
  search.addEventListener("input", update);
  category.addEventListener("change", update);
  extension.addEventListener("change", update);
}
