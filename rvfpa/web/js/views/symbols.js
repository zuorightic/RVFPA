/**
 * 符号分析页，可按类型、绑定和来源筛选函数或对象，并核对地址与占用大小。
 */

import { escapeHtml, formatAddress, formatBytes, formatNumber } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function renderRows(symbols) {
  return symbols.map((item) => `
    <tr>
      <td><strong class="mono">${escapeHtml(item.name)}</strong></td>
      <td><span class="badge ${item.symbol_type === "FUNC" ? "green" : item.symbol_type === "OBJECT" ? "amber" : ""}">${escapeHtml(item.symbol_type)}</span></td>
      <td>${escapeHtml(item.binding)}</td>
      <td>${escapeHtml(item.section_name)}</td>
      <td class="mono">${formatAddress(item.value)}</td>
      <td class="number">${formatBytes(item.size)}</td>
      <td title="${escapeHtml(item.source)}">${escapeHtml(item.source || "elf")}</td>
    </tr>`).join("");
}

export function render(context) {
  const analysis = context.state.analysis;
  if (!analysis) return `${pageHeader("符号分析", "查看函数、全局对象及其空间占用。")}${emptyState("没有分析数据", "请先选择一个固件版本。")}`;
  const types = [...new Set(analysis.symbols.map((item) => item.symbol_type))].sort();
  const top = [...analysis.symbols].sort((a, b) => b.size - a.size);
  return `
    ${pageHeader("符号分析", `${formatNumber(analysis.symbols.length)} 个符号 · 按大小排序`)}
    <div class="toolbar">
      <input id="symbol-search" class="search-input" type="search" placeholder="搜索符号、段或来源文件">
      <select id="symbol-type" class="filter-select"><option value="">全部类型</option>${types.map((item) => `<option>${escapeHtml(item)}</option>`).join("")}</select>
      <select id="symbol-binding" class="filter-select"><option value="">全部绑定</option><option>GLOBAL</option><option>LOCAL</option><option>WEAK</option></select>
      <span class="spacer"></span><span id="symbol-count">${top.length} 项</span>
    </div>
    <div class="data-table-wrap"><table class="data-table">
      <thead><tr><th>符号</th><th>类型</th><th>绑定</th><th>所在段</th><th>地址</th><th>大小</th><th>来源</th></tr></thead>
      <tbody id="symbol-body">${renderRows(top.slice(0, 1000))}</tbody>
    </table></div>`;
}

export function bind(context, root) {
  const analysis = context.state.analysis;
  if (!analysis) return;
  const search = root.querySelector("#symbol-search");
  const type = root.querySelector("#symbol-type");
  const binding = root.querySelector("#symbol-binding");
  const body = root.querySelector("#symbol-body");
  const count = root.querySelector("#symbol-count");
  const update = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = analysis.symbols.filter((item) => {
      const text = `${item.name} ${item.section_name} ${item.source}`.toLowerCase();
      return (!query || text.includes(query)) && (!type.value || item.symbol_type === type.value) && (!binding.value || item.binding === binding.value);
    }).sort((a, b) => b.size - a.size);
    body.innerHTML = renderRows(filtered.slice(0, 1000));
    count.textContent = filtered.length > 1000 ? `${filtered.length} 项，仅显示前1000项` : `${filtered.length} 项`;
  };
  search.addEventListener("input", update);
  type.addEventListener("change", update);
  binding.addEventListener("change", update);
}
