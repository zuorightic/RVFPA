import { escapeHtml, formatAddress, formatBytes, formatNumber } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function rows(sections) {
  return sections.map((item) => `
    <tr>
      <td class="number">${item.index}</td>
      <td><strong>${escapeHtml(item.name)}</strong></td>
      <td><span class="badge ${item.executable ? "green" : item.writable ? "amber" : "blue"}">${escapeHtml(item.section_type)}</span></td>
      <td class="mono">${formatAddress(item.address)}</td>
      <td class="mono">${formatAddress(item.address + item.size)}</td>
      <td class="number">${formatBytes(item.size)}</td>
      <td class="mono">${escapeHtml(item.permissions)}</td>
      <td class="number">${formatNumber(item.alignment)}</td>
    </tr>`).join("");
}

export function render(context) {
  const analysis = context.state.analysis;
  if (!analysis) return `${pageHeader("段布局", "查看ELF段地址、大小、类型和访问权限。")}${emptyState("没有分析数据", "请先选择一个固件版本。")}`;
  const types = [...new Set(analysis.sections.map((item) => item.section_type))].sort();
  return `
    ${pageHeader("段布局", `${analysis.sections.length} 个段 · ${analysis.identity.file_name}`)}
    <div class="toolbar">
      <input id="section-search" class="search-input" type="search" placeholder="搜索段名称、类型或地址">
      <select id="section-type" class="filter-select"><option value="">全部类型</option>${types.map((item) => `<option>${escapeHtml(item)}</option>`).join("")}</select>
      <label><input id="allocated-only" type="checkbox"> 仅已分配段</label>
      <span class="spacer"></span><span id="section-count">${analysis.sections.length} 项</span>
    </div>
    <div class="data-table-wrap"><table class="data-table">
      <thead><tr><th>#</th><th>名称</th><th>类型</th><th>起始地址</th><th>结束地址</th><th>大小</th><th>权限</th><th>对齐</th></tr></thead>
      <tbody id="section-body">${rows(analysis.sections)}</tbody>
    </table></div>`;
}

export function bind(context, root) {
  const analysis = context.state.analysis;
  if (!analysis) return;
  const search = root.querySelector("#section-search");
  const type = root.querySelector("#section-type");
  const allocated = root.querySelector("#allocated-only");
  const body = root.querySelector("#section-body");
  const count = root.querySelector("#section-count");
  const update = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = analysis.sections.filter((item) => {
      const text = `${item.name} ${item.section_type} ${formatAddress(item.address)}`.toLowerCase();
      return (!query || text.includes(query)) && (!type.value || item.section_type === type.value) && (!allocated.checked || item.allocated);
    });
    body.innerHTML = rows(filtered);
    count.textContent = `${filtered.length} 项`;
  };
  search.addEventListener("input", update);
  type.addEventListener("change", update);
  allocated.addEventListener("change", update);
}

