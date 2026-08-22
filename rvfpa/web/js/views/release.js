/**
 * 发布检查视图：展示布局、余量、权限、解码、熵和固件内容线索的复核结果。
 */

import { horizontalBars } from "../charts.js";
import { escapeHtml, formatAddress, formatNumber } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function releaseChecks(checks) {
  return `<div class="check-list">${checks.map((item) => `
    <article class="check-item ${escapeHtml(item.status)}">
      <div class="check-status">${item.status === "pass" ? "通过" : item.status === "warn" ? "复核" : "阻断"}</div>
      <div class="check-content"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.summary)}</span><p>${escapeHtml(item.detail)}</p>${item.recommendation ? `<small>${escapeHtml(item.recommendation)}</small>` : ""}</div>
    </article>`).join("")}</div>`;
}

function stringRows(strings) {
  return strings.map((item) => `
    <tr>
      <td>${escapeHtml(item.section_name)}</td>
      <td class="mono">${formatAddress(item.address)}</td>
      <td><span class="badge ${item.category === "sensitive-keyword" ? "red" : item.category === "diagnostic" ? "amber" : "blue"}">${escapeHtml(item.category)}</span></td>
      <td>${escapeHtml(item.encoding)}</td>
      <td class="number">${formatNumber(item.length)}</td>
      <td class="mono">${escapeHtml(item.text)}</td>
    </tr>`).join("");
}

export function render(context) {
  const analysis = context.state.analysis;
  if (!analysis) return `${pageHeader("发布检查", "复核布局、内存余量、权限、调试信息和固件内容线索。")}${emptyState("没有分析数据", "请先选择一个固件版本。")}`;
  const checks = analysis.release_checks || [];
  const summary = analysis.metadata?.release_check_summary || {};
  const strings = analysis.firmware_strings || [];
  const categories = analysis.metadata?.string_category_summary || {};
  return `
    ${pageHeader("发布检查", `${summary.pass || 0} 项通过 · ${summary.warn || 0} 项复核 · ${summary.fail || 0} 项阻断`)}
    <section class="release-summary ${escapeHtml(summary.overall || "pass")}">
      <div><span>综合状态</span><strong>${summary.overall === "fail" ? "存在阻断项" : summary.overall === "warn" ? "需要人工复核" : "检查通过"}</strong></div>
      <p>检查结果基于静态文件和配置，用于发布前复核，不替代硬件运行测试。</p>
    </section>
    <section class="content-grid">
      <section class="panel"><header class="panel-header"><h2>检查项目</h2><span>${checks.length} 项</span></header><div class="panel-body">${releaseChecks(checks)}</div></section>
      <section class="panel"><header class="panel-header"><h2>字符串类别</h2><span>${strings.length} 条</span></header><div class="panel-body">${horizontalBars(categories, { total: strings.length, limit: 10 })}</div></section>
    </section>
    <div style="height:16px"></div>
    <div class="toolbar">
      <input id="string-search" class="search-input" type="search" placeholder="搜索字符串、段或类别">
      <select id="string-category" class="filter-select"><option value="">全部类别</option>${Object.keys(categories).map((item) => `<option>${escapeHtml(item)}</option>`).join("")}</select>
      <span class="spacer"></span><span id="string-count">${strings.length} 项</span>
    </div>
    <div class="data-table-wrap"><table class="data-table"><thead><tr><th>段</th><th>地址</th><th>类别</th><th>编码</th><th>长度</th><th>文本</th></tr></thead><tbody id="string-body">${stringRows(strings.slice(0, 1000))}</tbody></table></div>`;
}

export function bind(context, root) {
  const strings = context.state.analysis?.firmware_strings || [];
  const search = root.querySelector("#string-search");
  if (!search) return;
  const category = root.querySelector("#string-category");
  const body = root.querySelector("#string-body");
  const count = root.querySelector("#string-count");
  const update = () => {
    const query = search.value.trim().toLowerCase();
    const filtered = strings.filter((item) => {
      const text = `${item.text} ${item.section_name} ${item.category}`.toLowerCase();
      return (!query || text.includes(query)) && (!category.value || item.category === category.value);
    });
    body.innerHTML = stringRows(filtered.slice(0, 1000));
    count.textContent = filtered.length > 1000 ? `${filtered.length} 项，仅显示前1000项` : `${filtered.length} 项`;
  };
  search.addEventListener("input", update);
  category.addEventListener("change", update);
}
