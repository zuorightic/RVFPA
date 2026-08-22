/**
 * 报告中心页，下载当前固件版本的HTML、JSON和各类CSV分析结果。
 */

import { escapeHtml } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

const REPORTS = [
  { format: "html", badge: "HTML", title: "固件资源画像报告", description: "包含固件身份、资源占用、段、符号、指令类别和诊断结果。" },
  { format: "json", badge: "JSON", title: "完整分析数据", description: "导出结构化分析结果，适合归档、二次处理和自动化核对。" },
  { format: "sections", badge: "CSV", title: "ELF段明细", description: "导出段名称、类型、地址、大小、权限和对齐信息。" },
  { format: "symbols", badge: "CSV", title: "符号占用明细", description: "导出函数、对象、地址、所在段、绑定方式和估算大小。" },
  { format: "instructions", badge: "CSV", title: "指令记录明细", description: "导出反汇编地址、机器码、助记符、类别、扩展和所属函数。" },
  { format: "functions", badge: "CSV", title: "函数画像明细", description: "导出函数规模、指令数、复杂度、调用方和被调用方。" },
  { format: "strings", badge: "CSV", title: "固件字符串明细", description: "导出固件中的文本、地址、编码和内容分类线索。" },
];

export function render(context) {
  const { state } = context;
  if (!state.snapshotId) {
    return `${pageHeader("报告中心", "导出当前固件版本的分析结果。")}${emptyState("没有可导出的版本", "请先导入并选择固件版本。")}`;
  }
  return `
    ${pageHeader("报告中心", `${escapeHtml(state.selectedSnapshot?.version_name || "当前版本")} · 导出结果不会修改项目数据`)}
    <section class="report-grid">${REPORTS.map((item) => `
      <article class="report-item">
        <span class="badge report-type ${item.format === "html" ? "green" : "blue"}">${item.badge}</span>
        <strong>${escapeHtml(item.title)}</strong>
        <p>${escapeHtml(item.description)}</p>
        <a class="secondary-button" style="display:inline-flex;align-items:center;justify-content:center;text-decoration:none" href="${context.api.reportUrl(state.snapshotId, item.format)}">下载</a>
      </article>`).join("")}</section>`;
}

export function bind() {}
