/**
 * 资源总览视图：聚合固件身份、程序空间、内存区域、主要段和布局诊断。
 */

import { memoryRegionChart, horizontalBars } from "../charts.js";
import { escapeHtml, formatAddress, formatBytes, formatNumber, severityLabel } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function metric(label, value, detail) {
  return `<div class="metric-card"><span class="label">${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></div>`;
}

function diagnosticList(items = []) {
  if (!items.length) {
    return '<div class="diagnostic-item"><strong>未发现异常</strong><p>当前固件通过已配置的布局检查。</p></div>';
  }
  return `<div class="diagnostic-list">${items.slice(0, 12).map((item) => `
    <article class="diagnostic-item ${escapeHtml(item.severity)}">
      <strong>${escapeHtml(severityLabel(item.severity))} · ${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.detail)}</p>
      ${item.suggestion ? `<small>${escapeHtml(item.suggestion)}</small>` : ""}
    </article>`).join("")}</div>`;
}

export function render(context) {
  const { state } = context;
  if (!state.snapshots.length) {
    return `${pageHeader("资源总览", "查看固件空间占用、架构信息和布局诊断。")}${emptyState(
      "尚未导入固件",
      "导入RISC-V ELF文件后，系统会生成资源画像并保存为版本快照。",
      '<button class="primary-button" data-action="import">导入固件</button> <button class="secondary-button" data-action="demo">导入示例</button>',
    )}`;
  }
  const analysis = state.analysis;
  if (!analysis) return '<div class="page-loading"><div class="loading-line"></div><div class="loading-line short"></div></div>';
  const summary = analysis.size_summary || {};
  const profile = analysis.instruction_profile || {};
  const ram = Number(summary.initialized_data_bytes || 0) + Number(summary.zero_fill_bytes || 0);
  const snapshot = state.selectedSnapshot;
  const errorCount = (analysis.diagnostics || []).filter((item) => item.severity === "error").length;
  const warningCount = (analysis.diagnostics || []).filter((item) => item.severity === "warning").length;
  return `
    ${pageHeader(
      "资源总览",
      `${snapshot?.version_name || "当前版本"} · ${analysis.identity.file_name}`,
      '<button class="secondary-button" data-action="switch-version">切换版本</button><button class="primary-button" data-action="import">导入新版本</button>',
    )}
    <section class="metric-grid">
      ${metric("目标架构", analysis.identity.architecture, analysis.identity.abi)}
      ${metric("代码空间", formatBytes(summary.code_bytes), `入口 ${formatAddress(analysis.identity.entry_point)}`)}
      ${metric("静态RAM", formatBytes(ram), `DATA ${formatBytes(summary.initialized_data_bytes)} · BSS ${formatBytes(summary.zero_fill_bytes)}`)}
      ${metric("指令数量", formatNumber(profile.total), `压缩指令 ${formatNumber(profile.compressed)}`)}
      ${metric("诊断结果", `${errorCount} 错误`, `${warningCount} 警告 · ${(analysis.diagnostics || []).length} 项`)}
    </section>
    <section class="content-grid">
      <div>
        <section class="panel">
          <header class="panel-header"><h2>内存区域占用</h2><span>${escapeHtml(analysis.metadata?.region_source || "configuration")}</span></header>
          <div class="panel-body">${memoryRegionChart(analysis.region_usage)}</div>
        </section>
        <section class="panel">
          <header class="panel-header"><h2>指令类别分布</h2><span>${formatNumber(profile.total)} 条</span></header>
          <div class="panel-body">${horizontalBars(profile.categories, { total: profile.total, limit: 10 })}</div>
        </section>
      </div>
      <div>
        <section class="panel">
          <header class="panel-header"><h2>布局诊断</h2><span>${(analysis.diagnostics || []).length} 项</span></header>
          <div class="panel-body">${diagnosticList(analysis.diagnostics)}</div>
        </section>
        <section class="panel">
          <header class="panel-header"><h2>固件身份</h2><span>SHA-256</span></header>
          <div class="panel-body">
            <div class="stat-line"><span>ELF位数</span><strong>${analysis.identity.elf_class} bit</strong></div>
            <div class="stat-line"><span>字节序</span><strong>${escapeHtml(analysis.identity.byte_order)}</strong></div>
            <div class="stat-line"><span>文件大小</span><strong>${formatBytes(analysis.identity.file_size)}</strong></div>
            <div class="stat-line"><span>段数量</span><strong>${formatNumber(analysis.sections.length)}</strong></div>
            <div class="stat-line"><span>符号数量</span><strong>${formatNumber(analysis.symbols.length)}</strong></div>
            <div class="stat-line"><span>摘要</span><strong class="mono" title="${escapeHtml(analysis.identity.sha256)}">${escapeHtml(analysis.identity.sha256.slice(0, 16))}…</strong></div>
          </div>
        </section>
      </div>
    </section>`;
}

export function bind(context, root) {
  root.querySelectorAll('[data-action="import"]').forEach((button) => button.addEventListener("click", context.openImport));
  root.querySelector('[data-action="demo"]')?.addEventListener("click", context.importDemo);
  root.querySelector('[data-action="switch-version"]')?.addEventListener("click", () => context.state.setView("versions"));
}
