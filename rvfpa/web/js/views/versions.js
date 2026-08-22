/**
 * 固件版本页，列出项目快照及程序空间、指令摘要，也负责版本切换和导入入口。
 */

import { escapeHtml, formatBytes, formatDate, formatNumber } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function versionRow(snapshot, selected) {
  const analysis = snapshot.analysis;
  const summary = analysis?.size_summary || {};
  return `
    <article class="version-row ${selected ? "selected" : ""}" data-snapshot-id="${snapshot.id}">
      <div class="version-title"><strong>${escapeHtml(snapshot.version_name)}</strong><small>${formatDate(snapshot.created_at)}</small></div>
      <div class="version-summary"><strong>${escapeHtml(analysis?.identity?.file_name || "固件快照")}</strong><small>${escapeHtml(snapshot.notes || "无版本备注")}</small></div>
      <div class="version-summary"><strong>${formatBytes(summary.code_bytes || 0)}</strong><small>${formatNumber(analysis?.instruction_profile?.total || 0)} 条指令</small></div>
      <div class="version-actions"><button class="secondary-button" data-action="select">查看</button></div>
    </article>`;
}

export function render(context) {
  const { state } = context;
  const actions = '<button class="secondary-button" data-action="demo">导入示例</button><button class="primary-button" data-action="import">导入固件</button>';
  if (!state.snapshots.length) {
    return `${pageHeader("固件版本", "管理项目中的ELF、MAP和分析快照。", actions)}${emptyState("没有固件版本", "导入第一份固件后，版本信息会保存在本地工作区。")}`;
  }
  return `
    ${pageHeader("固件版本", `${state.project.name} · 共 ${state.snapshots.length} 个快照`, actions)}
    <div class="version-list">${state.snapshots.map((item) => versionRow(item, item.id === state.snapshotId)).join("")}</div>`;
}

export function bind(context, root) {
  root.querySelector('[data-action="import"]')?.addEventListener("click", context.openImport);
  root.querySelector('[data-action="demo"]')?.addEventListener("click", context.importDemo);
  root.querySelectorAll('.version-row [data-action="select"]').forEach((button) => {
    button.addEventListener("click", async () => {
      const row = button.closest(".version-row");
      context.state.selectSnapshot(Number(row.dataset.snapshotId));
      await context.loadAnalysis();
      context.state.setView("overview");
    });
  });
}
