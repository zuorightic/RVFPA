/**
 * 版本对比页。用户选定基线和目标快照后，可以核对空间、节区、符号、
 * 指令扩展及符号地址变化。
 */

import { deltaClass, deltaText, escapeHtml, formatAddress, formatBytes, formatNumber } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

function options(snapshots, selectedId) {
  return snapshots.map((item) => `<option value="${item.id}" ${item.id === selectedId ? "selected" : ""}>${escapeHtml(item.version_name)} · ${escapeHtml(item.created_at.slice(0, 10))}</option>`).join("");
}

function deltaMetric(label, delta, formatter = formatBytes) {
  const before = Number(delta?.before || 0);
  const after = Number(delta?.after || 0);
  const value = Number(delta?.absolute ?? after - before);
  const percent = delta?.percent ?? (before === 0 ? (after === 0 ? null : 100) : Number((((after - before) * 100) / before).toFixed(3)));
  return `<div class="metric-card"><span class="label">${escapeHtml(label)}</span><strong class="${deltaClass(value)}">${value > 0 ? "+" : ""}${formatter(value)}</strong><small>${percent == null ? "无基线比例" : `${percent > 0 ? "+" : ""}${percent}%`}</small></div>`;
}

function symbolRows(items = []) {
  return items.filter((item) => item.status !== "unchanged").slice(0, 100).map((item) => {
    const delta = Number(item.delta ?? Number(item.after_size || 0) - Number(item.before_size || 0));
    return `
      <tr>
        <td><strong class="mono">${escapeHtml(item.name)}</strong></td>
        <td><span class="badge ${item.status === "added" ? "red" : item.status === "removed" ? "green" : "amber"}">${escapeHtml(item.status)}</span></td>
        <td class="number">${formatBytes(item.before_size)}</td>
        <td class="number">${formatBytes(item.after_size)}</td>
        <td class="number ${deltaClass(delta)}">${delta > 0 ? "+" : ""}${formatBytes(delta)}</td>
        <td class="mono">${item.before_address == null ? "-" : formatAddress(item.before_address)}</td>
        <td class="mono">${item.after_address == null ? "-" : formatAddress(item.after_address)}</td>
      </tr>`;
  }).join("");
}

export function render(context) {
  const { state } = context;
  if (state.snapshots.length < 2) {
    return `${pageHeader("版本对比", "比较两个固件快照的空间、符号和指令变化。")}${emptyState("至少需要两个版本", "继续导入固件版本后即可进行差异分析。", '<button class="primary-button" data-action="import">导入新版本</button>')}`;
  }
  const chronological = [...state.snapshots].reverse();
  const baselineId = chronological.at(-2)?.id || chronological[0].id;
  const targetId = chronological.at(-1)?.id || chronological[1].id;
  const diff = state.diff;
  return `
    ${pageHeader("版本对比", "选择基线和目标版本，检查资源增长、符号变化和新增诊断。")}
    <section class="compare-controls">
      <div class="form-field"><label for="baseline-select">基线版本</label><select id="baseline-select" class="form-control">${options(state.snapshots, diff?.baseline_id || baselineId)}</select></div>
      <div class="compare-arrow">→</div>
      <div class="form-field"><label for="target-select">目标版本</label><select id="target-select" class="form-control">${options(state.snapshots, diff?.target_id || targetId)}</select></div>
      <button id="compare-button" class="primary-button">开始比较</button>
    </section>
    ${diff ? `
      <div style="height:18px"></div>
      <section class="metric-grid">
        ${deltaMetric("文件大小", diff.size_deltas.file_bytes)}
        ${deltaMetric("代码空间", diff.size_deltas.code_bytes)}
        ${deltaMetric("只读数据", diff.size_deltas.readonly_bytes)}
        ${deltaMetric("初始化数据", diff.size_deltas.initialized_data_bytes)}
        ${deltaMetric("指令数量", diff.instruction_deltas.total, formatNumber)}
      </section>
      <section class="content-grid">
        <section class="panel"><header class="panel-header"><h2>差异摘要</h2><span>${diff.summary.changed_symbol_count} 个符号变化</span></header><div class="panel-body">
          <div class="stat-line"><span>变化段</span><strong>${formatNumber(diff.summary.changed_section_count)}</strong></div>
          <div class="stat-line"><span>新增符号</span><strong>${formatNumber(diff.summary.added_symbol_count)}</strong></div>
          <div class="stat-line"><span>移除符号</span><strong>${formatNumber(diff.summary.removed_symbol_count)}</strong></div>
          <div class="stat-line"><span>运行时空间变化</span><strong class="${deltaClass(diff.summary.runtime_delta)}">${deltaText(diff.summary.runtime_delta, " B")}</strong></div>
        </div></section>
        <section class="panel"><header class="panel-header"><h2>扩展变化</h2><span>${Object.keys(diff.extension_changes || {}).length} 项</span></header><div class="panel-body">
          ${Object.entries(diff.extension_changes || {}).map(([name, status]) => `<div class="stat-line"><span>${escapeHtml(name)}</span><strong>${escapeHtml(status)}</strong></div>`).join("") || '<p>无扩展变化</p>'}
        </div></section>
      </section>
      <div style="height:16px"></div>
      <div class="toolbar"><strong>主要符号变化</strong><span class="spacer"></span><span>按变化量排序</span></div>
      <div class="data-table-wrap"><table class="data-table"><thead><tr><th>符号</th><th>状态</th><th>基线大小</th><th>目标大小</th><th>变化</th><th>基线地址</th><th>目标地址</th></tr></thead><tbody>${symbolRows(diff.symbol_deltas)}</tbody></table></div>
    ` : '<div class="empty-state"><p>选择两个不同版本并开始比较。</p></div>'}`;
}

export function bind(context, root) {
  root.querySelector('[data-action="import"]')?.addEventListener("click", context.openImport);
  const button = root.querySelector("#compare-button");
  if (!button) return;
  button.addEventListener("click", async () => {
    const baseline = Number(root.querySelector("#baseline-select").value);
    const target = Number(root.querySelector("#target-select").value);
    if (baseline === target) {
      context.showToast("请选择两个不同的固件版本", "error");
      return;
    }
    button.disabled = true;
    button.textContent = "比较中";
    try {
      const payload = await context.api.compare(baseline, target);
      context.state.setDiff(payload.diff);
      context.renderCurrentView();
    } catch (error) {
      context.showToast(error.message, "error");
    } finally {
      button.disabled = false;
      button.textContent = "开始比较";
    }
  });
}
