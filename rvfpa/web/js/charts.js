/**
 * 轻量图表模块：用原生HTML和CSS生成内存占用条、横向统计条等图形，
 * 不依赖外部图表库。
 */

import { clamp, escapeHtml, formatBytes, formatNumber, formatPercent } from "./format.js";

export function memoryRegionChart(usages = []) {
  if (!usages.length) {
    return '<div class="empty-state"><p>当前版本没有可显示的内存区域。</p></div>';
  }
  return `<div class="region-list">${usages.map((item) => {
    const percent = Number(item.usage_percent || 0);
    const level = percent >= 100 ? "danger" : percent >= 90 ? "warning" : "";
    return `
      <div class="region-row">
        <div class="region-name">
          <strong>${escapeHtml(item.region.name)}</strong>
          <small>${escapeHtml(item.region.permissions)} · 0x${Number(item.region.origin).toString(16)}</small>
        </div>
        <div class="progress-track ${level}" title="${formatPercent(percent)}">
          <i style="--value:${clamp(percent, 0, 100)}%"></i>
        </div>
        <div class="region-value">
          <strong>${formatBytes(item.used_bytes)} / ${formatBytes(item.region.length)}</strong>
          <small>${formatPercent(percent)} · 剩余 ${formatBytes(item.free_bytes)}</small>
        </div>
      </div>`;
  }).join("")}</div>`;
}

export function horizontalBars(values = {}, options = {}) {
  const entries = Object.entries(values)
    .map(([name, value]) => [name, Number(value || 0)])
    .sort((a, b) => b[1] - a[1])
    .slice(0, options.limit || 12);
  const maximum = Math.max(1, ...entries.map((item) => item[1]));
  if (!entries.length) return '<div class="empty-state"><p>暂无统计数据。</p></div>';
  return `<div class="bar-list">${entries.map(([name, value]) => `
    <div class="region-row">
      <div class="bar-label"><strong>${escapeHtml(name)}</strong><small>${formatNumber(value)}</small></div>
      <div class="progress-track"><i style="--value:${clamp(value * 100 / maximum, 0, 100)}%"></i></div>
      <div class="region-value"><strong>${formatNumber(value)}</strong><small>${formatPercent(value * 100 / Math.max(1, options.total || maximum))}</small></div>
    </div>`).join("")}</div>`;
}
