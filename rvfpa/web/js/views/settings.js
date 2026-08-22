/**
 * 内存配置页，用于修改项目说明以及FLASH、RAM等内存区域。
 */

import { escapeHtml } from "../format.js";
import { pageHeader } from "../ui.js";

function regionRow(region, index) {
  return `
    <div class="memory-region-editor" data-region-index="${index}">
      <input class="form-control" name="region_name" value="${escapeHtml(region.name)}" aria-label="区域名称">
      <input class="form-control mono" name="region_origin" value="${escapeHtml(region.origin)}" aria-label="起始地址">
      <input class="form-control" name="region_length" value="${escapeHtml(region.length)}" aria-label="区域长度">
      <input class="form-control mono" name="region_permissions" value="${escapeHtml(region.permissions)}" aria-label="权限">
      <button class="icon-button" type="button" data-action="remove-region" title="删除区域" aria-label="删除区域">×</button>
    </div>`;
}

export function render(context) {
  const project = context.state.project;
  const config = project.memory_config || { architecture: "auto", regions: [] };
  return `
    ${pageHeader("内存配置", "定义链接地址空间，分析时用于检查段归属、容量和访问权限。", '<button id="save-settings" class="primary-button">保存配置</button>')}
    <section class="panel">
      <header class="panel-header"><h2>项目信息</h2><span>项目级配置</span></header>
      <div class="panel-body"><div class="form-grid">
        <div class="form-field"><label for="project-name">项目名称</label><input id="project-name" class="form-control" value="${escapeHtml(project.name)}"></div>
        <div class="form-field"><label for="architecture">目标架构</label><select id="architecture" class="form-control"><option value="auto" ${config.architecture === "auto" ? "selected" : ""}>自动识别</option><option value="rv32" ${config.architecture === "rv32" ? "selected" : ""}>RV32</option><option value="rv64" ${config.architecture === "rv64" ? "selected" : ""}>RV64</option></select></div>
        <div class="form-field full"><label for="project-description">项目说明</label><textarea id="project-description" class="form-control">${escapeHtml(project.description)}</textarea></div>
      </div></div>
    </section>
    <section class="panel">
      <header class="panel-header"><h2>内存区域</h2><button id="add-region" class="secondary-button" type="button">添加区域</button></header>
      <div class="panel-body flush">
        <div class="memory-region-editor" style="background:var(--surface-subtle);font-size:10px;color:var(--ink-muted)"><span>名称</span><span>起始地址</span><span>容量</span><span>权限</span><span></span></div>
        <div id="region-editor">${(config.regions || []).map(regionRow).join("")}</div>
      </div>
    </section>`;
}

export function bind(context, root) {
  const editor = root.querySelector("#region-editor");
  const reindex = () => editor.querySelectorAll(".memory-region-editor").forEach((row, index) => { row.dataset.regionIndex = index; });
  root.querySelector("#add-region").addEventListener("click", () => {
    editor.insertAdjacentHTML("beforeend", regionRow({ name: `REGION${editor.children.length + 1}`, origin: "0x00000000", length: "64K", permissions: "rwx" }, editor.children.length));
  });
  editor.addEventListener("click", (event) => {
    const button = event.target.closest('[data-action="remove-region"]');
    if (!button) return;
    button.closest(".memory-region-editor").remove();
    reindex();
  });
  root.querySelector("#save-settings").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const regions = [...editor.querySelectorAll(".memory-region-editor")].map((row) => ({
      name: row.querySelector('[name="region_name"]').value.trim(),
      origin: row.querySelector('[name="region_origin"]').value.trim(),
      length: row.querySelector('[name="region_length"]').value.trim(),
      permissions: row.querySelector('[name="region_permissions"]').value.trim(),
      description: "",
    }));
    button.disabled = true;
    try {
      await context.api.updateProject(context.state.projectId, {
        name: root.querySelector("#project-name").value.trim(),
        description: root.querySelector("#project-description").value.trim(),
        memory_config: { architecture: root.querySelector("#architecture").value, regions },
      });
      await context.reloadWorkspace();
      context.showToast("项目配置已保存");
    } catch (error) {
      context.showToast(error.message, "error");
    } finally {
      button.disabled = false;
    }
  });
}
