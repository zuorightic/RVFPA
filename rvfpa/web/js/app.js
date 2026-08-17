import { api, readFileAsBase64 } from "./api.js";
import { escapeHtml } from "./format.js";
import { state } from "./state.js";
import { showModal, showToast } from "./ui.js";
import { views } from "./views/index.js";

const elements = {
  content: document.querySelector("#main-content"),
  projectSelect: document.querySelector("#project-select"),
  newProject: document.querySelector("#new-project-button"),
  refresh: document.querySelector("#refresh-button"),
  importButton: document.querySelector("#import-button"),
  status: document.querySelector("#service-status"),
  navigation: document.querySelector("#main-navigation"),
  workspace: document.querySelector("#workspace-label"),
};

const context = {
  api,
  state,
  showToast,
  openImport,
  importDemo,
  loadAnalysis,
  reloadProject,
  reloadWorkspace,
  renderCurrentView,
};

function updateProjectSelector() {
  elements.projectSelect.innerHTML = state.projects.length
    ? state.projects.map((project) => `<option value="${project.id}" ${project.id === state.projectId ? "selected" : ""}>${escapeHtml(project.name)} · ${project.snapshot_count}版本</option>`).join("")
    : '<option value="">暂无项目</option>';
  elements.projectSelect.disabled = !state.projects.length;
  elements.importButton.disabled = !state.projectId;
}

function updateNavigation() {
  elements.navigation.querySelectorAll("[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.view);
  });
}

function renderEmptyWorkspace() {
  const template = document.querySelector("#empty-project-template");
  elements.content.replaceChildren(template.content.cloneNode(true));
  elements.content.querySelector('[data-action="create-project"]').addEventListener("click", openCreateProject);
}

function renderCurrentView() {
  updateProjectSelector();
  updateNavigation();
  if (!state.projectId || !state.project) {
    renderEmptyWorkspace();
    return;
  }
  const module = views[state.view] || views.overview;
  elements.content.innerHTML = module.render(context);
  module.bind(context, elements.content);
  elements.content.focus({ preventScroll: true });
}

async function loadAnalysis() {
  if (!state.snapshotId) {
    state.setAnalysis(null);
    return null;
  }
  state.setLoading(true, "正在读取分析结果");
  try {
    const payload = await api.getAnalysis(state.snapshotId);
    state.setAnalysis(payload.analysis);
    return payload.analysis;
  } catch (error) {
    showToast(error.message, "error");
    throw error;
  } finally {
    state.setLoading(false);
  }
}

async function reloadProject() {
  if (!state.projectId) return;
  const payload = await api.getProject(state.projectId);
  state.setProjectDetail(payload.project, payload.snapshots);
  if (state.snapshotId) await loadAnalysis();
}

async function reloadWorkspace() {
  state.setLoading(true, "正在刷新工作区");
  try {
    const payload = await api.listProjects();
    state.setProjects(payload.projects);
    if (state.projectId) {
      await reloadProject();
    } else {
      state.project = null;
    }
    renderCurrentView();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    state.setLoading(false);
  }
}

function defaultMemoryConfig() {
  return {
    architecture: "auto",
    regions: [
      { name: "FLASH", origin: "0x20000000", length: "512K", permissions: "rx", description: "代码与只读数据" },
      { name: "RAM", origin: "0x80000000", length: "256K", permissions: "rwx", description: "运行时数据与栈" },
    ],
  };
}

function openCreateProject() {
  showModal({
    title: "新建固件分析项目",
    width: "wide",
    submitText: "创建项目",
    body: `
      <div class="form-grid">
        <div class="form-field full"><label for="create-name">项目名称</label><input id="create-name" name="name" class="form-control" required maxlength="80" placeholder="例如：RV64控制器固件"></div>
        <div class="form-field full"><label for="create-description">项目说明</label><textarea id="create-description" name="description" class="form-control" maxlength="500" placeholder="记录目标芯片、固件用途或版本范围"></textarea></div>
        <div class="form-field"><label for="flash-origin">FLASH起始地址</label><input id="flash-origin" name="flash_origin" class="form-control mono" value="0x20000000" required></div>
        <div class="form-field"><label for="flash-length">FLASH容量</label><input id="flash-length" name="flash_length" class="form-control" value="512K" required></div>
        <div class="form-field"><label for="ram-origin">RAM起始地址</label><input id="ram-origin" name="ram_origin" class="form-control mono" value="0x80000000" required></div>
        <div class="form-field"><label for="ram-length">RAM容量</label><input id="ram-length" name="ram_length" class="form-control" value="256K" required></div>
      </div>`,
    onSubmit: async (formData) => {
      const config = defaultMemoryConfig();
      config.regions[0].origin = formData.get("flash_origin");
      config.regions[0].length = formData.get("flash_length");
      config.regions[1].origin = formData.get("ram_origin");
      config.regions[1].length = formData.get("ram_length");
      const result = await api.createProject({
        name: formData.get("name"),
        description: formData.get("description"),
        memory_config: config,
      });
      state.projectId = result.project.id;
      await reloadWorkspace();
      showToast("项目已创建");
      return true;
    },
  });
}

function openImport() {
  if (!state.projectId) {
    showToast("请先创建项目", "error");
    return;
  }
  const nextVersion = `V${state.snapshots.length + 1}`;
  showModal({
    title: "导入固件版本",
    width: "wide",
    submitText: "分析并保存",
    body: `
      <div class="form-grid">
        <div class="form-field"><label for="version-name">版本名称</label><input id="version-name" name="version_name" class="form-control" value="${nextVersion}" required maxlength="60"></div>
        <div class="form-field"><label for="version-notes">版本备注</label><input id="version-notes" name="notes" class="form-control" maxlength="300" placeholder="例如：启用压缩指令后的发布候选"></div>
        <div class="form-field full"><label>RISC-V ELF文件</label><div class="file-drop"><strong>选择已经链接的ELF固件</strong><span>系统将校验ELF机器类型并计算SHA-256</span><input id="elf-file" name="elf" type="file" required accept=".elf,.out,.axf,application/octet-stream"></div></div>
        <div class="form-field full"><label>GNU链接MAP文件（可选）</label><div class="file-drop"><strong>选择与ELF对应的MAP文件</strong><span>用于分析目标文件贡献和链接器内存区域</span><input id="map-file" name="map" type="file" accept=".map,text/plain"></div></div>
        <div class="form-field full"><label><input name="prefer_map_regions" type="checkbox" checked> MAP文件包含Memory Configuration时优先使用其中的区域</label></div>
      </div>`,
    onSubmit: async (formData, form) => {
      const elf = form.querySelector('[name="elf"]').files[0];
      const map = form.querySelector('[name="map"]').files[0];
      if (!elf) {
        showToast("请选择ELF固件文件", "error");
        return false;
      }
      if (elf.size > 128 * 1024 * 1024 || (map && map.size > 128 * 1024 * 1024)) {
        showToast("单个文件不能超过128 MiB", "error");
        return false;
      }
      const payload = {
        version_name: formData.get("version_name"),
        notes: formData.get("notes"),
        prefer_map_regions: formData.get("prefer_map_regions") === "on",
        elf_name: elf.name,
        elf_base64: await readFileAsBase64(elf),
      };
      if (map) {
        payload.map_name = map.name;
        payload.map_base64 = await readFileAsBase64(map);
      }
      const result = await api.createSnapshot(state.projectId, payload);
      state.snapshotByProject[state.projectId] = result.snapshot.id;
      await reloadProject();
      renderCurrentView();
      showToast("固件分析完成并已保存");
      return true;
    },
  });
}

async function importDemo() {
  if (!state.projectId) return;
  try {
    const result = await api.importDemo(state.projectId);
    const last = result.snapshots.at(-1);
    if (last) state.snapshotByProject[state.projectId] = last.id;
    await reloadProject();
    renderCurrentView();
    showToast("两版示例固件已导入");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function handleNavigation(view) {
  if (!views[view]) return;
  state.setView(view);
  const needsAnalysis = ["overview", "sections", "symbols", "instructions", "functions", "release", "policy"].includes(view);
  if (needsAnalysis && state.snapshotId && !state.analysis) {
    renderCurrentView();
    try {
      await loadAnalysis();
    } catch (_error) {
      return;
    }
  }
  renderCurrentView();
}

async function initialize() {
  elements.newProject.addEventListener("click", openCreateProject);
  elements.refresh.addEventListener("click", reloadWorkspace);
  elements.importButton.addEventListener("click", openImport);
  elements.projectSelect.addEventListener("change", async (event) => {
    state.selectProject(Number(event.target.value));
    await reloadProject();
    renderCurrentView();
  });
  elements.navigation.addEventListener("click", (event) => {
    const button = event.target.closest("[data-view]");
    if (button) handleNavigation(button.dataset.view);
  });
  try {
    state.health = await api.health();
    elements.status.classList.add("online");
    elements.status.innerHTML = "<i></i>服务正常";
    elements.workspace.textContent = state.health.workspace.split("/").at(-1) || "本地工作区";
  } catch (error) {
    elements.status.classList.add("offline");
    elements.status.innerHTML = "<i></i>服务异常";
    showToast(error.message, "error");
  }
  await reloadWorkspace();
}

initialize();
