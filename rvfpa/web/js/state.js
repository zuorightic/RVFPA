/**
 * 前端状态模块：保存当前项目、固件版本、分析结果和页面位置，
 * 并把必要的用户选择同步到浏览器本地存储。
 */

const STORAGE_KEYS = Object.freeze({
  projectId: "rvfpa.projectId",
  snapshotByProject: "rvfpa.snapshotByProject",
  view: "rvfpa.view",
});

function readJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch (_error) {
    return fallback;
  }
}

class ApplicationState extends EventTarget {
  constructor() {
    super();
    this.health = null;
    this.projects = [];
    this.project = null;
    this.snapshots = [];
    this.analysis = null;
    this.diff = null;
    this.view = localStorage.getItem(STORAGE_KEYS.view) || "overview";
    this.projectId = Number(localStorage.getItem(STORAGE_KEYS.projectId) || 0);
    this.snapshotId = 0;
    this.snapshotByProject = readJson(STORAGE_KEYS.snapshotByProject, {});
    this.loading = false;
  }

  emit(type = "change", detail = {}) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  setLoading(value, label = "") {
    this.loading = Boolean(value);
    this.emit("loading", { value: this.loading, label });
  }

  setProjects(projects) {
    this.projects = Array.isArray(projects) ? projects : [];
    if (this.projectId && !this.projects.some((item) => item.id === this.projectId)) {
      this.projectId = 0;
      this.project = null;
    }
    if (!this.projectId && this.projects.length) {
      this.projectId = this.projects[0].id;
    }
    localStorage.setItem(STORAGE_KEYS.projectId, String(this.projectId || ""));
    this.emit("projects");
  }

  selectProject(projectId) {
    this.projectId = Number(projectId || 0);
    this.project = this.projects.find((item) => item.id === this.projectId) || null;
    this.snapshots = [];
    this.analysis = null;
    this.diff = null;
    this.snapshotId = Number(this.snapshotByProject[this.projectId] || 0);
    localStorage.setItem(STORAGE_KEYS.projectId, String(this.projectId || ""));
    this.emit("project");
  }

  setProjectDetail(project, snapshots) {
    this.project = project || null;
    this.projectId = project?.id || 0;
    this.snapshots = Array.isArray(snapshots) ? snapshots : [];
    const remembered = Number(this.snapshotByProject[this.projectId] || 0);
    this.snapshotId = this.snapshots.some((item) => item.id === remembered)
      ? remembered
      : this.snapshots[0]?.id || 0;
    this.snapshotByProject[this.projectId] = this.snapshotId;
    localStorage.setItem(STORAGE_KEYS.snapshotByProject, JSON.stringify(this.snapshotByProject));
    this.analysis = null;
    this.diff = null;
    this.emit("project-detail");
  }

  selectSnapshot(snapshotId) {
    this.snapshotId = Number(snapshotId || 0);
    if (this.projectId) {
      this.snapshotByProject[this.projectId] = this.snapshotId;
      localStorage.setItem(STORAGE_KEYS.snapshotByProject, JSON.stringify(this.snapshotByProject));
    }
    this.analysis = null;
    this.diff = null;
    this.emit("snapshot");
  }

  setAnalysis(analysis) {
    this.analysis = analysis || null;
    this.emit("analysis");
  }

  setDiff(diff) {
    this.diff = diff || null;
    this.emit("diff");
  }

  setView(view) {
    this.view = view;
    localStorage.setItem(STORAGE_KEYS.view, view);
    this.emit("view", { view });
  }

  get selectedSnapshot() {
    return this.snapshots.find((item) => item.id === this.snapshotId) || null;
  }
}

export const state = new ApplicationState();
