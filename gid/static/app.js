"use strict";

const $ = (id) => document.getElementById(id);
const paths = {
  sun: ["M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6 7 7m10 10 1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4", "M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0"],
  inbox: ["M4 4h16v16H4z", "M4 13h5l1.5 3h3l1.5-3h5"],
  calendar: ["M5 5h14a1 1 0 0 1 1 1v14H4V6a1 1 0 0 1 1-1M8 3v4m8-4v4M4 10h16", "M8 14h2m4 0h2m-8 3h2"],
  alert: ["m12 3 10 18H2L12 3Z", "M12 9v5m0 3h.01"],
  share: ["M16 5a2.5 2.5 0 1 0 5 0 2.5 2.5 0 0 0-5 0m0 14a2.5 2.5 0 1 0 5 0 2.5 2.5 0 0 0-5 0M3 12a2.5 2.5 0 1 0 5 0 2.5 2.5 0 0 0-5 0", "m8 11 8-5m-8 7 8 5"],
  check: ["m5 12 4 4L19 6"],
  checkCircle: ["M21 11v1a9 9 0 1 1-5.4-8.3", "m8 11 4 4L21 5"],
  settings: ["M9 3h6l.6 3 2.4 1.4 2.9-.8 3 5.2-2.3 2.1v2.8l2.3 2.1-3 5.2-2.9-.8L15.6 25H9l-.6-3-2.4-1.4-2.9.8-3-5.2L2.4 14v-2.8L.1 9.1l3-5.2 2.9.8L8.4 3Z"],
  logout: ["M9 4H4v16h5m5-13 5 5-5 5m-6-5h13"],
  search: ["M16 10a6 6 0 1 1-12 0 6 6 0 0 1 12 0m-2 5 6 6"],
  plus: ["M12 5v14M5 12h14"],
  close: ["m6 6 12 12M6 18 18 6"],
  menu: ["M4 6h16M4 12h16M4 18h16"],
  location: ["M19 10c0 5-7 11-7 11S5 15 5 10a7 7 0 0 1 14 0Z", "M14 10a2 2 0 1 1-4 0 2 2 0 0 1 4 0"],
  clock: ["M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0", "M12 7v5l3 2"],
  download: ["M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"],
  edit: ["m15 4 5 5M4 20l5-1L21 7a2 2 0 0 0-5-5L4 14v6Z"],
  arrow: ["M4 12h16m-5-5 5 5-5 5"],
  undo: ["M8 4 3 9l5 5M3 9h10a7 7 0 0 1 0 14"],
  person: ["M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0M4 21v-2a8 8 0 0 1 16 0v2"],
};
// A compact cog keeps the same line weight as the other local SVG icons.
paths.settings = ["M10 3h4l.7 3 2 .9 2.7-.9 2 3.5-2.1 2.1v2.3l2.1 2.1-2 3.5-2.7-.9-2 .9-.7 3h-4l-.7-3-2-.9-2.7.9-2-3.5 2.1-2.1v-2.3L2.6 9.5l2-3.5 2.7.9 2-.9.7-3Z", "M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0"];

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const d of paths[name] || paths.inbox) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}
function node(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}
function action(label, className, handler, iconName) {
  const button = node("button", className);
  button.type = "button";
  if (iconName) button.append(icon(iconName));
  if (label) button.append(document.createTextNode(label));
  button.addEventListener("click", handler);
  return button;
}
function iconAction(label, iconName, handler) {
  const button = action("", "icon-button", handler, iconName);
  button.setAttribute("aria-label", label);
  button.title = label;
  return button;
}
function fieldError(id, message = "") {
  $(id).textContent = message;
  $(id).hidden = !message;
}
function toast(message, error = false) {
  const item = node("div", `toast${error ? " error" : ""}`, message);
  $("toast-region").append(item);
  setTimeout(() => item.remove(), error ? 7000 : 4200);
}

const views = {
  today: { label: "Today", icon: "sun", description: "Your tasks due today. Make a little room for what matters." },
  active: { label: "All tasks", icon: "inbox", description: "Your open tasks, including the ones shared with you." },
  upcoming: { label: "Upcoming", icon: "calendar", description: "A look ahead at tasks due in the next seven days." },
  overdue: { label: "Overdue", icon: "alert", description: "Give these a little attention: update the due date or mark them complete." },
  shared: { label: "Shared with me", icon: "share", description: "Tasks others have shared with you. Each owner decides who can make changes." },
  completed: { label: "Completed", icon: "checkCircle", description: "Progress worth keeping. Completed tasks stay here for history and reporting." },
};
const state = { user: null, csrf: "", settings: {}, view: "active", tasks: [], counts: {}, overdue: [], editing: null, initialPasswordChangeRequired: false, request: 0, users: [], resetUser: null };
const canUseApp = () => !!state.user && !state.user.must_change_password;

async function api(path, options = {}) {
  if (state.user?.must_change_password && !["/api/me", "/api/account/password", "/api/logout", "/api/bootstrap"].includes(path)) {
    showRequiredPasswordChange();
    throw new Error("Change your password before using GID.");
  }
  const requestCsrf = state.csrf;
  const headers = { Accept: "application/json", ...options.headers };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.method && !["GET", "HEAD"].includes(options.method) && state.csrf) headers["X-CSRF-Token"] = state.csrf;
  let response;
  try {
    response = await fetch(path, { credentials: "same-origin", ...options, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  } catch (_) {
    throw new Error("Can't reach GID right now. Check your connection and try again.");
  }
  let data;
  try { data = await response.json(); } catch (_) { data = {}; }
  if (!response.ok) {
    if (response.status === 401 && state.user && requestCsrf === state.csrf) {
      showAuth();
    }
    if (response.status === 403 && data.detail === "Change your password before using GID." && state.user && requestCsrf === state.csrf) {
      state.user = { ...state.user, must_change_password: true };
      showRequiredPasswordChange();
    }
    const message = typeof data.detail === "string" ? data.detail : response.status === 422 ? "Check the values you entered and try again." : "Something went wrong. Please try again.";
    throw new Error(message);
  }
  return data;
}
async function submitForm(form, errorId, callback) {
  fieldError(errorId);
  const submit = form.querySelector('[type="submit"]');
  if (submit) submit.disabled = true;
  try { await callback(); } catch (error) { fieldError(errorId, error.message); }
  finally { if (submit) submit.disabled = false; }
}

function clearSecrets() {
  for (const field of document.querySelectorAll('input[type="password"]')) field.value = "";
}
function clearWorkspace() {
  state.request++;
  state.tasks = [];
  state.counts = {};
  state.overdue = [];
  state.editing = null;
  state.sharing = null;
  state.users = [];
  state.resetUser = null;
  for (const dialog of document.querySelectorAll("dialog[open]")) dialog.close();
  for (const id of ["task-list", "overdue-tasks", "share-users", "task-history", "admin-user-list"]) $(id).replaceChildren();
  for (const id of ["task-form", "share-form", "password-form", "required-password-form", "create-user-form", "reset-form"]) $(id).reset();
  clearSecrets();
  setNavOpen(false);
}
function renderLoginHint() {
  $("initial-credentials-hint").hidden = !state.initialPasswordChangeRequired;
}
function showAuth() {
  clearWorkspace();
  state.user = null;
  state.csrf = "";
  fieldError("auth-error");
  $("auth-form").reset();
  $("loading-screen").hidden = true;
  $("application").hidden = true;
  $("skip-link").hidden = true;
  $("required-password-screen").hidden = true;
  $("auth-screen").hidden = false;
  renderLoginHint();
  $("auth-username").focus();
}
function showRequiredPasswordChange() {
  clearWorkspace();
  $("loading-screen").hidden = true;
  $("application").hidden = true;
  $("skip-link").hidden = true;
  $("auth-screen").hidden = true;
  $("required-password-screen").hidden = false;
  fieldError("required-password-error");
  $("required-current-password").focus();
}
function setSession(data) {
  clearWorkspace();
  state.view = "active";
  $("search-input").value = "";
  $("priority-filter").value = "";
  $("tag-filter").value = "";
  $("task-list").replaceChildren();
  $("overdue-section").hidden = true;
  state.user = data.user;
  state.csrf = data.csrf_token;
  state.settings = data.settings;
  if (state.user.must_change_password) {
    showRequiredPasswordChange();
    return;
  }
  state.initialPasswordChangeRequired = false;
  $("auth-screen").hidden = true;
  $("required-password-screen").hidden = true;
  $("loading-screen").hidden = true;
  $("application").hidden = false;
  $("skip-link").hidden = false;
  $("account-name").textContent = state.user.display_name || state.user.username;
  $("avatar").textContent = (state.user.display_name || state.user.username).split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
  $("admin-button").hidden = !state.user.is_admin;
  setNavOpen(false);
  renderSettings();
  renderNavigation();
  renderOverview();
  refreshTasks();
}
function renderSettings() {
  const timezone = state.settings.timezone || "America/New_York";
  document.title = `GID · ${state.settings.app_name || "Get It Done"}`;
  $("sidebar-app-name").textContent = (state.settings.app_name || "Get It Done").toUpperCase();
  $("timezone-label").textContent = timezone.replaceAll("_", " ");
  $("date-label").textContent = new Intl.DateTimeFormat("en-US", { weekday: "long", month: "long", day: "numeric", timeZone: timezone }).format(new Date()).toUpperCase();
  const hour = Number(new Intl.DateTimeFormat("en-US", { hour: "numeric", hourCycle: "h23", timeZone: timezone }).format(new Date()));
  const name = (state.user.display_name || state.user.username).split(/\s+/)[0];
  $("greeting").textContent = `${hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening"}, ${name}.`;
}
function todayDate() {
  const parts = new Intl.DateTimeFormat("en-CA", { year: "numeric", month: "2-digit", day: "2-digit", timeZone: state.settings.timezone || "America/New_York" }).formatToParts(new Date());
  const values = Object.fromEntries(parts.map(({ type, value }) => [type, value]));
  return `${values.year}-${values.month}-${values.day}`;
}
function dateLabel(date) {
  if (!date) return "No due date";
  if (date === todayDate()) return "Today";
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: date.slice(0, 4) !== todayDate().slice(0, 4) ? "numeric" : undefined, timeZone: "UTC" }).format(new Date(`${date}T12:00:00Z`));
}
function localDate(value) {
  const parts = new Intl.DateTimeFormat("en-CA", { year: "numeric", month: "2-digit", day: "2-digit", timeZone: state.settings.timezone || "America/New_York" }).formatToParts(new Date(value));
  const values = Object.fromEntries(parts.map(({ type, value: text }) => [type, text]));
  return `${values.year}-${values.month}-${values.day}`;
}
function timestampLabel(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", timeZone: state.settings.timezone || "America/New_York" }).format(new Date(value));
}
function timeLabel(value) {
  if (!value) return "";
  const [hour, minute] = value.split(":");
  return `${Number(hour) % 12 || 12}:${minute} ${Number(hour) < 12 ? "AM" : "PM"}`;
}
function renderNavigation() {
  $("view-navigation").replaceChildren();
  for (const [key, view] of Object.entries(views)) {
    const button = action("", `nav-item${state.view === key ? " active" : ""}`, () => changeView(key), view.icon);
    button.append(node("span", "", view.label));
    if (state.view === key) button.setAttribute("aria-current", "page");
    const count = state.counts[key] || 0;
    button.append(node("span", `nav-count${key === "overdue" && count ? " overdue-count" : ""}`, count));
    $("view-navigation").append(button);
  }
}
function renderOverview() {
  $("overview").replaceChildren();
  const cards = [
    ["active", "Open tasks", "inbox", "A little at a time"],
    ["today", "Due today", "sun", "Focus for today"],
    ["overdue", "Need attention", "alert", "Time to revisit"],
    ["completed", "Completed", "checkCircle", "Progress made"],
  ];
  for (const [key, label, iconName, hint] of cards) {
    const button = action("", `stat-card stat-${key}`, () => changeView(key));
    const top = node("span", "stat-top");
    top.append(node("span", "", label), icon(iconName));
    button.append(top, node("span", "stat-value", state.counts[key] || 0), node("span", "stat-hint", hint));
    button.setAttribute("aria-label", `${label}: ${state.counts[key] || 0}. Show tasks`);
    $("overview").append(button);
  }
}
function setNavOpen(open) {
  $("application").classList.toggle("nav-open", open);
  $("nav-backdrop").hidden = !open;
  $("menu-button").setAttribute("aria-expanded", String(open));
  if (open) $("view-navigation").querySelector("button")?.focus();
}
function changeView(view) {
  if (!canUseApp()) return;
  state.view = view;
  setNavOpen(false);
  renderNavigation();
  refreshTasks();
}
async function refreshTasks() {
  if (!canUseApp()) return;
  const request = ++state.request;
  const query = new URLSearchParams({ view: state.view });
  if ($("search-input").value.trim()) query.set("search", $("search-input").value.trim());
  if ($("priority-filter").value) query.set("priority", $("priority-filter").value);
  if ($("tag-filter").value.trim()) query.set("tag", $("tag-filter").value.trim());
  $("view-title").textContent = views[state.view].label;
  $("view-description").textContent = views[state.view].description;
  $("export-link").hidden = state.view !== "completed";
  $("task-load-error").hidden = true;
  $("task-list").hidden = false;
  $("task-list").setAttribute("aria-busy", "true");
  if (!state.tasks.length) {
    $("task-list").replaceChildren(...Array.from({ length: 3 }, () => node("div", "skeleton-row")));
  }
  try {
    const [result, overdue] = await Promise.all([api(`/api/tasks?${query}`), api("/api/tasks?view=overdue")]);
    if (request !== state.request || !canUseApp()) return;
    state.tasks = result.tasks;
    state.counts = result.counts;
    state.overdue = overdue.tasks;
    if (result.timezone) state.settings.timezone = result.timezone;
    renderNavigation();
    renderOverview();
    renderAttention();
    renderTasks();
    renderSettings();
  } catch (error) {
    if (request !== state.request) return;
    $("task-list").hidden = true;
    $("task-load-error").hidden = false;
    $("task-load-error-text").textContent = error.message;
  } finally {
    if (request === state.request) $("task-list").setAttribute("aria-busy", "false");
  }
}
function renderAttention() {
  const show = state.overdue.length > 0 && state.view !== "completed";
  $("overdue-section").hidden = !show;
  if (!show) return;
  const count = state.counts.overdue || state.overdue.length;
  $("overdue-title").textContent = `${count} ${count === 1 ? "task needs" : "tasks need"} your attention`;
  $("overdue-description").textContent = "Plans change. Update a due date or mark a task complete.";
  $("overdue-tasks").replaceChildren();
  for (const task of state.overdue.slice(0, 3)) {
    const row = node("div", "attention-row");
    const title = action(task.title, "text-button attention-row-title", () => openTask(task.id));
    title.title = task.title;
    row.append(title, node("span", "attention-date", `Due ${dateLabel(task.due_date)}${task.due_time ? ` · ${timeLabel(task.due_time)}` : ""}`));
    const actions = node("div", "attention-actions");
    if (task.permission !== "view") {
      actions.append(action("Update date", "button", async () => { await openTask(task.id); $("task-due-date").focus(); }));
      actions.append(iconAction(`Complete ${task.title}`, "check", () => toggleComplete(task)));
    } else actions.append(node("span", "attention-readonly", "View only"));
    row.append(actions);
    $("overdue-tasks").append(row);
  }
}
function meta(text, iconName, className = "") {
  const item = node("span", `task-meta ${className}`);
  if (iconName) item.append(icon(iconName));
  item.append(document.createTextNode(text));
  return item;
}
function renderTasks() {
  $("task-list").replaceChildren();
  $("result-count").textContent = state.tasks.length;
  const filtered = !!($("search-input").value || $("priority-filter").value || $("tag-filter").value);
  $("task-footer").textContent = state.view === "completed" ? "Completed tasks are kept for your records. Reopen one whenever you need to." : `${state.tasks.length} ${state.tasks.length === 1 ? "task" : "tasks"}${filtered ? " matching your filters" : " in this view"} · All dates use your workspace timezone.`;
  if (!state.tasks.length) {
    const empty = node("div", "empty-state");
    const emptyIcon = node("div", "empty-icon");
    emptyIcon.append(icon(filtered ? "search" : state.view === "overdue" ? "checkCircle" : views[state.view].icon));
    const titles = { active: "A little space for your next step.", today: "A clear day ahead.", upcoming: "Room to plan ahead.", overdue: "You're all caught up.", shared: "A space for working together.", completed: "Progress starts with one task." };
    const descriptions = { active: "Add something you want to get done. Big plans start with small steps.", today: "No tasks are due today. Find your next step in All tasks, or add a new one.", upcoming: "No tasks are due in the next seven days. Add a date to something on your list.", overdue: "No overdue tasks need your attention right now.", shared: "Tasks that other people share with you will appear here.", completed: "When you complete a task, it will be kept here for you to revisit and report on." };
    empty.append(emptyIcon, node("h3", "", filtered ? "No tasks found." : titles[state.view]), node("p", "", filtered ? "Try a different search, priority, or tag." : descriptions[state.view]));
    if (filtered) empty.append(action("Clear filters", "button button-secondary", clearFilters));
    else if (["active", "today", "upcoming"].includes(state.view)) empty.append(action("Add a task", "button button-primary", () => openTask(), "plus"));
    $("task-list").append(empty);
    return;
  }
  for (const task of state.tasks) {
    const completed = !!task.completed_at;
    const row = node("article", `task-row${completed ? " completed-row" : ""}`);
    const check = action("", `task-checkbox${completed ? " is-complete" : ""}`, () => toggleComplete(task));
    check.setAttribute("aria-label", `${completed ? "Reopen" : "Complete"} ${task.title}`);
    if (completed) check.append(icon("check"));
    if (task.permission === "view") { check.disabled = true; check.title = "This task is shared with view-only access"; }
    const body = node("div", "task-body");
    const titleLine = node("div", "task-title-line");
    titleLine.append(action(task.title, "task-title", () => openTask(task.id)));
    if (task.priority !== "normal") {
      const dot = node("span", `priority-dot priority-${task.priority}`);
      dot.title = `${task.priority === "high" ? "High" : "Low"} priority`;
      dot.setAttribute("aria-label", dot.title);
      titleLine.append(dot);
    }
    body.append(titleLine);
    if (task.notes) body.append(node("p", "task-notes-preview", task.notes.replace(/\s+/g, " ")));
    const metadata = node("div", "task-metadata");
    if (completed) metadata.append(meta(`Completed ${dateLabel(localDate(task.completed_at))}`, "checkCircle"));
    else if (task.due_date) metadata.append(meta(`${task.is_overdue ? "Overdue · " : ""}${dateLabel(task.due_date)}${task.due_time ? ` · ${timeLabel(task.due_time)}` : ""}`, "calendar", task.is_overdue ? "is-overdue" : task.due_date === todayDate() ? "is-today" : ""));
    else metadata.append(meta("No due date", "calendar"));
    if (task.location) metadata.append(meta(task.location, "location"));
    if (task.permission !== "owner") metadata.append(meta(`From ${task.owner.display_name || task.owner.username}`, "share", "shared-label"));
    else if (task.shares?.length) metadata.append(meta(`Shared with ${task.shares.length}`, "share", "shared-label"));
    for (const tag of task.tags) metadata.append(node("span", "task-tag", tag));
    body.append(metadata);
    const actions = node("div", "task-row-actions");
    if (task.permission === "view") actions.append(node("span", "readonly-badge", "View only"));
    else if (task.permission === "owner") actions.append(iconAction(`Share ${task.title}`, "share", () => openShares(task)));
    actions.append(iconAction(`Open ${task.title}`, "arrow", () => openTask(task.id)));
    row.append(check, body, actions);
    $("task-list").append(row);
  }
}
function clearFilters() {
  $("search-input").value = "";
  $("priority-filter").value = "";
  $("tag-filter").value = "";
  refreshTasks();
}
async function toggleComplete(task) {
  try {
    await api(`/api/tasks/${task.id}/${task.completed_at ? "reopen" : "complete"}`, { method: "POST" });
    toast(task.completed_at ? "Task reopened. Back on your list." : "Task complete. One less thing on your mind.");
    await refreshTasks();
  } catch (error) { toast(error.message, true); }
}

function showDialog(id, focusId) {
  if (!canUseApp()) return;
  const dialog = $(id);
  dialog.showModal();
  if (focusId) $(focusId).focus();
}
async function openTask(id) {
  if (!canUseApp()) return;
  try {
    const task = id ? await api(`/api/tasks/${id}`) : null;
    state.editing = task;
    $("task-form").reset();
    fieldError("task-error");
    const readOnly = task?.permission === "view";
    const editable = !readOnly;
    $("task-dialog-title").textContent = task ? "Task details" : "New task";
    $("task-dialog-eyebrow").textContent = task?.completed_at ? "PROGRESS MADE" : task ? "ONE STEP AT A TIME" : "MAKE IT HAPPEN";
    $("task-title").value = task?.title || "";
    $("task-notes").value = task?.notes || "";
    $("task-location").value = task?.location || "";
    $("task-due-date").value = task?.due_date || "";
    $("task-due-time").value = task?.due_time || "";
    $("task-due-time").disabled = readOnly || !$("task-due-date").value;
    $("task-priority").value = task?.priority || "normal";
    $("task-tags").value = task?.tags.join(", ") || "";
    for (const field of ["task-title", "task-notes", "task-location", "task-due-date", "task-priority", "task-tags"]) $(field).disabled = readOnly;
    $("task-save-button").hidden = !editable;
    $("task-save-button").textContent = task ? "Save changes" : "Create task";
    $("task-complete-button").hidden = !task || !editable;
    $("task-complete-button").textContent = task?.completed_at ? "Reopen task" : "Mark complete";
    $("task-share-button").hidden = !task || task.permission !== "owner";
    $("task-access-note").hidden = !task || task.permission === "owner";
    $("task-access-note").textContent = task ? `${task.owner.display_name || task.owner.username} shared this task with you. ${readOnly ? "You have view-only access." : "You can edit and complete it."}` : "";
    $("task-history").hidden = !task;
    $("task-history").replaceChildren();
    if (task) {
      for (const [label, value] of [["Created", task.created_at], ["Last updated", task.updated_at], ["Completed", task.completed_at]]) {
        if (!value) continue;
        const item = node("div", "", label);
        item.append(node("span", "", timestampLabel(value)));
        $("task-history").append(item);
      }
    }
    showDialog("task-dialog", readOnly ? undefined : "task-title");
  } catch (error) { toast(error.message, true); }
}
async function saveTask(event) {
  event.preventDefault();
  await submitForm(event.currentTarget, "task-error", async () => {
    const tags = [...new Set($("task-tags").value.split(",").map((tag) => tag.trim()).filter(Boolean))];
    if (tags.length > 10 || tags.some((tag) => tag.length > 32)) throw new Error("Use up to 10 tags, with no more than 32 characters in each.");
    if (!$("task-title").value.trim()) throw new Error("Give your task a title.");
    const body = {
      title: $("task-title").value.trim(), notes: $("task-notes").value,
      location: $("task-location").value.trim(), priority: $("task-priority").value,
      due_date: $("task-due-date").value || null,
      due_time: $("task-due-date").value && $("task-due-time").value || null, tags,
    };
    await api(state.editing ? `/api/tasks/${state.editing.id}` : "/api/tasks", { method: state.editing ? "PATCH" : "POST", body });
    $("task-dialog").close();
    toast(state.editing ? "Task updated." : "Task added. A good place to start.");
    await refreshTasks();
  });
}
async function openShares(task) {
  if (!canUseApp()) return;
  try {
    const [freshTask, users] = await Promise.all([api(`/api/tasks/${task.id}`), api("/api/users")]);
    if (freshTask.permission !== "owner") throw new Error("Only the task owner can manage sharing.");
    state.sharing = freshTask;
    $("share-users").replaceChildren();
    fieldError("share-error");
    const others = users.filter((user) => user.id !== state.user.id);
    if (!others.length) $("share-users").append(node("p", "share-empty", "There are no other active accounts yet. An administrator can add people in Administration."));
    for (const user of others) {
      const shared = freshTask.shares.find((share) => share.user_id === user.id);
      const row = node("div", "share-user");
      const label = node("label");
      const check = document.createElement("input");
      check.type = "checkbox";
      check.value = user.id;
      check.checked = !!shared;
      check.dataset.shareUser = String(user.id);
      const avatar = node("span", "avatar", (user.display_name || user.username)[0].toUpperCase());
      const person = node("span", "share-person");
      person.append(node("strong", "", user.display_name), node("span", "", `@${user.username}`));
      label.append(check, avatar, person);
      const permission = document.createElement("select");
      permission.setAttribute("aria-label", `Permission for ${user.display_name || user.username}`);
      permission.append(new Option("Can view", "view"), new Option("Can edit", "edit"));
      permission.value = shared?.permission || "view";
      permission.disabled = !check.checked;
      check.addEventListener("change", () => { permission.disabled = !check.checked; });
      row.append(label, permission);
      $("share-users").append(row);
    }
    showDialog("share-dialog");
  } catch (error) { toast(error.message, true); }
}
async function saveShares(event) {
  event.preventDefault();
  await submitForm(event.currentTarget, "share-error", async () => {
    const shares = [...$("share-users").querySelectorAll(".share-user")].filter((row) => row.querySelector("input").checked).map((row) => ({ user_id: Number(row.querySelector("input").value), permission: row.querySelector("select").value }));
    const task = await api(`/api/tasks/${state.sharing.id}/shares`, { method: "PUT", body: { shares } });
    if (state.editing?.id === task.id) state.editing = task;
    $("share-dialog").close();
    toast("Sharing permissions updated.");
    await refreshTasks();
  });
}

async function openAdmin() {
  if (!canUseApp()) return;
  fieldError("admin-error");
  fieldError("create-user-error");
  fieldError("settings-error");
  $("create-user-form").reset();
  adminTab("users");
  showDialog("admin-dialog");
  try {
    const [users, settings] = await Promise.all([api("/api/admin/users"), api("/api/admin/settings")]);
    state.users = users;
    renderAdminUsers();
    $("settings-app-name").value = settings.app_name;
    $("settings-timezone").value = settings.timezone;
  } catch (error) { fieldError("admin-error", error.message); }
}
function adminTab(tab, focus = false) {
  for (const name of ["users", "settings"]) {
    const active = name === tab;
    $(`${name}-tab`).classList.toggle("active", active);
    $(`${name}-tab`).setAttribute("aria-selected", String(active));
    $(`${name}-tab`).tabIndex = active ? 0 : -1;
    $(`admin-${name}-panel`).hidden = !active;
  }
  if (focus) $(`${tab}-tab`).focus();
}
function renderAdminUsers() {
  $("admin-user-list").replaceChildren();
  for (const user of state.users) {
    const row = node("div", `admin-user${user.is_active ? "" : " inactive-user"}`);
    const avatar = node("span", "avatar", (user.display_name || user.username)[0].toUpperCase());
    const details = node("div", "admin-user-info");
    const name = node("strong", "", user.display_name || user.username);
    if (user.is_admin) name.append(node("span", "user-role", "Admin"));
    details.append(name, node("small", "", `@${user.username}${user.is_active ? "" : " · Inactive"}${user.id === state.user.id ? " · You" : ""}`));
    const actions = node("div", "admin-user-actions");
    actions.append(action("Reset password", "button button-secondary", () => {
      state.resetUser = user;
      $("reset-form").reset();
      fieldError("reset-error");
      $("reset-person").textContent = `Set a new password for ${user.display_name || user.username}.`;
      showDialog("reset-dialog", "reset-password");
    }));
    if (user.id !== state.user.id) {
      actions.append(action(user.is_active ? "Deactivate" : "Activate", "button button-secondary", () => patchAdminUser(user, { is_active: !user.is_active }, user.is_active ? "Account deactivated." : "Account activated.")));
      if (user.is_active) actions.append(action(user.is_admin ? "Make user" : "Make admin", "button button-quiet", () => patchAdminUser(user, { is_admin: !user.is_admin }, "Account role updated.")));
    }
    row.append(avatar, details, actions);
    $("admin-user-list").append(row);
  }
}
async function patchAdminUser(user, body, successMessage) {
  fieldError("admin-error");
  try {
    await api(`/api/admin/users/${user.id}`, { method: "PATCH", body });
    state.users = await api("/api/admin/users");
    renderAdminUsers();
    toast(successMessage);
  } catch (error) { fieldError("admin-error", error.message); }
}

function debounce(callback, delay = 280) {
  let timer;
  return () => { clearTimeout(timer); timer = setTimeout(callback, delay); };
}
async function signOut(button) {
  button.disabled = true;
  try {
    await api("/api/logout", { method: "POST" });
    showAuth();
    try {
      const bootstrap = await api("/api/bootstrap");
      if (!state.user) {
        state.initialPasswordChangeRequired = !!bootstrap.initial_password_change_required;
        renderLoginHint();
      }
    } catch (_) { /* Signing out remains successful if the hint cannot refresh. */ }
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}
function bindEvents() {
  for (const placeholder of document.querySelectorAll("[data-icon]")) placeholder.append(icon(placeholder.dataset.icon));
  for (const close of document.querySelectorAll("[data-close]")) close.addEventListener("click", () => $(close.dataset.close).close());
  for (const dialog of document.querySelectorAll("dialog")) {
    dialog.addEventListener("click", (event) => {
      if (event.target !== dialog) return;
      const box = dialog.getBoundingClientRect();
      if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) dialog.close();
    });
  }
  $("auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitForm(event.currentTarget, "auth-error", async () => {
      const body = { username: $("auth-username").value.trim(), password: $("auth-password").value };
      setSession(await api("/api/login", { method: "POST", body }));
    });
  });
  $("required-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitForm(event.currentTarget, "required-password-error", async () => {
      if ($("required-new-password").value !== $("required-confirm-password").value) {
        $("required-confirm-password").focus();
        throw new Error("The new passwords don't match. Please enter the same password twice.");
      }
      const data = await api("/api/account/password", { method: "POST", body: { current_password: $("required-current-password").value, new_password: $("required-new-password").value } });
      setSession(data);
      toast("Password saved. Welcome to your workspace.");
    });
  });
  $("required-logout-button").addEventListener("click", () => signOut($("required-logout-button")));
  $("new-task-button").addEventListener("click", () => openTask());
  $("overdue-view-button").addEventListener("click", () => { clearFilters(); changeView("overdue"); });
  $("search-input").addEventListener("input", debounce(refreshTasks));
  $("tag-filter").addEventListener("input", debounce(refreshTasks));
  $("priority-filter").addEventListener("change", refreshTasks);
  $("retry-tasks").addEventListener("click", refreshTasks);
  $("task-form").addEventListener("submit", saveTask);
  $("task-due-date").addEventListener("input", () => {
    $("task-due-time").disabled = !$("task-due-date").value;
    if (!$("task-due-date").value) $("task-due-time").value = "";
  });
  $("task-complete-button").addEventListener("click", async () => {
    const button = $("task-complete-button");
    button.disabled = true;
    fieldError("task-error");
    try {
      const task = state.editing;
      await api(`/api/tasks/${task.id}/${task.completed_at ? "reopen" : "complete"}`, { method: "POST" });
      $("task-dialog").close();
      toast(task.completed_at ? "Task reopened." : "Task complete. Nice progress.");
      await refreshTasks();
    } catch (error) { fieldError("task-error", error.message); }
    finally { button.disabled = false; }
  });
  $("task-share-button").addEventListener("click", () => openShares(state.editing));
  $("share-form").addEventListener("submit", saveShares);
  $("menu-button").addEventListener("click", () => setNavOpen(!$("application").classList.contains("nav-open")));
  $("nav-backdrop").addEventListener("click", () => { setNavOpen(false); $("menu-button").focus(); });
  $("logout-button").addEventListener("click", () => signOut($("logout-button")));
  $("password-button").addEventListener("click", () => {
    $("password-form").reset(); fieldError("password-error"); showDialog("password-dialog", "current-password");
  });
  $("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitForm(event.currentTarget, "password-error", async () => {
      const data = await api("/api/account/password", { method: "POST", body: { current_password: $("current-password").value, new_password: $("new-password").value } });
      setSession(data);
      toast("Password updated. Other sessions have been signed out.");
    });
  });
  $("admin-button").addEventListener("click", openAdmin);
  $("users-tab").addEventListener("click", () => adminTab("users"));
  $("settings-tab").addEventListener("click", () => adminTab("settings"));
  for (const name of ["users", "settings"]) $(`${name}-tab`).addEventListener("keydown", (event) => {
    if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      adminTab(event.key === "Home" ? "users" : event.key === "End" ? "settings" : name === "users" ? "settings" : "users", true);
    }
  });
  $("create-user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitForm(event.currentTarget, "create-user-error", async () => {
      await api("/api/admin/users", { method: "POST", body: { display_name: $("new-user-name").value.trim(), username: $("new-user-username").value.trim(), password: $("new-user-password").value, is_admin: $("new-user-admin").checked } });
      $("create-user-form").reset();
      state.users = await api("/api/admin/users");
      renderAdminUsers();
      toast("Account created. They're ready to sign in.");
    });
  });
  $("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitForm(event.currentTarget, "settings-error", async () => {
      state.settings = await api("/api/admin/settings", { method: "PUT", body: { app_name: $("settings-app-name").value.trim(), timezone: $("settings-timezone").value.trim() } });
      renderSettings();
      await refreshTasks();
      toast("Workspace settings saved.");
    });
  });
  $("reset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitForm(event.currentTarget, "reset-error", async () => {
      await api(`/api/admin/users/${state.resetUser.id}`, { method: "PATCH", body: { password: $("reset-password").value } });
      $("reset-dialog").close();
      $("reset-form").reset();
      toast("Password reset. Existing sessions have been signed out.");
    });
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && $("application").classList.contains("nav-open")) { setNavOpen(false); $("menu-button").focus(); }
    if (event.key === "/" && canUseApp() && !document.querySelector("dialog[open]") && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) { event.preventDefault(); $("search-input").focus(); }
  });
  // Refresh attention states after the page has been left open or the user returns.
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && canUseApp() && !document.querySelector("dialog[open]")) refreshTasks(); });
  window.addEventListener("focus", debounce(() => { if (canUseApp() && !document.querySelector("dialog[open]")) refreshTasks(); }, 150));
  setInterval(() => { if (canUseApp() && document.visibilityState === "visible" && !document.querySelector("dialog[open]")) refreshTasks(); }, 60000);
}
async function initialize() {
  bindEvents();
  try {
    const bootstrap = await api("/api/bootstrap");
    state.settings = { app_name: bootstrap.app_name, timezone: bootstrap.timezone };
    state.initialPasswordChangeRequired = !!bootstrap.initial_password_change_required;
    try { setSession(await api("/api/me")); } catch (_) { showAuth(); }
  } catch (error) {
    $("loading-screen").replaceChildren(node("p", "muted", error.message), action("Try again", "button button-primary", () => location.reload()));
  }
}
initialize();
