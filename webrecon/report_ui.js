"use strict";

// 고정 UI 코드만 실행한다. 대상 코드 실행·네트워크·브라우저 저장소 접근은 하지 않는다.
const tabs = Array.from(document.querySelectorAll("[data-report-tab]"));
const panels = Array.from(document.querySelectorAll("[data-report-panel]"));
const tabBar = document.querySelector("[data-report-tabs]");

function activateTab(identifier, focus = false) {
  if (!panels.some(panel => panel.id === identifier)) return;
  panels.forEach(panel => { panel.hidden = panel.id !== identifier; });
  tabs.forEach(tab => {
    const selected = tab.getAttribute("aria-controls") === identifier;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && focus) tab.focus();
  });
}

// 역할/숨김은 JS 초기화 후에만 부여한다. JS가 꺼져 있어도 목차와 전체 표를 읽을 수 있다.
tabBar.setAttribute("role", "tablist");
tabs.forEach((tab, index) => {
  const identifier = tab.getAttribute("href").slice(1);
  tab.setAttribute("role", "tab");
  tab.setAttribute("aria-controls", identifier);
  const panel = panels.find(item => item.id === identifier);
  panel.setAttribute("role", "tabpanel");
  panel.setAttribute("aria-labelledby", tab.id);
  panel.tabIndex = 0;
  tab.addEventListener("click", event => {
    event.preventDefault();
    activateTab(identifier);
    window.location.hash = identifier;
  });
  tab.addEventListener("keydown", event => {
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else if (event.key !== " " && event.key !== "Enter") return;
    event.preventDefault();
    const target = tabs[next].getAttribute("aria-controls");
    activateTab(target, true);
    window.location.hash = target;
  });
});
const initialTab = window.location.hash.slice(1);
activateTab(panels.some(panel => panel.id === initialTab) ? initialTab : (tabBar.dataset.defaultTab || "document-section"));
window.addEventListener("hashchange", () => activateTab(window.location.hash.slice(1)));

const inventories = new Map();
document.querySelectorAll("[data-inventory]").forEach(inventory => {
  const search = inventory.querySelector("[data-search]");
  const filters = Array.from(inventory.querySelectorAll("[data-filter]"));
  const rows = Array.from(inventory.querySelectorAll("tbody > tr"));
  const text = new Map(rows.map(row => [row, row.textContent.toLocaleLowerCase()]));
  const pager = inventory.querySelector("[data-pagination]");
  const size = inventory.querySelector("[data-page-size]");
  const previous = inventory.querySelector("[data-previous]");
  const next = inventory.querySelector("[data-next]");
  const position = inventory.querySelector("[data-page-position]");
  let page = 0;
  pager.hidden = false;

  function update(resetPage = true) {
    if (resetPage) page = 0;
    const terms = search.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const matching = rows.filter(row => terms.every(term => text.get(row).includes(term)) && filters.every(filter => {
      const key = filter.dataset.filter;
      const value = row.dataset[key] || "";
      return !filter.value || ((key === "category" || key === "method") ? value.split(" ").includes(filter.value) : value === filter.value);
    }));
    const pageSize = Number(size.value) || 50;
    const pages = Math.max(1, Math.ceil(matching.length / pageSize));
    page = Math.min(page, pages - 1);
    const matched = new Set(matching);
    const visible = new Set(matching.slice(page * pageSize, (page + 1) * pageSize));
    rows.forEach(row => {
      row.hidden = !visible.has(row);
      // 인쇄에는 페이지 분할을 적용하지 않고 현재 검색/필터에 맞는 행 전체를 포함한다.
      row.dataset.matches = String(matched.has(row));
    });
    inventory.querySelector("[data-count]").textContent = matching.length + " / " + rows.length + "개 검색됨";
    inventory.querySelector("[data-empty]").hidden = matching.length !== 0;
    position.textContent = matching.length ? (page + 1) + " / " + pages + " 페이지" : "0 / 0 페이지";
    previous.disabled = page === 0 || !matching.length;
    next.disabled = page >= pages - 1 || !matching.length;
  }

  function reset() {
    search.value = "";
    size.value = "50";
    filters.forEach(filter => { filter.value = ""; });
    update();
  }
  search.addEventListener("input", () => update());
  filters.forEach(filter => filter.addEventListener("change", () => update()));
  size.addEventListener("change", () => update());
  previous.addEventListener("click", () => { if (page > 0) page--; update(false); });
  next.addEventListener("click", () => { page++; update(false); });
  inventory.querySelector("[data-reset]").addEventListener("click", reset);
  inventories.set(inventory.dataset.inventory, {element: inventory, update, reset});
  update();
});

document.querySelectorAll("[data-category]").forEach(button => {
  button.addEventListener("click", () => {
    const inventory = inventories.get("endpoints");
    inventory.reset();
    const filter = inventory.element.querySelector('[data-filter="category"]');
    filter.value = button.dataset.category;
    inventory.update();
    activateTab("endpoint-section");
    window.location.hash = "endpoint-section";
    filter.focus({preventScroll: true});
  });
});
