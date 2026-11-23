// 저장된 결과의 숫자 ID만 따라간다. 관찰 문자열은 항상 텍스트로만 표시한다.
(() => {
  const get = name => document.getElementById("ex-" + name);
  const nodes = JSON.parse(document.getElementById("explorer-data").textContent);
  const root = document.getElementById("explorer");
  const types = {page:"페이지", response:"별도 응답", js:"JavaScript", inline:"인라인 JS",
    api:"API 후보", pattern:"주소 패턴", asset:"리소스", form:"폼", function:"함수", variable:"변수",
    link:"링크", hint:"문자열 단서"};
  const group = {page:["page","response"], js:["js","inline"], api:["api","pattern"], asset:["asset"], function:["function"], variable:["variable"]};
  const incoming = nodes.map(() => []);
  nodes.forEach(source => source.edges.forEach(edge => incoming[edge.to].push({source, edge})));
  const expanded = new Set();
  const limits = new Map();
  const step = 40;
  let listLimit = step, anchor = null, selected = null;

  function element(tag, value, className) {
    const el = document.createElement(tag);
    if (value !== undefined) el.textContent = value;
    if (className) el.className = className;
    return el;
  }
  function button(label, click, cls) {
    const el = element("button", label, cls);
    el.type = "button";
    el.addEventListener("click", click);
    return el;
  }
  function short(item) {
    if (!item.address || item.label !== item.address) return item.label;
    try { const url = new URL(item.address); return url.pathname + url.search; }
    catch { return item.label; }
  }
  function sourceLabel(item) {
    const unit = nodes[item.unit];
    if (!unit) return "";
    if (unit.kind === "inline") return nodes[unit.file].address + " · " + unit.label;
    if (unit.address === "local:input.js") return "로컬 JS 입력";
    return unit.document ? unit.address + " · 문서 " + unit.document : unit.address;
  }
  // 파일 간 직접 호출도 양방향으로 표시하고 간선에는 원래 근거 종류를 남긴다.
  const isCall = edge => ["직접 호출","모듈 직접 호출"].includes(edge.via);
  function where(at) { return at ? at[0] + "행 " + at[1] + "열" : ""; }
  function basis(edge) { return [edge.via, edge.method && "선언 " + edge.method, where(edge.at)].filter(Boolean).join(" · "); }
  function matches(item) {
    const kinds = group[get("kind").value];
    const term = get("filter").value.trim().toLocaleLowerCase();
    const apiHint = get("kind").value === "api" && item.api_hint;
    return (!kinds || kinds.includes(item.kind) || apiHint) && (item.label + " " + item.address + " " + (item.document || "") + " " + sourceLabel(item)).toLocaleLowerCase().includes(term);
  }
  function drawList() {
    const found = nodes.filter(matches);
    get("list").replaceChildren();
    found.slice(0,listLimit).forEach(item => {
      const b = button(short(item), () => chooseRoot(item));
      if (sourceLabel(item)) b.append(element("small",sourceLabel(item) + (item.at ? " · " + where(item.at) : "")));
      if (item.address && item.address !== short(item)) b.append(element("small", item.address));
      if (item.document) b.append(element("small", "문서 · " + item.document));
      b.setAttribute("aria-pressed", String(item === anchor));
      get("list").append(b);
    });
    const symbolFilter = ["function","variable"].includes(get("kind").value);
    const missingGraph = symbolFilter && !found.length && !get("filter").value && !nodes.some(n => n.symbolsRecorded);
    get("count").textContent = missingGraph ? "이 결과에 저장된 심볼 근거가 없습니다." : found.length + "개 항목";
    get("more").hidden = found.length <= listLimit;
  }
  function childrenOf(item) {
    return get("direction").value === "in" ? incoming[item.id] : item.edges;
  }
  function neighbor(entry) {
    return get("direction").value === "in" ? entry.source : nodes[entry.to];
  }
  function chooseRoot(item, keepDirection = false) {
    anchor = item;
    if (!matches(item)) {
      get("kind").value = Object.keys(group).find(k => group[k].includes(item.kind)) || "all";
      get("filter").value = "";
    }
    if (!keepDirection) get("direction").value = item.api_hint || ["api","pattern","asset","hint","variable"].includes(item.kind) ? "in" : "out";
    expanded.clear(); limits.clear();
    // 첫 JS와 함수의 자식만 미리 펼쳐 큰 문서도 처음부터 전부 렌더링하지 않는다.
    expanded.add("root");
    let cur = item, path = "root";
    const order = get("direction").value === "in" ? [["function"], ["js","inline"]] : [["js","inline"], ["function"]];
    for (const kinds of order) {
      const entries = childrenOf(cur);
      const visible = entries.slice(0,step);
      const index = visible.findIndex(e => kinds.includes(neighbor(e).kind) && childrenOf(neighbor(e)).length);
      if (index < 0) continue;
      path += "/" + index;
      expanded.add(path);
      cur = neighbor(entries[index]);
    }
    select(item);
    drawList();
  }
  function drawTree() {
    const tree = get("tree");
    tree.replaceChildren();
    if (!anchor) return;
    get("path").textContent = anchor.address || anchor.label;
    function branch(parent, item, path, ancestors, edge) {
      const row = element("div", undefined, "ex-row");
      const cycle = ancestors.includes(item.id);
      const entries = childrenOf(item);
      const canExpand = entries.length && !cycle && ancestors.length < 12;
      const open = expanded.has(path);
      if (canExpand) {
        const toggle = button(open ? "−" : "+", () => {
          if (open) expanded.delete(path); else expanded.add(path);
          drawTree();
          tree.querySelector('[data-branch="' + path + '"]')?.focus();
        }, "ex-toggle");
        toggle.dataset.branch = path;
        toggle.setAttribute("aria-expanded", String(open));
        toggle.setAttribute("aria-label", short(item) + (open ? " 접기" : " 펼치기"));
        row.append(toggle);
      }
      const pick = button("", () => {
        select(item, edge);
        tree.querySelector('[data-pick="' + path + '"]')?.focus();
      }, "ex-select");
      pick.dataset.pick = path;
      pick.setAttribute("aria-pressed", String(item === selected));
      pick.append(element("span", types[item.kind], "ex-type"), element("span", short(item)));
      if (edge) pick.append(element("small", [basis(edge), cycle && "이미 표시한 경로"].filter(Boolean).join(" · ")));
      row.append(pick); parent.append(row);
      if (!canExpand || !open) return;
      const children = element("div", undefined, "ex-branch");
      const next = [...ancestors, item.id];
      const count = limits.get(path) || step;
      entries.slice(0,count).forEach((entry,i) => {
        const reverse = get("direction").value === "in";
        branch(children, neighbor(entry), path + "/" + i, next, reverse ? entry.edge : entry);
      });
      if (entries.length > count) children.append(button("참조 더 보기 (" + (entries.length-count) + ")", () => {
        limits.set(path,count+step); drawTree();
      }));
      parent.append(children);
    }
    branch(tree, anchor, "root", [], null);
    if (!childrenOf(anchor).length) tree.append(element("small","이 방향으로 기록된 참조가 없습니다."));
  }

  function listSection(holder, title, entries, render) {
    if (!entries.length) return;
    holder.append(element("h4", title + " · " + entries.length));
    const list = element("div"); holder.append(list);
    let count = 0;
    function more() {
      entries.slice(count,count+step).forEach(entry => list.append(render(entry)));
      count += step;
      if (entries.length > count) {
        const b = button("더 보기", () => { b.remove(); more(); });
        list.append(b);
      }
    }
    more();
  }
  function select(item, edge = null) {
    selected = item;
    drawTree();
    const detail = get("detail");
    detail.replaceChildren(element("small", item.api_hint ? types[item.kind] + " · API 경로 단서" : types[item.kind]), element("strong", short(item)));
    if (item.address) detail.append(element("p",item.address,"ex-address"));
    if (item.status) detail.append(element("p","관찰된 GET 응답 · HTTP " + item.status,"ex-meta"));
    if (edge) detail.append(element("p","선택한 참조 · " + basis(edge),"ex-meta"));
    if (item.document) detail.append(element("p","JS를 해석한 문서 · " + item.document,"ex-meta"));
    if (item.base && item.base !== item.document) detail.append(element("p","상대 주소 기준 · " + item.base,"ex-meta"));
    if (item.contextsLimited) detail.append(element("p","기록 상한으로 일부 페이지 문맥이 생략되었습니다.","ex-meta"));
    if (item.origin) detail.append(element("p","해석 기준 origin · " + item.origin,"ex-meta"));
    if (item.resolution) detail.append(element("p",{resolved:"정적 해석 완료", partial:"일부 변수 미확인", unresolved:"주소 값 미확인"}[item.resolution],"ex-meta"));
    if (item.contextMissing) detail.append(element("p","파일 응답은 관찰했으나 이 문서 기준의 해석 근거가 없습니다.","ex-meta"));
    else if (!item.captured && ["js","asset","link"].includes(item.kind)) detail.append(element("p","참조 발견 · 응답 미기록","ex-meta"));
    if (item.format) detail.append(element("p",item.format,"ex-meta"));
    const unit = nodes[item.unit];
    const original = unit ? (nodes[unit.file] || unit) : item;
    if (original.open) {
      const label = unit ? (original.kind === "js" ? "원본 JS 새 창 ↗" : "원본 페이지 새 창 ↗") : "원본 새 창 ↗";
      const b = button(label, () => {
        const url = new URL(original.address);
        if (url.href === original.address && ["https:","http:"].includes(url.protocol) && !url.search && !url.username && !url.password)
          window.open(url.href, "_blank", "noopener,noreferrer");
      });
      b.title = "현재 브라우저로 원본 주소에 직접 접속";
      detail.append(b);
    }
    if (sourceLabel(item)) detail.append(element("p",sourceLabel(item) + (item.at ? " · " + where(item.at) : ""),"ex-address"));
    if (item.graphLimited || nodes[item.unit]?.graphLimited) detail.append(element("p","기록 상한에 도달해 일부 선언·사용 위치가 생략되었습니다.","ex-meta"));
    const back = incoming[item.id];
    function reference(other, ref) {
      const b = button(short(other), () => chooseRoot(other), "ex-ref");
      b.append(element("small",basis(ref))); return b;
    }
    const symbol = ["function","variable"].includes(item.kind);
    if (symbol) {
      listSection(detail, "이 함수를 호출한 곳", back.filter(x => isCall(x.edge)), x => reference(x.source,x.edge));
      listSection(detail, "호출하는 함수", item.edges.filter(isCall), e => reference(nodes[e.to],e));
      listSection(detail, "변수 사용처", back.filter(x => ["변수 사용","주소식 의존"].includes(x.edge.via)), x => reference(x.source,x.edge));
      listSection(detail, "사용하는 변수", item.edges.filter(e => e.via === "변수 사용"), e => reference(nodes[e.to],e));
      if (item.uses?.length) {
        const known = new Set(back.filter(x => isCall(x.edge)).map(x => where(x.edge.at)));
        listSection(detail, "호출자 미확인 · 기록된 호출 위치", item.uses.filter(at => !known.has(where(at))), at => element("p",where(at),"ex-meta"));
      }
    }
    listSection(detail, "이 항목을 참조한 곳", symbol ? back.filter(x => !["직접 호출","모듈 직접 호출","변수 사용","주소식 의존"].includes(x.edge.via)) : back,
      x => reference(x.source,x.edge));
  }

  get("direction").addEventListener("change", () => { if (anchor) chooseRoot(anchor,true); });
  get("kind").addEventListener("change", () => {
    listLimit = step;
    const first = nodes.find(matches);
    if (first) chooseRoot(first);
    else { anchor = selected = null; get("tree").replaceChildren(); get("path").textContent = ""; get("detail").replaceChildren(); drawList(); }
  });
  get("filter").addEventListener("input", () => { listLimit = step; drawList(); });
  get("more").addEventListener("click", () => { listLimit += step; drawList(); });
  const first = nodes.find(n => n.kind === "page") || nodes.find(n => n.kind === "js") || nodes[0];
  if (first) {
    get("kind").value = Object.keys(group).find(k => group[k].includes(first.kind)) || "all";
    chooseRoot(first);
  } else {
    get("tree").textContent = "이 결과에는 페이지나 JS의 참조 기록이 없습니다.";
    drawList();
  }
  root.hidden = false;
})();
