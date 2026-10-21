// PhishGuard front-end. Every piece of scanned data is attacker-controlled,
// so it is only ever inserted with textContent (never innerHTML).
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  const TITLES = {
    phishing: "PHISHING DETECTED — High risk",
    suspicious: "SUSPICIOUS — Be careful",
    safe: "LOOKS SAFE — Low risk",
    unknown: "UNKNOWN — No data",
  };
  const EMAIL_TITLES = {
    phishing: "FAKE EMAIL \u2014 Phishing detected",
    suspicious: "SUSPICIOUS EMAIL \u2014 Be careful",
    safe: "NO RED FLAGS FOUND",
    unknown: "UNKNOWN",
  };
  const HASH_TITLES = Object.assign({}, TITLES, { phishing: "MALICIOUS FILE — High risk" });

  // ---------- tabs ----------
  document.querySelectorAll(".tab-btn").forEach((b) =>
    b.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      $("tab-" + b.dataset.tab).classList.add("active");
    })
  );
  document.querySelectorAll(".chip[data-sample]").forEach((c) =>
    c.addEventListener("click", () => { $("url-input").value = c.dataset.sample; $("url-input").focus(); })
  );
  const FAKE_EMAIL = [
    'From: "PayPal Support" <service@paypal-secure-help.tk>',
    "Reply-To: recovery.team88@gmail.com",
    "Subject: Urgent: your account has been suspended",
    "Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail",
    "",
    "Dear customer,",
    "We noticed unusual activity. Your account has been suspended. Verify your account",
    "within 24 hours or it will be closed. Reply with your password and OTP to restore access.",
    "",
    "https://paypal-secure-help.tk/verify",
  ].join("\n");
  const fe = $("fake-email-chip");
  if (fe) fe.addEventListener("click", () => { $("email-input").value = FAKE_EMAIL; });

  // ---------- status ----------
  function setStatus(msg, kind) {
    const s = $("status");
    s.replaceChildren();
    if (!msg) { s.hidden = true; return; }
    s.hidden = false;
    s.className = "status" + (kind === "err" ? " err" : "");
    if (kind === "busy") s.appendChild(el("div", "spinner"));
    s.appendChild(el("div", null, msg));
  }

  async function post(path, body, btn, busyMsg) {
    btn.disabled = true;
    setStatus(busyMsg, "busy");
    try {
      const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.error || "Request failed (" + r.status + ")");
      setStatus(data.db_warning || "", data.db_warning ? "err" : undefined);
      return data;
    } catch (e) {
      setStatus(e.message || "Something went wrong.", "err");
      return null;
    } finally {
      btn.disabled = false;
    }
  }

  // ---------- rendering ----------
  function verdictBox(res, titles) {
    const box = el("div", "verdict " + res.verdict);
    const ring = el("div", "ring");
    ring.style.setProperty("--p", res.score);
    ring.dataset.score = res.score;
    box.appendChild(ring);
    const t = el("div", "vtext");
    t.appendChild(el("p", "vtitle", titles[res.verdict] || res.verdict));
    const vt = res.vt && res.vt.found ? " · VirusTotal " + res.vt.flagged_count + "/" + res.vt.total_engines : "";
    t.appendChild(el("div", "vsub", "Risk score " + res.score + "/100" + vt));
    t.appendChild(el("div", "target", res.target));
    box.appendChild(t);
    return box;
  }

  function whyGrid(findings) {
    const g = el("div", "why");
    findings.forEach((f) => {
      const it = el("div", "item");
      it.appendChild(el("div", "dot " + f.severity));
      const body = el("div");
      body.appendChild(el("b", null, f.title));
      body.appendChild(el("span", null, f.detail));
      it.appendChild(body);
      if (f.points > 0) it.appendChild(el("div", "pts", "+" + f.points));
      g.appendChild(it);
    });
    return g;
  }

  function sourcesBlock(res) {
    const wrap = el("div");
    const row = el("div", "sources");
    if (res.vt && res.vt.found) {
      const a = el("a", "src " + (res.vt.flagged_count ? "listed" : "clean"),
        "VirusTotal " + res.vt.flagged_count + "/" + res.vt.total_engines);
      a.href = res.vt.permalink; a.target = "_blank"; a.rel = "noopener noreferrer";
      row.appendChild(a);
    } else if (res.vt_error) {
      const s = el("span", "src", "VirusTotal: " + res.vt_error);
      row.appendChild(s);
    }
    (res.feeds || []).forEach((f) => {
      const s = el("span", "src " + f.status, f.name + ": " + f.status);
      s.title = f.detail;
      row.appendChild(s);
    });
    if (res.domain_age_days !== null && res.domain_age_days !== undefined)
      row.appendChild(el("span", "src", "Domain age: " + res.domain_age_days + " days"));
    wrap.appendChild(row);
    if (res.vt && res.vt.engines_flagged && res.vt.engines_flagged.length) {
      wrap.appendChild(el("div", "engines", "Flagged by: " +
        res.vt.engines_flagged.map((e) => e.engine + (e.result ? " (" + e.result + ")" : "")).join(", ")));
    }
    return wrap;
  }

  function renderUrl(res) {
    const card = el("div", "card");
    card.appendChild(verdictBox(res, TITLES));
    card.appendChild(el("h3", null, "Why this was flagged"));
    card.appendChild(whyGrid(res.findings));
    card.appendChild(el("h3", null, "Threat-intel sources"));
    card.appendChild(sourcesBlock(res));
    card.appendChild(el("div", "note", "Score = local rules + VirusTotal + blocklists + domain age. A clean result lowers the score but never guarantees safety."));
    return card;
  }

  function renderEmail(res) {
    const card = el("div", "card");
    card.appendChild(verdictBox(res, EMAIL_TITLES));
    if (res.sender && res.sender.present) {
      const a = res.sender.auth || {};
      const auth = Object.keys(a).map((k) => k.toUpperCase() + ": " + a[k]).join("  \u00b7  ");
      card.appendChild(el("div", "note", "From: " + (res.sender.from_name ? res.sender.from_name + " " : "") +
        "<" + res.sender.from_addr + ">" + (auth ? "   |   " + auth : "")));
    }
    card.appendChild(el("h3", null, "Why this email was flagged"));
    card.appendChild(whyGrid(res.findings));
    if (res.links.length) card.appendChild(el("h3", null, res.links.length + " link(s) found"));
    res.links.forEach((l) => {
      const box = el("div", "sublink");
      const row = el("div", "row");
      row.appendChild(el("div", "u", l.target));
      row.appendChild(el("span", "badge " + l.verdict, l.verdict + " " + l.score + "%"));
      box.appendChild(row);
      const top = l.findings.filter((f) => f.severity !== "ok").slice(0, 3).map((f) => f.title);
      if (top.length) box.appendChild(el("div", "note", top.join(" · ")));
      box.appendChild(sourcesBlock(l));
      card.appendChild(box);
    });
    return card;
  }

  function renderHash(res) {
    const card = el("div", "card");
    card.appendChild(verdictBox(res, HASH_TITLES));
    card.appendChild(el("h3", null, "Details"));
    card.appendChild(whyGrid(res.findings));
    card.appendChild(sourcesBlock(res));
    return card;
  }

  function render(res) {
    const out = $("result");
    out.replaceChildren(res.type === "email" ? renderEmail(res) : res.type === "hash" ? renderHash(res) : renderUrl(res));
    out.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ---------- history / stats ----------
  async function refresh() {
    try {
      const [h, s] = await Promise.all([fetch("/api/history?limit=12").then((r) => r.json()), fetch("/api/stats").then((r) => r.json())]);
      $("st-phishing").textContent = s.phishing;
      $("st-suspicious").textContent = s.suspicious;
      $("st-safe").textContent = s.safe;
      $("st-total").textContent = s.total;
      const tb = $("history");
      tb.replaceChildren();
      if (!h.length) {
        const tr = el("tr"); const td = el("td", "muted", "No scans yet."); td.colSpan = 3; tr.appendChild(td); tb.appendChild(tr); return;
      }
      h.forEach((r) => {
        const tr = el("tr", "click");
        const t = el("td", null, r.target); t.title = r.target;
        const v = el("td"); v.appendChild(el("span", "badge " + r.verdict, r.verdict));
        tr.append(t, v, el("td", null, r.score + "%"));
        tr.tabIndex = 0;
        const open = async () => {
          const d = await fetch("/api/history/" + r.id).then((x) => x.json());
          if (d && d.type) render(d);
        };
        tr.addEventListener("click", open);
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
        tb.appendChild(tr);
      });
    } catch (e) { /* offline: leave as is */ }
  }

  // ---------- actions ----------
  $("url-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = $("url-input").value.trim();
    if (!v) return setStatus("Please enter a URL to scan.", "err");
    const r = await post("/api/scan-url", { url: v }, $("url-btn"), "Scanning — checking rules, VirusTotal and blocklists (new URLs can take ~20 seconds)…");
    if (r) { render(r); refresh(); }
  });
  $("email-btn").addEventListener("click", async () => {
    const v = $("email-input").value.trim();
    if (!v) return setStatus("Paste the email text first.", "err");
    const r = await post("/api/scan-email", { text: v }, $("email-btn"), "Extracting links and scanning the riskiest ones…");
    if (r) { render(r); refresh(); }
  });
  $("hash-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = $("hash-input").value.trim();
    if (!v) return setStatus("Enter a file hash.", "err");
    const r = await post("/api/scan-hash", { hash: v }, $("hash-btn"), "Looking up the hash on VirusTotal…");
    if (r) { render(r); refresh(); }
  });
  $("clear-btn").addEventListener("click", async () => {
    if (!confirm("Delete all scan history?")) return;
    await fetch("/api/history", { method: "DELETE" });
    $("result").replaceChildren();
    refresh();
  });

  refresh();
})();
