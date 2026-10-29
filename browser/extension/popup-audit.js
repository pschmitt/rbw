function auditItem(item) {
  // The vault list's own card; older hosts send names only, which can't be opened.
  if (item.id) return itemRow(item, "health");
  const row = element("div", null, "health-item"); row.append(element("strong", item.name)); return row;
}
function auditPaged(container, entries, size, render) {
  const more = element("button", null, "health-more"); more.type = "button"; let shown = 0;
  const step = () => {
    for (const entry of entries.slice(shown, shown + size)) container.insertBefore(render(entry), more);
    shown = Math.min(entries.length, shown + size);
    if (shown >= entries.length) more.remove(); else more.textContent = `Show ${Math.min(size, entries.length - shown)} more · ${entries.length - shown} left`;
  };
  more.onclick = step; container.append(more); step();
}
function auditSection(id, iconName, title, tone, count, note, fill) {
  const section = element(count ? "details" : "div", null, `health-section tone-${count ? tone : "ok"}`); section.id = id;
  const head = element(count ? "summary" : "div", null, count ? "" : "health-head");
  const badge = element("span", null, "health-badge small"); badge.append(icon(count ? iconName : "check"));
  const text = element("span", null, "health-section-title"); text.append(element("strong", title), element("small", count ? note : "All clear"));
  head.append(badge, text);
  if (!count) { section.append(head); return section; }
  const chevron = element("span", null, "health-chevron"); chevron.append(icon("chevron-down"));
  head.append(element("span", String(count), "health-count"), chevron); section.append(head);
  const body = element("div", null, "health-body"); fill(body); section.append(body);
  return section;
}
function renderAudit(result) {
  // Older hosts only list names: show those, without links.
  const named = items => items.map(item => typeof item === "string" ? { name: item } : item);
  const reused = result.reused_items || result.reused.map(named), short = result.short_items || named(result.short);
  const noTotp = result.without_totp_items || [], noTotpCount = result.without_totp_items ? noTotp.length : result.without_totp;
  const sharing = reused.reduce((total, group) => total + group.length, 0);
  const card = (body, entries) => { const box = element("div", null, "health-group"); body.append(box); auditPaged(box, entries, AUDIT_PAGE.items, auditItem); };
  const sections = [
    auditSection("health-reused", "warning", "Reused passwords", "danger", reused.length, `${sharing} logins share ${reused.length} ${reused.length === 1 ? "password" : "passwords"}`, body => auditPaged(body, reused, AUDIT_PAGE.groups, group => {
      const box = element("div", null, "health-group"); box.append(element("div", `Shared by ${group.length} logins`, "health-group-head"), ...group.map(auditItem)); return box;
    })),
    auditSection("health-short", "lock", "Short passwords", "warn", short.length, "Fewer than 12 characters", body => card(body, short)),
    auditSection("health-totp", "shield", "No authenticator code", "warn", noTotpCount, "Says nothing about the site’s other 2FA options", body => {
      if (noTotp.length) card(body, noTotp); else body.append(element("p", `${noTotpCount} password logins have no TOTP saved.`, "hint"));
    }),
  ];
  const tiles = element("div", null, "health-tiles");
  for (const [label, count, tone, section] of [["Reused", reused.length, "danger", sections[0]], ["Short", short.length, "warn", sections[1]], ["No TOTP", noTotpCount, "warn", sections[2]]]) {
    const tile = element("button", null, `health-tile tone-${count ? tone : "ok"}`); tile.type = "button"; tile.append(element("strong", String(count)), element("small", label));
    tile.onclick = () => { if (section.tagName === "DETAILS") section.open = true; section.scrollIntoView({ block: "start", behavior: "smooth" }); };
    tiles.append(tile);
  }
  const note = result.logins == null ? "Checked locally." : `${result.logins} ${result.logins === 1 ? "login" : "logins"} checked locally.`;
  $("audit-results").replaceChildren(tiles, ...sections, element("p", `${note} Passwords never leave rbw.`, "hint health-foot"));
  const first = sections.find(section => section.tagName === "DETAILS"); if (first) first.open = true;
}
function renderAuditLoading() {
  const box = element("div", null, "health-loading"), spin = element("span", null, "health-spinner"); spin.append(icon("refresh"));
  box.append(spin, element("strong", "Checking your vault"), element("small", "Looking for reused and short passwords. This stays on this device."));
  $("audit-results").replaceChildren(box);
}
async function runAudit() {
  if (healthState === "loading") return;
  healthState = "loading"; const run = healthRun;
  // A re-check keeps the old results in view while it runs.
  if (!$("audit-results").children.length) renderAuditLoading();
  $("audit").classList.add("is-syncing"); $("audit").disabled = true;
  try {
    const result = await request("audit");
    if (run !== healthRun) return;
    renderAudit(result); healthState = "done";
  } catch (error) {
    if (run === healthRun) { healthState = "idle"; $("audit-results").replaceChildren(); }
    throw error;
  } finally { $("audit").classList.remove("is-syncing"); $("audit").disabled = false; }
}
