// Airlock UI. All event text is untrusted (it can quote package contents), so it
// is only ever inserted with textContent, never innerHTML.
const Airlock = (() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const ago = (ts) => {
    const s = Math.round(Date.now() / 1000 - ts);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    return new Date(ts * 1000).toLocaleString();
  };
  const pill = (text, cls) => el('span', `pill ${cls || text}`, text);

  // Who is looking: a signed-in reviewer, or someone holding a read-only share link.
  const meP = fetch('/api/me').then((r) => (r.ok ? r.json() : {})).catch(() => ({}));

  const avatar = (login, size) => {
    const img = el('img', 'avatar');
    img.src = `https://github.com/${encodeURIComponent(login)}.png?size=${size * 2}`;
    img.width = img.height = size;
    img.alt = '';
    return img;
  };
  const postForm = (action, label, cls, title) => {
    const form = el('form'); form.method = 'post'; form.action = action;
    const b = el('button', cls, label);
    b.type = 'submit';
    if (title) b.title = title;
    form.append(b);
    return form;
  };

  // Top-right of the nav: the GitHub avatar opens a menu with the account dialog and sign-out.
  async function user() {
    const box = $('user');
    if (!box) return;
    const me = await meP;
    if (me.share) { box.replaceChildren(el('span', 'muted', 'Shared read-only view')); return; }
    if (!me.login) return;
    const btn = el('button', 'avatar-btn');
    btn.type = 'button';
    btn.setAttribute('aria-haspopup', 'menu');
    btn.setAttribute('aria-expanded', 'false');
    btn.title = `Signed in as @${me.login}`;
    btn.append(avatar(me.login, 28), el('span', 'caret', '▾'));
    const menu = el('div', 'menu');
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    const who = el('div', 'menu-who');
    who.append(el('span', 'muted', 'Signed in as'), el('b', 'mono', `@${me.login}`));
    const account = el('button', 'menu-item', 'Account…');
    account.type = 'button';
    const out = postForm('/auth/logout', 'Sign out', 'menu-item');
    menu.append(who, account, el('hr'), out);
    const open = (yes) => { menu.hidden = !yes; btn.setAttribute('aria-expanded', String(yes)); };
    btn.addEventListener('click', (e) => { e.stopPropagation(); open(menu.hidden); });
    document.addEventListener('click', (e) => { if (!menu.contains(e.target)) open(false); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') open(false); });
    account.addEventListener('click', () => { open(false); accountDialog(me); });
    box.replaceChildren(btn, menu);
  }
  user();

  // Account dialog: who you are, sessions, and (for guests) deleting everything you made.
  function accountDialog(me) {
    let dlg = $('account');
    if (dlg) { dlg.showModal(); return; }
    dlg = el('dialog', 'modal');
    dlg.id = 'account';
    const head = el('div', 'modal-head');
    const id = el('div');
    id.append(el('div', 'modal-title mono', `@${me.login}`),
      el('div', 'muted small', me.owner ? 'Owner: you can see and decide every run.' : 'Guest: you see your own runs and the demo runs.'));
    const close = el('button', 'ghost icon', '✕');
    close.type = 'button'; close.title = 'Close';
    close.addEventListener('click', () => dlg.close());
    head.append(avatar(me.login, 56), id, close);
    const gh = el('a', 'small', 'View GitHub profile ↗');
    gh.href = `https://github.com/${encodeURIComponent(me.login)}`; gh.target = '_blank'; gh.rel = 'noopener';
    id.append(gh);

    const sessions = el('section', 'modal-sec');
    sessions.append(el('h3', '', 'Sessions'),
      el('p', 'muted', 'Signing out everywhere ends every session of this account, on every device, including this one.'),
      postForm('/auth/logout-everywhere', 'Sign out everywhere', 'ghost'));

    const danger = el('section', 'modal-sec danger');
    danger.append(el('h3', '', 'Delete account'));
    if (me.owner) {
      danger.append(el('p', 'muted', 'Owner accounts hold the demo runs, so they are managed on the host, not here.'));
    } else {
      danger.append(el('p', 'muted',
        'Permanently deletes every run and self-test you submitted, with their timelines, revokes your share links and signs you out everywhere. '
        + 'Decisions already posted to GitHub stay on GitHub. You keep access, so you can sign in again later.'));
      const label = el('label', 'small', `Type ${me.login} to confirm`);
      const input = el('input');
      input.type = 'text'; input.autocomplete = 'off'; input.spellcheck = false;
      const go = el('button', 'reject', 'Delete my account');
      go.type = 'button'; go.disabled = true;
      const err = el('p', 'err');
      input.addEventListener('input', () => { go.disabled = input.value.trim().toLowerCase() !== me.login.toLowerCase(); });
      go.addEventListener('click', async () => {
        go.disabled = true; go.textContent = 'Deleting…'; err.textContent = '';
        const r = await fetch('/api/me', { method: 'DELETE' });
        if (r.ok) { location.href = '/login'; return; }
        const j = await r.json().catch(() => ({}));
        err.textContent = j.detail || r.statusText;
        go.disabled = false; go.textContent = 'Delete my account';
      });
      danger.append(label, input, go, err);
    }
    dlg.append(head, sessions, danger);
    dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });  // backdrop
    document.body.append(dlg);
    dlg.showModal();
  }

  // Live share links for this page, each revocable on its own.
  async function shareList(btn, query) {
    let ul = btn.nextElementSibling;
    if (!ul || !ul.classList.contains('shares')) { ul = el('ul', 'shares'); btn.after(ul); }
    const r = await fetch(`/api/shares?${query}`);
    const links = r.ok ? await r.json() : [];
    const day = (ts) => new Date(ts * 1000).toLocaleDateString();
    ul.replaceChildren(...links.map((s) => {
      const li = el('li', 'pr-meta', `Read-only link by @${s.by || '?'}, made ${day(s.iat)}, expires ${day(s.exp)} `);
      const x = el('button', 'ghost', 'Revoke');
      x.addEventListener('click', async () => {
        x.disabled = true;
        const d = await fetch(`/api/shares/${encodeURIComponent(s.id)}`, { method: 'DELETE' });
        if (d.ok) shareList(btn, query); else { x.disabled = false; x.textContent = 'Revoke failed'; }
      });
      li.append(x);
      return li;
    }));
  }

  // "Share" button: mints a signed read-only link and copies it.
  async function shareButton(btn, endpoint, query) {
    if (!btn || !(await meP).login) return;
    btn.hidden = false;
    shareList(btn, query);
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        const r = await fetch(endpoint, { method: 'POST' });
        const j = await r.json();
        if (!r.ok) throw new Error(j.detail || r.statusText);
        shareList(btn, query);
        try { await navigator.clipboard.writeText(j.url); btn.textContent = 'Link copied'; }
        catch { prompt('Read-only share link:', j.url); btn.textContent = 'Share read-only link'; }
      } catch (e) { btn.textContent = `Share failed: ${e.message}`; }
      setTimeout(() => { btn.disabled = false; btn.textContent = 'Share read-only link'; }, 2500);
    });
  }

  // ---------------------------------------------------------------- index
  function index() {
    const form = $('submit'), spec = $('spec'), file = $('file'), drop = $('drop'), err = $('err'), go = $('go');
    let picked = null;

    const pick = (f) => {
      picked = f;
      drop.classList.toggle('has-file', !!f);
      $('drop-label').textContent = f ? `${f.name} (${Math.round(f.size / 1024)} KB) — ready` : '…or drop a package: npm .tgz or Python sdist (.tar.gz / .zip)';
      if (f) spec.value = '';
    };
    file.addEventListener('change', () => pick(file.files[0] || null));
    ['dragenter', 'dragover'].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', (ev) => pick(ev.dataTransfer.files[0] || null));
    spec.addEventListener('input', () => { if (spec.value) pick(null); });
    document.querySelectorAll('.chip').forEach((c) => c.addEventListener('click', () => { spec.value = c.dataset.spec; pick(null); spec.focus(); }));

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.textContent = '';
      const body = new FormData();
      if (picked) body.append('file', picked);
      else if (spec.value.trim()) body.append('spec', spec.value.trim());
      else { err.textContent = 'Enter an npm or PyPI package, a PR URL, or drop a package file.'; return; }
      go.disabled = true; go.textContent = 'Starting…';
      try {
        const r = await fetch('/api/runs', { method: 'POST', body });
        const j = await r.json();
        if (!r.ok) throw new Error(j.detail || r.statusText);
        location.href = j.url;
      } catch (e) {
        err.textContent = e.message;
        go.disabled = false; go.textContent = 'Detonate';
      }
    });

    // Runs, a page at a time. The page survives the 5 s refresh; new runs push older ones down.
    const PAGE = 10;
    let page = 0, runs = [];
    const pages = () => Math.max(1, Math.ceil(runs.length / PAGE));
    $('prev').addEventListener('click', () => { page--; render(); });
    $('next').addEventListener('click', () => { page++; render(); });
    let landed = false;
    const load = async () => {
      runs = await (await fetch('/api/runs')).json();
      render();
      if (!landed && location.hash === '#runs-panel') $('runs-panel').scrollIntoView();  // "Runs" in the nav
      landed = true;
    };
    const render = () => {
      page = Math.min(Math.max(page, 0), pages() - 1);
      const tb = $('runs');
      tb.replaceChildren();
      $('empty').hidden = runs.length > 0;
      $('pager').hidden = runs.length <= PAGE;
      $('prev').disabled = page === 0;
      $('next').disabled = page >= pages() - 1;
      $('page-info').textContent = `${page * PAGE + 1}–${Math.min(runs.length, (page + 1) * PAGE)} of ${runs.length}`;
      for (const r of runs.slice(page * PAGE, (page + 1) * PAGE)) {
        const tr = el('tr', 'link');
        const a = el('a', 'mono', r.target); a.href = `/runs/${r.id}`;
        tr.addEventListener('click', (e) => { if (!e.target.closest('a') && !getSelection().toString()) location.href = a.href; });
        const td = (child) => { const c = el('td'); if (child) c.append(child); tr.append(c); };
        td(a);
        td(pill(r.status));
        td(r.verdict ? pill(r.verdict) : el('span', 'muted', '—'));
        td(el('span', r.contained ? 'count-hazard' : '', String(r.contained)));
        td(r.decision ? pill(r.decision) : el('span', '', '—'));
        td(el('span', '', ago(r.created)));
        tb.append(tr);
      }
    };
    load();
    setInterval(load, 5000);

    const last = async () => {
      const t = await (await fetch('/api/selftests/latest')).json();
      const span = $('selftest-last');
      span.replaceChildren();
      if (!t) { span.textContent = 'Not run yet.'; return; }
      const a = el('a', t.done ? (t.passed === t.total ? 'pass' : 'fail') : '',
        t.done ? `Last run: ${t.passed}/${t.total} passed` : `In progress: ${t.passed}/${t.total} passed so far`);
      a.href = `/selftests/${t.id}`;
      span.append(a, el('span', 'muted', ` · ${ago(t.created)}`));
    };
    last();
    setInterval(last, 5000);
    $('selftest-go').addEventListener('click', async (ev) => {
      ev.target.disabled = true;
      $('selftest-err').textContent = '';
      try {
        const r = await fetch('/api/selftests', { method: 'POST' });
        const j = await r.json();
        if (!r.ok) throw new Error(j.detail || r.statusText);
        location.href = j.url;
      } catch (e) {
        $('selftest-err').textContent = e.message;
        ev.target.disabled = false;
      }
    });
  }

  // ---------------------------------------------------------------- self-test
  function selftest() {
    const id = location.pathname.split('/').pop();
    let shareWired = false;
    const load = async () => {
      const t = await (await fetch(`/api/selftests/${id}`)).json();
      const me = await meP;
      if (!shareWired && (me.owner || (me.login && (t.submitted_by || '').toLowerCase() === me.login.toLowerCase()))) {
        shareButton($('share'), `/api/selftests/${id}/share`, `selftest=${encodeURIComponent(id)}`);
        shareWired = true;
      }
      const head = $('score');
      head.className = `verdict-big ${t.done ? (t.passed === t.total ? 'benign' : 'malicious') : 'pending'}`;
      head.textContent = t.done ? `${t.passed}/${t.total} passed` : `Running… ${t.passed}/${t.total} passed so far`;
      $('meta').textContent = `started ${ago(t.created)}${t.submitted_by ? ` by @${t.submitted_by}` : ''}`;
      const tb = $('probes');
      tb.replaceChildren();
      for (const p of t.probes) {
        const tr = el('tr');
        const td = (child) => { const c = el('td'); if (child) c.append(child); tr.append(c); };
        const a = el('a', '', p.label); a.href = `/runs/${p.run_id}`;
        td(a);
        td(pill(p.expect));
        td(p.verdict ? pill(p.verdict) : pill(p.status));
        td(el('span', p.contained ? 'count-hazard' : '', String(p.contained)));
        td(el('span', p.proven ? 'count-hazard' : 'muted', p.proven ? 'PROVEN' : '—'));
        const res = el('td');
        res.append(el('span', `result ${p.result}`, p.result.toUpperCase()), el('div', 'muted small', p.why));
        tr.append(res);
        tb.append(tr);
      }
      if (!t.done) setTimeout(load, 2000);
    };
    load();
  }

  // ---------------------------------------------------------------- run
  function run() {
    const id = location.pathname.split('/').pop();
    const tl = $('timeline');
    const counts = { contain: 0, canary: 0, egress: 0, guard: 0 };
    let t0 = null, runRow = null;

    $('show-exec').addEventListener('change', (e) => document.body.classList.toggle('hide-exec', !e.target.checked));

    const flash = (n) => {
      const row = document.getElementById(`E${n}`);
      if (!row) return;
      if (row.classList.contains('exec')) { $('show-exec').checked = true; document.body.classList.remove('hide-exec'); }
      reveal(row);
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      row.classList.add('flash');
      setTimeout(() => row.classList.remove('flash'), 1600);
    };

    const fact = (label, value) => {
      const li = el('li'); li.append(el('span', '', `${label}: `), el('b', '', value)); $('facts').append(li);
    };

    // Which part of the run an event belongs to, from what the backend records.
    const STAGES = {
      setup: ['Setup', 'Fresh microVM, fake credentials planted, package fetched. Airlock code, no AI.'],
      detonate: ['Detonation', 'The package is installed with the tracer on. Anything it tries shows up here.'],
      agent: ['Agent investigation', 'Commands chosen by the AI reviewer, run inside the same VM.'],
      verdict: ['Verdict', 'The agent\'s conclusion, then the VM is destroyed. A human decides on the right.'],
      decision: ['Decision', 'What was decided, by whom, and what was posted to GitHub.'],
    };
    // Each stage is a collapsible section, like a CI job's steps: the stage in progress is open, and a
    // finished one folds away unless it holds something worth seeing or the reader opened or closed it.
    const HOT = ['error', 'limit_hit', 'coverage_incomplete', 'snapshot_partial', 'guard_flagged', 'citation_invalid'];
    let stage = null, sec = null;
    const stageOf = (ev) => {
      if (ev.kind === 'decision') return 'decision';
      if (['verdict', 'vm_destroyed', 'error'].includes(ev.kind)) return 'verdict';
      if (stage === 'verdict' || stage === 'decision') return 'decision';  // posted after the run
      if (ev.kind === 'agent_start' || ev.kind === 'guard_flagged') return 'agent';
      if (ev.kind === 'behaviour_diff') return 'detonate';
      const src = ev.data.source || ev.data.stage;
      if (src === 'agent') return 'agent';
      if (src === 'detonate') return 'detonate';
      return stage === 'agent' ? 'agent' : 'setup';
    };
    const badges = (s) => {
      const b = [];
      if (s.contained) b.push(el('span', 'badge hot', `${s.contained} contained`));
      if (s.name === 'detonate' && s.done && s.signals === 0) b.push(el('span', 'badge ok', '✓ nothing suspicious'));
      b.push(el('span', 'badge', `${s.events} event${s.events === 1 ? '' : 's'}`));
      if (s.t1 > s.t0) b.push(el('span', 'badge', `${(s.t1 - s.t0).toFixed(1)}s`));
      s.badges.replaceChildren(...b);
    };
    const finishStage = (s) => {
      s.done = true;
      if (s.name === 'detonate' && s.signals === 0) {
        s.ol.append(el('li', 'stage-note', '✓ Nothing suspicious observed during install: no credential reads, no outbound requests, no spawned processes.'));
      }
      if (!s.touched && !s.hot && !['verdict', 'decision'].includes(s.name)) s.details.open = false;
      badges(s);
    };
    const enterStage = (next) => {
      if (next === stage) return;
      if (sec) finishStage(sec);
      stage = next;
      const [title, desc] = STAGES[next];
      const li = el('li', `stage stage-${next}`);
      const details = el('details');
      details.open = true;
      const head = el('summary', 'stage-head');
      const s = { name: next, details, ol: el('ol', 'stage-events'), badges: el('span', 'stage-badges'),
        events: 0, signals: 0, contained: 0, hot: false, touched: false, done: false, t0: null, t1: null };
      head.append(el('span', 'chev'), el('span', 'stage-title', title), el('span', 'stage-desc', desc), s.badges);
      head.addEventListener('click', () => { s.touched = true; });
      details.append(head, s.ol);
      li.append(details);
      tl.append(li);
      sec = s;
    };
    const reveal = (row) => { const d = row.closest('details'); if (d) d.open = true; };

    function addEvent(ev) {
      if (t0 === null) t0 = ev.ts;
      enterStage(stageOf(ev));
      const li = el('li', `ev ${ev.kind}`);
      li.id = `E${ev.id}`;
      const repro = ev.containment && ev.data.stage === 'agent';
      if (ev.containment) li.classList.add('contain');
      if (ev.kind !== 'exec' && ev.kind !== 'behaviour_diff') sec.signals++;
      sec.events++;
      if (sec.t0 === null) sec.t0 = ev.ts;
      sec.t1 = ev.ts;
      if (ev.containment && !repro) { sec.contained++; sec.hot = true; }
      if (HOT.includes(ev.kind) || (ev.kind === 'behaviour_diff' && (ev.data.new || []).length)) sec.hot = true;
      if (repro) li.classList.add('repro');
      if (ev.kind === 'exec') {
        li.classList.add('exec');
        if (ev.data.source === 'agent') li.classList.add('agent');
        if (ev.data.source === 'detonate') li.classList.add('key');
      }
      li.append(el('span', 't', `+${(ev.ts - t0).toFixed(1)}s`), el('span', 'id', `E${ev.id}`));
      const s = el('div');
      s.append(el('span', 'kind', ev.kind.replace(/_/g, ' ')));
      if (ev.kind === 'exec') s.append(el('span', `who ${ev.data.source === 'agent' ? 'ai' : 'sys'}`,
        ev.data.source === 'agent' ? 'AI' : 'AIRLOCK'));
      s.append(el('span', 'sum', ev.summary));
      if (ev.containment) s.append(el('span', 'flag', repro ? 'REPRODUCED BY AGENT' : 'CONTAINED'));
      li.append(s);
      if (ev.kind === 'behaviour_diff') showDiff(li, ev.data);
      if (ev.kind === 'guard_flagged' && ev.data.text) li.append(el('div', 'detail', `“${ev.data.text}”`));
      if (ev.kind === 'canary_exfil') {
        // PROVEN only for a host-captured payload with this run's token; the Node tracer runs in the
        // guest, where the package could forge its log, so its reports are OBSERVED.
        const label = ev.data.proven ? 'PROVEN' : ev.data.source_kind === 'node' ? 'OBSERVED' : 'INFERRED';
        s.append(el('span', `proof ${ev.data.proven ? 'proven' : 'inferred'}`, label));
      }
      if (ev.data.payload) {
        // Captured request body: untrusted text, built with text nodes; canary tokens highlighted.
        const d = el('div', 'detail payload');
        d.append(el('div', 'payload-head', `captured ${ev.data.method || ''} ${ev.data.url || ''} · ${ev.data.bytes || 0} bytes`));
        const pre = el('pre');
        for (const part of String(ev.data.payload).split(/(AIRLOCKCANARY[A-Z0-9]+)/g)) {
          if (!part) continue;
          pre.append(/^AIRLOCKCANARY/.test(part) ? el('mark', '', part) : document.createTextNode(part));
        }
        d.append(pre);
        li.append(d);
      }
      sec.ol.append(li);
      if (sec.hot && !sec.touched) sec.details.open = true;
      badges(sec);

      if (ev.containment && !repro) counts.contain++;
      if (ev.kind === 'canary_read' && !repro) counts.canary++;
      if (ev.kind === 'egress_blocked' && !repro) counts.egress++;
      if (ev.kind === 'guard_flagged') counts.guard++;
      $('n-contain').textContent = counts.contain;
      $('n-canary').textContent = counts.canary;
      $('n-egress').textContent = counts.egress;
      $('n-guard').textContent = counts.guard;

      if (ev.kind === 'vm_created') {
        fact('microVM', ev.summary.replace(/^microVM \S+ /, ''));
        fact('egress', `${ev.data.egress}, allow ${ (ev.data.allow || []).join(', ')}`);
        fact('resources', `${ev.data.cpus} vCPU, ${ev.data.memory_mb} MB`);
        if (ev.data.sinkhole) fact('sinkhole', `${ev.data.sinkhole}: other names get fake addresses answered by Airlock`);
      }
      if (ev.kind === 'canaries_seeded') fact('canaries', (ev.data.files || []).join(', '));
      if (ev.kind === 'agent_start') { $('verdict').textContent = 'Agent investigating…'; fact('agent', ev.data.model); }
      if (ev.kind === 'vm_destroyed') finishStage(sec);
      if (ev.kind === 'verdict') showVerdict(ev.data.verdict, ev.data.evidence || [], ev.data.turns, ev.data.forced);
      if (ev.kind === 'vm_destroyed') fact('lifecycle', 'VM destroyed after run');
    }

    // Base vs head: tag the head's events as new or unchanged, list what's new, offer a filter.
    function showDiff(li, d) {
      li.classList.add('diff');
      if (!d.available) return;
      for (const id of d.new_ids || []) {
        const e = $(`E${id}`);
        if (e && !e.classList.contains('is-new')) {
          e.classList.add('is-new');
          e.querySelector('div').append(el('span', 'flag-new', 'NEW IN THIS PR'));
        }
      }
      for (const id of d.unchanged_ids || []) $(`E${id}`)?.classList.add('is-same');
      const box = el('div', 'detail diff-box');
      const ul = el('ul');
      for (const item of d.new || []) {
        const row = el('li', item.containment ? 'risky' : '');
        row.append(document.createTextNode(item.label + ' '));
        for (const id of (item.ids || []).slice(0, 3)) {
          const a = el('a', 'ref', `[E${id}]`); a.href = `#E${id}`;
          a.addEventListener('click', (e) => { e.preventDefault(); flash(id); });
          row.append(a, document.createTextNode(' '));
        }
        ul.append(row);
      }
      if (!(d.new || []).length) ul.append(el('li', '', 'Nothing new: the head behaves like its merge base.'));
      box.append(ul);
      const pre = (d.unchanged || []).filter((x) => x.containment).length;
      if (pre) box.append(el('p', 'risky', `${pre} risky behaviour${pre > 1 ? 's are' : ' is'} already in the base branch: not introduced by this PR, but still there.`));
      const label = el('label', 'only-new');
      const cb = el('input'); cb.type = 'checkbox';
      cb.addEventListener('change', () => document.body.classList.toggle('only-new', cb.checked));
      label.append(cb, document.createTextNode(` only what this PR adds (hides ${(d.unchanged_ids || []).length} events the base also showed)`));
      box.append(label);
      li.append(box);
    }

    function showVerdict(verdict, evidence, turns, forced) {
      const v = $('verdict');
      v.className = `verdict-big ${verdict}`;
      v.textContent = verdict;
      $('verdict-meta').textContent = turns ? `after ${turns} agent turns${forced ? ' (budget forced)' : ''}` : '';
      const ul = $('evidence');
      ul.replaceChildren();
      for (const point of evidence) {
        const li = el('li');
        // "[E9]" or a list such as "[E11, E12, E15]": each id becomes its own link.
        for (const part of String(point).split(/(\[E\d+(?:,\s*E\d+)*\])/g)) {
          if (!/^\[E\d+(?:,\s*E\d+)*\]$/.test(part)) { if (part) li.append(document.createTextNode(part)); continue; }
          part.slice(1, -1).split(/,\s*/).forEach((ref, i) => {
            if (i) li.append(document.createTextNode(' '));
            const n = ref.slice(1);
            const a = el('a', 'ref', `[${ref}]`); a.href = `#E${n}`;
            a.addEventListener('click', (e) => { e.preventDefault(); flash(n); });
            li.append(a);
          });
        }
        ul.append(li);
      }
    }

    function renderHead(r) {
      runRow = r;
      document.title = `Airlock · ${r.target}`;
      $('target').textContent = r.target;
      const st = $('status');
      st.className = `pill ${r.status}`;
      st.textContent = r.status;
      $('meta').textContent = `run ${r.id}${r.model ? ' · ' + r.model : ''}${r.submitted_by ? ' · by @' + r.submitted_by : ''}`;
      $('live').hidden = !(r.status === 'running' || r.status === 'queued');
      renderPR(r.meta || {});
      renderGate(r);
    }

    function renderPR(m) {
      if (m.kind !== 'pr') return;
      $('pr-panel').hidden = false;
      const b = $('pr');
      b.replaceChildren();
      const a = el('a', 'pr-title', `#${m.number} ${m.title}`); a.href = m.html_url; a.target = '_blank'; a.rel = 'noopener';
      b.append(a, el('div', 'pr-meta', `${m.owner}/${m.repo} · @${m.author} · ${m.head_ref} → ${m.base_ref} · ${String(m.head_sha).slice(0, 7)}`));
      const ul = el('ul', 'pr-files');
      for (const f of (m.files || []).slice(0, 12)) {
        const li = el('li');
        li.append(el('span', `fs ${f.status}`, f.status), el('span', 'mono', f.filename), el('span', 'pr-meta', ` +${f.additions} −${f.deletions}`));
        ul.append(li);
      }
      b.append(ul);
      if (m.posted) {
        const p = el('p', 'pr-posted');
        if (m.posted.comment_url) {
          const l = el('a', '', `Posted to the PR as a comment + "${m.posted.status}" commit status`);
          l.href = m.posted.comment_url; l.target = '_blank'; l.rel = 'noopener';
          p.append(l);
        } else {
          p.textContent = `Posting to GitHub failed after retries: ${m.posted.error}. The PR stays pending until it's posted. `;
          if (!readOnly) {
            const retry = el('button', 'ghost', 'Post again');
            retry.addEventListener('click', async () => {
              retry.disabled = true;
              const resp = await fetch(`/api/runs/${id}/post`, { method: 'POST' });
              if (resp.ok) { renderHead(await resp.json()); return; }
              const err = await resp.json().catch(() => ({}));
              retry.textContent = `Not posted: ${err.detail || resp.statusText}`;
            });
            p.append(retry);
          }
        }
        b.append(p);
      }
    }

    function renderGate(r) {
      const g = $('gate');
      g.replaceChildren();
      const m = r.meta || {};
      const unsynced = m.kind === 'pr' && m.gate && !m.gate.synced;
      const waiting = (m.kind !== 'pr' ? 'Nothing is let through until a human decides.'
        : unsynced ? `GitHub could not be updated, so ${m.owner}/${m.repo}#${m.number} is not held by this run.`
          : `${m.owner}/${m.repo}#${m.number} is held at a pending airlock status, so it can't merge until a human decides.`)
        + ' Waiting for the verdict…';
      if (unsynced && !r.decision) g.append(el('p', 'warn',
        `⚠ Setting the GitHub status failed (${m.gate.error}). The PR keeps any earlier airlock status, which may be a success. Deciding here posts the status again.`));
      const viewOnly = readOnly || (me.login && !me.owner && (r.submitted_by || '').toLowerCase() !== me.login.toLowerCase());
      if (viewOnly && !r.decision) {
        g.append(el('p', '', r.status !== 'done'
          ? waiting
          : readOnly ? 'Read-only shared view. A signed-in reviewer approves or rejects this run.'
            : 'This run belongs to the Airlock team, so only they can approve or reject it. Submit your own run to try the gate.'));
        return;
      }
      if (r.decision) {
        const d = el('div', 'done');
        d.append(pill(r.decision), document.createTextNode(
          ` ${(r.meta || {}).auto_decision ? 'automatically: ' + r.meta.auto_decision + ' · '
            : r.decided_by ? 'by @' + r.decided_by + ' · ' : ''}${new Date(r.decided * 1000).toLocaleString()}`));
        g.append(d);
        if (r.decision_note) g.append(el('p', '', r.decision_note));
        return;
      }
      if (r.status === 'error') { g.append(el('p', '', `Run failed: ${r.error || 'unknown error'}`)); return; }
      if (r.status !== 'done') { g.append(el('p', '', waiting)); return; }
      g.append(el('p', '', r.verdict === 'benign'
        ? 'The agent found nothing harmful. Approve to let this change through.'
        : r.verdict === 'inconclusive'
          ? 'Airlock couldn\'t fully observe this change, so it can\'t be called clean. Reject it, or approve only if you have checked it yourself.'
          : 'The agent found harmful behaviour. Reject to block it, or approve to override.'));
      if ((r.meta || {}).kind === 'pr') g.append(el('p', '',
        `Your decision is posted to ${r.meta.owner}/${r.meta.repo}#${r.meta.number} as the final commit status (it is pending until then) and a comment from the Airlock GitHub App. Proven theft is rejected automatically. Only people with write access to ${r.meta.owner}/${r.meta.repo} on GitHub can decide, here or by commenting /airlock approve or /airlock reject on the PR.`));
      const snap = (r.meta || {}).snapshot;
      if (snap && !snap.complete) g.append(el('p', 'warn',
        `The reviewer saw part of this PR: ${(snap.notes || []).join('; ')}. Install and tests ran on the full head.`));
      const note = el('textarea'); note.placeholder = 'Note (optional)';
      const row = el('div', 'row');
      const refused = el('p', 'warn'); refused.hidden = true;
      const mk = (label, cls, decision) => {
        const b = el('button', cls, label);
        b.addEventListener('click', async () => {
          b.disabled = true;
          const resp = await fetch(`/api/runs/${id}/decision`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, note: note.value }),
          });
          if (resp.ok) { renderHead(await resp.json()); return; }
          b.disabled = false;
          const err = await resp.json().catch(() => ({}));
          refused.textContent = `Not recorded: ${err.detail || resp.statusText}`;
          refused.hidden = false;
        });
        return b;
      };
      const reject = mk('Reject', 'reject', 'rejected'), approve = mk('Approve', 'approve', 'approved');
      row.append(...(r.verdict === 'benign' ? [approve, reject] : [reject, approve]));
      g.append(note, row, refused);
    }

    let readOnly = false, me = {};
    (async () => {
      me = await meP;
      readOnly = !!me.share;
      const first = await (await fetch(`/api/runs/${id}`)).json();
      if (me.owner || (me.login && (first.submitted_by || '').toLowerCase() === me.login.toLowerCase())) {
        shareButton($('share'), `/api/runs/${id}/share`, `run=${encodeURIComponent(id)}`);
      }
      renderHead(first);
      const es = new EventSource(`/api/runs/${id}/events`);
      es.addEventListener('ev', (m) => addEvent(JSON.parse(m.data)));
      es.addEventListener('done', (m) => {
        es.close();
        const r = JSON.parse(m.data);
        renderHead(r);
        if (r.verdict && $('evidence').childElementCount === 0) showVerdict(r.verdict, r.evidence);
      });
      es.onerror = () => { /* EventSource reconnects on its own; replay is idempotent by id */ };
    })();
  }

  return { index, run, selftest };
})();
