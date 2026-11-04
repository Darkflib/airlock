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

  async function user() {
    const nav = $('user');
    if (!nav) return;
    const me = await meP;
    if (me.share) { nav.replaceChildren(el('span', 'muted', 'Shared read-only view')); return; }
    if (!me.login) return;
    nav.append(el('span', 'mono', `@${me.login}`));
    const form = el('form'); form.method = 'post'; form.action = '/auth/logout';
    form.append(el('button', 'ghost', 'Sign out'));
    nav.append(form);
  }
  user();

  // "Share" button: mints a signed read-only link and copies it.
  async function shareButton(btn, endpoint) {
    if (!btn || !(await meP).login) return;
    btn.hidden = false;
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        const r = await fetch(endpoint, { method: 'POST' });
        const j = await r.json();
        if (!r.ok) throw new Error(j.detail || r.statusText);
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
      $('drop-label').textContent = f ? `${f.name} (${Math.round(f.size / 1024)} KB) — ready` : '…or drop a package tarball (.tgz) here';
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
      else { err.textContent = 'Enter an npm package or drop a .tgz.'; return; }
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

    const load = async () => {
      const runs = await (await fetch('/api/runs')).json();
      const tb = $('runs');
      tb.replaceChildren();
      $('empty').hidden = runs.length > 0;
      for (const r of runs) {
        const tr = el('tr');
        const a = el('a', 'mono', r.target); a.href = `/runs/${r.id}`;
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
        shareButton($('share'), `/api/selftests/${id}/share`);
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
    };
    let stage = null, stageSignals = 0;  // non-exec events seen in the current stage
    const stageOf = (ev) => {
      if (['verdict', 'vm_destroyed', 'error'].includes(ev.kind)) return 'verdict';
      if (ev.kind === 'agent_start' || ev.kind === 'guard_flagged') return 'agent';
      const src = ev.data.source || ev.data.stage;
      if (src === 'agent') return 'agent';
      if (src === 'detonate') return 'detonate';
      return stage === 'agent' ? 'agent' : 'setup';
    };
    const enterStage = (next) => {
      if (next === stage) return;
      if (stage === 'detonate' && stageSignals === 0) {
        tl.append(el('li', 'stage-note', '✓ Nothing suspicious observed during install: no credential reads, no outbound requests, no spawned processes.'));
      }
      stage = next;
      stageSignals = 0;
      const [title, desc] = STAGES[next];
      const h = el('li', `stage-head stage-${next}`);
      h.append(el('span', 'stage-title', title), el('span', 'stage-desc', desc));
      tl.append(h);
    };

    function addEvent(ev) {
      if (t0 === null) t0 = ev.ts;
      enterStage(stageOf(ev));
      const li = el('li', `ev ${ev.kind}`);
      li.id = `E${ev.id}`;
      const repro = ev.containment && ev.data.stage === 'agent';
      if (ev.containment) li.classList.add('contain');
      if (ev.kind !== 'exec') stageSignals++;
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
      tl.append(li);

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
      if (ev.kind === 'verdict') showVerdict(ev.data.verdict, ev.data.evidence || [], ev.data.turns, ev.data.forced);
      if (ev.kind === 'vm_destroyed') fact('lifecycle', 'VM destroyed after run');
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
        for (const part of String(point).split(/(\[E\d+\])/g)) {
          const m = part.match(/^\[E(\d+)\]$/);
          if (m) {
            const a = el('a', 'ref', part); a.href = `#E${m[1]}`;
            a.addEventListener('click', (e) => { e.preventDefault(); flash(m[1]); });
            li.append(a);
          } else if (part) li.append(document.createTextNode(part));
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
        } else p.textContent = `Posting to GitHub failed: ${m.posted.error}`;
        b.append(p);
      }
    }

    function renderGate(r) {
      const g = $('gate');
      g.replaceChildren();
      const waiting = ((r.meta || {}).kind === 'pr'
        ? `${r.meta.owner}/${r.meta.repo}#${r.meta.number} is held at a pending airlock status, so it can't merge until a human decides.`
        : 'Nothing is let through until a human decides.') + ' Waiting for the verdict…';
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
          ` ${r.decided_by ? 'by @' + r.decided_by + ' · ' : ''}${new Date(r.decided * 1000).toLocaleString()}`));
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
        `Your decision is posted to ${r.meta.owner}/${r.meta.repo}#${r.meta.number} as the final commit status (it is pending until then) and a comment from the Airlock GitHub App.`));
      const note = el('textarea'); note.placeholder = 'Note (optional)';
      const row = el('div', 'row');
      const mk = (label, cls, decision) => {
        const b = el('button', cls, label);
        b.addEventListener('click', async () => {
          b.disabled = true;
          const resp = await fetch(`/api/runs/${id}/decision`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, note: note.value }),
          });
          if (resp.ok) renderHead(await resp.json()); else b.disabled = false;
        });
        return b;
      };
      const reject = mk('Reject', 'reject', 'rejected'), approve = mk('Approve', 'approve', 'approved');
      row.append(...(r.verdict === 'benign' ? [approve, reject] : [reject, approve]));
      g.append(note, row);
    }

    let readOnly = false, me = {};
    (async () => {
      me = await meP;
      readOnly = !!me.share;
      const first = await (await fetch(`/api/runs/${id}`)).json();
      if (me.owner || (me.login && (first.submitted_by || '').toLowerCase() === me.login.toLowerCase())) {
        shareButton($('share'), `/api/runs/${id}/share`);
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
