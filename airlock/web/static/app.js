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

    function addEvent(ev) {
      if (t0 === null) t0 = ev.ts;
      const li = el('li', `ev ${ev.kind}`);
      li.id = `E${ev.id}`;
      const repro = ev.containment && ev.data.stage === 'agent';
      if (ev.containment) li.classList.add('contain');
      if (repro) li.classList.add('repro');
      if (ev.kind === 'exec') {
        li.classList.add('exec');
        if (ev.data.source === 'agent') li.classList.add('agent');
      }
      li.append(el('span', 't', `+${(ev.ts - t0).toFixed(1)}s`), el('span', 'id', `E${ev.id}`));
      const s = el('div');
      s.append(el('span', 'kind', ev.kind.replace(/_/g, ' ')), el('span', 'sum', ev.summary));
      if (ev.containment) s.append(el('span', 'flag', repro ? 'REPRODUCED BY AGENT' : 'CONTAINED'));
      li.append(s);
      if (ev.kind === 'guard_flagged' && ev.data.text) li.append(el('div', 'detail', `“${ev.data.text}”`));
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
      $('meta').textContent = `run ${r.id}${r.model ? ' · ' + r.model : ''}`;
      $('live').hidden = !(r.status === 'running' || r.status === 'queued');
      renderGate(r);
    }

    function renderGate(r) {
      const g = $('gate');
      g.replaceChildren();
      if (r.decision) {
        const d = el('div', 'done');
        d.append(pill(r.decision), document.createTextNode(` ${new Date(r.decided * 1000).toLocaleString()}`));
        g.append(d);
        if (r.decision_note) g.append(el('p', '', r.decision_note));
        return;
      }
      if (r.status === 'error') { g.append(el('p', '', `Run failed: ${r.error || 'unknown error'}`)); return; }
      if (r.status !== 'done') { g.append(el('p', '', 'Nothing leaves Airlock until a human decides. Waiting for the verdict…')); return; }
      g.append(el('p', '', r.verdict === 'benign'
        ? 'The agent found nothing harmful. Approve to let this change through.'
        : 'The agent found harmful behaviour. Reject to block it, or approve to override.'));
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

    (async () => {
      renderHead(await (await fetch(`/api/runs/${id}`)).json());
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

  return { index, run };
})();
