'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { RULES, FALLBACK } = require('./guard-rules.js');

const MAX_INPUT_BYTES = 100 * 1024;
const MAX_SEGMENTS = 3000;

const RANK = { allow: 0, allowlog: 1, ask: 2, deny: 3 };
const TIER_RANK = { allow: 0, allowlog: 1, ask: 2, block: 3 };

function normRoot(p) {
  let v = String(p).replace(/^['"]|['"]$/g, '');
  v = v.replace(/\\/g, '/').toLowerCase();
  v = v.replace(/^\/([a-z])\//, '$1:/');
  v = v.replace(/\/+$/, '');
  return v;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function loadConfig() {
  const empty = { protectedRoots: [], safeRoots: [] };
  try {
    const custom = process.env.DESTRUCTIVE_GUARD_CONFIG;
    const file = custom && custom.trim()
      ? custom.trim()
      : path.join(os.homedir(), '.claude', 'guard-config.json');
    const raw = fs.readFileSync(file, 'utf8');
    const cfg = JSON.parse(raw);
    const list = (v) => (Array.isArray(v) ? v : [])
      .filter((x) => typeof x === 'string' && x.trim())
      .map(normRoot)
      .filter((r) => r && r !== '/' && !/^[a-z]:?$/.test(r));
    return { protectedRoots: list(cfg.protectedRoots), safeRoots: list(cfg.safeRoots) };
  } catch (_) {
    return empty;
  }
}

const CONFIG = loadConfig();
const HOME = normRoot(os.homedir());
const HOME_RE = HOME ? new RegExp('^' + escapeRe(HOME) + '(?:\\/[^\\/]+)?\\/?$') : null;

const DEFAULT_PROTECTED = [
  '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot',
  '/dev', '/proc', '/sys', '/var', '/opt', '/root',
  'c:/windows', 'c:/programdata',
];

function normalizeSegment(s) {
  let t = String(s).trim();
  while (t.length > 1 &&
    ((t[0] === '"' && t[t.length - 1] === '"') ||
     (t[0] === "'" && t[t.length - 1] === "'") ||
     (t[0] === '`' && t[t.length - 1] === '`'))) {
    t = t.slice(1, -1).trim();
  }
  t = t.replace(/\s+/g, ' ');
  t = t.replace(/(^|[\s;&|(])\/(?:usr\/)?(?:local\/)?s?bin\//g, '$1');
  return t;
}

const MAX_INNER_PER_KIND = 200;

function extractInner(text) {
  const inners = [];
  const push = (v) => { if (v && v.trim()) inners.push(v); };
  const stripQuote = (v) => {
    const m = String(v).match(/^\s*(["'])([\s\S]*)\1\s*$/);
    return m ? m[2] : v;
  };
  const reInterp = /\b(?:bash|sh|zsh|dash|python3?|node|nodejs|perl|ruby|php|powershell|pwsh)\b(?:\s+-\w+)*\s+(?:-c|-e|-command|--command)\s+("(?:[^"\\]|\\.)*"|'(?:[^']|\\.)*'|\S+)/gi;
  const reCmd = /\bcmd(?:\.exe)?\s+\/[ck]\s+("[^"]*"|'[^']*'|[^\n]+)/gi;
  const reHeredoc = /<<-?\s*['"]?(\w+)['"]?\s*\n([\s\S]*?)\n\s*\1\b/g;
  const reDollar = /\$\(([\s\S]*?)\)/g;
  const reBack = /`([^`]*)`/g;
  const scan = (re, group) => {
    let m; let n = 0;
    while (n++ < MAX_INNER_PER_KIND && (m = re.exec(text))) push(group === 2 ? m[2] : stripQuote(m[1]));
  };
  scan(reInterp, 1);
  scan(reCmd, 1);
  scan(reHeredoc, 2);
  scan(reDollar, 1);
  scan(reBack, 1);
  return inners;
}

function collect(text, depth, out) {
  const whole = normalizeSegment(text);
  if (whole) out.push(whole);
  for (const piece of String(text).split(/&&|\|\||;|\n|\|/)) {
    const n = normalizeSegment(piece);
    if (n && n !== whole) out.push(n);
    if (out.length > MAX_SEGMENTS) throw new Error('segment explosion');
  }
  if (depth > 0) {
    for (const inner of extractInner(text)) {
      collect(inner, depth - 1, out);
      if (out.length > MAX_SEGMENTS) throw new Error('segment explosion');
    }
  }
}

function cleanTarget(t) {
  let v = String(t).replace(/^['"]|['"]$/g, '');
  v = v.replace(/\\/g, '/').toLowerCase();
  v = v.replace(/^\/([a-z])\//, '$1:/');
  return v;
}

function isDangerTarget(t) {
  if (['~', '/', '..', '*', '.', '~/', '/*', '~/*', './'].includes(t)) return true;
  if (/^[a-z]:\/?$/.test(t)) return true;
  if (/(^|\/)\.\.(\/|$)/.test(t)) return true;
  if (/(^|\/)\*(\/|$)/.test(t) || t.endsWith('/*')) return true;
  if (/(^|\/)\.(claude|codex|ssh|git|gnupg|aws)(\/|$)/.test(t)) return true;
  if (HOME_RE && HOME_RE.test(t)) return true;
  for (const root of DEFAULT_PROTECTED) {
    if (t === root || t.startsWith(root + '/')) return true;
  }
  for (const root of CONFIG.protectedRoots) {
    if (root && (t === root || t.startsWith(root + '/'))) return true;
  }
  return false;
}

function isSafeTarget(t) {
  if (/[$`]/.test(t) || /%[^%\s]*%/.test(t)) return false;
  for (const root of CONFIG.safeRoots) {
    if (root && (t === root || t.startsWith(root + '/'))) return true;
  }
  if (/\/appdata\/local\/temp\//.test(t)) return true;
  if (/(^|\/)tmp(\/|$)/.test(t)) return true;
  if (/^\/tmp\//.test(t)) return true;
  if (/(^|\/)(node_modules|\.next-prod|\.next|dist|build|__pycache__|\.cache)(\/|$)/.test(t)) return true;
  if (!/^([a-z]:|\/|~)/.test(t) && !t.includes('..') && !t.includes('*')) return true;
  return false;
}

function classifyTargets(targets) {
  if (!targets.length) return 'ask';
  let anyDanger = false;
  let allSafe = true;
  for (const t of targets) {
    if (isDangerTarget(t)) anyDanger = true;
    else if (!isSafeTarget(t)) allSafe = false;
  }
  if (anyDanger) return 'block';
  if (allSafe) return 'allow';
  return 'ask';
}

function deleteTargets(seg) {
  const m = seg.match(/\b(?:rm|rimraf|remove-item|ri|del|erase|rd|rmdir)\b(.*)$/i);
  if (!m) return [];
  const rest = m[1].split(/[|&;><]/)[0];
  return rest.trim().split(/\s+/)
    .filter(Boolean)
    .filter((t) => !/^-/.test(t) && !/^\/[a-z]$/i.test(t))
    .map(cleanTarget);
}

function isFsDeleteCommand(seg) {
  if (/\brm\b[^|&;]*\s-\w*r/i.test(seg)) return true;
  if (/\brm\b[^|&;]*--recursive\b/i.test(seg)) return true;
  if (/\brimraf\b/i.test(seg) && deleteTargets(seg).length > 0) return true;
  if (/\b(?:remove-item|ri)\b[^|]*\s-r(?:ecurse)?\b/i.test(seg)) return true;
  if (/\b(?:del|erase)\b[^|]*\s\/s\b/i.test(seg)) return true;
  if (/\b(?:rd|rmdir)\b[^|]*\s\/s\b/i.test(seg)) return true;
  if (/\brm\s+(?:-\S+\s+)*(?:\/|~|\*|\.\.)(?:\s|$)/i.test(seg)) return true;
  return false;
}

function inScriptDelete(seg) {
  const pats = [
    /\bshutil\.rmtree\s*\(\s*([^),]*)/i,
    /\bos\.removeall\s*\(\s*([^),]*)/i,
    /\bfs\.rm(?:sync|dirsync)?\s*\(\s*([^,)]*)/i,
    /require\(\s*['"](?:node:)?fs['"]\s*\)\.rm(?:sync|dirsync)?\s*\(\s*([^,)]*)/i,
    /\bfileutils\.rm_rf\s*\(?\s*([^)\s]*)/i,
    /\brimraf(?:\.sync)?\s*\(\s*([^,)]*)/i,
    /require\(\s*['"]rimraf['"]\s*\)(?:\.\w+)?\s*\(\s*([^,)]*)/i,
  ];
  for (const p of pats) {
    const m = seg.match(p);
    if (m) {
      const arg = (m[1] || '').trim();
      const lit = arg.match(/^['"]([^'"]*)['"]/);
      if (lit) return classifyTargets([cleanTarget(lit[1])]);
      return 'ask';
    }
  }
  return null;
}

function isForcePush(seg) {
  if (!/\bgit\s+push\b/i.test(seg)) return false;
  return /--force(?:-with-lease)?\b/i.test(seg) || /\s-f\b/i.test(seg) || /\s\+[\w.\/-]+/.test(seg);
}

function forcePushHitsProtected(seg) {
  const m = seg.match(/\bgit\s+push\b(.*)$/i);
  if (!m) return false;
  const toks = m[1].split(/[|&;]/)[0].trim().split(/\s+/).filter(Boolean).filter((t) => !/^-/.test(t));
  for (const t of toks) {
    let dst = t.includes(':') ? t.split(':').pop() : t;
    dst = dst.replace(/^\+/, '').replace(/^refs\/heads\//i, '');
    if (/^(?:main|master|head)$/i.test(dst)) return true;
  }
  return false;
}

function isBranchDelete(seg) {
  if (!/\bgit\s+push\b/i.test(seg)) return false;
  return /(?:--delete\b|\s-d\b)/i.test(seg) || /\s:[\w./-]+/.test(seg);
}

function gitDecision(seg) {
  if (isForcePush(seg) || isBranchDelete(seg)) {
    const del = isBranchDelete(seg) && !isForcePush(seg);
    return forcePushHitsProtected(seg)
      ? { rank: RANK.deny, decision: 'deny', ruleId: del ? 'git_delete_protected_branch' : 'git_force_push_protected', note: del ? 'delete of a default branch (main/master/HEAD)' : 'force push to a default branch (main/master/HEAD)' }
      : { rank: RANK.ask, decision: 'ask', ruleId: del ? 'git_delete_branch' : 'git_force_push_branch', note: del ? 'delete of a named remote branch' : 'force push to a named branch' };
  }
  if (/\bgit\s+reset\s+--hard\b/i.test(seg)) return { rank: RANK.ask, decision: 'ask', ruleId: 'git_reset_hard', note: 'git reset --hard discards local work' };
  if (/\bgit\s+clean\s+-\S*f/i.test(seg)) return { rank: RANK.ask, decision: 'ask', ruleId: 'git_clean_force', note: 'git clean -f deletes untracked files' };
  if (/\bgit\s+(?:filter-branch|filter-repo)\b/i.test(seg)) return { rank: RANK.ask, decision: 'ask', ruleId: 'git_filter', note: 'git history rewrite' };
  if (/\bgit\s+reflog\s+expire\b/i.test(seg)) return { rank: RANK.ask, decision: 'ask', ruleId: 'git_reflog_expire', note: 'reflog expire destroys recovery points' };
  if (/\bgit\s+gc\b[\s\S]*--prune/i.test(seg)) return { rank: RANK.ask, decision: 'ask', ruleId: 'git_gc_prune', note: 'gc --prune drops unreachable objects' };
  if (/\bgit\s+remote\s+(?:rm|remove)\b/i.test(seg)) return { rank: RANK.ask, decision: 'ask', ruleId: 'git_remote_remove', note: 'removes a git remote' };
  return null;
}

function escalate(best, cand) {
  return cand && cand.rank > best.rank ? cand : best;
}

const DB_CLIENT_CMDS = new Set(['mysql', 'mariadb', 'psql', 'sqlite', 'sqlite3', 'sqlcmd', 'mongo', 'mongosh', 'clickhouse-client', 'cockroach']);
const SQL_FLAG_RE = {
  mysql: '(?:--execute|-e)',
  mariadb: '(?:--execute|-e)',
  psql: '(?:--command|-c)',
  sqlcmd: '(?:-Q|-q)',
  'clickhouse-client': '(?:--query|-q)',
  mongosh: '(?:--eval)',
  mongo: '(?:--eval)',
  cockroach: '(?:--execute|-e)',
};

const WRAPPER_ARG_OPTS = {
  sudo: /^-[uUgpCcrtThRD]$/,
  doas: /^-[uC]$/,
  env: /^-[uCS]$/,
  nice: /^-n$/,
  time: /^-[of]$/,
  nohup: /^$/,
  command: /^$/,
  exec: /^-a$/,
};
const WRAP_LONG_ARG = /^--(?:user|group|prompt|role|type|host|chroot|adjustment|unset|chdir|close-from|format|output)$/i;

function consumeWrapperOpts(toks, i, wrapper) {
  const argOpt = WRAPPER_ARG_OPTS[wrapper] || /^$/;
  while (i < toks.length) {
    const o = toks[i];
    if (/^[\w.]+=/.test(o)) { i++; continue; }
    if (!/^-/.test(o) || o === '-') break;
    if (o === '--') { i++; break; }
    if (/^--/.test(o)) { i += (!o.includes('=') && WRAP_LONG_ARG.test(o)) ? 2 : 1; continue; }
    const cluster = o.slice(1);
    let consumed = false;
    for (let k = 0; k < cluster.length; k++) {
      if (argOpt.test('-' + cluster[k])) { i += (k === cluster.length - 1) ? 2 : 1; consumed = true; break; }
    }
    if (!consumed) i += 1;
  }
  return i;
}

function leadingCmd(seg) {
  const toks = seg.trim().split(/\s+/);
  const bn = (t) => t.replace(/^.*[/\\]/, '').toLowerCase();
  let i = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (/^[\w.]+=/.test(t)) { i++; continue; }
    const b = bn(t);
    if (Object.prototype.hasOwnProperty.call(WRAPPER_ARG_OPTS, b)) { i = consumeWrapperOpts(toks, i + 1, b); continue; }
    return b;
  }
  return '';
}

function sqlPayloads(seg) {
  const out = [];
  const bareDelete = /^\s*delete\b/i.test(seg);
  const cmd = leadingCmd(seg);
  const isClient = DB_CLIENT_CMDS.has(cmd);
  if (!bareDelete && !isClient) return out;
  const unquote = (v) => v.replace(/^['"]|['"]$/g, '');
  if (isClient) {
    if (/^sqlite3?$/.test(cmd)) {
      const qre = /("(?:[^"\\]|\\.)*"|'(?:[^']|\\.)*')/g;
      let qm; let qn = 0;
      while (qn++ < 50 && (qm = qre.exec(seg))) out.push(unquote(qm[1]));
    } else if (SQL_FLAG_RE[cmd]) {
      const re = new RegExp(SQL_FLAG_RE[cmd] + '\\s*=?\\s*("(?:[^"\\\\]|\\\\.)*"|\'(?:[^\']|\\\\.)*\'|[^\\s"\']\\S*)', 'gi');
      let m; let n = 0;
      while (n++ < 50 && (m = re.exec(seg))) out.push(unquote(m[1]));
    }
  }
  if (bareDelete) out.push(seg);
  return out;
}

function matchSegment(seg) {
  let best = { rank: RANK.allow, decision: 'allow' };

  if (isFsDeleteCommand(seg)) {
    const c = classifyTargets(deleteTargets(seg));
    if (c === 'block') best = escalate(best, { rank: RANK.deny, decision: 'deny', ruleId: 'fs_recursive_delete_protected', note: 'recursive delete of a protected path' });
    else if (c === 'ask') best = escalate(best, { rank: RANK.ask, decision: 'ask', ruleId: 'fs_recursive_delete_unknown', note: 'recursive delete outside a known-safe zone' });
  }

  const ins = inScriptDelete(seg);
  if (ins === 'block') best = escalate(best, { rank: RANK.deny, decision: 'deny', ruleId: 'api_recursive_delete_protected', note: 'in-script recursive delete of a protected path' });
  else if (ins === 'ask') best = escalate(best, { rank: RANK.ask, decision: 'ask', ruleId: 'api_recursive_delete_unknown', note: 'in-script recursive delete outside a known-safe zone' });

  const g = gitDecision(seg);
  if (g) best = escalate(best, g);

  for (const p of sqlPayloads(seg)) {
    const sql = p
      .replace(/\/\*[^*]*\*+(?:[^/*][^*]*\*+)*\//g, ' ')
      .replace(/--[ \t][^\n]*/g, ' ')
      .replace(/#[^\n]*/g, ' ')
      .replace(/\$\$[\s\S]*?\$\$/g, ' ')
      .replace(/'[^']*'/g, ' ')
      .replace(/"[^"]*"/g, ' ');
    if (/\bdelete\s+from\b/i.test(sql) && !/\bwhere\b/i.test(sql)) {
      best = escalate(best, { rank: RANK.deny, decision: 'deny', ruleId: 'db_delete_no_where', note: 'DELETE FROM without a WHERE clause' });
      break;
    }
  }

  for (const r of RULES) {
    if (r.pattern.test(seg)) {
      best = escalate(best, { rank: TIER_RANK[r.tier], decision: r.tier === 'block' ? 'deny' : (r.tier === 'ask' ? 'ask' : 'allow'), ruleId: r.id, note: r.note, log: r.tier === 'allowlog' });
    }
  }

  return best;
}

function analyze(command) {
  const segs = [];
  collect(command, 1, segs);
  const full = normalizeSegment(command);
  let best = { rank: RANK.allow, decision: 'allow' };
  for (const s of segs) best = escalate(best, matchSegment(s));
  if (best.decision !== 'deny' && /\bgit\s+reset\s+--hard\b/i.test(full) && /\bgit\s+push\b/i.test(full)) {
    best = { rank: RANK.deny, decision: 'deny', ruleId: 'git_reset_hard_and_push', note: 'reset --hard combined with a push rewrites shared history' };
  }
  return best;
}

function fallbackMatch(command) {
  for (const r of FALLBACK) {
    if (r.pattern.test(command)) return r;
  }
  return null;
}

function evaluate(command) {
  try {
    if (typeof command !== 'string') throw new Error('no command');
    if (Buffer.byteLength(command, 'utf8') > MAX_INPUT_BYTES) throw new Error('oversized');
    return analyze(command);
  } catch (e) {
    try {
      const fb = fallbackMatch(String(command || '').slice(0, MAX_INPUT_BYTES));
      if (fb) return { rank: RANK.deny, decision: 'deny', ruleId: fb.id, note: fb.note };
    } catch (_) { void 0; }
    return { rank: RANK.deny, decision: 'deny', ruleId: 'guard-internal-error', note: 'guard-internal-error (fail-closed)' };
  }
}

function redactForLog(s) {
  return String(s)
    .replace(/(--?(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|auth)[=\s:]+)\S+/gi, '$1***')
    .replace(/(authorization:\s*bearer\s+)\S+/gi, '$1***');
}

function logDecision(result, command) {
  try {
    const dir = path.join(os.homedir(), '.claude', 'automation');
    fs.mkdirSync(dir, { recursive: true });
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      decision: result.decision,
      ruleId: result.ruleId || null,
      sha256: crypto.createHash('sha256').update(String(command || '')).digest('hex'),
      cmd: redactForLog(String(command || '')).slice(0, 120),
    });
    fs.appendFileSync(path.join(dir, 'guard-log.jsonl'), line + '\n');
  } catch (_) { void 0; }
}

function reasonText(result) {
  const id = result.ruleId ? ' [' + result.ruleId + ']' : '';
  if (result.decision === 'deny') {
    return 'Blocked by destructive-command-guard' + id + ': ' + (result.note || 'destructive command') +
      '. If this is genuinely intended and safe, run it yourself outside the agent, or narrow the target to a known-safe path.';
  }
  return 'destructive-command-guard flagged this for confirmation' + id + ': ' + (result.note || 'potentially destructive command') + '.';
}

function emit(result) {
  console.log(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: result.decision === 'deny' ? 'deny' : 'ask',
      permissionDecisionReason: reasonText(result),
    },
  }));
}

if (require.main === module) {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => (input += d));
  process.stdin.on('end', () => {
    let command;
    let result;
    try {
      const payload = JSON.parse(input);
      const toolName = String(payload.tool_name || '');
      const hasCommand = typeof (payload.tool_input || {}).command === 'string';
      const shellish = /^(bash|shell|local_shell)$/i.test(toolName) || (!toolName && hasCommand);
      if (!shellish) { process.exit(0); }
      command = (payload.tool_input || {}).command;
      result = evaluate(command);
    } catch (e) {
      result = { decision: 'deny', ruleId: 'guard-internal-error', note: 'guard-internal-error (fail-closed)' };
    }
    if (result.decision !== 'allow' || result.log) logDecision(result, command);
    if (result.decision === 'allow') { process.exit(0); }
    try {
      emit(result);
      process.exit(0);
    } catch (_) {
      try { process.stderr.write(reasonText(result)); } catch (__) { void 0; }
      process.exit(2);
    }
  });
}

module.exports = { evaluate, analyze, fallbackMatch, matchSegment, classifyTargets };
