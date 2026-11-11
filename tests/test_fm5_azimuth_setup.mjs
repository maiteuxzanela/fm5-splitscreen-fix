#!/usr/bin/env node
/**
 * test_fm5_azimuth_setup.mjs — Suíte determinística do setup FM5 + Azimuth.
 *
 * Escopo (SDET, sem mocks):
 *   1. Estrutura extraída da build 1.0.0.20 (era.vbi, Mount/, EmbeddedXvd/, assets)
 *   2. Integridade do wrapper oficial Azimuth (sha256 do binário, payload data/)
 *   3. Launcher run_fm5_azimuth.sh (permissão, sintaxe bash, --check/--dry-run/--list-runners)
 *   4. Runner Proton + prefixo Wine/Proton reais e ausência de processos órfãos
 *   5. Paridade byte-a-byte de NOMES+TAMANHOS contra o RAR oficial (3295 arquivos / 172 dirs)
 *      e CRC32 de arquivos-chave contra o CRC armazenado no RAR.
 *   6. Sensibilidade por mutação: sandbox temporária prova que --check REPROVA
 *      estrutura incompleta/versão errada e que o trap mata a árvore de processos.
 *
 * Execução: node --test tests/test_fm5_azimuth_setup.mjs
 */
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import zlib from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const GAME = path.join(ROOT, 'Game');
const LAUNCHER = path.join(ROOT, 'run_fm5_azimuth.sh');
const RAR = '/mnt/94CCB337CCB3130A/downloads/(Forza Motorsport 5) Forza_1.0.0.20_x64__8wekyb3d8bbwe.rar';
const RAR_PREFIX = 'Forza_1.0.0.20_x64__8wekyb3d8bbwe/';
const RUNNER = '/mnt/94CCB337CCB3130A/LinuxAppsData/heroic_tools/proton/GE-Proton-latest';
const PREFIX_PFX = '/mnt/94CCB337CCB3130A/LinuxAppsData/ForzaMotorsport5/prefix/pfx';

const ERA_SIZE = 9031680;
const ERA_MAGIC = Buffer.from('31494256', 'hex'); // "1IBV" (magic VBI/XVD little-endian)
const GAME_EXE_SIZE = 39317504;
const AZIMUTH_SIZE = 8613376;
const AZIMUTH_SHA256 = '56d2c9cb6ccf3ae1836dee9676b64285f3a247efa2d12cf02c6c742696b3b092';
const PIPELINES_SIZE = 11389290;
const BUILD = '1.0.0.20';
const EXPECTED_FILES = 3295;
const EXPECTED_DIRS = 172;

const read = (p) => fs.readFileSync(p);
const exists = (p) => fs.existsSync(p);
const isExec = (p) => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } };

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 64 * 1024 * 1024, ...opts });
}

function walk(dir) {
  const files = new Map();
  const dirs = new Set();
  const stack = [[dir, '']];
  while (stack.length) {
    const [abs, rel] = stack.pop();
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      const a = path.join(abs, e.name);
      if (e.isDirectory()) { dirs.add(r); stack.push([a, r]); }
      else if (e.isFile()) { files.set(r, fs.statSync(a).size); }
    }
  }
  return { files, dirs };
}

function parse7zListing(stdout) {
  const out = [];
  let cur = null;
  for (const line of stdout.split('\n')) {
    if (line.startsWith('Path = ')) {
      if (cur) out.push(cur);
      cur = { path: line.slice(7) };
    } else if (cur && line.includes(' = ')) {
      const i = line.indexOf(' = ');
      cur[line.slice(0, i)] = line.slice(i + 3);
    }
  }
  if (cur) out.push(cur);
  const files = new Map();
  const dirs = new Set();
  for (const r of out) {
    const p = r.path;
    if (!p.startsWith(RAR_PREFIX)) continue;
    const rel = p.slice(RAR_PREFIX.length);
    if (!rel) continue;
    if (r.Folder === '+') dirs.add(rel.replace(/\/$/, ''));
    else files.set(rel, Number(r.Size));
  }
  return { files, dirs, records: out };
}

const crc32 = (file) => {
  const buf = read(file);
  return (zlib.crc32(buf) >>> 0).toString(16).toUpperCase().padStart(8, '0');
};

// ---------------------------------------------------------------------------
describe('1. Estrutura da build Xbox One 1.0.0.20', () => {
  test('era.vbi presente, tamanho e magic "1IBV"', () => {
    const p = path.join(GAME, 'era.vbi');
    assert.ok(exists(p), `ausente: ${p}`);
    assert.equal(fs.statSync(p).size, ERA_SIZE);
    assert.deepEqual(read(p).subarray(0, 4), ERA_MAGIC);
  });

  test('nós mandatórios Mount/ e EmbeddedXvd/ são diretórios', () => {
    for (const d of ['Mount', 'EmbeddedXvd']) {
      const p = path.join(GAME, d);
      assert.ok(exists(p) && fs.statSync(p).isDirectory(), `ausente/não-dir: ${p}`);
    }
  });

  test('AppxManifest.xml declara Identity Version 1.0.0.20', () => {
    const p = path.join(GAME, 'Mount', 'AppxManifest.xml');
    assert.ok(exists(p), `ausente: ${p}`);
    const xml = read(p).toString('utf8');
    assert.match(xml, /<Identity\b[^>]*\bVersion="1\.0\.0\.20"/);
  });

  test('executável do jogo presente, PE (MZ) e tamanho exato', () => {
    const p = path.join(GAME, 'Mount', 'forza_durango_release_final.exe');
    assert.ok(exists(p), `ausente: ${p}`);
    assert.equal(fs.statSync(p).size, GAME_EXE_SIZE);
    assert.equal(read(p).subarray(0, 2).toString('latin1'), 'MZ');
  });

  test('assets mandatórios presentes (media/, Resources.pri, hash.manifest, Xbox DLLs, EmbeddedXvd/Windows)', () => {
    const must = [
      'Mount/media',
      'Mount/media/ui',
      'Mount/media/tracks',
      'Mount/media/cars',
      'Mount/media/UI.zip',
      'Mount/Resources.pri',
      'Mount/hash.manifest',
      'Mount/Microsoft.Xbox.Services.dll',
      'Mount/Microsoft.Xbox.Input.Wheel.dll',
      'Mount/networkmanifest.xml',
      'EmbeddedXvd/Windows/System32',
      'EmbeddedXvd/Users/Default/NTUSER.DAT',
    ];
    for (const rel of must) assert.ok(exists(path.join(GAME, rel)), `ausente: Game/${rel}`);
    assert.ok(fs.statSync(path.join(GAME, 'Mount', 'media')).isDirectory());
  });

  test(`contagem extraída = ${EXPECTED_FILES} arquivos / ${EXPECTED_DIRS} diretórios`, () => {
    const { files, dirs } = walk(GAME);
    assert.equal(files.size, EXPECTED_FILES);
    assert.equal(dirs.size, EXPECTED_DIRS);
    const total = [...files.values()].reduce((a, b) => a + b, 0);
    assert.ok(total > 40e9, `total extraído baixo: ${total}`);
  });
});

// ---------------------------------------------------------------------------
describe('2. Wrapper oficial Azimuth 1.0.4', () => {
  test('azimuth.exe com sha256 oficial e assinatura PE', () => {
    const p = path.join(ROOT, 'azimuth.exe');
    assert.ok(exists(p), `ausente: ${p}`);
    assert.equal(fs.statSync(p).size, AZIMUTH_SIZE);
    const sha = createHash('sha256').update(read(p)).digest('hex');
    assert.equal(sha, AZIMUTH_SHA256);
    assert.equal(read(p).subarray(0, 2).toString('latin1'), 'MZ');
  });

  test('payload data/ completo (pipelines + DLLs de runtime)', () => {
    const pipelines = path.join(ROOT, 'data', 'bin', 'azimuth.pipelines');
    assert.ok(exists(pipelines), `ausente: ${pipelines}`);
    assert.equal(fs.statSync(pipelines).size, PIPELINES_SIZE);
    for (const dll of ['vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'avcodec-62.dll', 'avutil-60.dll']) {
      assert.ok(exists(path.join(ROOT, 'data', 'bin', dll)), `DLL ausente: ${dll}`);
    }
    assert.ok(exists(path.join(ROOT, 'data', 'azimuth.ini')));
    assert.ok(exists(path.join(ROOT, 'data', 'licenses.txt')));
  });

  test('README documenta origem oficial, hashes e avisos de hardware', () => {
    const p = path.join(ROOT, 'README-FM5-AZIMUTH.md');
    assert.ok(exists(p), `ausente: ${p}`);
    const md = read(p).toString('utf8');
    assert.ok(md.includes('almost-there-games.itch.io/azimuth'), 'origem oficial não documentada');
    assert.ok(md.includes('f0e603a4548ae7c40c1cef584ce691dbeae0bc178666bed896ab87ab6cd52994'), 'sha256 do ZIP ausente');
    assert.ok(md.includes('56d2c9cb6ccf3ae1836dee9676b64285f3a247efa2d12cf02c6c742696b3b092'), 'sha256 do exe ausente');
    assert.match(md, /16 GiB/);
    assert.match(md, /ray tracing|DXR/);
  });
});

// ---------------------------------------------------------------------------
describe('3. Launcher run_fm5_azimuth.sh', () => {
  test('é executável e tem shebang bash', () => {
    assert.ok(isExec(LAUNCHER), 'launcher sem bit de execução');
    assert.match(read(LAUNCHER).subarray(0, 64).toString('utf8'), /^#!\/usr\/bin\/env bash/);
  });

  test('sintaxe válida (bash -n)', () => {
    const r = run('bash', ['-n', LAUNCHER]);
    assert.equal(r.status, 0, r.stderr);
  });

  test('--check retorna 0 e reporta todos os nós [OK]', () => {
    const r = run(LAUNCHER, ['--check']);
    assert.equal(r.status, 0, `stdout=${r.stdout}\nstderr=${r.stderr}`);
    for (const needle of [
      'Game/era.vbi',
      'Game/Mount',
      'Game/EmbeddedXvd',
      'Identity Version=1.0.0.20 (build suportada)',
      'forza_durango_release_final.exe',
      'wrapper',
      'data/bin/azimuth.pipelines',
      'Validação concluída com sucesso (--check).',
    ]) {
      assert.ok(r.stdout.includes(needle), `--check não reportou: ${needle}`);
    }
    assert.ok(!/AUSENTE|\[ERRO\]/.test(r.stdout + r.stderr), 'check com falha inesperada');
  });

  test('--dry-run retorna 0 e monta comando proton run com VKD3D_CONFIG="" (DXR desativado por padrão)', () => {
    const r = run(LAUNCHER, ['--dry-run']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /STEAM_COMPAT_DATA_PATH=/);
    assert.match(r.stdout, /VKD3D_CONFIG=''/);
    assert.match(r.stdout, /proton run .*azimuth\.exe/);
  });

  test('--list-runners prioriza GE-Proton e retorna 0', () => {
    const r = run(LAUNCHER, ['--list-runners']);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes(`[OK]   ${RUNNER}`), 'GE-Proton-latest não marcado [OK]');
    assert.ok(r.stdout.includes(`Selecionado: proton -> ${RUNNER}`));
  });

  test('--help retorna 0', () => {
    const r = run(LAUNCHER, ['--help']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /run_fm5_azimuth\.sh/);
  });
});

// ---------------------------------------------------------------------------
describe('4. Runner Proton real, prefixo e ausência de órfãos', () => {
  test('binários do runner são executáveis', () => {
    assert.ok(isExec(path.join(RUNNER, 'proton')), 'proton não executável');
    assert.ok(isExec(path.join(RUNNER, 'files', 'bin', 'wineserver')), 'wineserver não executável');
  });

  test('prefixo criado e probe real de runtime gravado', () => {
    assert.ok(exists(PREFIX_PFX) && fs.statSync(PREFIX_PFX).isDirectory(), `prefixo ausente: ${PREFIX_PFX}`);
    for (const rel of ['drive_c', 'system.reg', 'user.reg']) {
      assert.ok(exists(path.join(PREFIX_PFX, rel)), `prefixo incompleto: ${rel}`);
    }
    const probe = path.join(PREFIX_PFX, 'drive_c', 'proton_ok.txt');
    assert.ok(exists(probe), 'probe proton_ok.txt ausente');
    assert.equal(read(probe).toString('utf8').trim(), 'PROTON_RUNTIME_OK');
  });

  test('nenhum processo desta instalação (launcher/Azimuth) órfão em execução', () => {
    // Padrões ancorados nesta instalação: não confundem outros jogos Proton do host.
    for (const pat of ['[F]orzaMotorsport5/azimuth\\.exe', '[r]un_fm5_azimuth\\.sh']) {
      const r = run('pgrep', ['-af', pat]);
      assert.equal(r.status, 1, `processo órfão detectado (${pat}):\n${r.stdout}`);
    }
  });
});

// ---------------------------------------------------------------------------
describe('5. Paridade com o RAR oficial (nomes, tamanhos, CRC)', () => {
  let rar = null;
  before(() => {
    assert.ok(exists(RAR), `RAR oficial ausente: ${RAR}`);
    const r = run('7z', ['l', '-slt', RAR]);
    assert.equal(r.status, 0, r.stderr);
    rar = parse7zListing(r.stdout);
  });

  test('mesmo conjunto de arquivos e diretórios (sem faltas/extras)', () => {
    const disk = walk(GAME);
    const missing = [...rar.files.keys()].filter((k) => !disk.files.has(k));
    const extra = [...disk.files.keys()].filter((k) => !rar.files.has(k));
    const dm = [...rar.dirs].filter((d) => !disk.dirs.has(d));
    const de = [...disk.dirs].filter((d) => !rar.dirs.has(d));
    assert.deepEqual(missing, [], 'arquivos faltando');
    assert.deepEqual(extra, [], 'arquivos extras');
    assert.deepEqual(dm, [], 'diretórios faltando');
    assert.deepEqual(de, [], 'diretórios extras');
    assert.equal(disk.files.size, rar.files.size);
    assert.equal(disk.dirs.size, rar.dirs.size);
  });

  test('todos os tamanhos e o total de bytes batem com o RAR', () => {
    const disk = walk(GAME);
    const mism = [];
    let rarTotal = 0;
    let diskTotal = 0;
    for (const [rel, size] of rar.files) {
      rarTotal += size;
      const d = disk.files.get(rel);
      diskTotal += d ?? 0;
      if (d !== size) mism.push(`${rel}: rar=${size} disk=${d}`);
    }
    assert.deepEqual(mism, [], `divergências de tamanho:\n${mism.slice(0, 20).join('\n')}`);
    assert.equal(diskTotal, rarTotal);
  });

  test('CRC32 de arquivos-chave idêntico ao armazenado no RAR', () => {
    const rarCrc = new Map();
    for (const r of rar.records) {
      if (r.path.startsWith(RAR_PREFIX) && r.CRC) rarCrc.set(r.path.slice(RAR_PREFIX.length), r.CRC);
    }
    const keys = [
      'era.vbi',
      'Mount/forza_durango_release_final.exe',
      'Mount/AppxManifest.xml',
      'Mount/hash.manifest',
      'Mount/Resources.pri',
      'EmbeddedXvd/autoexec.bat',
    ];
    for (const k of keys) {
      assert.ok(rarCrc.has(k), `CRC ausente no listing: ${k}`);
      assert.equal(crc32(path.join(GAME, k)), rarCrc.get(k), `CRC divergente: ${k}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Sensibilidade: mutações REAIS em sandbox isolada (nunca toca a árvore entregue)
// ---------------------------------------------------------------------------
function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeManifest(file, version) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(
    file,
    `<Package>\n  <Identity Name="Forza" Publisher="CN=Microsoft Corporation" Version="${version}" ProcessorArchitecture="x64" />\n</Package>\n`,
  );
}

/** Cria uma árvore Game mínima e VÁLIDA para o auditor do launcher. */
function makeFakeGame(base, { version = BUILD, embedded = true, exe = true } = {}) {
  const g = path.join(base, 'Game');
  fs.mkdirSync(g, { recursive: true });
  fs.writeFileSync(path.join(g, 'era.vbi'), ERA_MAGIC);
  writeManifest(path.join(g, 'Mount', 'AppxManifest.xml'), version);
  if (exe) fs.writeFileSync(path.join(g, 'Mount', 'forza_durango_release_final.exe'), 'MZ');
  if (embedded) fs.mkdirSync(path.join(g, 'EmbeddedXvd'), { recursive: true });
  return g;
}

/** Cópia do launcher com ROOT em tmp (symlinks p/ wrapper e data reais). */
function makeLauncherSandbox(base) {
  const root = path.join(base, 'root');
  fs.mkdirSync(root, { recursive: true });
  fs.copyFileSync(LAUNCHER, path.join(root, 'run_fm5_azimuth.sh'));
  fs.chmodSync(path.join(root, 'run_fm5_azimuth.sh'), 0o755);
  fs.symlinkSync(path.join(ROOT, 'azimuth.exe'), path.join(root, 'azimuth.exe'));
  fs.symlinkSync(path.join(ROOT, 'data'), path.join(root, 'data'));
  fs.symlinkSync(GAME, path.join(root, 'Game'));
  return path.join(root, 'run_fm5_azimuth.sh');
}

function checkSandbox(launcher, base, gameDir) {
  return run('bash', [launcher, '--check'], {
    env: {
      ...process.env,
      FM5_GAME_DIR: gameDir,
      FM5_COMPAT_DATA: path.join(base, 'prefix'),
      FM5_PROTON: RUNNER,
    },
  });
}

describe('6. Sensibilidade por mutação (sandbox temporária)', () => {
  test('controle: árvore mínima válida PASSA no --check', () => {
    const base = mkTmp('fm5-ctl-');
    try {
      const launcher = makeLauncherSandbox(base);
      const game = makeFakeGame(base);
      const r = checkSandbox(launcher, base, game);
      assert.equal(r.status, 0, `controle deveria passar\nstdout=${r.stdout}\nstderr=${r.stderr}`);
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test('mutante 1: sem EmbeddedXvd/ o --check REPROVA', () => {
    const base = mkTmp('fm5-mut1-');
    try {
      const launcher = makeLauncherSandbox(base);
      const game = makeFakeGame(base, { embedded: false });
      const r = checkSandbox(launcher, base, game);
      assert.notEqual(r.status, 0, 'mutação sem EmbeddedXvd passou indevidamente');
      assert.match(r.stdout + r.stderr, /EmbeddedXvd/);
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test('mutante 2: build 9.9.9.9 no AppxManifest REPROVA', () => {
    const base = mkTmp('fm5-mut2-');
    try {
      const launcher = makeLauncherSandbox(base);
      const game = makeFakeGame(base, { version: '9.9.9.9' });
      const r = checkSandbox(launcher, base, game);
      assert.notEqual(r.status, 0, 'versão errada passou indevidamente');
      assert.match(r.stdout + r.stderr, /9\.9\.9\.9/);
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test('mutante 3: executável do jogo ausente REPROVA', () => {
    const base = mkTmp('fm5-mut3-');
    try {
      const launcher = makeLauncherSandbox(base);
      const game = makeFakeGame(base, { exe: false });
      const r = checkSandbox(launcher, base, game);
      assert.notEqual(r.status, 0, 'ausência do executável passou indevidamente');
      assert.match(r.stdout + r.stderr, /Executável do jogo ausente|forza_durango_release_final/);
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test('override FM5_VKD3D_CONFIG="" desliga DXR no --dry-run', () => {
    const base = mkTmp('fm5-dxr-');
    try {
      const launcher = makeLauncherSandbox(base);
      const game = makeFakeGame(base);
      const r = run('bash', [launcher, '--dry-run'], {
        env: { ...process.env, FM5_GAME_DIR: game, FM5_COMPAT_DATA: path.join(base, 'prefix'), FM5_PROTON: RUNNER, FM5_VKD3D_CONFIG: '' },
      });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /VKD3D_CONFIG=''/);
      assert.ok(!r.stdout.includes('dxr11'), 'override vazio manteve dxr11');
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });

  test('trap do launcher mata a árvore inteira (sem órfão) e invoca wineserver -k', { timeout: 40000 }, async () => {
    const base = mkTmp('fm5-orphan-');
    const pidfile = path.join(base, 'child.pid');
    const wslog = path.join(base, 'wineserver.log');
    let child = null;
    let childPid = null;
    try {
      const launcher = makeLauncherSandbox(base);
      const game = makeFakeGame(base);
      // Runner falso: registra o próprio PID e dorme (emula proton em execução).
      const runner = path.join(base, 'fake-proton');
      fs.mkdirSync(path.join(runner, 'files', 'bin'), { recursive: true });
      fs.writeFileSync(path.join(runner, 'proton'),
        '#!/usr/bin/env bash\necho $$ > "$FM5_FAKE_PIDFILE"\nexec sleep 300\n');
      fs.chmodSync(path.join(runner, 'proton'), 0o755);
      fs.writeFileSync(path.join(runner, 'files', 'bin', 'wineserver'),
        '#!/usr/bin/env bash\necho "invoked $*" >> "$FM5_FAKE_WINESERVER_LOG"\nexit 0\n');
      fs.chmodSync(path.join(runner, 'files', 'bin', 'wineserver'), 0o755);

      child = spawn('bash', [launcher], {
        env: {
          ...process.env,
          FM5_GAME_DIR: game,
          FM5_COMPAT_DATA: path.join(base, 'prefix'),
          FM5_PROTON: runner,
          FM5_FAKE_PIDFILE: pidfile,
          FM5_FAKE_WINESERVER_LOG: wslog,
        },
        stdio: 'ignore',
      });

      // Espera o runner falso subir de fato.
      const deadline = Date.now() + 15000;
      while (!exists(pidfile) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      assert.ok(exists(pidfile), 'runner falso não iniciou');
      childPid = Number(read(pidfile).toString().trim());
      assert.ok(isAlive(childPid), `filho ${childPid} não está vivo antes do SIGTERM`);
      // Deixa o launcher instalar o trap (linha imediatamente após o spawn) antes do sinal.
      await new Promise((r) => setTimeout(r, 250));

      child.kill('SIGTERM');
      await waitExit(child, 15000);

      const gone = await waitFor(() => !isAlive(childPid), 10000);
      assert.ok(gone, `processo ${childPid} sobreviveu ao trap (órfão)`);
      assert.ok(exists(wslog) && read(wslog).toString().includes('invoked'), 'cleanup não invocou wineserver -k');
    } finally {
      if (child && child.exitCode === null) { try { child.kill('SIGKILL'); } catch {} }
      if (childPid && isAlive(childPid)) { try { process.kill(childPid, 'SIGKILL'); } catch {} }
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});

function isAlive(pid) {
  try { process.kill(pid, 0); } catch { return false; }
  try {
    const st = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const state = st.slice(st.lastIndexOf(')') + 2, st.lastIndexOf(')') + 3);
    return state !== 'Z';
  } catch { return false; }
}

function waitExit(child, ms) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    const t = setTimeout(() => resolve(null), ms);
    child.once('exit', (code) => { clearTimeout(t); resolve(code); });
  });
}

async function waitFor(fn, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return fn();
}
