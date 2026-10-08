import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createContext, SourceTextModule } from 'node:vm';
import { patterns } from '../xdr/brute-force/patterns.mjs';

test('실행용 패턴이 JSON 정의와 일치한다', async () => {
  const doc = JSON.parse(await readFile(new URL('../xdr/brute-force/patterns.json', import.meta.url), 'utf8'));
  assert.deepEqual(patterns, doc.patterns.map(({ name, matchAll }) => ({ name, matchAll })));
});

test('내장·npm import와 process 없는 격리 환경에서 28건을 판정한다', async () => {
  const directory = new URL('../xdr/brute-force/', import.meta.url);
  const context = createContext({ setTimeout, clearTimeout });
  const cache = new Map();
  async function load(url) {
    if (!cache.has(url.href)) {
      cache.set(url.href, new SourceTextModule(await readFile(url, 'utf8'), {
        context, identifier: url.href,
      }));
    }
    return cache.get(url.href);
  }
  const entry = await load(new URL('decide.mjs', directory));
  await entry.link(async (specifier, parent) => {
    assert.ok(specifier.startsWith('./'), `금지된 import: ${specifier}`);
    const url = new URL(specifier, parent.identifier);
    assert.ok(url.href.startsWith(directory.href));
    return load(url);
  });
  await entry.evaluate();
  const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const result = await entry.namespace.decide(alert);
    assert.ok(Object.hasOwn(counts, result.action));
    assert.ok(Number.isFinite(result.confidence));
    counts[result.action]++;
  }
  assert.equal(Object.values(counts).reduce((a, b) => a + b, 0), fixture.alerts.length);
  assert.equal(typeof context.process, 'undefined');
});
