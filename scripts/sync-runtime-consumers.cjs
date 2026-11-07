'use strict';
// Synchronize only the SDK package, never consumer configuration or credentials.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const check = process.argv.includes('--check');
const roots = process.argv.slice(2).filter(arg => arg !== '--check');
if (!roots.length) throw Error('Pass explicit consumer repository paths');
const files = fs.readdirSync(path.join(root, 'runtime-client')).filter(name => /\.(cjs|cts|ts)$/.test(name));
for (const consumer of roots) {
  const target = path.resolve(consumer, 'vendor/local-key-vault-runtime');
  if (!fs.existsSync(path.join(consumer, 'package.json'))) throw Error('Consumer package missing');
  const data = {name:manifest.name, version:manifest.version, engines:manifest.engines,
    type:manifest.type, exports:manifest.exports, typesVersions:manifest.typesVersions,
    files:manifest.files, private:true, dependencies:{ajv:manifest.dependencies.ajv}};
  const entries = [['package.json', Buffer.from(JSON.stringify(data, null, 2)+'\n')],
    ...files.map(name => ['runtime-client/'+name, fs.readFileSync(path.join(root, 'runtime-client', name))])];
  for (const [name, bytes] of entries) {
    const filename = path.join(target, name);
    if (check) {
      if (!fs.existsSync(filename) || !fs.readFileSync(filename).equals(bytes)) throw Error('Stale SDK: '+filename);
    } else { fs.mkdirSync(path.dirname(filename), {recursive:true}); fs.writeFileSync(filename, bytes); }
  }
  process.stdout.write((check?'Verified ':'Synchronized ')+target+'\n');
}
