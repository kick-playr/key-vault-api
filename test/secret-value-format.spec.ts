import { inferSecretValueFormat, validateSecretValueFormat, classifySecretVersions } from '../src/secret-value-format.js';
import { emptyNamespace } from '../src/types.js';
import { newSecret } from '../src/vault.js';
describe('secret value formats', () => {
  const hex='aB01'.repeat(16), b64=Buffer.alloc(32,7).toString('base64');
  it('validates declarations without transforming the original value',()=>{
    expect(validateSecretValueFormat(hex,'hex64')).toBe('hex64');
    expect(validateSecretValueFormat(b64,'base64')).toBe('base64');
    expect(validateSecretValueFormat('plain text','text')).toBe('text');
    for(const [value,format]of [[hex+'0','hex64'],['g'.repeat(64),'hex64'],[b64.trimEnd()+'\n','base64'],['Zh==','base64'],['Zg','base64'],['','base64'],['x','unknown']])expect(()=>validateSecretValueFormat(value!,format)).toThrow();
  });
  it('infers hex before base64 and otherwise preserves plain text',()=>{
    expect(inferSecretValueFormat(hex)).toBe('hex64');expect(inferSecretValueFormat(b64)).toBe('base64');
    for(const value of ['','a password','Zg','Zh==','Zg==\n'])expect(inferSecretValueFormat(value)).toBe('text');
  });
  it('classifies historical and disabled versions idempotently, preserving values and explicit formats',()=>{
    const ns=emptyNamespace();const one=newSecret({value:hex}),two=newSecret({value:b64,attributes:{enabled:false}}),explicit=newSecret({value:hex,valueFormat:'text'});
    delete one.valueFormat;delete two.valueFormat;ns.secrets.sample=[one,two,explicit];const original=structuredClone(ns);
    expect(classifySecretVersions(ns,true)).toBe(2);expect(ns).toEqual(original);
    expect(classifySecretVersions(ns)).toBe(2);expect(ns.secrets.sample.map(v=>v.valueFormat)).toEqual(['hex64','base64','text']);
    expect(ns.secrets.sample.map(v=>[v.version,v.value,v.attributes])).toEqual(original.secrets.sample!.map(v=>[v.version,v.value,v.attributes]));
    expect(classifySecretVersions(ns)).toBe(0);
  });
});
