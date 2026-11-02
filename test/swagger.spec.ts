import request from 'supertest';
import { api, call, fixture, token } from './helpers.js';

describe('live Swagger documentation', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  beforeEach(async () => { f = await fixture(); });
  afterEach(async () => { await f.cleanup(); });
  it('serves local UI, bundled assets and a credential-free OpenAPI document', async () => {
    const ui = await request(f.app.getHttpServer()).get('/docs').expect(200);
    expect(ui.text).toContain('Key Vault API');
    await request(f.app.getHttpServer()).get('/docs/swagger-ui.css').expect(200);
    await request(f.app.getHttpServer()).get('/docs/swagger-ui-init.js').expect(200);
    const { body: doc } = await request(f.app.getHttpServer()).get('/docs-json').expect(200);
    expect(doc.paths['/local/applications'].get.tags).toEqual(['Applications']);
    expect(doc.paths['/local/applications/{application}/resources/{kind}/{name}'].put.requestBody.content['application/json'].schema.$ref).toBe('#/components/schemas/ApplicationLink');
    expect(doc.info.title).toBe('Key Vault API');
    expect(doc.components.securitySchemes.bearer).toMatchObject({ type: 'http', scheme: 'bearer' });
    expect(JSON.stringify(doc)).not.toContain(token);
    expect(JSON.stringify(doc)).not.toContain(f.config.masterKey.toString('base64'));
    const set = doc.paths['/secrets/{name}'].put;
    expect(set.security).toContainEqual({ bearer: [] });
    expect(set.requestBody.content['application/json'].schema.$ref).toBe('#/components/schemas/SetSecret');
    expect(set.parameters).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'x-vault-tenant', in: 'header', required: true }),
      expect.objectContaining({ name: 'x-vault-environment', in: 'header', required: true }),
      expect.objectContaining({ name: 'api-version', in: 'query', required: true }),
    ]));
    expect(doc.paths['/local/reconcile'].post.requestBody.content['application/json'].schema.$ref).toBe('#/components/schemas/Reconcile');
    expect(doc.paths['/local/inventory'].get.tags).toEqual(['Inventory']);
    expect(doc.paths['/secrets'].get.parameters).toEqual(expect.arrayContaining([expect.objectContaining({ name: 'maxresults', in: 'query' }), expect.objectContaining({ name: '$skiptoken', in: 'query' })]));
    expect(doc.paths['/keys/{name}/{version}/decrypt'].post.responses['200'].content['application/json'].schema.$ref).toBe('#/components/schemas/CryptoResult');
    expect(doc.paths['/namespaces/{environment}/{tenant}/secrets/{name}']).toBeDefined();
    expect(doc.paths['/keys/{name}/create'].post.tags).toEqual(['Keys']);
    expect(doc.paths['/local/snapshot'].post.tags).toEqual(['Runtime']);
    expect(doc.paths['/namespaces/{environment}/{tenant}/secrets/{name}'].get.tags).toEqual(['Namespace aliases']);
    const declaredTags = new Set(doc.tags.map((tag: { name: string }) => tag.name));
    const validateReferences = (value: unknown) => {
      if (!value || typeof value !== 'object') return;
      if (Array.isArray(value)) { value.forEach(validateReferences); return; }
      const object = value as Record<string, unknown>;
      if (typeof object.$ref === 'string') {
        const name = object.$ref.replace('#/components/schemas/', '');
        expect(doc.components.schemas[name]).toBeDefined();
      }
      if (Array.isArray(object.required)) expect(object.required.length).toBeGreaterThan(0);
      Object.values(object).forEach(validateReferences);
    };
    validateReferences(doc);
    const ids: string[] = [];
    for (const [path, operations] of Object.entries(doc.paths) as [string, Record<string, any>][]) {
      for (const operation of Object.values(operations)) {
        expect(operation.tags).toHaveLength(1);
        expect(declaredTags.has(operation.tags[0])).toBe(true);
        ids.push(operation.operationId);
        const parameters = operation.parameters.filter((p: any) => p.in === 'path');
        expect(parameters.map((p: any) => p.name).sort()).toEqual([...path.matchAll(/\{([^}]+)\}/g)].map(m => m[1]).sort());
        expect(parameters.every((p: any) => p.required)).toBe(true);
      }
    }
    expect(new Set(ids).size).toBe(ids.length);
  });
  it('supports authenticated same-origin Try it out without allowing unauthenticated or cross-origin API calls', async () => {
    await call(f.app, 'put', '/secrets/swagger-example' + api).set('Host', '127.0.0.1:4000').set('Origin', 'http://127.0.0.1:4000')
      .send({ value: 'test-only-value' }).expect(200);
    await request(f.app.getHttpServer()).get('/secrets/swagger-example' + api).expect(401);
    await call(f.app, 'get', '/secrets/swagger-example' + api).set('Origin', 'https://untrusted.example').expect(403);
    await request(f.app.getHttpServer()).post('/docs-json').send({}).expect(401);
    await request(f.app.getHttpServer()).get('/docs-json').set('Host', 'untrusted.example').expect(403);
  });
});
