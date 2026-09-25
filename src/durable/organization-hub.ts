export class OrganizationHub implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/notify' && request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      await this.state.storage.put('lastEvent', { at: Date.now(), body });
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/last' && request.method === 'GET') {
      const lastEvent = await this.state.storage.get('lastEvent');
      return Response.json(lastEvent || null);
    }
    return new Response('Not found', { status: 404 });
  }
}

export class DirectorySyncActor implements DurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/apply' && request.method === 'POST') {
      const body = await request.json() as { idempotencyKey?: string };
      const key = String(body.idempotencyKey || '');
      if (key) {
        const seen = await this.state.storage.get<boolean>(`idemp:${key}`);
        if (seen) return Response.json({ duplicate: true });
        await this.state.storage.put(`idemp:${key}`, true);
      }
      return Response.json({ duplicate: false });
    }
    return new Response('Not found', { status: 404 });
  }
}
