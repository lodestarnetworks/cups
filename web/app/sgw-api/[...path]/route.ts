const permittedPaths = new Set([
  'api/v1/dashboard',
  'api/v1/events',
  'api/v1/sgwc',
  'api/v1/sgwu',
  'healthz',
  'metrics',
]);

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

function jsonError(status: number, error: string) {
  return Response.json(
    { error },
    {
      status,
      headers: {
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
      },
    },
  );
}

export async function GET(request: Request, context: RouteContext) {
  const { path } = await context.params;
  const requestedPath = path.join('/');
  if (!permittedPaths.has(requestedPath)) {
    return jsonError(404, 'not found');
  }

  const upstreamBase = process.env.SGW_API_UPSTREAM ?? 'http://127.0.0.1:8080';
  let upstreamURL: URL;
  try {
    upstreamURL = new URL(`/${requestedPath}`, upstreamBase);
  } catch {
    return jsonError(503, 'dashboard telemetry is unavailable');
  }
  upstreamURL.search = new URL(request.url).search;

  try {
    const upstream = await fetch(upstreamURL, {
      cache: 'no-store',
      headers: { Accept: request.headers.get('Accept') ?? 'application/json' },
      signal: AbortSignal.timeout(1_500),
    });
    const headers = new Headers({
      'Cache-Control': 'no-store',
      'Content-Type': upstream.headers.get('Content-Type') ?? 'application/octet-stream',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    });
    return new Response(upstream.body, { status: upstream.status, headers });
  } catch {
    return jsonError(502, 'dashboard telemetry is unavailable');
  }
}
