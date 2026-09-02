'use client';

import { useEffect, useMemo, useState } from 'react';

type ComponentState = 'healthy' | 'degraded' | 'down' | 'starting';
type Severity = 'info' | 'warning' | 'error';
type PFCPAssociationPhase = 'associated' | 'grace' | 'reconciling' | 'unavailable';

interface PeerSnapshot {
  name: string;
  interface: string;
  address: string;
  state: ComponentState;
  rttMillis: number;
  missedEchoes: number;
}

interface ProcedureSnapshot {
  name: string;
  requests: number;
  successes: number;
  failures: number;
  active: number;
  p95DurationMillis: number;
}

interface EventSnapshot {
  id: number;
  at: string;
  component: string;
  severity: Severity;
  kind: string;
  summary: string;
  context?: Record<string, string>;
}

interface TrafficSnapshot {
  at: string;
  uplinkBitsPerSecond: number;
  downlinkBitsPerSecond: number;
  packetsPerSecond: number;
}

interface BufferUsageSnapshot {
  qci: number;
  currentPackets: number;
  currentBytes: number;
  enqueued: number;
  flushed: number;
  expired: number;
  overflowDrops: number;
  purged: number;
}

interface DDNPagingHistogramSnapshot {
  qci: number;
  enb: string;
  count: number;
  sumSeconds: number;
  buckets: Array<{ upperBoundSeconds: number; count: number }>;
}

interface DashboardSnapshot {
  generatedAt: string;
  mode: string;
  sgwc: {
    state: ComponentState;
    activeSessions: number;
    activeBearers: number;
    activeTransactions: number;
    retransmissions: number;
    controlSocketDrops: number;
    transactionCollisions: number;
    recoveryCounter: number;
    durableStateEnabled: boolean;
    stateWalBytes: number;
    stateWalRecords: number;
    stateStarts: number;
    stateCompactions: number;
    recoveredSessions: number;
    stateTailRecovered: boolean;
    pendingPaging: number;
    ddnPagingHistograms: DDNPagingHistogramSnapshot[];
    peers: PeerSnapshot[];
    procedures: ProcedureSnapshot[];
  };
  sgwu: {
    state: ComponentState;
    pfcpAssociationState: ComponentState;
    pfcpAssociationPhase: PFCPAssociationPhase;
    pfcpGraceSecondsRemaining: number;
    pfcpGraceEntries: number;
    pfcpGraceExpirations: number;
    pfcpReconciliations: number;
    pfcpSocketDrops: number;
    pfcpSessions: number;
    pdrs: number;
    fars: number;
    qers: number;
    urrs: number;
    dataplaneMode: string;
    uplinkBitsPerSecond: number;
    downlinkBitsPerSecond: number;
    packetsPerSecond: number;
    forwardedPackets?: number;
    forwardedBytes?: number;
    lastTrafficAt?: string;
    uplinkTxPackets?: number;
    uplinkTxBytes?: number;
    downlinkTxPackets?: number;
    downlinkTxBytes?: number;
    droppedPackets: number;
    accessSocketDrops: number;
    coreSocketDrops: number;
    dropPercent: number;
    unknownTeids: number;
    unauthorizedPeers: number;
    downlinkReports: number;
    bufferedPackets: number;
    bufferedBytes: number;
    bufferEnqueued: number;
    bufferFlushed: number;
    bufferExpired: number;
    bufferOverflowDrops: number;
    bufferPurged: number;
    bufferClasses: BufferUsageSnapshot[];
    fastPathFallbacks: number;
    fastPathForwardedPackets: number;
    fastPathForwardedBytes: number;
    fastPathSyncFailures: number;
    fastPathRewriteErrors: number;
    fastPathP95LatencyMillis: number;
    p95LatencyMillis: number;
  };
  history: TrafficSnapshot[];
  events: EventSnapshot[];
}

const numberFormat = new Intl.NumberFormat('en-GB');
const API_URL = (process.env.NEXT_PUBLIC_SGW_API_URL ?? '/sgw-api').replace(/\/$/, '');

function useDashboard() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let active = true;
    let controller: AbortController | undefined;
    const refresh = async () => {
      controller?.abort();
      controller = new AbortController();
      try {
        const response = await fetch(`${API_URL}/api/v1/dashboard`, { cache: 'no-store', signal: controller.signal });
        if (!response.ok) throw new Error(`dashboard API returned ${response.status}`);
        const next = await response.json() as DashboardSnapshot;
        if (active) {
          setSnapshot(next);
          setConnected(true);
        }
      } catch (error) {
        if (active && !(error instanceof DOMException && error.name === 'AbortError')) setConnected(false);
      }
    };
    void refresh();
    const timer = window.setInterval(refresh, 2_000);
    return () => {
      active = false;
      controller?.abort();
      window.clearInterval(timer);
    };
  }, []);

  return { snapshot, connected };
}

function successRate(procedure?: ProcedureSnapshot) {
  if (!procedure?.requests) return null;
  return procedure.successes / procedure.requests * 100;
}

function eventContext(context?: Record<string, string>) {
  if (!context) return '—';
  return Object.values(context).join(', ');
}

function formatMbps(value: number) {
  if (value > 0 && value < .01) return '<0.01';
  if (value >= 100) return value.toFixed(0);
  if (value >= 10) return value.toFixed(1);
  return value.toFixed(2);
}

function formatBytes(value: number) {
  if (value >= 1024 * 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TiB`;
  if (value >= 1024 * 1024 * 1024) return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${numberFormat.format(value)} B`;
}

function lastTrafficLabel(value: string | undefined, forwardedPackets: number) {
  if (!value) return forwardedPackets > 0 ? 'timestamp unavailable' : 'none since start';
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return 'not reported';
  const ageSeconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1_000));
  if (ageSeconds < 5) return 'just now';
  if (ageSeconds < 60) return `${ageSeconds} s ago`;
  if (ageSeconds < 3_600) return `${Math.floor(ageSeconds / 60)} min ago`;
  if (ageSeconds < 86_400) return `${Math.floor(ageSeconds / 3_600)} h ago`;
  return new Date(timestamp).toLocaleString('en-GB', { hour12: false });
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function niceMbpsCeiling(bitsPerSecond: number) {
  const megabits = Math.max(bitsPerSecond / 1_000_000, 1);
  const magnitude = 10 ** Math.floor(Math.log10(megabits));
  const normalised = megabits / magnitude;
  const step = normalised <= 1 ? 1 : normalised <= 2 ? 2 : normalised <= 5 ? 5 : 10;
  return step * magnitude;
}

function chartTime(value: string) {
  return new Date(value).toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function pagingP95Millis(histograms?: DDNPagingHistogramSnapshot[]) {
  if (!histograms?.length) return null;
  const total = histograms.reduce((sum, histogram) => sum + histogram.count, 0);
  if (!total) return null;
  const cumulative = new Map<number, number>();
  for (const histogram of histograms) {
    for (const bucket of histogram.buckets) {
      cumulative.set(bucket.upperBoundSeconds, (cumulative.get(bucket.upperBoundSeconds) ?? 0) + bucket.count);
    }
  }
  const target = Math.ceil(total * .95);
  const bounds = [...cumulative.keys()].sort((a, b) => a - b);
  const bound = bounds.find((candidate) => (cumulative.get(candidate) ?? 0) >= target);
  return (bound ?? bounds[bounds.length - 1] ?? 0) * 1_000;
}

function Status({ children, tone = 'live' }: { children: React.ReactNode; tone?: 'live' | 'warn' | 'info' }) {
  return <span className={`status status-${tone}`}><i />{children}</span>;
}

export default function Home() {
  const { snapshot, connected } = useDashboard();
  const sgwc = snapshot?.sgwc;
  const sgwu = snapshot?.sgwu;
  const forwardedPackets = sgwu?.forwardedPackets ?? ((sgwu?.uplinkTxPackets ?? 0) + (sgwu?.downlinkTxPackets ?? 0));
  const forwardedBytes = sgwu?.forwardedBytes ?? ((sgwu?.uplinkTxBytes ?? 0) + (sgwu?.downlinkTxBytes ?? 0));
  const lastTraffic = sgwu ? lastTrafficLabel(sgwu.lastTrafficAt, forwardedPackets) : 'preview';
  const totalBitsPerSecond = (sgwu?.uplinkBitsPerSecond ?? 0) + (sgwu?.downlinkBitsPerSecond ?? 0);
  const totalMegabits = totalBitsPerSecond / 1_000_000;
  const createSession = sgwc?.procedures.find((procedure) => procedure.name === 'Create Session');
  const sessionSuccess = successRate(createSession);
  const bothHealthy = sgwc?.state === 'healthy' && sgwu?.state === 'healthy';
  const pfcpPhase = sgwu?.pfcpAssociationPhase ?? (sgwu?.pfcpAssociationState === 'healthy' ? 'associated' : 'unavailable');
  const pfcpAttention = pfcpPhase !== 'associated';
  const graceSeconds = Math.max(0, Math.ceil(sgwu?.pfcpGraceSecondsRemaining ?? 0));
  const liveFeed = connected && snapshot?.mode.startsWith('live');
  const feedTime = snapshot ? new Date(snapshot.generatedAt).toLocaleTimeString('en-GB', { hour12: false }) : '';
  const pagingP95 = pagingP95Millis(sgwc?.ddnPagingHistograms);

  const chartCeilingMbps = useMemo(() => {
    if (!snapshot?.history.length) return 1_000;
    const peak = Math.max(
      totalBitsPerSecond,
      ...snapshot.history.map((point) => point.uplinkBitsPerSecond + point.downlinkBitsPerSecond),
    );
    return niceMbpsCeiling(peak);
  }, [snapshot, totalBitsPerSecond]);

  const recentPeakMegabits = useMemo(() => {
    if (!snapshot?.history.length) return totalMegabits;
    return Math.max(
      totalBitsPerSecond,
      ...snapshot.history.map((point) => point.uplinkBitsPerSecond + point.downlinkBitsPerSecond),
    ) / 1_000_000;
  }, [snapshot, totalBitsPerSecond, totalMegabits]);

  const trafficBars = useMemo(() => {
    if (!snapshot?.history.length) {
      return Array.from({ length: 24 }, () => ({ down: 0, up: 0 }));
    }
    const max = chartCeilingMbps * 1_000_000;
    return snapshot.history.map((point) => ({
      down: point.downlinkBitsPerSecond / max * 100,
      up: point.uplinkBitsPerSecond / max * 100,
    }));
  }, [chartCeilingMbps, snapshot]);

  const trafficTimes = useMemo(() => {
    if (!snapshot?.history.length) return ['−60s', '−40s', '−20s', 'NOW'];
    const last = snapshot.history.length - 1;
    return [0, Math.round(last / 3), Math.round(last * 2 / 3), last]
      .map((index) => chartTime(snapshot.history[index].at));
  }, [snapshot]);

  const procedures = sgwc?.procedures.map((procedure) => ({
    name: procedure.name,
    interface: 'S11 / S5-C',
    success: successRate(procedure) === null ? 'NO REQUESTS' : `${successRate(procedure)!.toFixed(3)}%`,
    p95: `${procedure.p95DurationMillis.toFixed(1)} ms`,
    active: numberFormat.format(procedure.active),
  })) ?? [];

  const peers = sgwc?.peers.map((peer) => ({
    name: peer.name,
    interface: peer.interface,
    address: peer.address,
    rtt: `${peer.rttMillis.toFixed(1)} ms`,
    state: peer.state,
  })) ?? [];

  const events = snapshot?.events.slice(0, 4).map((event) => ({
    time: new Date(event.at).toLocaleTimeString('en-GB', { hour12: false }),
    component: event.component.toUpperCase(),
    summary: event.summary,
    context: eventContext(event.context),
    tone: event.severity === 'warning' ? 'warn' : event.severity === 'error' ? 'warn' : 'live',
  })) ?? [];

  return (
    <main id="top">
      <header className="site-header">
        <a className="wordmark" href="#top" aria-label="Lodestar CUPS dashboard home">
          <span className="wordmark-glyph">L</span>
          <span>LODESTAR CUPS</span>
        </a>
        <nav aria-label="Dashboard sections">
          <a className="active" href="#overview">Overview</a>
          <a href="#sgwc">SGW-C</a>
          <a href="#sgwu">SGW-U</a>
          <a href="#events">Events</a>
        </nav>
        <div className="header-actions">
          <a className="header-throughput" href="#sgwu" aria-label="Open live SGW-U throughput">
            <span>GTP-U NOW</span>
            <strong>{liveFeed ? formatMbps(totalMegabits) : '—'} Mbps</strong>
            <small>60s peak {liveFeed ? formatMbps(recentPeakMegabits) : '—'} Mbps</small>
          </a>
          <span className="build-label">{liveFeed ? 'LIVE INPUT' : 'LAB INPUT'}</span>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="technical-label">LTE CUPS OPERATIONS</p>
          <h1>LTE SERVING<br />GATEWAY<br />TELEMETRY</h1>
          <p className="hero-intro">Operational telemetry for SGW-C signalling, PFCP session state and SGW-U GTP-U forwarding. The local management API is sampled every 2 seconds.</p>
          <div className="hero-status">
            <Status tone={bothHealthy ? 'live' : 'warn'}>{bothHealthy ? 'Both components healthy' : 'Component attention required'}</Status>
            <span>{connected ? `Source local API, mode ${snapshot?.mode}, sampled ${feedTime}` : 'Source unavailable, displaying lab values'}</span>
          </div>
        </div>
        <div className="hero-facts" aria-label="Current SGW metrics">
          <div><span>Active sessions</span><strong>{sgwc ? numberFormat.format(sgwc.activeSessions) : '—'}</strong><small>SGW-C contexts</small></div>
          <div><span>Active bearers</span><strong>{sgwc ? numberFormat.format(sgwc.activeBearers) : '—'}</strong><small>default + dedicated</small></div>
          <div><span>GTP-U traffic</span><strong>{sgwu ? formatMbps(totalMegabits) : '—'}</strong><small>Mbps aggregate</small></div>
          <div><span>Session success</span><strong>{sessionSuccess === null ? '—' : sessionSuccess.toFixed(3)}</strong><small>{sessionSuccess === null ? 'awaiting requests' : 'lifetime success rate, percent'}</small></div>
        </div>
      </section>

      <section id="overview" className="paper-section">
        <div className="section-heading">
          <div>
            <p className="technical-label">COMPONENT STATUS</p>
            <h2>SGW PROCESS<br />STATUS</h2>
          </div>
          <p>SGW-C terminates S11 and controls S5/S8-C session state. SGW-U applies Sxa PFCP rules to S1-U and S5/S8-U packet forwarding.</p>
        </div>

        <div className="component-grid">
          <article className="component-card">
            <div className="component-top"><span>CONTROL PLANE</span><Status tone={sgwc?.state === 'down' ? 'warn' : 'live'}>{sgwc?.state ?? 'Preview'}</Status></div>
            <h3>SGW-C</h3>
            <p>Session ownership, GTPv2-C transactions, bearer lifecycle, peer recovery and PFCP programming.</p>
            <dl>
              <div><dt>sessions</dt><dd>{sgwc ? numberFormat.format(sgwc.activeSessions) : '—'}</dd></div>
              <div><dt>transactions</dt><dd>{sgwc ? `${numberFormat.format(sgwc.activeTransactions)} active` : '—'}</dd></div>
              <div><dt>retransmissions</dt><dd>{sgwc ? numberFormat.format(sgwc.retransmissions) : '—'}</dd></div>
              <div><dt>kernel queue drops</dt><dd>{sgwc ? numberFormat.format(sgwc.controlSocketDrops) : '—'}</dd></div>
              <div><dt>recovery counter</dt><dd>{sgwc?.recoveryCounter ?? '—'}</dd></div>
              <div><dt>session authority</dt><dd>{sgwc ? (sgwc.durableStateEnabled ? 'durable, fsync enabled' : 'volatile') : 'preview'}</dd></div>
              <div><dt>restart recovery</dt><dd>{sgwc ? (isFiniteNumber(sgwc.recoveredSessions) && isFiniteNumber(sgwc.stateWalBytes) ? `${numberFormat.format(sgwc.recoveredSessions)} sessions, ${formatBytes(sgwc.stateWalBytes)} WAL` : 'not reported') : 'preview'}</dd></div>
              <div><dt>state compaction</dt><dd>{sgwc ? (isFiniteNumber(sgwc.stateCompactions) ? `${numberFormat.format(sgwc.stateCompactions)} atomic` : 'not reported') : 'preview'}</dd></div>
              <div><dt>paging response p95</dt><dd>{pagingP95 === null ? 'awaiting DDN' : `${pagingP95.toFixed(1)} ms`}</dd></div>
              <div><dt>pending paging</dt><dd>{sgwc ? numberFormat.format(sgwc.pendingPaging) : '—'}</dd></div>
            </dl>
            <a href="#sgwc">Open control-plane metrics</a>
          </article>

          <article className="component-card inverted">
            <div className="component-top"><span>USER PLANE</span><Status tone={sgwu?.state === 'down' ? 'warn' : 'live'}>{sgwu?.state ?? 'Preview'}</Status></div>
            <h3>SGW-U</h3>
            <p>PFCP sessions, GTP-U tunnel forwarding, per-rule accounting, QoS enforcement and dataplane health.</p>
            <dl>
              <div><dt>PFCP sessions</dt><dd>{sgwu ? numberFormat.format(sgwu.pfcpSessions) : '—'}</dd></div>
              <div><dt>PFCP phase</dt><dd>{sgwu ? `${pfcpPhase}, ${numberFormat.format(sgwu.pfcpSocketDrops)} queue drops` : '—'}</dd></div>
              <div><dt>PDR / FAR</dt><dd>{sgwu ? `${numberFormat.format(sgwu.pdrs)} / ${numberFormat.format(sgwu.fars)}` : '—'}</dd></div>
              <div><dt>packet rate</dt><dd>{sgwu ? `${(sgwu.packetsPerSecond / 1_000_000).toFixed(2)} Mpps` : '—'}</dd></div>
              <div><dt>dataplane</dt><dd>{sgwu?.dataplaneMode ?? '—'}</dd></div>
              <div><dt>idle buffer</dt><dd>{sgwu ? `${numberFormat.format(sgwu.bufferedPackets)} packets, ${formatBytes(sgwu.bufferedBytes)}` : '—'}</dd></div>
              <div><dt>buffer released</dt><dd>{sgwu ? `${numberFormat.format(sgwu.bufferFlushed)} released, ${numberFormat.format(sgwu.bufferExpired + sgwu.bufferOverflowDrops)} dropped` : '—'}</dd></div>
              <div><dt>forwarded total</dt><dd>{sgwu ? `${formatBytes(forwardedBytes)} across ${numberFormat.format(forwardedPackets)} packets` : '—'}</dd></div>
              <div><dt>last traffic</dt><dd>{lastTraffic}</dd></div>
            </dl>
            <a href="#sgwu">Open user-plane metrics</a>
          </article>
        </div>

        <div className="interface-table">
          <div className="table-caption">LTE CUPS INTERFACE STATUS</div>
          <div className="interface-row"><span>S11</span><strong>SGW-C ↔ MME</strong><code>GTPv2-C on UDP/2123</code><Status tone={sgwc?.state === 'healthy' ? 'live' : 'warn'}>{sgwc?.state ?? 'Offline'}</Status></div>
          <div className="interface-row"><span>S5/S8-C</span><strong>SGW-C ↔ PGW-C</strong><code>GTPv2-C on UDP/2123</code><Status tone={sgwc?.state === 'healthy' ? 'live' : 'warn'}>{sgwc?.state ?? 'Offline'}</Status></div>
          <div className="interface-row"><span>Sxa</span><strong>SGW-C ↔ SGW-U</strong><code>PFCP on UDP/8805</code><Status tone={pfcpAttention ? 'warn' : 'live'}>{pfcpPhase}</Status></div>
          <div className="interface-row"><span>S1-U / S5-U</span><strong>SGW-U dataplane</strong><code>GTP-U on UDP/2152</code><Status tone={sgwu?.state === 'healthy' ? 'live' : 'warn'}>{sgwu?.state ?? 'Offline'}</Status></div>
        </div>
      </section>

      <section id="sgwu" className="dark-section">
        <div className="section-heading dark-heading">
          <div>
            <p className="technical-label">SGW-U USER PLANE</p>
            <h2>GTP-U DATAPLANE<br />TRAFFIC / LOSS / LATENCY</h2>
          </div>
          <p>SGW-U forwarding counters sampled from the running dataplane. Rates use a 60-second window; loss and latency values are reported in percent and ms.</p>
        </div>

        <div className={`pfcp-recovery ${pfcpAttention ? 'pfcp-recovery-attention' : ''}`}>
          <div><span>PFCP ASSOCIATION</span><Status tone={pfcpAttention ? 'warn' : 'live'}>{pfcpPhase}</Status></div>
          <div><span>GRACE REMAINING</span><strong>{pfcpPhase === 'grace' || pfcpPhase === 'reconciling' ? graceSeconds : 0}</strong><small>seconds</small></div>
          <div><span>GRACE ENTRIES</span><strong>{numberFormat.format(sgwu?.pfcpGraceEntries ?? 0)}</strong><small>since process start</small></div>
          <div><span>RECONCILIATIONS</span><strong>{numberFormat.format(sgwu?.pfcpReconciliations ?? 0)}</strong><small>{numberFormat.format(sgwu?.pfcpGraceExpirations ?? 0)} expired</small></div>
        </div>

        <div className="traffic-layout">
          <article className="traffic-chart">
            <div className="chart-header">
              <div><span className="technical-label">GTP-U THROUGHPUT (60 SECOND WINDOW)</span><strong>{sgwu ? formatMbps(totalMegabits) : '—'} Mbps</strong></div>
              <div className="chart-legend"><span><i className="up" />UPLINK {sgwu ? formatMbps(sgwu.uplinkBitsPerSecond / 1_000_000) : '—'} Mbps</span><span><i className="down" />DOWNLINK {sgwu ? formatMbps(sgwu.downlinkBitsPerSecond / 1_000_000) : '—'} Mbps</span></div>
            </div>
            <div className="chart-body">
              <div className="axis"><span>{formatMbps(chartCeilingMbps)} Mbps</span><span>{formatMbps(chartCeilingMbps * .75)} Mbps</span><span>{formatMbps(chartCeilingMbps * .5)} Mbps</span><span>{formatMbps(chartCeilingMbps * .25)} Mbps</span><span>0 Mbps</span></div>
              <div className="bars">
                {trafficBars.map((height, index) => (
                  <div className="bar-group" key={`${height.down}-${index}`}>
                    <i className="bar-down" style={{ height: `${height.down}%` }} />
                    <i className="bar-up" style={{ height: `${height.up}%` }} />
                  </div>
                ))}
              </div>
              <div className="time-axis">{trafficTimes.map((time, index) => <span key={`${time}-${index}`}>{time}</span>)}</div>
            </div>
          </article>

          <aside className="dataplane-metrics">
            <div><span>PACKET RATE</span><strong>{sgwu ? (sgwu.packetsPerSecond / 1_000_000).toFixed(2) : '—'}</strong><small>Mpps</small></div>
            <div><span>P95 LATENCY</span><strong>{sgwu ? sgwu.p95LatencyMillis.toFixed(2) : '—'}</strong><small>ms</small></div>
            <div><span>PACKET LOSS</span><strong>{sgwu ? sgwu.dropPercent.toFixed(3) : '—'}</strong><small>{sgwu ? `${numberFormat.format(sgwu.accessSocketDrops + sgwu.coreSocketDrops)} kernel queue drops, percent` : 'awaiting SGW-U feed'}</small></div>
            <div><span>IDLE BUFFER</span><strong>{sgwu ? numberFormat.format(sgwu.bufferedPackets) : '—'}</strong><small>{sgwu ? `${formatBytes(sgwu.bufferedBytes)} buffered, ${numberFormat.format(sgwu.bufferOverflowDrops)} overflow drops` : 'awaiting SGW-U feed'}</small></div>
            <div><span>FORWARDED TOTAL</span><strong>{sgwu ? formatBytes(forwardedBytes) : '—'}</strong><small>{sgwu ? `${numberFormat.format(forwardedPackets)} packets, last packet ${lastTraffic}, ${numberFormat.format(sgwu.fastPathForwardedPackets)} fast-path packets` : 'awaiting SGW-U feed'}</small></div>
          </aside>
        </div>

        <div className="rules-grid">
          <div><span>PDR</span><strong>{sgwu ? numberFormat.format(sgwu.pdrs) : '—'}</strong><small>packet detection rules</small></div>
          <div><span>FAR</span><strong>{sgwu ? numberFormat.format(sgwu.fars) : '—'}</strong><small>forwarding action rules</small></div>
          <div><span>QER</span><strong>{sgwu ? numberFormat.format(sgwu.qers) : '—'}</strong><small>QoS enforcement rules</small></div>
          <div><span>URR</span><strong>{sgwu ? numberFormat.format(sgwu.urrs) : '—'}</strong><small>usage reporting rules</small></div>
        </div>
      </section>

      <section id="sgwc" className="paper-section control-section">
        <div className="section-heading">
          <div><p className="technical-label">SGW-C CONTROL PLANE</p><h2>GTPv2-C CONTROL<br />PROCEDURES / PEERS</h2></div>
          <p>Procedure counters cover SGW-C-owned S11 and S5/S8-C transactions. Peer RTT and state are read from the SGW-C management feed.</p>
        </div>

        <div className="control-grid">
          <article>
            <div className="table-caption">PROCEDURE HEALTH</div>
            <div className="data-row data-head"><span>PROCEDURE</span><span>PATH</span><span>SUCCESS</span><span>P95</span><span>ACTIVE</span></div>
            {procedures.length === 0 && <div className="data-row"><strong>SGW-C feed unavailable</strong><code>—</code><span>—</span><span>—</span><span>—</span></div>}
            {procedures.map((procedure) => (
              <div className="data-row" key={procedure.name}>
                <strong>{procedure.name}</strong><code>{procedure.interface}</code><span>{procedure.success}</span><span>{procedure.p95}</span><span>{procedure.active}</span>
              </div>
            ))}
          </article>

          <article>
            <div className="table-caption">SGW-C PEER STATUS</div>
            {peers.length === 0 && <div className="peer-row"><Status tone="warn">Offline</Status><div><strong>No peer data</strong><span>SGW-C feed unavailable</span></div><code>—</code><span>—</span></div>}
            {peers.map((peer) => (
              <div className="peer-row" key={peer.name}>
                <Status tone={peer.state === 'healthy' ? 'live' : 'warn'}>{peer.state}</Status>
                <div><strong>{peer.name}</strong><span>{peer.interface}</span></div>
                <code>{peer.address}</code>
                <span>{peer.rtt}</span>
              </div>
            ))}
          </article>
        </div>
      </section>

      <section id="events" className="events-section">
        <div className="section-heading dark-heading">
          <div><p className="technical-label">COMPONENT EVENT LOG</p><h2>RUNTIME EVENTS<br />WARNINGS / FAULTS</h2></div>
          <p>Events are sourced from the SGW-C and SGW-U management feeds. Input mode is shown explicitly as live process data or deterministic lab data.</p>
        </div>
        <div className="lab-notice"><b>{liveFeed ? '●' : '!'}</b><p>{liveFeed ? <><strong>LIVE PROCESS DATA:</strong> metrics come from the running SGW-C and SGW-U processes. “Live” describes this local gateway instance, not production certification.</> : <><strong>PREVIEW DATA:</strong> the API is offline or serving the deterministic UI lab feed. Values shown here are not traffic from a live gateway.</>}</p></div>
        <div className="event-table">
          <div className="event-head"><span>TIME</span><span>COMPONENT</span><span>EVENT</span><span>CONTEXT</span><span>STATE</span></div>
          {events.length === 0 && <div className="event-row"><time>—</time><strong>SGW</strong><span>Event feed unavailable</span><code>—</code><Status tone="warn">Offline</Status></div>}
          {events.map((event) => (
            <div className="event-row" key={`${event.time}-${event.summary}`}>
              <time>{event.time}</time><strong>{event.component}</strong><span>{event.summary}</span><code>{event.context}</code><Status tone={event.tone as 'live' | 'warn' | 'info'}>{event.tone === 'warn' ? 'Watch' : 'OK'}</Status>
            </div>
          ))}
        </div>
      </section>

      <footer className="site-footer">
        <div className="wordmark"><span className="wordmark-glyph">L</span><span>LODESTAR CUPS</span></div>
        <p>LTE SGW-C / SGW-U local engineering build</p>
        <p>4G EPC scope only, pre-production software</p>
      </footer>
    </main>
  );
}
