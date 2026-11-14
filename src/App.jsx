import { useCallback, useEffect, useRef, useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

const NAV_ITEMS = [
  { label: 'Overview', icon: '◫' },
  { label: 'Live Monitoring', icon: '⌁' },
  { label: 'Security Events', icon: '▤' },
  { label: 'SSRF Detection', icon: '⌕' },
  { label: 'Token Management', icon: '◇' },
  { label: 'Security Rules', icon: '⊞' },
  { label: 'Test Center', icon: '▶' },
  { label: 'IaC Security Assessment', icon: '⌁' },
  { label: 'Configuration', icon: '⚙' },
]

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(body.error || body.reason || `Request failed (${response.status})`)
  }
  return body
}

function App() {
  const [page, setPage] = useState('Overview')
  const [overview, setOverview] = useState({
    totalRequests: 0,
    allowedRequests: 0,
    blockedRequests: 0,
    ssrfAttempts: 0,
    invalidTokenAttempts: 0,
    securityAlerts: 0,
    attackCategories: [],
    activity: [],
  })
  const [events, setEvents] = useState([])
  const [rules, setRules] = useState([])
  const [configuration, setConfiguration] = useState(null)
  const [health, setHealth] = useState(null)
  const [cloudHealth, setCloudHealth] = useState(null)
  const [cloudFindings, setCloudFindings] = useState([])
  const [cloudAlerts, setCloudAlerts] = useState([])
  const [cloudSummary, setCloudSummary] = useState(null)
  const [findingsNextCursor, setFindingsNextCursor] = useState(null)
  const [cloudError, setCloudError] = useState('')
  const [cloudLoading, setCloudLoading] = useState(true)
  const [findingsCursor, setFindingsCursor] = useState('0')
  const cloudLoaded = useRef(false)
  const [prowlerHealth, setProwlerHealth] = useState(null)
  const [prowlerStatus, setProwlerStatus] = useState(null)
  const [prowlerFindings, setProwlerFindings] = useState([])
  const [prowlerSummary, setProwlerSummary] = useState(null)
  const [prowlerCompliance, setProwlerCompliance] = useState(null)
  const [prowlerHistory, setProwlerHistory] = useState([])
  const [prowlerProvider, setProwlerProvider] = useState('iac')
  const [prowlerAuthorized, setProwlerAuthorized] = useState(false)
  const [prowlerQuery, setProwlerQuery] = useState('')
  const [prowlerSeverity, setProwlerSeverity] = useState('')
  const [prowlerServiceFilter, setProwlerServiceFilter] = useState('')
  const [prowlerResourceFilter, setProwlerResourceFilter] = useState('')
  const [prowlerError, setProwlerError] = useState('')
  const [prowlerLoading, setProwlerLoading] = useState(true)
  const [prowlerCursor, setProwlerCursor] = useState('0')
  const [prowlerNextCursor, setProwlerNextCursor] = useState(null)
  const [activeFinding, setActiveFinding] = useState(null)
  const [runs, setRuns] = useState([])
  const [selectedRun, setSelectedRun] = useState(null)
  const [activeEvent, setActiveEvent] = useState(null)
  const [token, setToken] = useState('')
  const [tokenExpiry, setTokenExpiry] = useState(0)
  const [clock, setClock] = useState(Date.now())
  const [tokenTtl, setTokenTtl] = useState(300)
  const [resource, setResource] = useState('instance-id')
  const [metadataResult, setMetadataResult] = useState(null)
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadOverview = useCallback(async () => {
    setOverview(await api('/security/overview'))
  }, [])

  const loadEvents = useCallback(async () => {
    const params = new URLSearchParams({
      status: statusFilter,
      severity: severityFilter,
      search: query,
    })
    const result = await api(`/security/events?${params}`)
    setEvents(result)
    if (activeEvent && !result.some((event) => event.id === activeEvent.id)) {
      setActiveEvent(null)
    }
  }, [activeEvent, query, severityFilter, statusFilter])

  const loadSupportingData = useCallback(async () => {
    const [healthResult, rulesResult, configResult, runsResult] = await Promise.all([
      api('/health'),
      api('/security/rules'),
      api('/config'),
      api('/security/test-center/runs'),
    ])
    setHealth(healthResult)
    setRules(rulesResult)
    setConfiguration(configResult)
    setRuns(runsResult)
  }, [])

  const loadCloudFindings = useCallback(async () => {
    if (!cloudLoaded.current) setCloudLoading(true)
    try {
      const healthResult = await api('/security/health')
      const params = new URLSearchParams({ limit: '20', cursor: findingsCursor })
      const alertParams = new URLSearchParams({ limit: '10', cursor: '0' })
      const [findingsResult, summaryResult, alertsResult] = await Promise.all([
        api(`/security/findings?${params}`),
        api('/security/summary'),
        api(`/security/alerts?${alertParams}`),
      ])
      setCloudHealth(healthResult)
      setCloudFindings(findingsResult.items || [])
      setFindingsNextCursor(findingsResult.next_cursor)
      setCloudSummary(summaryResult)
      setCloudAlerts(alertsResult.items || [])
      setCloudError('')
    } catch (requestError) {
      setCloudHealth(null)
      setCloudFindings([])
      setFindingsNextCursor(null)
      setCloudSummary(null)
      setCloudAlerts([])
      setCloudError(requestError.message)
    } finally {
      cloudLoaded.current = true
      setCloudLoading(false)
    }
  }, [findingsCursor])

  const loadProwlerData = useCallback(async () => {
    setProwlerLoading(true)
    try {
      const filters = new URLSearchParams({ limit: '25', cursor: prowlerCursor })
      if (prowlerQuery) filters.set('search', prowlerQuery)
      if (prowlerSeverity) filters.set('severity', prowlerSeverity)
      if (prowlerServiceFilter) filters.set('service', prowlerServiceFilter)
      if (prowlerResourceFilter) filters.set('resource', prowlerResourceFilter)
      const [healthResult, statusResult, findingResult, summaryResult, historyResult] = await Promise.all([
        api('/cloud-security/health'),
        api('/cloud-security/status'),
        api(`/cloud-security/findings?${filters}`),
        api('/cloud-security/summary'),
        api('/cloud-security/scan-history?limit=10'),
      ])
      const complianceResult = await api('/cloud-security/compliance')
      setProwlerHealth(healthResult)
      setProwlerStatus(statusResult)
      setProwlerFindings(findingResult.items || [])
      setProwlerNextCursor(findingResult.next_cursor)
      setProwlerSummary(summaryResult)
      setProwlerCompliance(complianceResult)
      setProwlerHistory(historyResult.items || [])
      setProwlerError('')
      setActiveFinding((current) => (
        current && !findingResult.items?.some((item) => item.finding_id === current.finding_id)
          ? null
          : current
      ))
    } catch (requestError) {
      setProwlerHealth(null)
      setProwlerStatus(null)
      setProwlerFindings([])
      setProwlerSummary(null)
      setProwlerCompliance(null)
      setProwlerHistory([])
      setProwlerError(requestError.message)
    } finally {
      setProwlerLoading(false)
    }
  }, [
    prowlerCursor,
    prowlerQuery,
    prowlerResourceFilter,
    prowlerServiceFilter,
    prowlerSeverity,
  ])

  const refresh = useCallback(async () => {
    setError('')
    void loadCloudFindings()
    void loadProwlerData()
    try {
      await Promise.all([loadOverview(), loadEvents(), loadSupportingData()])
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setLoading(false)
    }
  }, [loadCloudFindings, loadEvents, loadOverview, loadProwlerData, loadSupportingData])

  useEffect(() => {
    void refresh()
    const intervalId = window.setInterval(() => void refresh(), 5000)
    return () => window.clearInterval(intervalId)
  }, [refresh])

  useEffect(() => {
    if (!notice) return undefined
    const timeoutId = window.setTimeout(() => setNotice(''), 3500)
    return () => window.clearTimeout(timeoutId)
  }, [notice])

  useEffect(() => {
    const intervalId = window.setInterval(() => setClock(Date.now()), 1000)
    return () => window.clearInterval(intervalId)
  }, [])

  const runTests = async () => {
    setBusy(true)
    setError('')
    try {
      const result = await api('/security/test-center/run', { method: 'POST' })
      setSelectedRun(result)
      setNotice(`Test run ${result.passed}/${result.total} passed and was saved.`)
      await refresh()
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  const openRun = async (id) => {
    try {
      setSelectedRun(await api(`/security/test-center/runs/${id}`))
    } catch (requestError) {
      setError(requestError.message)
    }
  }

  const startProwlerScan = async () => {
    setBusy(true)
    setProwlerError('')
    try {
      const result = await api('/cloud-security/scan', {
        method: 'POST',
        body: JSON.stringify({
          provider: prowlerProvider,
          mode: prowlerProvider === 'iac' ? 'local' : 'live',
          ...(prowlerProvider === 'iac' ? {} : { authorized: prowlerAuthorized }),
        }),
      })
      setProwlerMode('actual')
      setProwlerCursor('0')
      setNotice(`Prowler scan ${result.scan_id} queued.`)
    } catch (requestError) {
      setProwlerError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  const cancelProwlerScan = async () => {
    const scanId = prowlerStatus?.active_scan?.scan_id
    if (!scanId) return
    setBusy(true)
    setProwlerError('')
    try {
      await api(`/cloud-security/scan/${scanId}/cancel`, { method: 'POST' })
      await loadProwlerData()
    } catch (requestError) {
      setProwlerError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  const openProwlerFinding = async (finding) => {
    if (!finding) {
      setActiveFinding(null)
      return
    }
    try {
      const result = await api(`/cloud-security/findings/${encodeURIComponent(finding.finding_id)}`)
      setActiveFinding(result)
    } catch (requestError) {
      setProwlerError(requestError.message)
    }
  }

  const acquireToken = async () => {
    setBusy(true)
    setError('')
    try {
      const result = await api('/metadata/token', {
        method: 'PUT',
        headers: { 'X-aws-ec2-metadata-token-ttl-seconds': String(tokenTtl) },
      })
      setToken(result.token)
      setTokenExpiry(Date.now() + result.expires_in * 1000)
      setMetadataResult(null)
      setNotice(`Lab token issued for ${result.expires_in} seconds.`)
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  const requestMetadata = async () => {
    if (!token) {
      setError('Acquire a session token before requesting metadata.')
      return
    }
    setBusy(true)
    setError('')
    try {
      const result = await api(`/proxy/${encodeURIComponent(resource)}`, {
        headers: { 'X-IMDS-Token': token },
      })
      setMetadataResult(result)
      setNotice('Authorized mock metadata response received.')
      await Promise.all([loadOverview(), loadEvents()])
    } catch (requestError) {
      setError(requestError.message)
      await Promise.all([loadOverview(), loadEvents()])
    } finally {
      setBusy(false)
    }
  }

  const toggleRule = async (rule) => {
    setBusy(true)
    setError('')
    try {
      const updated = await api(`/security/rules/${rule.rule_id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !rule.enabled }),
      })
      setRules((previous) => previous.map((item) => item.rule_id === updated.rule_id ? updated : item))
      setNotice(`${updated.name} ${updated.enabled ? 'enabled' : 'disabled'}.`)
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  const clearLab = async () => {
    if (!window.confirm('Delete all local security events and saved test runs?')) return
    setBusy(true)
    setError('')
    try {
      await api('/security/clear', { method: 'POST' })
      setSelectedRun(null)
      setActiveEvent(null)
      setNotice('Local lab events and test history cleared.')
      await refresh()
    } catch (requestError) {
      setError(requestError.message)
    } finally {
      setBusy(false)
    }
  }

  const exportCsv = () => {
    const columns = ['timestamp', 'source', 'requested_path', 'method', 'detection_reason', 'severity', 'result', 'status_code']
    const rows = [columns, ...events.map((event) => columns.map((column) => event[column] ?? ''))]
    const csv = rows.map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\r\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'metaguard-security-events.csv'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const pageTitle = NAV_ITEMS.find((item) => item.label === page)?.label || page

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-icon" aria-hidden="true">M</div>
          <div>
            <div className="eyebrow">Security Operations</div>
            <h2>MetaGuard</h2>
          </div>
        </div>
        <div className="lab-label">
          <span className={`status-dot ${cloudHealth?.status === 'ok' ? 'live' : 'offline'}`} />
          {cloudHealth?.mode === 'live' ? 'AWS Security Hub · Live' : cloudHealth?.mode === 'demo' ? 'Demo findings' : 'Findings source unavailable'}
        </div>
        <nav aria-label="Main navigation">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.label}
              className={`nav-item ${page === item.label ? 'active' : ''}`}
              onClick={() => setPage(item.label)}
              aria-current={page === item.label ? 'page' : undefined}
            >
              <span className="nav-icon" aria-hidden="true">{item.icon}</span>
              {item.label}
              {item.label === 'Security Events' && overview?.blockedRequests > 0 && (
                <span className="nav-count">{overview.blockedRequests}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className={`status-dot ${health?.status === 'ok' ? 'live' : 'offline'}`} />
          API {health?.status === 'ok' ? 'Connected' : 'Unavailable'}
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Cloud Security Lab / {pageTitle}</p>
            <h1>{page === 'Overview' ? 'Metadata Protection Proxy' : pageTitle}</h1>
          </div>
          <div className="header-actions">
            <CloudDataBadge health={cloudHealth} error={cloudError} />
            <span className="refresh-label"><span className="status-dot live" /> Dashboard refresh 5s · provider cache 60s</span>
            <button className="secondary-btn" onClick={exportCsv} disabled={!events.length}>Export CSV</button>
            <button className="danger-btn" onClick={clearLab} disabled={busy}>Clear Lab</button>
          </div>
        </header>

        {error && <div className="notice error-notice" role="alert">{error}<button onClick={() => setError('')}>Dismiss</button></div>}
        {notice && <div className="notice success-notice" role="status">{notice}</div>}
        {loading && !overview && <div className="panel loading-panel">Connecting to the local security service…</div>}

        {page === 'Overview' && (
          <OverviewPage
            overview={overview}
            events={events.slice(0, 7)}
            health={health}
            cloudSummary={cloudSummary}
            cloudFindings={cloudFindings.slice(0, 5)}
            cloudLoading={cloudLoading}
            cloudError={cloudError}
            onSelectEvent={setActiveEvent}
            onNavigate={setPage}
          />
        )}
        {page === 'Live Monitoring' && (
          <LiveMonitoringPage
            events={events.slice(0, 30)}
            overview={overview}
            findings={cloudFindings}
            alerts={cloudAlerts}
            summary={cloudSummary}
            loading={cloudLoading}
            error={cloudError}
            cursor={findingsCursor}
            nextCursor={findingsNextCursor}
            setCursor={setFindingsCursor}
            onSelectEvent={setActiveEvent}
          />
        )}
        {page === 'Security Events' && (
          <EventsPage
            events={events}
            activeEvent={activeEvent}
            onSelectEvent={setActiveEvent}
            query={query}
            setQuery={setQuery}
            statusFilter={statusFilter}
            setStatusFilter={setStatusFilter}
            severityFilter={severityFilter}
            setSeverityFilter={setSeverityFilter}
          />
        )}
        {page === 'SSRF Detection' && (
          <SsrfPage
            events={events.filter((event) => event.severity === 'critical' || /ssrf|destination|path/i.test(event.detection_reason))}
            busy={busy}
            onRun={runTests}
            onSelectEvent={setActiveEvent}
          />
        )}
        {page === 'Token Management' && (
          <TokenPage
            token={token}
            tokenExpiry={tokenExpiry}
            clock={clock}
            tokenTtl={tokenTtl}
            setTokenTtl={setTokenTtl}
            resource={resource}
            setResource={setResource}
            metadataResult={metadataResult}
            busy={busy}
            onAcquire={acquireToken}
            onRequest={requestMetadata}
          />
        )}
        {page === 'Security Rules' && <RulesPage rules={rules} busy={busy} onToggle={toggleRule} />}
        {page === 'Test Center' && (
          <TestCenterPage
            runs={runs}
            selectedRun={selectedRun}
            busy={busy}
            onRun={runTests}
            onOpenRun={openRun}
          />
        )}
        {page === 'IaC Security Assessment' && (
          <ProwlerPage
            health={prowlerHealth}
            status={prowlerStatus}
            findings={prowlerFindings}
            summary={prowlerSummary}
            compliance={prowlerCompliance}
            history={prowlerHistory}
            loading={prowlerLoading}
            error={prowlerError}
            provider={prowlerProvider}
            setProvider={(value) => {
              setProwlerProvider(value)
              setProwlerAuthorized(false)
            }}
            authorized={prowlerAuthorized}
            setAuthorized={setProwlerAuthorized}
            query={prowlerQuery}
            setQuery={setProwlerQuery}
            severity={prowlerSeverity}
            setSeverity={setProwlerSeverity}
            serviceFilter={prowlerServiceFilter}
            setServiceFilter={setProwlerServiceFilter}
            resourceFilter={prowlerResourceFilter}
            setResourceFilter={setProwlerResourceFilter}
            cursor={prowlerCursor}
            nextCursor={prowlerNextCursor}
            setCursor={setProwlerCursor}
            activeFinding={activeFinding}
            onSelectFinding={openProwlerFinding}
            busy={busy}
            onStartScan={startProwlerScan}
            onCancelScan={cancelProwlerScan}
          />
        )}
        {page === 'Configuration' && <ConfigurationPage configuration={configuration} health={health} />}
      </main>
    </div>
  )
}

function OverviewPage({ overview, events, health, cloudSummary, cloudFindings, cloudLoading, cloudError, onSelectEvent, onNavigate }) {
  const stats = overview || {}
  const total = Math.max(stats.allowedRequests + stats.blockedRequests, 1)
  const allowedPercent = Math.round((stats.allowedRequests / total) * 100)
  const categories = stats.attackCategories || []
  const activity = stats.activity || []
  return (
    <>
      <div className="status-banner">
        <span className={`status-dot ${health?.status === 'ok' ? 'live' : 'offline'}`} />
        <span><strong>{health?.status === 'ok' ? 'Protection active' : 'Backend unavailable'}</strong> · {health?.mode || 'Waiting for local API'}</span>
        <button className="text-button" onClick={() => onNavigate('Configuration')}>View configuration →</button>
      </div>
      <CloudFindingsPanel
        summary={cloudSummary}
        findings={cloudFindings}
        loading={cloudLoading}
        error={cloudError}
      />
      <MetricGrid overview={overview} />
      <section className="panel-grid two-col">
        <div className="panel">
          <PanelHeading title="Allowed vs blocked" aside={`${stats.totalRequests || 0} total requests`} />
          <div className="bar-stack" aria-label={`${allowedPercent}% allowed`}>
            <div className="bar-segment allowed" style={{ width: `${allowedPercent}%` }} />
            <div className="bar-segment blocked" style={{ width: `${100 - allowedPercent}%` }} />
          </div>
          <div className="legend-row">
            <span><i className="dot allowed" />Allowed {stats.allowedRequests || 0}</span>
            <span><i className="dot blocked" />Blocked {stats.blockedRequests || 0}</span>
          </div>
        </div>
        <div className="panel">
          <PanelHeading title="Threat activity trend" aside="Hourly request pattern" />
          <ThreatTrendChart activity={activity} />
        </div>
      </section>
      <section className="panel-grid two-col">
        <div className="panel">
          <PanelHeading title="Blocked request categories" aside="From security event log" />
          {categories.length ? <div className="category-list">
            {categories.map((item) => (
              <div key={item.category} className="category-row">
                <span>{item.category}</span><strong>{item.count}</strong>
              </div>
            ))}
          </div> : <EmptyState title="No detections yet" detail="Blocked request classifications will appear here." />}
        </div>
        <div className="panel">
          <PanelHeading title="Request activity" aside="Hourly event counts" />
          {activity.length ? <div className="mini-bars">
            {activity.map((point) => (
              <div key={point.hour} className="mini-bar-wrap" title={`${point.count} requests`}>
                <div className="mini-bar" style={{ height: `${Math.max((point.count / Math.max(...activity.map((entry) => entry.count))) * 100, 8)}%` }} />
                <span>{point.hour.slice(11)}:00</span>
              </div>
            ))}
          </div> : <EmptyState title="No activity data" detail="Requests will be charted once the proxy receives traffic." />}
        </div>
      </section>
      <OverviewCharts overview={stats} />
      <section className="panel-grid two-col">
        <div className="panel">
          <PanelHeading title="Recent security events" aside={<button className="text-button" onClick={() => onNavigate('Security Events')}>View all →</button>} />
          <EventList events={events} onSelectEvent={onSelectEvent} />
        </div>
      </section>
    </>
  )
}

function OverviewCharts({ overview }) {
  return (
    <section className="panel-grid chart-grid" aria-label="Security analytics charts">
      <div className="panel">
        <PanelHeading title="Severity distribution" aside="Events by severity" />
        <DonutChart data={overview.severityBreakdown} />
      </div>
      <div className="panel">
        <PanelHeading title="HTTP methods" aside="Request method mix" />
        <DonutChart data={overview.methodBreakdown} />
      </div>
      <div className="panel">
        <PanelHeading title="Response status codes" aside="Most common responses" />
        <HorizontalBarChart data={overview.statusCodeBreakdown} />
      </div>
      <div className="panel">
        <PanelHeading title="Most requested paths" aside="Top 6 paths" />
        <HorizontalBarChart data={overview.topPaths} />
      </div>
      <div className="panel">
        <PanelHeading title="Top client sources" aside="Top 6 source IPs" />
        <HorizontalBarChart data={overview.sourceBreakdown} />
      </div>
      <div className="panel">
        <PanelHeading title="Hourly request outcomes" aside="Allowed vs blocked" />
        <HourlyOutcomeChart data={overview.hourlyResults} />
      </div>
    </section>
  )
}

function DonutChart({ data = [] }) {
  const entries = data.filter((item) => item.count > 0)
  const total = entries.reduce((sum, item) => sum + item.count, 0)
  if (!total) return <EmptyState title="No event data" detail="Chart data will appear as requests are recorded." />

  const colors = ['#52d8e1', '#4cd5a5', '#fa7481', '#f4bc62', '#b098ff', '#ee8dc4']
  const radius = 35
  const circumference = 2 * Math.PI * radius
  let offset = 0

  return (
    <div className="donut-chart">
      <svg viewBox="0 0 100 100" role="img" aria-label={`Distribution of ${total} events`}>
        <circle cx="50" cy="50" r={radius} fill="none" stroke="rgba(144, 163, 190, .12)" strokeWidth="12" />
        {entries.map((item, index) => {
          const length = (item.count / total) * circumference
          const segment = (
            <circle
              key={item.label}
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              stroke={colors[index % colors.length]}
              strokeWidth="12"
              strokeDasharray={`${length} ${circumference - length}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 50 50)"
            >
              <title>{item.label}: {item.count}</title>
            </circle>
          )
          offset += length
          return segment
        })}
        <text x="50" y="48" textAnchor="middle" className="donut-total">{total.toLocaleString()}</text>
        <text x="50" y="59" textAnchor="middle" className="donut-caption">events</text>
      </svg>
      <div className="donut-legend">
        {entries.map((item, index) => (
          <div className="donut-legend-row" key={item.label}>
            <span><i style={{ backgroundColor: colors[index % colors.length] }} />{item.label}</span>
            <strong>{item.count}</strong>
          </div>
        ))}
      </div>
    </div>
  )
}

function HorizontalBarChart({ data = [] }) {
  const entries = data.filter((item) => item.count > 0)
  if (!entries.length) return <EmptyState title="No event data" detail="Chart data will appear as requests are recorded." />

  const maxValue = Math.max(...entries.map((item) => item.count), 1)
  return (
    <div className="horizontal-chart">
      {entries.map((item, index) => (
        <div className="horizontal-chart-row" key={item.label} title={`${item.label}: ${item.count}`}>
          <span className="horizontal-chart-label">{item.label}</span>
          <span className="horizontal-chart-track">
            <span className={`horizontal-chart-bar chart-color-${index % 6}`} style={{ width: `${(item.count / maxValue) * 100}%` }} />
          </span>
          <strong>{item.count}</strong>
        </div>
      ))}
    </div>
  )
}

function HourlyOutcomeChart({ data = [] }) {
  const entries = data.filter((item) => item.allowed + item.blocked > 0)
  if (!entries.length) return <EmptyState title="No activity data" detail="Requests will be charted once the proxy receives traffic." />

  const maxValue = Math.max(...entries.map((item) => item.allowed + item.blocked), 1)
  return (
    <div className="hourly-outcome-chart">
      <div className="hourly-outcome-bars">
        {entries.map((item) => {
          const total = item.allowed + item.blocked
          return (
            <div className="hourly-outcome-column" key={item.hour} title={`${item.hour}: ${item.allowed} allowed, ${item.blocked} blocked`}>
              <div className="hourly-outcome-stack" style={{ height: `${Math.max((total / maxValue) * 100, 4)}%` }}>
                <span className="hourly-allowed" style={{ flex: item.allowed || '0 0 0%' }} />
                <span className="hourly-blocked" style={{ flex: item.blocked || '0 0 0%' }} />
              </div>
              <span>{item.hour.slice(11, 13)}:00</span>
            </div>
          )
        })}
      </div>
      <div className="legend-row outcome-legend">
        <span><i className="dot allowed" />Allowed</span>
        <span><i className="dot blocked" />Blocked</span>
      </div>
    </div>
  )
}

function ThreatTrendChart({ activity }) {
  if (!activity?.length) {
    return <EmptyState title="No activity data" detail="Requests will be charted once the proxy receives traffic." />
  }

  const values = activity.map((point) => point.count)
  const maxValue = Math.max(...values, 1)
  const points = activity.map((point, index) => {
    const x = activity.length === 1 ? 50 : (index / (activity.length - 1)) * 100
    const y = 100 - (point.count / maxValue) * 72 - 12
    return `${x},${y}`
  })

  return (
    <div className="trend-chart-wrap">
      <svg className="trend-chart" viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="Threat activity trend chart">
        <polyline points={points.join(' ')} fill="none" stroke="#57dcc5" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="trend-axis-labels">
        {activity.map((point) => (
          <span key={point.hour}>{point.hour.slice(11, 16)}</span>
        ))}
      </div>
    </div>
  )
}

function MetricGrid({ overview }) {
  const metrics = [
    ['Total Requests', overview?.totalRequests ?? 0, 'cyan'],
    ['Allowed Requests', overview?.allowedRequests ?? 0, 'green'],
    ['Blocked Requests', overview?.blockedRequests ?? 0, 'red'],
    ['SSRF Attempts', overview?.ssrfAttempts ?? 0, 'amber'],
    ['Invalid Tokens', overview?.invalidTokenAttempts ?? 0, 'purple'],
    ['Security Alerts', overview?.securityAlerts ?? 0, 'pink'],
  ]
  return <section className="stats-grid">{metrics.map(([label, value, accent]) => (
    <div className={`metric-card ${accent}`} key={label}>
      <div className="metric-label">{label}</div><div className="metric-value">{value.toLocaleString()}</div>
      <div className="metric-foot">Persisted lab events</div>
    </div>
  ))}</section>
}

function LiveMonitoringPage({ events, overview, findings, alerts, summary, loading, error, cursor, nextCursor, setCursor, onSelectEvent }) {
  return (
    <>
      <CloudFindingsPanel
        summary={summary}
        findings={findings}
        loading={loading}
        error={error}
        cursor={cursor}
        nextCursor={nextCursor}
        onNext={() => nextCursor && setCursor(nextCursor)}
        onPrevious={() => setCursor(String(Math.max(Number(cursor) - 20, 0)))}
      />
      <section className="panel">
        <PanelHeading title="High and critical alerts" aside={`${alerts.length} open alerts`} />
        <FindingList findings={alerts} loading={loading} error={error} />
      </section>
      <MetricGrid overview={overview} />
      <div className="panel">
        <PanelHeading title="Proxy security event stream" aside="Newest events first · refreshes every 5 seconds" />
        <EventList events={events} onSelectEvent={onSelectEvent} showPath />
      </div>
    </>
  )
}

function CloudDataBadge({ health, error }) {
  if (error) return <span className="tag critical" title="Cloud findings could not be verified">SOURCE ERROR</span>
  if (!health) return <span className="tag muted">CHECKING SOURCE</span>
  if (health.mode === 'demo') return <span className="tag muted">DEMO DATA</span>
  if (health.mode === 'live' && health.liveVerified) return <span className="tag allowed">LIVE DATA · VERIFIED</span>
  return <span className="tag high">LIVE DATA · NOT VERIFIED</span>
}

function CloudFindingsPanel({ summary, findings, loading, error, cursor, nextCursor, onNext, onPrevious }) {
  return (
    <section className="panel cloud-findings-panel">
      <PanelHeading
        title="Cloud security findings"
        aside={summary ? `${summary.provider} · fetched ${summary.fetched_at}` : 'AWS Security Hub'}
      />
      {error ? (
        <EmptyState title="Cloud findings unavailable" detail={error} />
      ) : loading && !summary ? (
        <div className="loading-panel">Loading cloud security findings…</div>
      ) : summary ? (
        <>
          <div className="cloud-summary">
            <div><span>Total findings</span><strong>{summary.total}</strong></div>
            <div><span>Open</span><strong>{summary.open}</strong></div>
            <div><span>High</span><strong>{summary.high}</strong></div>
            <div><span>Critical</span><strong>{summary.critical}</strong></div>
          </div>
          {summary.truncated && <p className="cloud-truncated" role="status">Showing a bounded snapshot; additional findings may be omitted.</p>}
          <FindingList findings={findings} loading={loading} error={error} />
          {onNext && onPrevious && (
            <div className="finding-pagination">
              <button className="secondary-btn" onClick={onPrevious} disabled={!cursor || cursor === '0'}>Previous</button>
              <button className="secondary-btn" onClick={onNext} disabled={!nextCursor}>Next</button>
            </div>
          )}
        </>
      ) : <EmptyState title="No findings available" detail="The provider has not returned a findings snapshot." />}
    </section>
  )
}

function FindingList({ findings, loading, error }) {
  if (error) return <EmptyState title="Alerts unavailable" detail="Provider access failed; no demo findings were substituted." />
  if (loading && !findings.length) return <div className="loading-panel">Loading findings…</div>
  if (!findings.length) return <EmptyState title="No findings" detail="The provider returned no findings for this view." />
  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <article className="finding-card" key={finding.finding_id}>
          <div className="finding-card-heading">
            <strong>{finding.title}</strong>
            <span className={`tag ${finding.severity}`}>{finding.severity}</span>
          </div>
          <p>{finding.description || 'No description provided.'}</p>
          <div className="finding-meta">
            <span>{finding.resource_name || 'Resource unavailable'}</span>
            <span>{finding.resource_type || 'Unknown resource type'}</span>
            <span>{finding.status}</span>
            <span>{finding.cloud_provider.toUpperCase()}</span>
          </div>
          {finding.remediation && <p className="finding-remediation"><b>Remediation:</b> {finding.remediation}</p>}
          <time>Updated {finding.updated_at || 'not provided'}</time>
        </article>
      ))}
    </div>
  )
}

function ProwlerPage({
  health,
  status,
  findings,
  summary,
  compliance,
  history,
  loading,
  error,
  provider,
  setProvider,
  authorized,
  setAuthorized,
  query,
  setQuery,
  severity,
  setSeverity,
  serviceFilter,
  setServiceFilter,
  resourceFilter,
  setResourceFilter,
  cursor,
  nextCursor,
  setCursor,
  activeFinding,
  onSelectFinding,
  busy,
  onStartScan,
  onCancelScan,
}) {
  const activeScan = status?.active_scan
  const latestScan = status?.latest_scan
  const resultLabel = summary?.scan?.mode === 'live_scan'
    ? 'LIVE CLOUD SCAN'
    : summary?.scan?.mode === 'local_assessment'
      ? 'IAC SECURITY ASSESSMENT'
      : 'NO SCAN DATA'
  const providerReady = provider === 'iac'
    || health?.cloud_providers_ready?.[provider] === true

  return (
    <>
      <section className="panel prowler-controls">
        <div className="panel-heading">
          <div>
            <h2>IaC Security Assessment</h2>
            <p className="prowler-description">Run Prowler against supported infrastructure configuration files in this project. These results assess local files and are not findings from a deployed cloud account.</p>
          </div>
          <span className={`tag ${summary?.scan?.mode === 'live_scan' ? 'allowed' : summary?.scan?.mode === 'local_assessment' ? 'medium' : 'muted'}`}>{resultLabel}</span>
        </div>
        {error && <div className="notice error-notice" role="alert">{error}</div>}
        <div className="prowler-health-row">
          <span className={`status-dot ${health?.installed ? 'live' : 'offline'}`} />
          <span><b>Scanner:</b> {health?.installed ? `${health.version} · installed` : health?.error || 'Checking scanner availability…'}</span>
          <span><b>Scan status:</b> {activeScan ? `${activeScan.status} · ${activeScan.provider}` : latestScan ? `${latestScan.status} · ${latestScan.provider}` : 'No scans yet'}</span>
          <span><b>Last scan:</b> {latestScan?.completed_at || 'not available'}</span>
        </div>
        {health?.error && !health.installed && (
          <p className="prowler-help">Install Prowler on the backend to enable a real IaC assessment. No findings are shown until an actual scan completes.</p>
        )}
        <div className="prowler-scan-controls">
          <label className="prowler-field">
            <span>Scan target</span>
            <select value={provider} onChange={(event) => setProvider(event.target.value)}>
              <option value="iac">Local project · IaC (no cloud credentials)</option>
              <option value="aws" disabled={!health?.cloud_providers_ready?.aws}>AWS account (backend credentials required)</option>
              <option value="azure" disabled={!health?.cloud_providers_ready?.azure}>Azure subscription (backend credentials required)</option>
              <option value="gcp" disabled={!health?.cloud_providers_ready?.gcp}>Google Cloud project (backend credentials required)</option>
            </select>
          </label>
          {provider !== 'iac' && providerReady && (
            <label className="prowler-authorize">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(event) => setAuthorized(event.target.checked)}
              />
              I am authorized to scan this cloud account.
            </label>
          )}
          <button
            className="primary-btn"
            onClick={onStartScan}
            disabled={busy || !health?.installed || Boolean(activeScan) || !providerReady || (provider !== 'iac' && !authorized)}
          >
            {busy ? 'Working…' : provider === 'iac' ? 'Run local assessment' : 'Run live cloud scan'}
          </button>
          {activeScan && (
            <button className="danger-btn" onClick={onCancelScan} disabled={busy}>Cancel scan</button>
          )}
        </div>
        <p className="prowler-help">
          IaC assessments require no cloud account. Cloud-provider scans stay disabled until backend credentials are configured and still require explicit authorization; they are separate from local IaC results.
        </p>
      </section>

      <section className="panel">
        <div className="prowler-heading-row">
          <PanelHeading title="Findings" aside="Actual Prowler scan output only" />
        </div>
        <div className="cloud-summary">
          <div><span>Total findings</span><strong>{summary?.total_findings ?? '—'}</strong></div>
          <div><span>Critical</span><strong>{summary?.critical ?? '—'}</strong></div>
          <div><span>High</span><strong>{summary?.high ?? '—'}</strong></div>
          <div><span>Failed checks</span><strong>{summary?.failed_checks ?? '—'}</strong></div>
        </div>
        <div className="filters prowler-filters">
          <input aria-label="Search findings" placeholder="Search title, description, check, or resource" value={query} onChange={(event) => { setQuery(event.target.value); setCursor('0') }} />
          <select aria-label="Filter severity" value={severity} onChange={(event) => { setSeverity(event.target.value); setCursor('0') }}>
            <option value="">All severities</option>
            {['critical', 'high', 'medium', 'low', 'informational', 'unknown'].map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <input aria-label="Filter service" placeholder="Service" value={serviceFilter} onChange={(event) => { setServiceFilter(event.target.value); setCursor('0') }} />
          <input aria-label="Filter resource" placeholder="Resource" value={resourceFilter} onChange={(event) => { setResourceFilter(event.target.value); setCursor('0') }} />
        </div>
        {loading && !summary ? (
          <div className="loading-panel">Loading Prowler findings…</div>
        ) : error ? (
          <EmptyState title="Prowler data unavailable" detail={error} />
        ) : findings.length ? (
          <div className="table-wrap">
            <table className="prowler-table">
              <thead><tr><th>Finding</th><th>Check ID</th><th>Severity</th><th>Status</th><th>Affected file</th><th>Remediation</th></tr></thead>
              <tbody>
                {findings.map((finding, index) => (
                  <tr key={`${finding.finding_id}-${finding.scan_id || index}`} onClick={() => onSelectFinding(finding)}>
                    <td>{finding.title || finding.check_id || 'Untitled finding'}</td>
                    <td><code>{finding.check_id || '—'}</code></td>
                    <td><span className={`tag ${finding.severity}`}>{finding.severity}</span></td>
                    <td>{finding.status}</td>
                    <td><code>{finding.affected_file || 'Not provided'}</code></td>
                    <td className="prowler-remediation" title={finding.remediation || ''}>{finding.remediation || 'Not provided'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No scan findings yet"
            detail="Run a local IaC assessment. Findings appear only when returned in Prowler's actual report."
          />
        )}
        <div className="finding-pagination">
          <button className="secondary-btn" onClick={() => setCursor(String(Math.max(Number(cursor) - 25, 0)))} disabled={!cursor || cursor === '0'}>Previous</button>
          <button className="secondary-btn" onClick={() => nextCursor && setCursor(nextCursor)} disabled={!nextCursor}>Next</button>
        </div>
        {activeFinding && (
          <div className="event-detail-box">
            <div className="prowler-heading-row">
              <PanelHeading title={activeFinding.title || activeFinding.check_id} aside={`${activeFinding.provider} · ${activeFinding.status}`} />
              <button className="text-button" onClick={() => onSelectFinding(null)}>Close</button>
            </div>
            <dl className="detail-grid">
              <div><dt>Finding ID</dt><dd>{activeFinding.finding_id}</dd></div>
              <div><dt>Check ID</dt><dd>{activeFinding.check_id || 'Not provided'}</dd></div>
              <div><dt>Severity</dt><dd>{activeFinding.severity || 'Not provided'}</dd></div>
              <div><dt>Affected file</dt><dd>{activeFinding.affected_file || 'Not provided'}</dd></div>
              <div><dt>Resource</dt><dd>{activeFinding.resource_name || activeFinding.resource_id || 'Not provided'}</dd></div>
              <div><dt>Finding timestamp</dt><dd>{activeFinding.detected_at || activeFinding.last_updated || 'Not provided'}</dd></div>
              <div className="wide"><dt>Description</dt><dd>{activeFinding.description || 'Not provided'}</dd></div>
              <div className="wide"><dt>Remediation</dt><dd>{activeFinding.remediation || 'Not provided'}</dd></div>
              {activeFinding.raw && <div className="wide"><dt>Provider report</dt><dd><pre className="json-result">{JSON.stringify(activeFinding.raw, null, 2)}</pre></dd></div>}
            </dl>
          </div>
        )}
      </section>

      <div className="panel-grid two-col">
        <section className="panel">
          <PanelHeading title="Compliance coverage" aside={compliance?.scan_id ? `Scan ${compliance.scan_id.slice(0, 8)}` : 'Latest scan'} />
          {compliance?.frameworks?.length ? (
            <div className="resource-chips">{compliance.frameworks.map((framework) => <code key={framework}>{framework}</code>)}</div>
          ) : (
            <EmptyState title="No compliance frameworks reported" detail="Framework coverage appears only when included in the actual Prowler report." />
          )}
        </section>
        <section className="panel">
          <PanelHeading title="Recent scan history" aside={`${history.length} saved scans`} />
          {history.length ? (
            <div className="run-list">{history.map((scan) => (
              <div className="run-row" key={scan.scan_id}>
                <span>{scan.provider}</span><span>{scan.submitted_at}</span>
                <strong className={scan.status === 'completed' ? 'pass' : scan.status === 'failed' ? 'fail' : ''}>{scan.status} · {scan.findings_count} findings</strong>
              </div>
            ))}</div>
          ) : <EmptyState title="No scan history" detail="Completed, failed, and cancelled scan records will be listed here." />}
        </section>
      </div>
    </>
  )
}

function EventsPage({ events, activeEvent, onSelectEvent, query, setQuery, statusFilter, setStatusFilter, severityFilter, setSeverityFilter }) {
  return (
    <div className="panel">
      <div className="panel-heading-row">
        <PanelHeading title="Security event log" aside={`${events.length} matching events`} />
        <div className="filters">
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search events" aria-label="Search events" />
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label="Filter by status">
            <option value="all">All results</option><option value="allowed">Allowed</option><option value="blocked">Blocked</option>
          </select>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} aria-label="Filter by severity">
            <option value="all">All severities</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
          </select>
        </div>
      </div>
      <EventTable events={events} activeEvent={activeEvent} onSelectEvent={onSelectEvent} />
      {activeEvent && <EventDetails event={activeEvent} />}
    </div>
  )
}

function SsrfPage({ events, busy, onRun, onSelectEvent }) {
  return (
    <>
      <section className="panel ssrf-intro">
        <div>
          <div className="eyebrow">Detection policy</div>
          <h2>Destination validation and SSRF indicators</h2>
          <p>Every proxy request is constrained to the in-process mock metadata provider. The lab never sends requests to a user-supplied or cloud metadata URL.</p>
        </div>
        <button className="primary-btn" onClick={onRun} disabled={busy}>{busy ? 'Running…' : 'Run safe SSRF simulation'}</button>
      </section>
      <div className="panel">
        <PanelHeading title="Related detections" aside={`${events.length} matching events`} />
        <EventList events={events} onSelectEvent={onSelectEvent} showPath />
      </div>
    </>
  )
}

function TokenPage({ token, tokenExpiry, clock, tokenTtl, setTokenTtl, resource, setResource, metadataResult, busy, onAcquire, onRequest }) {
  const remaining = token && tokenExpiry ? Math.max(Math.ceil((tokenExpiry - clock) / 1000), 0) : 0
  const allowed = ['instance-id', 'hostname', 'instance-type', 'placement/availability-zone', 'region', 'iam/security-credentials', 'iam/security-credentials/demo-web-role']
  return (
    <div className="panel token-layout">
      <div className="token-copy">
        <div className="eyebrow">IMDSv2-style lab flow</div>
        <h2>Short-lived session tokens</h2>
        <p>Acquire a token using a PUT request, then present it to the metadata proxy. The in-memory token store is cleared when the backend restarts.</p>
        <label className="field-label" htmlFor="ttl">Token lifetime (seconds)</label>
        <div className="inline-controls">
          <input id="ttl" type="number" min="1" max="21600" value={tokenTtl} onChange={(event) => setTokenTtl(Number(event.target.value))} />
          <button className="primary-btn" onClick={onAcquire} disabled={busy}>{busy ? 'Working…' : 'Acquire token'}</button>
        </div>
        {token && <div className="token-value">
          <span>Current lab token</span><code>{token}</code><strong>{remaining ? `Expires in ${remaining}s` : 'Expired'}</strong>
        </div>}
      </div>
      <div className="token-request">
        <PanelHeading title="Request mock metadata" aside="GET through protected proxy" />
        <label className="field-label" htmlFor="resource">Allowlisted resource</label>
        <select id="resource" value={resource} onChange={(event) => setResource(event.target.value)}>
          {allowed.map((item) => <option value={item} key={item}>{item}</option>)}
        </select>
        <button className="secondary-btn" onClick={onRequest} disabled={busy || !token}>Send authorized request</button>
        {metadataResult && <pre className="json-result">{JSON.stringify(metadataResult, null, 2)}</pre>}
        {!metadataResult && <EmptyState title="No metadata response" detail="Acquire a token, select a field, and send a request." />}
      </div>
    </div>
  )
}

function RulesPage({ rules, busy, onToggle }) {
  return (
    <section className="rules-grid">
      <div className="rule-note"><strong>Secure lab boundary:</strong> external network forwarding is disabled in code and cannot be enabled from this page.</div>
      {rules.map((rule) => (
        <article className="panel rule-card" key={rule.rule_id}>
          <div className="rule-header">
            <div><h3>{rule.name}</h3><span className={`tag ${rule.enabled ? 'allowed' : 'muted'}`}>{rule.enabled ? 'Enabled' : 'Disabled'}</span></div>
            <button className={`switch ${rule.enabled ? 'on' : ''}`} role="switch" aria-checked={rule.enabled} aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.name}`} onClick={() => onToggle(rule)} disabled={busy}><span /></button>
          </div>
          <p>{rule.description}</p>
          <div className="rule-effect"><span>Security effect</span><p>{rule.effect}</p></div>
        </article>
      ))}
    </section>
  )
}

function TestCenterPage({ runs, selectedRun, busy, onRun, onOpenRun }) {
  return (
    <>
      <section className="panel test-hero">
        <div><div className="eyebrow">Backend verification</div><h2>Run the security test suite</h2><p>Eight cases issue requests to the running Flask application using its local test client. Each result is persisted in SQLite.</p></div>
        <button className="primary-btn" onClick={onRun} disabled={busy}>{busy ? 'Executing tests…' : 'Run all 8 tests'}</button>
      </section>
      <section className="panel">
        <PanelHeading title="Saved test executions" aside={`${runs.length} saved runs`} />
        {runs.length ? <div className="run-list">{runs.map((run) => (
          <button className={`run-row ${selectedRun?.id === run.id ? 'selected' : ''}`} key={run.id} onClick={() => onOpenRun(run.id)}>
            <span>Run #{run.id}</span><span>{run.timestamp}</span><strong className={run.passed === run.total ? 'pass' : 'fail'}>{run.passed}/{run.total} passed</strong>
          </button>
        ))}</div> : <EmptyState title="No saved test runs" detail="Run the suite to record results here." />}
      </section>
      {selectedRun && <section className="panel">
        <PanelHeading title={`Execution details · Run #${selectedRun.id}`} aside={selectedRun.timestamp} />
        <div className="test-results">
          {(selectedRun.results || []).map((test) => (
            <article key={test.name} className="test-result">
              <div className="test-result-top">
                <div><h3>{test.name}</h3><p>{test.description}</p></div>
                <strong className={test.pass ? 'pass' : 'fail'}>{test.pass ? 'PASS' : 'FAIL'}</strong>
              </div>
              <div className="test-metadata">
                <span>Expected <b>{test.expectedResult}</b></span>
                <span>Actual <b>{test.actualResult}</b></span>
                <span>HTTP <b>{test.actualStatus}</b></span>
              </div>
              <p className="security-explanation">{test.explanation}</p>
            </article>
          ))}
        </div>
      </section>}
    </>
  )
}

function ConfigurationPage({ configuration, health }) {
  if (!configuration) return <div className="panel"><EmptyState title="Configuration unavailable" detail="The backend has not returned its lab configuration." /></div>
  return (
    <div className="panel">
      <PanelHeading title="Runtime configuration" aside={health?.status === 'ok' ? 'API online' : 'API offline'} />
      <dl className="config-list">
        <div><dt>Environment</dt><dd>{configuration.mode}</dd></div>
        <div><dt>Mock service</dt><dd>{configuration.mockService}</dd></div>
        <div><dt>User-controlled destination forwarding</dt><dd>{configuration.externalRequestsEnabled ? 'Enabled' : 'Disabled by design'}</dd></div>
        <div><dt>Cloud findings mode</dt><dd>{configuration.cloudFindingsMode}</dd></div>
        <div><dt>Cloud findings provider</dt><dd>{configuration.cloudFindingsProvider}</dd></div>
        <div><dt>Default token TTL</dt><dd>{configuration.tokenTtlSeconds} seconds</dd></div>
        <div><dt>Maximum token TTL</dt><dd>{configuration.maximumTokenTtlSeconds} seconds</dd></div>
        <div><dt>API port</dt><dd>{configuration.apiPort}</dd></div>
      </dl>
      <h3 className="subheading">Approved mock resources</h3>
      <div className="resource-chips">{configuration.allowedResources.map((item) => <code key={item}>{item}</code>)}</div>
    </div>
  )
}

function EventList({ events, onSelectEvent, showPath = false }) {
  if (!events.length) return <EmptyState title="No events to display" detail="Events appear here after the proxy receives requests." />
  return <div className="event-feed">{events.map((event) => (
    <button className="feed-row" key={event.id} onClick={() => onSelectEvent(event)}>
      <span className={`event-marker ${event.result}`} />
      <span className="feed-main"><strong>{event.detection_reason}</strong>{showPath && <code>{event.method} {event.requested_path}</code>}</span>
      <span className={`tag ${event.severity}`}>{event.severity}</span>
      <time>{event.timestamp}</time>
    </button>
  ))}</div>
}

function EventTable({ events, activeEvent, onSelectEvent }) {
  if (!events.length) return <EmptyState title="No matching events" detail="Try changing the status, severity, or search filters." />
  return <div className="table-wrap"><table>
    <thead><tr><th>Timestamp</th><th>Source</th><th>Path</th><th>Method</th><th>Reason</th><th>Severity</th><th>Result</th><th>HTTP</th></tr></thead>
    <tbody>{events.map((event) => (
      <tr key={event.id} onClick={() => onSelectEvent(event)} className={activeEvent?.id === event.id ? 'selected' : ''} tabIndex={0} onKeyDown={(keyEvent) => { if (keyEvent.key === 'Enter') onSelectEvent(event) }}>
        <td>{event.timestamp}</td><td>{event.source}</td><td><code>{event.requested_path}</code></td><td>{event.method}</td><td>{event.detection_reason}</td>
        <td><span className={`tag ${event.severity}`}>{event.severity}</span></td><td><span className={`tag ${event.result}`}>{event.result}</span></td><td>{event.status_code}</td>
      </tr>
    ))}</tbody>
  </table></div>
}

function EventDetails({ event }) {
  return <div className="event-detail-box">
    <PanelHeading title={`Event #${event.id} details`} aside={`${event.severity} severity`} />
    <dl className="detail-grid">
      <div><dt>Timestamp</dt><dd>{event.timestamp}</dd></div><div><dt>Source</dt><dd>{event.source}</dd></div>
      <div><dt>Request</dt><dd>{event.method} {event.requested_path}</dd></div><div><dt>HTTP status</dt><dd>{event.status_code}</dd></div>
      <div className="wide"><dt>Detection reason</dt><dd>{event.detection_reason}</dd></div>
    </dl>
  </div>
}

function PanelHeading({ title, aside }) {
  return <div className="panel-heading"><h2>{title}</h2>{aside && <span>{aside}</span>}</div>
}

function EmptyState({ title, detail }) {
  return <div className="empty-state"><span className="empty-icon">◇</span><strong>{title}</strong><p>{detail}</p></div>
}

export default App
