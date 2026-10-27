const runButton = document.querySelector('#runButton');
const downloadButton = document.querySelector('#downloadButton');
const status = document.querySelector('#status');
const sections = ['summarySection', 'tableSection', 'detailSection', 'graphSection'].map((id) => document.querySelector(`#${id}`));
const COLORS = ['#60d5ff', '#f6c85f', '#6ee7b7', '#f28bb8', '#b794f4'];

function escapeHtml(value) { return String(value).replace(/[&<>"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[char]); }

function drawGraph(records) {
  const canvas = document.querySelector('#consistencyGraph');
  const context = canvas.getContext('2d');
  context.clearRect(0, 0, canvas.width, canvas.height);
  const clients = ['selenium', 'requests'];
  clients.forEach((client, row) => {
    const entries = records[client] || [];
    const colorByHash = new Map();
    context.fillStyle = '#b8c9dc'; context.font = '14px system-ui'; context.fillText(client, 18, 42 + row * 82);
    entries.forEach((entry, index) => {
      const hash = entry.ja3_md5;
      if (!colorByHash.has(hash)) colorByHash.set(hash, COLORS[colorByHash.size % COLORS.length]);
      context.fillStyle = colorByHash.get(hash);
      context.fillRect(130 + index * 125, 22 + row * 82, 100, 36);
      context.fillStyle = '#07121f'; context.fillText(`#${entry.run}`, 165 + index * 125, 45 + row * 82);
    });
  });
}

function render(payload) {
  const { running, logs, summary } = payload;
  const selenium = summary.clients.selenium;
  const requests = summary.clients.requests;
  status.textContent = running ? `실험 실행 중 — Selenium ${selenium.count}/5, requests ${requests.count}/5 캡처됨` : (selenium.count || requests.count ? '실험 완료 — 실제 캡처 결과입니다.' : '측정 대기 중 — 실제 실험을 시작하면 결과가 표시됩니다.');
  document.querySelector('#logs').textContent = logs.length ? logs.join('\n') : '아직 실행 로그가 없습니다.';
  if (!selenium.count && !requests.count) return;
  sections.forEach((section) => { section.hidden = false; });
  downloadButton.classList.toggle('disabled', running);
  const comparison = summary.comparison;
  document.querySelector('#summary').innerHTML = `<div class="summary-grid">
    <div class="metric">Selenium Chrome<strong>${selenium.count}/5 captures</strong>JA3 일관성: ${selenium.consistent_ja3 ? '일관' : '변동 또는 대기'}</div>
    <div class="metric">Python requests<strong>${requests.count}/5 captures</strong>JA3 일관성: ${requests.consistent_ja3 ? '일관' : '변동 또는 대기'}</div>
    <div class="metric">클라이언트 비교<strong>${escapeHtml(comparison.verdict)}</strong>${comparison.available ? (comparison.same_ja3 ? '같은 JA3는 정상적인 실험 결과입니다.' : '자동화 여부를 단정하지 않습니다.') : '양쪽 캡처가 필요합니다.'}</div>
    <div class="metric">전송 경로 확인<strong>${summary.loopback_peer_only ? '127.0.0.1 loopback 확인' : '확인 필요'}</strong>${summary.loopback_peer_only ? '서버가 직접 loopback peer를 관측했습니다.' : 'proxy/VPN/보안 장비 설정과 로그의 peer를 확인하세요.'}</div>
  </div>`;
  const all = [...(summary.records.selenium || []), ...(summary.records.requests || [])];
  document.querySelector('#records').innerHTML = all.map((item) => `<tr><td>${item.client}</td><td>${item.run}</td><td>${item.peer}</td><td>${item.ja3_md5}</td><td>${item.normalized_comparison_md5}</td><td>${item.cipher_suites_without_grease.length}</td><td>${item.extensions_without_grease.length}</td></tr>`).join('');
  document.querySelector('#details').textContent = comparison.available ? JSON.stringify({
    cipher_suites: comparison.cipher_suites,
    extensions: comparison.extensions,
    supported_groups: comparison.supported_groups,
    extension_order_equal: comparison.extension_order_equal,
  }, null, 2) : '양쪽 클라이언트의 캡처가 완료되면 차이를 계산합니다.';
  drawGraph(summary.records);
}

async function refresh() {
  try {
    const response = await fetch('/api/results');
    if (!response.ok) throw new Error(`API 응답 ${response.status}`);
    render(await response.json());
  } catch (error) {
    status.textContent = '대시보드 서버에 연결할 수 없습니다. run.bat을 실행한 뒤 http://127.0.0.1:5000 으로 접속하세요.';
    document.querySelector('#logs').textContent = `연결 오류: ${error.message}`;
  }
}

runButton.addEventListener('click', async () => {
  try {
    const response = await fetch('/api/run', { method: 'POST' });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.message || `API 응답 ${response.status}`);
    runButton.disabled = true;
    await refresh();
    const timer = setInterval(async () => {
      try {
        const latest = await fetch('/api/results').then((reply) => reply.json());
        render(latest);
        if (!latest.running) { clearInterval(timer); runButton.disabled = false; refresh(); }
      } catch (error) {
        clearInterval(timer); runButton.disabled = false;
        status.textContent = `실험 상태를 불러오지 못했습니다: ${error.message}`;
      }
    }, 900);
  } catch (error) {
    status.textContent = `실험을 시작하지 못했습니다: ${error.message}`;
    runButton.disabled = false;
  }
});

refresh();

