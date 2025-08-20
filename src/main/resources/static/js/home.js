const $ = s => document.querySelector(s);
const log = (msg) => {
  const c = $('#console');
  c.textContent += (typeof msg==='string' ? msg : JSON.stringify(msg, null, 2)) + '\n';
  c.scrollTop = c.scrollHeight;
};
const safeJson = async (r) => { try { return await r.json(); } catch { return null; } };

// 로그인 페이지에서 저장해둔 JWT 복구 (세션/쿠키는 쿠키로 자동 전송됨)
let accessToken = sessionStorage.getItem('accessToken') || '';

const isSuccess = (body) => {
  if (!body) return false;
  // CommonResponse V1: { code: 0, data: {...} }
  if (typeof body.code === 'number') return body.code === 0;
  // CommonResponse V2: { status: 200, data: {...} }
  if (typeof body.status === 'number') return body.status === 200;
  // 마지막 안전장치: data가 있으면 성공으로 취급
  return !!body.data;
};

// 통합 me 호출
async function fetchMe() {
  const headers = {};
  if (accessToken) headers['Authorization'] = 'Bearer ' + accessToken; // JWT면 헤더 필요
  const r = await fetch('/api/common/me', { credentials: 'include', headers });
  const body = await safeJson(r);
  return { ok: r.ok, body };
}

document.addEventListener('DOMContentLoaded', async () => {
  const { ok, body } = await fetchMe();
  if (!ok || !isSuccess(body)) {
    $('#username').textContent = '게스트';
    $('#authType').textContent = '(not logged in)';
    log(body || 'me 호출 실패');
    return;
  }

  const d = body.data || {};
  $('#username').textContent = d.nickname || d.loginId || 'user';
  // authType: 역할(권한)을 보여주고 싶다면 role 사용
  $('#authType').textContent = '(' + (d.role || 'USER') + ')';
  log('로그인 상태 확인 완료');
});


// ----- Buttons -----
$('#btnSessionMe').onclick = async () => {
  const r = await fetch('/api/session/me', { credentials:'include' });
  log(await safeJson(r) || `status=${r.status}`);
};
$('#btnSessionLogout').onclick = async () => {
  const r = await fetch('/api/session/logout', { method:'POST', credentials:'include' });
  log(`Session logout → ${r.status}`);
};

$('#btnCookieMe').onclick = async () => {
  const r = await fetch('/api/cookie/me', { credentials:'include' });
  log(await safeJson(r) || `status=${r.status}`);
};
$('#btnCookieLogout').onclick = async () => {
  const r = await fetch('/api/cookie/logout', { method:'POST', credentials:'include' });
  log(`Cookie logout → ${r.status}`);
};

$('#btnJwtPing').onclick = async () => {
  const r = await fetch('/api/jwt/protected', {
    headers: accessToken ? { Authorization:'Bearer '+accessToken } : {}
  });
  log(await safeJson(r) || `status=${r.status}`);
};
$('#btnJwtClear').onclick = () => {
  accessToken = '';
  sessionStorage.removeItem('accessToken');
  log('accessToken 제거(메모리+sessionStorage)');
};

$('#btnLogoutAll').onclick = async () => {
  try { await fetch('/api/session/logout', { method:'POST', credentials:'include' }); } catch(e){}
  try { await fetch('/api/cookie/logout',  { method:'POST', credentials:'include' }); } catch(e){}
  accessToken = '';
  sessionStorage.removeItem('accessToken');
  alert('로그아웃 처리되었습니다.');
  location.href = '/login';
};

$('#btnClear').onclick = () => { $('#console').textContent = ''; };
