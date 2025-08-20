// ---------------- Tabs ----------------
const tabs = document.querySelectorAll('.tab');
const panels = {
  session: document.getElementById('panel-session'),
  cookie:  document.getElementById('panel-cookie'),
  jwt:     document.getElementById('panel-jwt'),
  social:  document.getElementById('panel-social'),
};
tabs.forEach(t => t.addEventListener('click', () => {
  tabs.forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  Object.values(panels).forEach(p => p.classList.remove('active'));
  panels[t.dataset.tab].classList.add('active');
}));

// ---------------- Helpers ----------------
const $ = s => document.querySelector(s);
const log = (msg, cls='') => { const c=$('#console'); const line = document.createElement('div'); line.className=cls; line.textContent = typeof msg==='string'? msg : JSON.stringify(msg,null,2); c.appendChild(line); c.scrollTop=c.scrollHeight; };
$('#btnClear').onclick = () => $('#console').textContent = '';

function getCookie(name){
  const m = document.cookie.match('(^|;)\\s*'+name+'\\s*=\\s*([^;]+)');
  return m ? decodeURIComponent(m.pop()) : '';
}

// CSRF 헤더 붙이는 fetch 래퍼(필요시 사용)
async function fetchWithCsrf(url, options={}){
  const token = getCookie('XSRF-TOKEN'); // CookieCsrfTokenRepository.withHttpOnlyFalse()
  const headers = new Headers(options.headers || {});
  if (token) headers.set('X-XSRF-TOKEN', token);
  return fetch(url, { ...options, headers, credentials:'include' });
}

// ---------------- Session login ----------------
const formSession = $('#form-session');
$('#btnSessionLogin').onclick = async () => {
  const payload = {
    loginId: formSession.loginId.value,
    password: formSession.password.value
  };
  const res = await fetch('/api/session/login', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    credentials:'include',
    body: JSON.stringify(payload)
  });
  log(`Session Login → ${res.status} ${res.ok?'OK':'FAIL'}`, res.ok?'ok':'err');
};

$('#btnSessionMe').onclick = async () => {
  const res = await fetch('/api/session/me', { credentials:'include' });
  const data = await res.json().catch(()=>null);
  log(data || `status=${res.status}`, res.ok?'ok':'err');
};

$('#btnSessionLogout').onclick = async () => {
  const res = await fetch('/api/session/logout', { method:'POST', credentials:'include' });
  log(`Session Logout → ${res.status}`, res.ok?'ok':'err');
};

// ---------------- Signed-Cookie login ----------------
const formCookie = $('#form-cookie');
$('#btnCookieLogin').onclick = async () => {
  const payload = {
    loginId: formCookie.loginId.value,
    password: formCookie.password.value
  };
  const res = await fetch('/api/cookie/login', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    credentials:'include',
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(()=>null);
  log(data || `status=${res.status}`, res.ok?'ok':'err');
};

// 보호 API
$('#btnCookiePing').onclick = async () => {
  const res = await fetch('/api/cookie/me', { credentials:'include' });
  const data = await res.json().catch(()=>null);
  log(data || `status=${res.status}`, res.ok?'ok':'err');
};

$('#btnCookieLogout').onclick = async () => {
  const res = await fetch('/api/cookie/logout', { method:'POST', credentials:'include' });
  log(`Cookie Logout → ${res.status}`, res.ok?'ok':'err');
};

// ---------------- JWT login ----------------
let accessToken = '';           // 메모리
const formJwt = document.querySelector('#form-jwt');

document.getElementById('btnJwtLogin').onclick = async () => {
  const payload = {
    loginId: formJwt.loginId.value,
    password: formJwt.password.value
  };
  const res = await fetch('/api/jwt/login', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(()=>null);

  if (res.ok && data && data.accessToken) {
    accessToken = data.accessToken;

    // 홈에서 쓰도록 sessionStorage에 저장
    sessionStorage.setItem('accessToken', accessToken);

    // 토큰을 콘솔에 표시
    log({ message: 'JWT 로그인 성공', accessToken: data.accessToken, refreshToken: data.refreshToken }, 'ok');
  } else {
    log(data || `status=${res.status}`, 'err');
  }
};

// JWT 보호 API
document.getElementById('btnJwtPing').onclick = async () => {
  const res = await fetch('/api/jwt/protected', {
    headers: accessToken ? { Authorization: 'Bearer ' + accessToken } : {}
  });
  const data = await res.json().catch(()=>null);
  log(data || `status=${res.status}`, res.ok?'ok':'err');
};

// 토큰 삭제(로그아웃 대용)
document.getElementById('btnJwtLogout').onclick = () => {
  accessToken = '';
  sessionStorage.removeItem('accessToken');
  log('accessToken 제거(메모리+sessionStorage)', 'ok');
};

// 공통: JSON 안전 파서
async function safeJson(res) {
  try { return await res.json(); } catch(e) { return null; }
}

// 로그인 상태 확인: 세션/쿠키/JWT 순서로 체크
async function checkAnyLogin() {
  // 1) 세션
  try {
    const r = await fetch('/api/session/me', { credentials:'include' });
    if (r.ok) return { ok:true, type:'session', data: await safeJson(r) };
  } catch(e){}

  // 2) 서명 쿠키
  try {
    const r = await fetch('/api/cookie/me', { credentials:'include' });
    if (r.ok) return { ok:true, type:'cookie', data: await safeJson(r) };
  } catch(e){}

  // 3) JWT (데모: 메모리 accessToken 사용)
  if (typeof accessToken === 'string' && accessToken) {
    try {
      const r = await fetch('/api/jwt/protected', {
        headers: { 'Authorization': 'Bearer ' + accessToken }
      });
      if (r.ok) return { ok:true, type:'jwt', data: await safeJson(r) };
    } catch(e){}
  }

  return { ok:false };
}

// 버튼 바인딩
document.getElementById('btnGoHome').onclick = async () => {
  const result = await checkAnyLogin();
  if (result.ok) {
    log(`로그인 확인됨 → ${result.type}`, 'ok');
    location.href = '/home';
  } else {
    log('로그인 된 계정이 없습니다.', 'err');
    alert('로그인 된 계정이 없습니다.');
  }
};
