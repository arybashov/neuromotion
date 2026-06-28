/* Лёгкий клиентский заслон для GitHub Pages.
 * ВНИМАНИЕ: это НЕ настоящая защита — контент уходит в браузер, технарь обойдёт
 * (devtools / view-source). Отсекает только случайных посетителей.
 *
 * Пароль в исходнике не хранится — только SHA-256-хэш. Хэш считается чистым JS
 * (работает по HTTP и HTTPS, без зависимости от crypto.subtle / secure context).
 *
 * Сменить пароль: в консоли браузера на странице сайта выполнить
 *   pgSha256('НОВЫЙ_ПАРОЛЬ')
 * и вставить полученный хэш в PASSWORD_HASH ниже.
 */
(function () {
  'use strict';
  var KEY = 'pg_auth_v1';
  // default password: poligon2026  (поменяй хэш по инструкции выше)
  var PASSWORD_HASH = 'e8fe21ea200e0db011dd6e2398aefe042c855cc1e7b47ff2e3e16999e9e15321';

  // --- компактный SHA-256 (geraintluff), вход — UTF-8 байты строки ---
  function sha256(ascii) {
    function rr(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
    var mathPow = Math.pow, maxWord = mathPow(2, 32), result = '', words = [];
    var asciiBitLength = ascii.length * 8;
    var hash = sha256.h = sha256.h || [], k = sha256.k = sha256.k || [];
    var primeCounter = k.length, isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (var i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (var i = 0; i < ascii.length; i++) {
      var j = ascii.charCodeAt(i);
      if (j >> 8) return '';
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;
    for (var j = 0; j < words.length;) {
      var w = words.slice(j, j += 16), oldHash = hash;
      hash = hash.slice(0, 8);
      for (var i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
        var t1 = hash[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & hash[5]) ^ (~e & hash[6])) + k[i] +
          (w[i] = (i < 16) ? w[i] : (
            w[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) +
            w[i - 7] + (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))
          ) | 0);
        var t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(t1 + t2) | 0].concat(hash);
        hash[4] = (hash[4] + t1) | 0;
      }
      for (var i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (var i = 0; i < 8; i++) {
      for (var j = 3; j + 1; j--) {
        var b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? 0 : '') + b.toString(16);
      }
    }
    return result;
  }
  function pgSha256(str) { return sha256(unescape(encodeURIComponent(str))); }
  window.pgSha256 = pgSha256; // для смены пароля из консоли

  // Локальный запуск (dev-сервер на этой же машине) — без пароля.
  // LAN-доступ (телефон по IP) и продакшен на GitHub Pages остаются под заслоном.
  try {
    var h = location.hostname;
    if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return;
  } catch (e) {}

  try { if (sessionStorage.getItem(KEY) === '1') return; } catch (e) {}

  var overlay = document.createElement('div');
  overlay.id = 'pg-auth-gate';
  overlay.setAttribute('style', [
    'position:fixed', 'inset:0', 'z-index:2147483647', 'background:#0a0a0a',
    'display:flex', 'align-items:center', 'justify-content:center',
    'font-family:system-ui,-apple-system,sans-serif'
  ].join(';'));
  overlay.innerHTML =
    '<div style="width:320px;max-width:86vw;padding:28px 26px;border:1px solid rgba(138,155,255,.4);' +
      'border-radius:10px;background:#111;box-shadow:0 0 30px rgba(138,155,255,.15);text-align:center">' +
      '<div style="font:700 14px monospace;letter-spacing:.12em;color:#8a9bff;text-transform:uppercase;margin-bottom:6px">ПОЛИГОН 3D</div>' +
      '<div style="font-size:13px;color:#999;margin-bottom:18px">Доступ по паролю</div>' +
      '<input id="pg-auth-input" type="password" autocomplete="current-password" placeholder="Пароль" ' +
        'style="width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid rgba(138,155,255,.35);' +
        'border-radius:6px;background:#0a0a0a;color:#fff;font-size:16px;outline:none">' +
      '<div id="pg-auth-err" style="height:16px;margin:8px 0 4px;color:#e06a6a;font-size:12px"></div>' +
      '<button id="pg-auth-btn" type="button" ' +
        'style="width:100%;padding:11px;border:1px solid #8a9bff;border-radius:6px;background:transparent;' +
        'color:#8a9bff;font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:.05em;cursor:pointer">Войти</button>' +
    '</div>';

  document.documentElement.appendChild(overlay);
  document.addEventListener('DOMContentLoaded', function () {
    var i = document.getElementById('pg-auth-input'); if (i) i.focus();
  });
  var inp0 = document.getElementById('pg-auth-input'); if (inp0) inp0.focus();

  function check() {
    var input = document.getElementById('pg-auth-input');
    var err = document.getElementById('pg-auth-err');
    var pw = input ? input.value : '';
    if (pgSha256(pw) === PASSWORD_HASH) {
      try { sessionStorage.setItem(KEY, '1'); } catch (e) {}
      overlay.remove();
    } else {
      if (err) err.textContent = 'Неверный пароль';
      if (input) { input.value = ''; input.focus(); }
    }
  }

  overlay.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'pg-auth-btn') check();
  });
  overlay.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); check(); }
  });
})();
