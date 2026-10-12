(function () {
  'use strict';

  var form = document.getElementById('gateForm');
  var input = document.getElementById('passphrase');
  var error = document.getElementById('gateError');
  var gate = document.getElementById('gate');
  var wrap = document.getElementById('resumeWrap');
  var frame = document.getElementById('resumeFrame');

  var toolbar = document.getElementById('resumeToolbar');
  var statusEl = document.getElementById('resumeStatus');
  var historyPanel = document.getElementById('historyPanel');
  var historyList = document.getElementById('historyList');
  var sigInput = document.getElementById('sigInput');

  var CUR_KEY = 'jeffin.resume.current';
  var VER_KEY = 'jeffin.resume.versions';
  var MAX_VERSIONS = 25;

  var passphrase = '';
  var originalHtml = '';
  var saveTimer = null;
  var resizeTimer = null;

  /* ---------- crypto ---------- */

  function b64toBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function decrypt(payload, pass) {
    var enc = new TextEncoder();
    var material = await crypto.subtle.importKey(
      'raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']
    );
    var key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64toBytes(payload.salt), iterations: payload.iterations, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    var data = b64toBytes(payload.data);
    var tag = b64toBytes(payload.tag);
    var ciphertext = new Uint8Array(data.length + tag.length);
    ciphertext.set(data);
    ciphertext.set(tag, data.length);
    var plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64toBytes(payload.iv), tagLength: 128 },
      key,
      ciphertext
    );
    return new TextDecoder().decode(plain);
  }

  /* ---------- helpers ---------- */

  function setStatus(text, saved) {
    statusEl.textContent = text;
    statusEl.className = 'tb-status' + (saved ? ' saved' : '');
  }

  function timeLabel(ts) {
    return new Date(ts).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  }

  function safeSet(key, value) {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      setStatus('Storage full — export to keep your edits');
      return false;
    }
  }

  /* Serialize the live resume, stripping editor-only markup. */
  function cleanHtml() {
    var doc = frame.contentDocument;
    if (!doc || !doc.documentElement) return originalHtml;
    var clone = doc.documentElement.cloneNode(true);
    clone.querySelectorAll('[contenteditable]').forEach(function (el) {
      el.removeAttribute('contenteditable');
    });
    clone.querySelectorAll('.empty').forEach(function (el) {
      el.classList.remove('empty');
    });
    var body = clone.querySelector('body');
    if (body) body.classList.remove('editing');
    var slot = clone.querySelector('#signature-slot');
    if (slot) slot.classList.remove('empty');
    return '<!DOCTYPE html>\n' + clone.outerHTML;
  }

  function resizeFrame() {
    try {
      var doc = frame.contentDocument;
      if (!doc || !doc.documentElement) return;
      frame.style.height = Math.max(doc.documentElement.scrollHeight, 600) + 'px';
    } catch (e) { /* ignore */ }
  }

  /* ---------- persistence ---------- */

  function saveCurrent() {
    if (!safeSet(CUR_KEY, cleanHtml())) return;
    setStatus('All changes saved · ' + new Date().toLocaleTimeString(), true);
  }

  function debounceSave() {
    clearTimeout(saveTimer);
    setStatus('Editing…');
    saveTimer = setTimeout(saveCurrent, 700);
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(resizeFrame, 120);
  }

  function getVersions() {
    try { return JSON.parse(localStorage.getItem(VER_KEY) || '[]'); }
    catch (e) { return []; }
  }

  function setVersions(list) {
    safeSet(VER_KEY, JSON.stringify(list));
  }

  function snapshot(note) {
    var list = getVersions();
    list.unshift({ ts: Date.now(), note: note || 'Manual save', html: cleanHtml() });
    if (list.length > MAX_VERSIONS) list = list.slice(0, MAX_VERSIONS);
    setVersions(list);
    renderHistory();
    setStatus('Version saved · ' + new Date().toLocaleTimeString(), true);
  }

  function renderHistory() {
    var list = getVersions();
    historyList.innerHTML = '';
    if (!list.length) {
      historyList.innerHTML = '<div class="hist-empty">No saved versions yet.</div>';
      return;
    }
    list.forEach(function (item, i) {
      var row = document.createElement('div');
      row.className = 'hist-row';

      var meta = document.createElement('div');
      meta.className = 'hist-meta';
      var title = document.createElement('b');
      title.textContent = item.note || 'Version';
      var when = document.createElement('span');
      when.textContent = timeLabel(item.ts);
      meta.appendChild(title);
      meta.appendChild(when);

      var restore = document.createElement('button');
      restore.type = 'button';
      restore.textContent = 'Restore';
      restore.addEventListener('click', function () { restoreVersion(i); });

      var del = document.createElement('button');
      del.type = 'button';
      del.className = 'ghost';
      del.textContent = 'Delete';
      del.addEventListener('click', function () {
        var v = getVersions();
        v.splice(i, 1);
        setVersions(v);
        renderHistory();
      });

      row.appendChild(meta);
      row.appendChild(restore);
      row.appendChild(del);
      historyList.appendChild(row);
    });
  }

  function restoreVersion(index) {
    var list = getVersions();
    var item = list[index];
    if (!item) return;
    if (!window.confirm('Restore version from ' + timeLabel(item.ts) + '?\nYour current edits will be replaced.')) return;
    if (!safeSet(CUR_KEY, item.html)) return;
    render(item.html);
    setStatus('Restored · ' + timeLabel(item.ts));
    historyPanel.classList.remove('open');
  }

  /* ---------- rendering / editing ---------- */

  function enableEditing() {
    var doc = frame.contentDocument;
    if (!doc || !doc.body) return;

    doc.body.classList.add('editing');
    doc.body.contentEditable = 'true';
    doc.body.spellcheck = false;

    var slot = doc.getElementById('signature-slot');
    if (slot && !slot.querySelector('img')) {
      slot.classList.add('empty');
      if (!slot.textContent.trim()) slot.textContent = 'Name & Signature';
    }

    doc.body.addEventListener('input', debounceSave);
    resizeFrame();
  }

  function render(html) {
    frame.onload = function () { enableEditing(); };
    frame.srcdoc = html;
  }

  /* ---------- signature ---------- */

  function addSignature(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var doc = frame.contentDocument;
      var slot = doc && doc.getElementById('signature-slot');
      if (!slot) return;
      slot.classList.remove('empty');
      slot.innerHTML = '';
      var img = doc.createElement('img');
      img.src = reader.result;
      img.alt = 'Signature';
      slot.appendChild(img);
      saveCurrent();
      setStatus('Signature added', true);
    };
    reader.readAsDataURL(file);
  }

  /* ---------- export ---------- */

  function exportHtml() {
    var blob = new Blob([cleanHtml()], { type: 'text/html' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'Jeffin-Issac-Resume.html';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus('Exported HTML file', true);
  }

  function revertOriginal() {
    if (!window.confirm('Discard all edits and reload the original resume?')) return;
    snapshot('Before revert');
    localStorage.removeItem(CUR_KEY);
    render(originalHtml);
    setStatus('Reverted to original');
  }

  /* ---------- toolbar wiring ---------- */

  document.getElementById('btnSave').addEventListener('click', function () { snapshot('Manual save'); });
  document.getElementById('btnHistory').addEventListener('click', function () {
    renderHistory();
    historyPanel.classList.toggle('open');
  });
  document.getElementById('btnSig').addEventListener('click', function () { sigInput.click(); });
  document.getElementById('btnExport').addEventListener('click', exportHtml);
  document.getElementById('btnRevert').addEventListener('click', revertOriginal);
  document.getElementById('btnPrint').addEventListener('click', printResume);
  sigInput.addEventListener('change', function () {
    if (this.files && this.files[0]) addSignature(this.files[0]);
    this.value = '';
  });

  document.addEventListener('click', function (e) {
    if (!historyPanel.classList.contains('open')) return;
    if (historyPanel.contains(e.target)) return;
    if (document.getElementById('btnHistory').contains(e.target)) return;
    historyPanel.classList.remove('open');
  });

  function printResume() {
    try {
      saveCurrent();
      frame.contentWindow.focus();
      frame.contentWindow.print();
    } catch (e) { /* ignore */ }
  }

  /* ---------- unlock ---------- */

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var entered = input.value;
    if (!entered) return;
    error.style.display = 'none';

    var payload = window.RESUME_SECRET;
    if (!payload) {
      error.textContent = 'Resume data not loaded.';
      error.style.display = 'block';
      return;
    }

    try {
      passphrase = entered;
      originalHtml = await decrypt(payload, passphrase);

      var saved = null;
      try { saved = localStorage.getItem(CUR_KEY); } catch (err) { saved = null; }

      render(saved || originalHtml);

      gate.style.display = 'none';
      wrap.style.display = 'block';
      toolbar.classList.add('open');

      if (!getVersions().length) {
        setVersions([{ ts: Date.now(), note: 'Original (decrypted)', html: originalHtml }]);
      }
      renderHistory();
      setStatus(saved ? 'Loaded your saved edits' : 'Showing original resume');
    } catch (err) {
      error.textContent = 'Incorrect passphrase. Try again.';
      error.style.display = 'block';
      input.select();
    }
  });

  window.printResume = printResume;

  input.focus();
})();
