(function () {
  var form = document.getElementById('gateForm');
  var input = document.getElementById('passphrase');
  var error = document.getElementById('gateError');
  var gate = document.getElementById('gate');
  var wrap = document.getElementById('resumeWrap');
  var frame = document.getElementById('resumeFrame');

  function b64toBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function decrypt(payload, passphrase) {
    var enc = new TextEncoder();
    var material = await crypto.subtle.importKey(
      'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
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

  function resizeFrame() {
    try {
      var doc = frame.contentDocument || frame.contentWindow.document;
      var height = doc.body.scrollHeight;
      frame.style.height = Math.max(height, 600) + 'px';
    } catch (e) { /* ignore cross-origin issues */ }
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var passphrase = input.value;
    if (!passphrase) return;
    error.style.display = 'none';

    var payload = window.RESUME_SECRET;
    if (!payload) {
      error.textContent = 'Resume data not loaded.';
      error.style.display = 'block';
      return;
    }

    try {
      var html = await decrypt(payload, passphrase);
      frame.srcdoc = html;
      gate.style.display = 'none';
      wrap.style.display = 'block';
      frame.addEventListener('load', resizeFrame);
      resizeFrame();
    } catch (err) {
      error.textContent = 'Incorrect passphrase. Try again.';
      error.style.display = 'block';
      input.select();
    }
  });

  window.printResume = function () {
    try { frame.contentWindow.focus(); frame.contentWindow.print(); } catch (e) {}
  };

  input.focus();
})();
