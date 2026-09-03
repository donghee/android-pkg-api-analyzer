import Java from "frida-java-bridge";

'use strict';

// android-pkg-api-analyzer :: generic protocol-analysis frida agent
//
// Package-agnostic. Hooks TLS (libssl.so: conscrypt/BoringSSL), DNS, TCP
// connect, OkHttp request/response, and java.net.HttpURLConnection so any
// target app's on-device network traffic can be captured in plaintext
// before/after TLS, regardless of what HTTP client it uses.
//
// Captured tags:
//   [LOAD]      native libraries the app loads (crypto/network stack fingerprint)
//   [DNS]       hostname -> ip resolution
//   [TCP]       socket connect target (ip:port)
//   [SNI]       TLS SNI hostname
//   [ALPN]      TLS ALPN protocol list (h2 / http/1.1)
//   [TLS-W/R]   TLS plaintext bytes (HTTP/2 frames auto-annotated)
//   [REQ]       OkHttp request: method, URL
//   [REQ-H]     request headers (auth/session tokens included, in full)
//   [REQ-BODY]  request body metadata (contentType, length)
//   [RESP]      response: status, protocol (h2/http/1.1), method, URL
//   [RESP-H]    response headers
//   [RESP-BODY] response body (peek = non-destructive read)
//   [JDK-*]     java.net.HttpURLConnection traffic (non-OkHttp clients)

var RAW_TLS = '__RAW_TLS__';

// ---------------- generic helpers ----------------
function out(tag, msg) { send('[' + tag + '] ' + msg); }

function truncate(s, max) {
  return s.length > max ? s.substring(0, max) + ' ...[truncated, total ' + s.length + ' chars]' : s;
}

function hexDump(u8, max) {
  var n = Math.min(u8.length, max);
  var lines = [], row = '';
  for (var i = 0; i < n; i++) {
    row += ('0' + u8[i].toString(16)).slice(-2) + ' ';
    if (i % 16 === 15 || i === n - 1) { lines.push(row); row = ''; }
  }
  if (u8.length > max) lines.push('...[truncated, total ' + u8.length + ' bytes]');
  return lines.join('\n');
}

function isPrintable(u8) {
  var n = Math.min(u8.length, 4096);
  if (n === 0) return false;
  var ok = 0;
  for (var i = 0; i < n; i++) {
    var c = u8[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) ok++;
  }
  return ok / n > 0.9;
}

function bytesToUtf8(u8, max) {
  var s = '', i = 0, n = Math.min(u8.length, max);
  while (i < n) {
    var c = u8[i];
    if (c < 0x80) { s += String.fromCharCode(c); i += 1; }
    else if (c < 0xe0 && i + 1 < n) { s += String.fromCharCode(((c & 0x1f) << 6) | (u8[i + 1] & 0x3f)); i += 2; }
    else if (c < 0xf0 && i + 2 < n) { s += String.fromCharCode(((c & 0x0f) << 12) | ((u8[i + 1] & 0x3f) << 6) | (u8[i + 2] & 0x3f)); i += 3; }
    else { s += String.fromCharCode(0xfffd); i += 1; }
  }
  return s;
}

// ---------------- HTTP/2 framing annotation ----------------
var H2_TYPES = { 0: 'DATA', 1: 'HEADERS', 2: 'PRIORITY', 3: 'RST_STREAM', 4: 'SETTINGS', 5: 'PUSH_PROMISE', 6: 'PING', 7: 'GOAWAY', 8: 'WINDOW_UPDATE', 9: 'CONTINUATION' };
var H2_PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';

function h2Describe(u8) {
  var off = 0, frames = [], guard = 0;
  if (u8.length >= H2_PREFACE.length) {
    var m = true;
    for (var i = 0; i < H2_PREFACE.length; i++) if (u8[i] !== H2_PREFACE.charCodeAt(i)) { m = false; break; }
    if (m) { off = H2_PREFACE.length; frames.push('CLIENT_PREFACE'); }
  }
  while (off + 9 <= u8.length && guard++ < 256) {
    var len = (u8[off] << 16) | (u8[off + 1] << 8) | u8[off + 2];
    var type = u8[off + 3];
    var flags = u8[off + 4];
    var sid = ((u8[off + 5] << 24) | (u8[off + 6] << 16) | (u8[off + 7] << 8) | u8[off + 8]) & 0x7fffffff;
    if (!(type in H2_TYPES) || len > 262144 || off + 9 + len > u8.length) break;
    frames.push('H2 ' + H2_TYPES[type] + ' sid=' + sid + ' flags=0x' + flags.toString(16) + ' len=' + len);
    off += 9 + len;
  }
  return frames.length ? frames.join(' | ') : null;
}

function logTls(dir, n, u8) {
  var note = h2Describe(u8);
  if (note) {
    out('TLS-' + dir, n + 'B  ' + note);
  } else {
    var head = Math.min(u8.length, 128);
    out('TLS-' + dir, n + 'B  ' + (isPrintable(u8) ? JSON.stringify(bytesToUtf8(u8, head)) : hexDump(u8, head)));
  }
  if (RAW_TLS === '1') {
    if (isPrintable(u8)) out('TLS-' + dir + '-FULL', truncate(bytesToUtf8(u8, 65536), 32768));
    else out('TLS-' + dir + '-FULL', hexDump(u8, 65536));
  }
}

// ---------------- TLS layer (libssl.so: conscrypt/BoringSSL) ----------------
function hookTlsModule(m) {
  var hooked = {};
  function att(name) {
    if (hooked[name]) return;
    var f = m.findExportByName(name);
    if (!f) return;
    hooked[name] = true;

    if (name === 'SSL_write' || name === 'SSL_read') {
      var dir = name === 'SSL_write' ? 'W' : 'R';
      Interceptor.attach(f, {
        onEnter: function (a) { this.buf = a[1]; },
        onLeave: function (r) {
          try {
            var n = r.toInt32(); // SSL_write/SSL_read return a signed int; <=0 is an error/retry code
            if (n > 0 && this.buf) {
              logTls(dir, n, new Uint8Array(this.buf.readByteArray(Math.min(n, 65536))));
            }
          } catch (e) {}
        }
      });
    } else if (name === 'SSL_write_ex' || name === 'SSL_read_ex') {
      var dir2 = name === 'SSL_write_ex' ? 'W' : 'R';
      Interceptor.attach(f, {
        onEnter: function (a) { this.buf = a[1]; this.written = a[3]; },
        onLeave: function (r) {
          try {
            if (r.toInt32() === 1 && this.written) {
              var n = Number(this.written.readU64());
              if (n > 0) logTls(dir2, n, new Uint8Array(this.buf.readByteArray(Math.min(n, 65536))));
            }
          } catch (e) {}
        }
      });
    } else if (name === 'SSL_set_tlsext_host_name') {
      Interceptor.attach(f, {
        onEnter: function (a) { try { out('SNI', a[1].readCString()); } catch (e) {} }
      });
    } else if (name === 'SSL_set_tlsext_alpn_protos') {
      Interceptor.attach(f, {
        onEnter: function (a) {
          try {
            var list = [], i = 0;
            while (i < 32) {
              var pp = a[1].add(i * Process.pointerSize).readPointer();
              if (pp.isNull()) break;
              list.push(pp.readCString());
              i++;
            }
            if (list.length) out('ALPN', list.join(','));
          } catch (e) {}
        }
      });
    }
  }
  ['SSL_write', 'SSL_read', 'SSL_write_ex', 'SSL_read_ex',
   'SSL_set_tlsext_host_name', 'SSL_set_tlsext_alpn_protos'].forEach(att);
  out('SYS', 'tls hooks installed on ' + m.path);
}

var tlsHooked = {};
function scanTlsModules() {
  var found = false;
  Process.enumerateModules().forEach(function (m) {
    if (m.name === 'libssl.so' && !tlsHooked[m.path]) {
      tlsHooked[m.path] = true;
      try { hookTlsModule(m); found = true; } catch (e) { out('ERR', 'tls hook: ' + e); }
    }
  });
  return found;
}
if (!scanTlsModules()) {
  var tlsTimer = setInterval(function () { if (scanTlsModules()) clearInterval(tlsTimer); }, 1000);
  setTimeout(function () {
    clearInterval(tlsTimer);
    if (!Object.keys(tlsHooked).length) out('SYS', 'libssl.so never loaded; TLS-level hooks unavailable');
  }, 60000);
}

// ---------------- module loader logging ----------------
(function () {
  var dl = Module.findGlobalExportByName('android_dlopen_ext') || Module.findGlobalExportByName('dlopen');
  if (!dl) return;
  var seen = {};
  Interceptor.attach(dl, {
    onEnter: function (a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } },
    onLeave: function () {
      if (this.p && !seen[this.p]) { seen[this.p] = true; out('LOAD', this.p); }
    }
  });
})();

// ---------------- Java layer hooks ----------------
function waitJavaClass(cls, cb, tries) {
  tries = tries || 400; // ~3.3 min
  function attempt() {
    Java.perform(function () {
      try {
        Java.use(cls);
        cb();
      } catch (e) {
        if (tries-- > 0) setTimeout(attempt, 500);
      }
    });
  }
  attempt();
}

// DNS resolution
waitJavaClass('java.net.InetAddress', function () {
  var IA = Java.use('java.net.InetAddress');
  try {
    var gAll = IA.getAllByName.overload('java.lang.String');
    gAll.implementation = function (host) {
      var res = gAll.call(this, host);
      var a = [];
      for (var i = 0; i < res.length; i++) a.push(res[i].getHostAddress());
      out('DNS', host + ' -> ' + a.join(','));
      return res;
    };
  } catch (e) {}
  try {
    var gOne = IA.getByName.overload('java.lang.String');
    gOne.implementation = function (host) {
      var r = gOne.call(this, host);
      out('DNS', host + ' -> ' + r.getHostAddress());
      return r;
    };
  } catch (e) {}
  out('SYS', 'dns hooks installed');
});

// TCP connect targets
waitJavaClass('java.net.Socket', function () {
  var S = Java.use('java.net.Socket');
  try {
    var c1 = S.connect.overload('java.net.InetSocketAddress', 'int');
    c1.implementation = function (addr, to) {
      try { out('TCP', addr.getAddress().getHostAddress() + ':' + addr.getPort()); } catch (e) {}
      return c1.call(this, addr, to);
    };
  } catch (e) {}
  try {
    var c2 = S.connect.overload('java.net.InetSocketAddress');
    c2.implementation = function (addr) {
      try { out('TCP', addr.getAddress().getHostAddress() + ':' + addr.getPort()); } catch (e) {}
      return c2.call(this, addr);
    };
  } catch (e) {}
  try {
    var c3 = S.connect.overload('java.lang.String', 'int');
    c3.implementation = function (host, port) {
      out('TCP', host + ':' + port);
      return c3.call(this, host, port);
    };
  } catch (e) {}
  out('SYS', 'socket hooks installed');
});

// OkHttp request: method, url, headers
waitJavaClass('okhttp3.Request$Builder', function () {
  var B = Java.use('okhttp3.Request$Builder');
  var build = B.build;
  build.implementation = function () {
    var req = build.call(this);
    try {
      out('REQ', req.method() + ' ' + req.url().toString());
      var h = req.headers();
      for (var i = 0; i < h.size(); i++) out('REQ-H', h.name(i) + ': ' + h.value(i));
      var b = req.body();
      if (b !== null) {
        var ct = b.contentType();
        out('REQ-BODY', 'contentType=' + (ct ? ct.toString() : 'unknown') + ' contentLength=' + b.contentLength());
      }
    } catch (e) { out('ERR', 'okhttp req: ' + e); }
    return req;
  };
  out('SYS', 'okhttp request hook installed');
});

// OkHttp request body content (at creation time, non-destructive)
waitJavaClass('okhttp3.RequestBody', function () {
  var RB = Java.use('okhttp3.RequestBody');
  try {
    var cs = RB.create.overload('okhttp3.MediaType', 'java.lang.String');
    cs.implementation = function (mt, s) {
      try {
        out('REQ-BODY-TEXT', 'create(String) contentType=' + (mt ? mt.toString() : 'null') + '\n' + truncate(s, 16384));
      } catch (e) {}
      return cs.call(this, mt, s);
    };
  } catch (e) {}
  try {
    var cb = RB.create.overload('okhttp3.MediaType', '[B');
    cb.implementation = function (mt, arr) {
      try {
        var u8 = new Uint8Array(arr);
        out('REQ-BODY-BIN', 'create(byte[]) contentType=' + (mt ? mt.toString() : 'null') + ' len=' + u8.length);
        if (isPrintable(u8)) out('REQ-BODY-TEXT', truncate(bytesToUtf8(u8, 16384), 16384));
        else out('REQ-BODY-HEX', hexDump(u8, 8192));
      } catch (e) {}
      return cb.call(this, mt, arr);
    };
  } catch (e) {}
  out('SYS', 'okhttp request-body hook installed');
});

// OkHttp response: status, protocol, headers, body (peek = non-destructive)
waitJavaClass('okhttp3.internal.connection.RealCall', function () {
  var RC = Java.use('okhttp3.internal.connection.RealCall');
  var orig = RC.getResponseWithInterceptorChain;
  orig.implementation = function () {
    var resp = orig.call(this);
    try {
      var proto = '';
      try { proto = resp.protocol().toString(); } catch (e) {}
      out('RESP', resp.code() + ' ' + proto + ' ' + this.request().method() + ' ' + this.request().url().toString());
      var h = resp.headers();
      for (var i = 0; i < h.size(); i++) out('RESP-H', h.name(i) + ': ' + h.value(i));
      var b = resp.body();
      if (b !== null) {
        var ct = b.contentType();
        out('RESP-BODY', 'contentType=' + (ct ? ct.toString() : 'unknown') + ' contentLength=' + b.contentLength());
        try {
          var peek = b.peek(65536);
          if (peek.size() > 0) {
            var u8 = new Uint8Array(peek.copy().toByteArray());
            if (isPrintable(u8)) out('RESP-BODY-TEXT', truncate(bytesToUtf8(u8, 32768), 16384));
            else out('RESP-BODY-HEX', hexDump(u8, 4096));
          }
        } catch (e) { out('ERR', 'resp body: ' + e); }
      }
    } catch (e) { out('ERR', 'okhttp resp: ' + e); }
    return resp;
  };
  out('SYS', 'okhttp response hook installed');
}, 2880); // keep waiting: class loads on first network call

// java.net.HttpURLConnection (fallback client, e.g. Volley)
waitJavaClass('java.net.HttpURLConnection', function () {
  try {
    var H = Java.use('java.net.HttpURLConnection');
    var conn = H.connect;
    conn.implementation = function () {
      try {
        out('JDK-REQ', this.getRequestMethod() + ' ' + this.getURL());
        var props = this.getRequestProperties();
        if (props !== null) {
          var keys = props.keySet().toArray();
          for (var i = 0; i < keys.length; i++) out('JDK-REQ-H', keys[i] + ': ' + props.get(keys[i]));
        }
      } catch (e) {}
      return conn.call(this);
    };
    var gis = H.getInputStream;
    gis.implementation = function () {
      try {
        out('JDK-RESP', this.getResponseCode() + ' ' + this.getResponseMessage() + ' ' + this.getURL());
        out('JDK-RESP-H', 'Content-Type: ' + this.getContentType());
      } catch (e) {}
      return gis.call(this);
    };
    out('SYS', 'httpurlconnection hooks installed');
  } catch (e) {
    out('SYS', 'httpurlconnection hook skipped: ' + e);
  }
});

out('SYS', 'protocol analysis hooks armed');
