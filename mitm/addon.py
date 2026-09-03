"""
mitmproxy addon — network-level HTTPS capture, package-agnostic.

Logs every flow in a format that mirrors analyze.sh's Frida-based log so the
two capture methods can be diffed/compared:

  [REQ]       METHOD URL
  [REQ-H]     Header: value        (one line per header)
  [REQ-BODY-TEXT] ...
  [RESP]      status protocol METHOD URL
  [RESP-H]    Header: value        (one line per header)
  [RESP-BODY-TEXT] ...

Usage:
  mitmdump -s addon.py --set logfile=/path/to/out.log --listen-host 192.168.240.1 --listen-port 8080
"""
from mitmproxy import ctx, http


class ReqRespLogger:
    def load(self, loader):
        loader.add_option(
            "logfile", str, "", "Path to append human-readable capture log to."
        )

    def running(self):
        path = ctx.options.logfile
        if not path:
            ctx.log.warn("addon.py: no 'logfile' option set, logging to stdout only")
            self.fh = None
        else:
            self.fh = open(path, "a", buffering=1)

    def emit(self, line):
        print(line)
        if self.fh:
            self.fh.write(line + "\n")

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        self.emit("[REQ] %s %s" % (req.method, req.pretty_url))
        for k, v in req.headers.items(multi=True):
            self.emit("[REQ-H] %s: %s" % (k, v))
        text = req.get_text(strict=False)
        if text:
            self.emit("[REQ-BODY-TEXT] %s" % text)

    def response(self, flow: http.HTTPFlow):
        req = flow.request
        resp = flow.response
        if resp is None:
            return
        self.emit(
            "[RESP] %s %s %s %s"
            % (resp.status_code, resp.http_version, req.method, req.pretty_url)
        )
        for k, v in resp.headers.items(multi=True):
            self.emit("[RESP-H] %s: %s" % (k, v))
        text = resp.get_text(strict=False)
        if text:
            self.emit("[RESP-BODY-TEXT] %s" % text)

    def error(self, flow: http.HTTPFlow):
        req = flow.request
        err = flow.error.msg if flow.error else "unknown error"
        self.emit("[ERR] %s %s -> %s" % (req.method, req.pretty_url, err))


addons = [ReqRespLogger()]
