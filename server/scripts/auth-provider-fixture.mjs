// Private-network helper for external-auth-drill.mjs. It never forwards mail.
import { readFile } from "node:fs/promises";
import { createServer as httpsServer } from "node:https";
import { createServer as httpServer } from "node:http";
import { createServer as tcpServer } from "node:net";

const issuer = "https://auth-provider:8443";
const sockets = new Set(), messages = [];
let discoveryAvailable = false, rejectMail = false;
const track = (socket) => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
  socket.on("error", () => {});
  socket.setTimeout(30_000, () => socket.destroy());
};
const discovery = httpsServer({ key: await readFile("/tmp/provider-key.pem"),
  cert: await readFile("/tmp/provider-ca.pem") }, (req, res) => {
  if (!discoveryAvailable) { res.writeHead(503); res.end("injected discovery failure"); return; }
  if (req.url !== "/.well-known/openid-configuration") { res.writeHead(404); res.end(); return; }
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ issuer, authorization_endpoint: issuer + "/authorize",
    token_endpoint: issuer + "/token", jwks_uri: issuer + "/jwks",
    response_types_supported: ["code"], subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"] }));
});
discovery.on("connection", track);
const control = httpServer(async (req, res) => {
  if (req.headers.authorization !== "Bearer " + process.env.FIXTURE_CONTROL_TOKEN) {
    res.writeHead(401); res.end(); return;
  }
  if (req.method === "POST") {
    let body = "";
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 1024) { res.writeHead(413); res.end(); return; }
    }
    try {
      const value = JSON.parse(body);
      if (typeof value.discoveryAvailable === "boolean") discoveryAvailable = value.discoveryAvailable;
      if (typeof value.rejectMail === "boolean") rejectMail = value.rejectMail;
    } catch { res.writeHead(400); res.end(); return; }
  }
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ discoveryAvailable, rejectMail, messages }));
});
control.on("connection", track);
const smtp = tcpServer((socket) => {
  track(socket);
  socket.write("220 fixture.example.test ESMTP\r\n");
  let pending = "", data = null, recipient = null;
  socket.on("data", (chunk) => {
    pending += chunk;
    if (pending.length + (data?.length || 0) > 1024 * 1024) { socket.destroy(); return; }
    let end;
    while ((end = pending.indexOf("\r\n")) >= 0) {
      const line = pending.slice(0, end); pending = pending.slice(end + 2);
      if (data !== null) {
        if (line === ".") {
          messages.push({ to: recipient, data, accepted: !rejectMail });
          data = null; recipient = null;
          socket.write(rejectMail ? "451 4.3.0 injected delivery failure\r\n" : "250 2.0.0 fixture-accepted\r\n");
        } else data += line + "\r\n";
      } else if (/^(EHLO|HELO) /i.test(line)) socket.write("250 fixture.example.test\r\n");
      else if (/^MAIL FROM:/i.test(line)) socket.write("250 2.1.0 OK\r\n");
      else if (/^RCPT TO:/i.test(line)) {
        const address = line.match(/<([^>]+)>/)?.[1];
        if (!address?.endsWith("@example.test")) { socket.write("550 fixture recipients only\r\n"); continue; }
        recipient = address; socket.write("250 2.1.0 OK\r\n");
      } else if (line === "DATA" && recipient) { data = ""; socket.write("354 End with dot\r\n"); }
      else if (line === "QUIT") socket.end("221 goodbye\r\n");
      else socket.write("250 OK\r\n");
    }
  });
});
discovery.listen(8443, "0.0.0.0");
control.listen(8081, "0.0.0.0");
smtp.listen(2525, "0.0.0.0");
function close() {
  for (const socket of sockets) socket.destroy();
  for (const server of [discovery, control, smtp]) server.close();
}
process.on("SIGTERM", close); process.on("SIGINT", close);
