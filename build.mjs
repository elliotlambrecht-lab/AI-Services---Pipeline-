// Encrypts or decrypts the pipeline page. The password is never stored here.
//   node build.mjs encrypt <plain page.html> <password>   -> writes index.html
//   node build.mjs decrypt <password> <out page.html>     -> reads index.html
import { readFileSync, writeFileSync } from "node:fs";
import { pbkdf2Sync, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const norm = p => p.replace(/[-\s]/g, "").toUpperCase();
const key = (pw, salt) => pbkdf2Sync(norm(pw), salt, 600000, 32, "sha256");
const [mode, a, b] = process.argv.slice(2);
if (mode === "encrypt") {
  const plain = readFileSync(a);
  const salt = randomBytes(16), iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key(b, salt), iv);
  const data = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  const blob = JSON.stringify({ salt: salt.toString("base64"), iv: iv.toString("base64"), data: data.toString("base64") });
  const shell = readFileSync(join(here, "shell.html"), "utf8").replace("__BLOB__", blob);
  writeFileSync(join(here, "index.html"), shell);
  console.log("index.html written,", data.length, "bytes encrypted");
} else if (mode === "decrypt") {
  const html = readFileSync(join(here, "index.html"), "utf8");
  const d = JSON.parse(html.match(/const BLOB = (\{.*?\});/s)[1]);
  const raw = Buffer.from(d.data, "base64");
  const dc = createDecipheriv("aes-256-gcm", key(a, Buffer.from(d.salt, "base64")), Buffer.from(d.iv, "base64"));
  dc.setAuthTag(raw.subarray(raw.length - 16));
  writeFileSync(b, Buffer.concat([dc.update(raw.subarray(0, raw.length - 16)), dc.final()]));
  console.log("decrypted to", b);
} else { console.log("usage: see top of file"); process.exit(1); }
