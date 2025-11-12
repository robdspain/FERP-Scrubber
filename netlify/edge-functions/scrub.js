import { GoogleGenerativeAI } from "@google/generative-ai";

// Utilities: base64url helpers
const b64u = {
  enc: (buf) => {
    let b = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return b.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  },
  dec: (str) => {
    const s = str.replaceAll("-", "+").replaceAll("_", "/");
    const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
    const p = s + "=".repeat(pad);
    const bin = atob(p);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  },
};

async function importKey(rawB64) {
  const raw = b64u.dec(rawB64);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function generateKey() {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", key);
  return { key, kB64: b64u.enc(raw) };
}

async function encryptText(plain, key) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain));
  return { c: b64u.enc(ct), iv: b64u.enc(iv) };
}

async function decryptText(cB64, ivB64, key) {
  const dec = new TextDecoder();
  const ct = b64u.dec(cB64);
  const iv = new Uint8Array(b64u.dec(ivB64));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

export default async (req, context) => {
  const { text, action, key: keyB64, tokenMap } = await req.json();

  // Replace FERPA-like data with tokens and encrypt originals
  const deidentifyAndEncrypt = async (input) => {
    let cleaned = input;
    const found = [];
    const patterns = [
      { type: 'EMAIL', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
      { type: 'PHONE', regex: /\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
      { type: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
      { type: 'ADDRESS', regex: /\b\d{1,5}\s+[A-Za-z0-9'.\-]+(?:\s+[A-Za-z0-9'.\-]+){1,3}\b/g },
    ];

    for (const { type, regex } of patterns) {
      cleaned = cleaned.replace(regex, (match) => {
        const idx = found.filter(f => f.type === type).length + 1;
        const token = `[[FERPA:${type}:${idx}]]`;
        found.push({ type, token, value: match });
        return token;
      });
    }

    const { key, kB64 } = await generateKey();
    const map = {};
    for (const item of found) {
      map[item.token] = await encryptText(item.value, key);
    }
    return { cleanedText: cleaned, key: kB64, tokenMap: map };
  };

  if (action === 'deidentify') {
    const result = await deidentifyAndEncrypt(text || '');
    return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
  }

  if (action === 'decrypt') {
    try {
      const key = await importKey(keyB64);
      let output = text || '';
      // Find tokens present in the text and replace
      const tokenRegex = /\[\[FERPA:([A-Z_]+):(\d+)\]\]/g;
      const promises = [];
      const seen = new Set();
      let m;
      while ((m = tokenRegex.exec(output)) !== null) {
        const token = m[0];
        if (seen.has(token)) continue;
        seen.add(token);
        const entry = tokenMap?.[token];
        if (!entry) continue;
        promises.push(
          (async () => {
            const original = await decryptText(entry.c, entry.iv, key);
            output = output.split(token).join(original);
          })()
        );
      }
      await Promise.all(promises);
      return new Response(JSON.stringify({ decryptedText: output }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Decrypt failed' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // For AI actions, only use cleaned (non-sensitive) text provided by the client
  if (action === 'summarize' || action === 'simplify' || action === 'extract' || action === 'narrative') {
    const cleanedText = text || '';
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: 'gemini-pro' });

    let prompt;
    switch (action) {
      case 'summarize':
        prompt = `Summarize the following text: ${cleanedText}`;
        break;
      case 'simplify':
        prompt = `Simplify the following text for a 6th-grade reading level: ${cleanedText}`;
        break;
      case 'extract':
        prompt = `Extract key information from the following text: ${cleanedText}`;
        break;
      case 'narrative':
        prompt = `Create a narrative from the following text: ${cleanedText}`;
        break;
    }

    try {
      const result = await model.generateContent(prompt);
      const response = await result.response;
      const geminiText = await response.text();
      return new Response(JSON.stringify({ geminiText }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Error calling Gemini API' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  return new Response(JSON.stringify({ error: 'Invalid action' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
};
