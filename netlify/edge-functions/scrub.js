// Secrets policy: no provider API keys in code or env here.
// AI calls are proxied to an external gateway that retrieves secrets from a vault.

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
  const { text, action, key: keyB64, tokenMap, rules, directions } = await req.json();

  // Replace FERPA-like data with tokens and encrypt originals
  const deidentifyAndEncrypt = async (input) => {
    let cleaned = input;
    const found = [];
    const ALL_RULES = {
      // Student emails (prioritized to avoid double tokenization when EMAIL is also selected)
      STUDENT_EMAIL: [{ type: 'STUDENT_EMAIL', regex: /[a-zA-Z0-9._%+-]+@(?:(?:student\.)?[A-Za-z0-9.-]*k12\.[A-Za-z.]+|[A-Za-z0-9.-]+\.edu)\b/gi }],
      EMAIL: [{ type: 'EMAIL', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g }],
      PHONE: [{ type: 'PHONE', regex: /\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g }],
      SSN: [{ type: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g }],
      ADDRESS: [{ type: 'ADDRESS', regex: /\b\d{1,5}\s+[A-Za-z0-9'.\-]+(?:\s+[A-Za-z0-9'.\-]+){1,3}\b/g }],
      // Names: First [M.] Last(-Hyphen), supports O' and Mc prefixes; also Last, First M.
      NAME: [
        { type: 'NAME', regex: /\b([A-Z][a-z]+(?:\s+[A-Z]\.)?\s+(?:O'|Mc)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?)\b/g, group: 1 },
        { type: 'NAME', regex: /\b((?:O'|Mc)?[A-Z][a-z]+(?:-[A-Z][a-z]+)?,\s+[A-Z][a-z]+(?:\s+[A-Z]\.)?)\b/g, group: 1 },
      ],
      STUDENT_ID: [{ type: 'STUDENT_ID', regex: /(?:(?:Student\s*ID|SID|ID)\s*[:#]?\s*)(\b\d{6,10}\b)/gi, group: 1 }],
      DATE: [
        { type: 'DATE', regex: /\b\d{4}-\d{2}-\d{2}\b/g },                               // 2024-10-31
        { type: 'DATE', regex: /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g },             // 10/31/2024
        { type: 'DATE', regex: /\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},\s+\d{4}\b/gi },
        { type: 'DATE', regex: /\b\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{4}\b/gi }, // 31 Oct 2024
      ],
    };

    // Determine which rule buckets are enabled from client; if none provided, enable all.
    const ruleKeys = Array.isArray(rules) && rules.length ? rules : Object.keys(ALL_RULES);
    const selectedPatterns = ruleKeys.flatMap((k) => ALL_RULES[k] || []);

    // Apply requested patterns
    for (const { type, regex, group } of selectedPatterns) {
      cleaned = cleaned.replace(regex, (...args) => {
        const match = args[0];
        const idx = found.filter(f => f.type === type).length + 1;
        const token = `[[FERPA:${type}:${idx}]]`;
        if (group) {
          const groups = args;
          const full = match;
          const captured = args[group];
          if (!captured) return match;
          found.push({ type, token, value: captured });
          // Replace only the captured portion within the full match
          return full.replace(captured, token);
        } else {
          found.push({ type, token, value: match });
          return token;
        }
      });
    }

    const { key, kB64 } = await generateKey();
    const map = {};
    for (const item of found) {
      map[item.token] = await encryptText(item.value, key);
    }
    // Build simple counts per type for UI feedback
    const counts = found.reduce((acc, cur) => { acc[cur.type] = (acc[cur.type] || 0) + 1; return acc; }, {});
    const stats = { total: found.length, counts };
    return { cleanedText: cleaned, key: kB64, tokenMap: map, stats };
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

  // For AI actions, only use cleaned (non-sensitive) text provided by the client.
  // Prompt safety: sanitize inputs, add a system policy, and request a constrained response.
  const stripUrls = (s = '') => s.replace(/https?:\/\/\S+/gi, '[link removed]');
  const sanitizeForAI = (s = '') => {
    // Remove typical prompt-injection phrases/headers and URLs
    const withoutUrls = stripUrls(s);
    const blocked = /(ignore (?:all|previous|earlier) instructions|disregard|override|bypass|jailbreak|system:|developer message|assistant:|user:)/i;
    return withoutUrls
      .split(/\r?\n/)
      .filter((line) => !blocked.test(line))
      .join('\n');
  };

  const systemPolicy = (
    'SYSTEM POLICY:\n' +
    '- Never request or reveal real-world identifiers (names, emails, phone numbers, addresses, SSNs, student IDs, dates).\n' +
    '- Do not ask the user to provide any sensitive data.\n' +
    '- Preserve any tokens of the form [[FERPA:TYPE:N]] verbatim if present in the input; do not alter their formatting.\n' +
    '- Do not include live URLs; if necessary, state [link removed].\n' +
    '- Follow the required output schema strictly.'
  );
  const outputSchema = {
    type: 'object',
    properties: {
      content: { type: 'string' },
    },
    required: ['content'],
    additionalProperties: false,
  };

  // Forward to an external AI Gateway that fetches provider credentials from a vault.
  if (action === 'summarize' || action === 'simplify' || action === 'extract' || action === 'narrative') {
    const cleanedText = text || '';
    const gateway = (typeof Deno !== 'undefined' && Deno.env?.get('AI_GATEWAY_URL')) ||
                    (typeof process !== 'undefined' && process.env?.AI_GATEWAY_URL);

    let meta = { path: 'gateway', model: undefined };
    if (gateway) {
      try {
        const resp = await fetch(`${gateway.replace(/\/$/, '')}/ai`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action,
            text: sanitizeForAI(cleanedText),
            directions: sanitizeForAI(directions || ''),
            system: systemPolicy,
            schema: outputSchema,
            format: 'json',
          })
        });
        if (resp.ok) {
          const data = await resp.json();
          const raw = data?.content ?? data?.text ?? data?.geminiText ?? '';
          const safe = stripUrls(String(raw || ''));
          return new Response(JSON.stringify({ geminiText: safe, meta }), { headers: { 'Content-Type': 'application/json' } });
        }
        // fall through to direct call on non-OK
      } catch (_) {
        // fall through to direct call on error
      }
    }

    // Fallback: call Gemini directly if API key is present (primarily for dev/testing).
    const getEnv = (name) => (typeof Deno !== 'undefined' && Deno.env?.get(name)) || (typeof process !== 'undefined' && process.env?.[name]);
    const apiKey = getEnv('GEMINI_API_KEY');
    const modelName = getEnv('GEMINI_MODEL') || 'gemini-2.5-flash';
    if (!apiKey) {
      return new Response(JSON.stringify({
        error: 'AI gateway not configured and no direct API key available',
        hint: 'Set AI_GATEWAY_URL (preferred) or GEMINI_API_KEY for a direct dev fallback.'
      }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    meta = { path: 'direct', model: modelName };
    const prompt = [
      systemPolicy,
      '',
      'TASK:',
      directions && directions.trim() ? sanitizeForAI(directions.trim()) : `Perform action: ${action}.`,
      '',
      'CONTENT:',
      sanitizeForAI(cleanedText)
    ].join('\n');

    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(modelName)}:generateContent?key=${encodeURIComponent(apiKey)}`;
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { role: 'system', parts: [{ text: systemPolicy }] },
          contents: [{ role: 'user', parts: [{ text: [
            'TASK:',
            directions && directions.trim() ? sanitizeForAI(directions.trim()) : `Perform action: ${action}.`,
            '',
            'CONTENT:',
            sanitizeForAI(cleanedText)
          ].join('\n') }] }],
          generationConfig: { response_mime_type: 'application/json' }
        })
      });
      if (!resp.ok) {
        return new Response(JSON.stringify({ error: 'Gemini API error' }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
      const data = await resp.json();
      const parts = data?.candidates?.[0]?.content?.parts || [];
      const textOut = parts.map((p) => p.text).filter(Boolean).join('\n');
      const safe = stripUrls(String(textOut || ''));
      return new Response(JSON.stringify({ geminiText: safe, meta }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Direct Gemini call failed' }), { status: 502, headers: { 'Content-Type': 'application/json' } });
    }
  }

  return new Response(JSON.stringify({ error: 'Invalid action' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
};
