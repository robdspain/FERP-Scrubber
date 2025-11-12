# FERPA Scrubber

This application is a FERPA-focused scrubber that uses a Netlify Edge Function to tokenize and encrypt sensitive student information. It also uses the Gemini API to perform AI actions on the de-identified text only.

The application provides clear progress indicators during encryption and decryption to give the user transparency of how it is functioning.

The front-end uses Atomic Design principles and supports light/dark themes with a Behavior School palette.

## Security Model

- Client sends raw text to the Edge Function for de-identification.
- The Edge Function replaces matches (emails, phones, SSNs, addresses, names, student IDs, dates) with tokens and encrypts original values with AES‑256‑GCM.
- The client receives `cleanedText`, a base64url key, and an encrypted token map.
- AI actions use only `cleanedText` — no FERPA data is sent to the LLM.
- When needed, the client can request decryption by sending the token map + key back to the Edge, which returns the reconstructed text.

## Running the application

To run this application, you will need to have the [Netlify CLI](https://docs.netlify.com/cli/get-started/) installed. You will also need to have a Netlify account and be logged in.

1.  **Install dependencies:**
    ```
    pnpm install
    ```

2.  **Run the application:**
    You can run the application locally using the Netlify CLI:
    ```
    pnpm start
    ```

This will start a local development server and you will be able to access the application at `http://localhost:8888`.

## Secrets Management (Vault-first)

- No secrets are stored in code or as app environment variables. Instead, an external AI Gateway service retrieves provider credentials (e.g., Gemini API key) from a vault at request time and calls the model provider.
- Configure the Edge Function with a non-sensitive endpoint URL only:
  - `AI_GATEWAY_URL`: The base URL of your gateway (e.g., `https://ai-gateway.behaviorschool.org`).

### Reference Architecture

- Vault (e.g., HashiCorp Vault or Cloud Secret Manager) holds the provider key and rotates it per policy. The secret is KMS‑wrapped and never checked into code or stored in app env.
- AI Gateway authenticates to the vault, obtains a short‑lived credential or decrypts the KMS‑wrapped secret, and invokes the provider API (Gemini) on behalf of the Edge.
- Netlify Edge Function forwards cleaned text only to the AI Gateway. The Edge never sees nor stores the provider secret.

## Prompt Safety

- System policy enforced: forbids asking for real identifiers, instructs preserving tokens `[[FERPA:TYPE:N]]` verbatim, and disallows live URLs in the response.
- Injection hardening: incoming `text` and `directions` are sanitized to remove URLs and lines with injection patterns (e.g., “ignore previous instructions”, “system:”, “developer message”).
- Output schema: the Edge requests a strict `{ content: string }` shape from the gateway and strips URLs from the returned content.

### Optional: Dynamic DB Credentials

- If you later add a database, use Vault’s Database Secrets Engine for dynamic credentials per request/session and client‑side AES‑GCM for field‑level protection. Use KMS envelope encryption to protect any long‑lived keys.
