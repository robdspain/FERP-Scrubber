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

2.  **Set up your environment variables:**
    You will need to create a `.env` file in the root of the project and add your Gemini API key to it:
    ```
    GEMINI_API_KEY=your_api_key
    ```

3.  **Run the application:**
    You can run the application locally using the Netlify CLI:
    ```
    pnpm start
    ```

This will start a local development server and you will be able to access the application at `http://localhost:8888`.
