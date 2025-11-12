# PII & PHI Scrubber with Gemini

This application is a PII & PHI scrubber that uses a Netlify edge function to redact sensitive information from text. It also uses the Gemini API to perform AI actions on the de-identified text.

The application provides a graphic display of the scrubbing process to give the user full transparency of how it is functioning.

The front-end has been refactored using Atomic Design principles for better maintainability and scalability.

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
