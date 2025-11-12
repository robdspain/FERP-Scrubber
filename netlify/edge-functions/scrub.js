import { GoogleGenerativeAI } from "@google/generative-ai";

export default async (req, context) => {
  const { text, action } = await req.json();

  // De-identification logic
  const deidentify = (text) => {
    let cleanedText = text;

    const regexPatterns = [
      // Emails
      { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, replacement: '[REDACTED_EMAIL]' },
      // Phone Numbers (various formats)
      { regex: /\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[REDACTED_PHONE]' },
      // Social Security Numbers
      { regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
      // Addresses (basic)
      { regex: /\d{1,5}\s\w+\s\w+/g, replacement: '[REDACTED_ADDRESS]' },
    ];

    regexPatterns.forEach(({ regex, replacement }) => {
      cleanedText = cleanedText.replace(regex, replacement);
    });

    return cleanedText;
  };

  const cleanedText = deidentify(text);

  if (action === 'deidentify') {
    return new Response(JSON.stringify({ cleanedText }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: "gemini-pro" });

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
    default:
      return new Response(JSON.stringify({ error: 'Invalid action' }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
  }

  try {
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const geminiText = await response.text();

    return new Response(JSON.stringify({ geminiText }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Error calling Gemini API' }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};