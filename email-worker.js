/**
 * Cloudflare Email Worker
 * Forwards incoming emails to your API with authentication
 */

export default {
  async email(message, env, ctx) {
    // Mail API entrypoint proxied via disctools.store (see nginx /mail/ route)
    const API_URL = "https://disctools.store/mail/webhook/inbound";
    const API_PASSWORD = "jfmao1039foqptzv";
    
    try {
      // Get raw email as text
      const rawEmail = await streamToText(message.raw);
      
      const to = message.to;
      const from = message.from;
      const subject = message.headers.get('subject') || '';
      
      // Extract HTML and text content from raw email
      let htmlContent = '';
      let textContent = '';
      
      // Simple regex extraction for HTML
      const htmlMatch = rawEmail.match(/Content-Type: text\/html[^]*?(<html[^]*?<\/html>)/i);
      if (htmlMatch && htmlMatch[1]) {
        htmlContent = htmlMatch[1];
      }
      
      // Simple regex extraction for plain text
      const textMatch = rawEmail.match(/Content-Type: text\/plain[^]*?\r?\n\r?\n([^]*?)(?=\r?\n--|\r?\nContent-Type:|$)/i);
      if (textMatch && textMatch[1]) {
        textContent = textMatch[1].trim();
      }
      
      // If no content found, use the raw email
      if (!htmlContent && !textContent) {
        textContent = rawEmail;
      }
      
      const payload = {
        to: to,
        from: from,
        subject: subject,
        html: htmlContent,
        text: textContent,
        raw: rawEmail
      };
      
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${API_PASSWORD}`
        },
        body: JSON.stringify(payload)
      });
      
      if (response.ok) {
        console.log('Email forwarded successfully to API');
      } else {
        console.error('Failed to forward email to API:', await response.text());
      }
      
    } catch (error) {
      console.error('Error processing email:', error);
    }
  }
}

// Helper function to convert stream to text
async function streamToText(stream) {
  const reader = stream.getReader();
  const chunks = [];
  
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  
  const uint8Array = new Uint8Array(chunks.reduce((acc, chunk) => acc + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    uint8Array.set(chunk, offset);
    offset += chunk.length;
  }
  
  return new TextDecoder().decode(uint8Array);
}
