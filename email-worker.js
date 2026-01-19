/**
 * Cloudflare Email Worker
 * Forwards incoming emails to your API with authentication
 */

export default {
  async email(message, env, ctx) {
    // Mail API entrypoint proxied via disctools.store (see nginx /mail/ route)
    const API_URL = env?.API_URL || "https://disctools.store/mail/webhook/inbound";
    const API_PASSWORD = env?.API_PASSWORD || "jfmao1039foqptzv";
    
    try {
      const forward = async () => {
        // Get raw email as text
        const rawEmail = await streamToText(message.raw);
      
        const to = Array.isArray(message.to) ? message.to.join(', ') : message.to;
        const from = Array.isArray(message.from) ? message.from.join(', ') : message.from;
        const subject = message.headers.get('subject') || message.headers.get('Subject') || '';
      
        const payload = {
          to,
          from,
          subject,
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
          console.error('Failed to forward email to API:', response.status, await response.text());
        }
      };

      if (ctx?.waitUntil) {
        ctx.waitUntil(forward());
      } else {
        await forward();
      }
      
    } catch (error) {
      console.error('Error processing email:', error);
    }
  }
}

// Helper function to convert stream to text
async function streamToText(stream) {
  try {
    return await new Response(stream).text();
  } catch (error) {
    console.error('streamToText: failed to read raw email stream', error);
    return '';
  }
}
