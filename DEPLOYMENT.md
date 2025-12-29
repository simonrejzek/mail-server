# Cloudflare Email Server - Free Deployment

## Deployed on Render.com

This is your personal email API server, working exactly like pixiboost.fun!

### Your API Endpoints

Once deployed, you'll have:
- `https://your-app.onrender.com/generate` - Generate temp email
- `https://your-app.onrender.com/emails/<email>` - Fetch emails (needs Bearer token)
- `https://your-app.onrender.com/health` - Health check
- `https://your-app.onrender.com/webhook/inbound` - Email webhook

### After Deployment

1. Copy your Render URL: `https://your-app.onrender.com`
2. Update main.py with this URL
3. Setup Cloudflare Email Worker with this URL
4. Done!

### Environment Variables on Render

Make sure to set these in Render Dashboard:
- `CLOUDFLARE_API_TOKEN` = gGPiTHCgoyliIiVmicp0u9ImJpdeLiizU2Jcs0-W
- `CLOUDFLARE_ZONE_ID` = ea0203c466fb571150bffff1d54cc128
- `DOMAIN_NAME` = axilon.app
- `DESTINATION_EMAIL` = axilon.contact@gmail.com
- `API_PASSWORD` = terimkcchut976
- `FLASK_RUN_PORT` = 10000
- `FLASK_DEBUG` = false

## Local usage with the main site

- Copy `.env.example` to `.env` and fill your Cloudflare/domain settings. `MAIL_SERVER_PORT` defaults to `6020`.
- Install the mail server dependencies locally with `pip install -r mail_server/requirements.txt` if they are not already present.
- Starting the root `server.py` now also launches the mail server in the background (main site uses `PORT`/`5500`, mail server uses `MAIL_SERVER_PORT`/`6020`).
- Stop the main process to stop the mail server; it is terminated automatically on shutdown.
