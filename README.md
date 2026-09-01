# MyServer

Secure self-hosted local file server for sharing photos, videos, documents, and other files over your local network.

## Features

- Upload any file type
- No application-imposed file-size limit
- Original files stored without re-encoding
- Large file streaming
- Video seeking
- Download original files
- Multiple file uploads
- Secure login
- First-time administrator setup
- bcrypt password hashing
- Path traversal protection
- Security headers
- Rate limiting
- LAN access
- No cloud or API keys required

## Requirements

- Node.js 18 or newer
- npm
- macOS, Windows, or Linux

## Installation

```bash
git clone https://github.com/Ankushkushwaha1/myserver.git
cd myserver
npm install
npm start
```

Then open `http://localhost:3000`.

On first launch, create your administrator username and password.

## Local Network Access

Make sure the other device is connected to the same Wi-Fi network.

### macOS

```bash
ipconfig getifaddr en0
```

### Windows

```cmd
ipconfig
```

Then open `http://YOUR-IP-ADDRESS:3000` on the other device.

## Storage

Uploaded files are stored in the `media/` directory. Account configuration is stored in `data/`.

Both directories are excluded from Git.

## File Size

MyServer has no application-level file-size limit. The practical limit depends on available storage, filesystem limits, browser limitations, and network conditions.

Large files are streamed instead of loading the entire file into memory.

## Security

MyServer includes authentication, bcrypt password hashing, secure sessions, rate limiting, security headers, filename sanitization, and path traversal protection.

MyServer is intended for trusted local networks. Do not expose port 3000 directly to the public internet.

## Stopping the Server

Press `Control + C`. Your uploaded files remain on the computer.

## Updating

```bash
git pull
npm install
npm start
```

## Git Exclusions

The following are intentionally excluded from Git:

```text
media/
data/
node_modules/
.env
*.log
```
