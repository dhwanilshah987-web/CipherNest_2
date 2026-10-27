# CipherNest — Local Encrypted Vault

A local-first browser app built with React, TypeScript, Vite, Tailwind CSS and the Web Crypto API.

## Features
- Encrypts selected file bytes in the browser using AES-256-GCM.
- Derives a key from a user-supplied passphrase with PBKDF2-SHA-256 (310,000 iterations), using a random salt and random 96-bit GCM IV per file.
- Calculates SHA-256 over the actual original file contents.
- Stores encrypted bytes and metadata in IndexedDB in the current browser profile.
- Decrypts files only when the correct passphrase is entered, checks the decrypted content hash, and downloads the recovered file.
- Integrity verification decrypts and re-hashes the content; it is not a blockchain proof.

## Run locally
Requires Node.js 18 or newer.

```bash
npm install
npm run dev
```

Build for production:
```bash
npm run build
```

## Deploy
Import this repository into Vercel. Framework: Vite; build command: `npm run build`; output directory: `dist`.

## Important scope and security notes
This version is a **local-first encrypted vault**, not shared cloud storage. File bytes are not uploaded to Vercel or a backend. IndexedDB data is available only in the same browser profile on the same device. Browser site-data deletion can erase the vault. There is no account system, remote sync, multi-user sharing, or blockchain integration. A lost passphrase cannot be recovered. Do not use it for highly sensitive production data without a professional security review and a tested backup strategy.
