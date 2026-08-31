# CyberKitchen

> Recipes for hackers.

**[Live site](https://bitwyser.github.io/CyberKitchen/)**

CyberKitchen is a fast, 100% client-side security and developer toolkit that runs entirely in your browser. It bundles encryption, hashing, encoding, number conversion and data generators into one installable, offline-first app. No servers, no tracking, and no data ever leaves your machine, so every tool works with no network after the first load.

It is built with vanilla JavaScript and no build step. Cryptography uses the Web Crypto API where possible, with vendored libraries for the rest (crypto-js, bcrypt.js, argon2-browser, and a self-authored hashlib.js for MD5, SHA-3, Keccak, RIPEMD-160 and CRC32). A service worker precaches the app so it keeps working fully offline, with light and dark themes (dark by default).
