# Live webapp email login tests

Run `npm run test:e2e:live-mail` after installing the repository dependencies and Playwright Chromium (`npx playwright install chromium`). The default is a visible browser, so Linux needs a display or `xvfb-run -a npm run test:e2e:live-mail`. For CI, set `LIVE_MAIL_HEADLESS=1`.

The runner builds the webapp and starts its own local Wrangler on an unused localhost port. Its configuration, D1 state, dummy push-installation credentials and EMAIL simulator files live in a new OS temporary directory. It does not load the repository's `.dev.vars`, enable remote bindings, send real email or register a push installation. No Cloudflare account credentials are needed.

Two synthetic accounts use real PBKDF2-derived passwords, RSA keys and AES-CBC/HMAC encrypted user keys and vault items. Email-2FA is enrolled through the real setup API and its simulated setup email. The second account has no factor; its local fixture is aged, has a different known device, and runs with `ENABLE_NEW_DEVICE_VERIFICATION=1` only in the temporary config.

The live specs submit browser forms, read delivered simulator codes, reject a wrong code, resend, then verify a successful `/api/sync` and a decrypted item title. They do not intercept or mock API responses. The existing mocked `webapp-login.spec.ts` remains separate.

The runner supplies `E2E_LIVE_MAIL_FIXTURES` automatically. Without it, `e2e/webapp-live-mail.spec.ts` skips. Fixtures contain only generated test credentials; their file is mode `0600`. Build, Worker and Playwright logs remain in the reported temporary directory. The runner stops its Worker, and Playwright closes its browsers, after success or failure.
