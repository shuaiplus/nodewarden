import { readFileSync, statSync } from 'node:fs';

// Read the simulator's own paths: Miniflare has used both files/email-text and email/email-text.
export function readLocalEmailCode(logPath: string, recipient: string, after: number, setup = false) {
  const log = readFileSync(logPath, 'utf8').replace(/\u001b\[[0-9;]*m/g, '');
  const messages = [...log.matchAll(/To: ([^\r\n]+)[\s\S]*?Text: ([^\r\n]+\.txt)/g)].reverse();
  for (const [, to, path] of messages) {
    if (to.trim() !== recipient) continue;
    try {
      if (statSync(path).mtimeMs < after) continue;
      const text = readFileSync(path, 'utf8');
      const code = text.match(setup ? /set up email two-step login: (\d{6})/ : /Your sign-in code is: (\d{6})/)?.[1];
      if (code) return { code, text, path };
    } catch {
      /* The local simulator may still be writing the message. */
    }
  }
  return null;
}
