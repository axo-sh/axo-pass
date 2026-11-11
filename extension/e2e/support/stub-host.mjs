// Stub native messaging host for the Playwright tests.
//
// Usage: node stub-host.mjs <state dir> [arguments from the browser]
//
// Sends the hello, reads one request, answers it with a canned broker reply,
// and exits when the browser closes stdin. Every request is appended to
// `<state dir>/requests.jsonl` with the arguments the browser passed. Replies
// default to the response fixtures. `<state dir>/responses.json` overrides
// them per request kind: `{"<kind>": {"response": {...}, "delay_ms": 0}}`.
import {randomBytes} from 'node:crypto';
import {appendFileSync, existsSync, readFileSync} from 'node:fs';
import {endianness} from 'node:os';
import {join} from 'node:path';

const [stateDir, ...browserArgs] = process.argv.slice(2);
const VERSION = 1;
const little = endianness() === 'LE';
const fixtures = join(import.meta.dirname, '../../../fixtures/native-messaging/responses');

const fixture = (name) => JSON.parse(readFileSync(join(fixtures, `${name}.json`), 'utf8'));

/** Canned reply for each request kind, from the shared response fixtures. */
const defaults = {
  list_logins_locked: () => {
    const reply = fixture('locked_logins');
    reply.logins[0].has_totp = true;
    return reply;
  },
  list_logins: () => fixture('logins'),
  fill_login: () => fixture('login_fill'),
  generate_totp: () => fixture('totp_code'),
  generate_password: () => fixture('generated_password'),
  save_login: () => fixture('login_saved'),
  update_login_password: () => fixture('acknowledged'),
};

const send = (message) => {
  const body = Buffer.from(JSON.stringify(message));
  const header = Buffer.alloc(4);
  if (little) {
    header.writeUInt32LE(body.length);
  } else {
    header.writeUInt32BE(body.length);
  }
  process.stdout.write(Buffer.concat([header, body]));
};

/** The first frame on stdin. The rest is read and dropped. */
const readFirstFrame = () => {
  return new Promise((resolve) => {
    let pending = Buffer.alloc(0);
    let done = false;
    process.stdin.on('data', (chunk) => {
      if (done) {
        return;
      }
      pending = Buffer.concat([pending, chunk]);
      if (pending.length < 4) {
        return;
      }
      const length = little ? pending.readUInt32LE(0) : pending.readUInt32BE(0);
      if (pending.length >= 4 + length) {
        done = true;
        resolve(JSON.parse(pending.subarray(4, 4 + length).toString('utf8')));
      }
    });
    process.stdin.on('end', () => resolve(null));
  });
};

const nonce = randomBytes(32).toString('hex');
send({version: VERSION, nonce});

const envelope = await readFirstFrame();
if (envelope === null) {
  process.exit(0);
}

const kind = envelope.body?.request;
appendFileSync(
  join(stateDir, 'requests.jsonl'),
  `${JSON.stringify({args: browserArgs, version: envelope.version, nonce_ok: envelope.nonce === nonce, body: envelope.body})}\n`
);

if (envelope.nonce !== nonce || envelope.version !== VERSION) {
  send({status: 'failed', message: 'Bad nonce or version'});
} else {
  const overridesPath = join(stateDir, 'responses.json');
  const overrides = existsSync(overridesPath) ? JSON.parse(readFileSync(overridesPath, 'utf8')) : {};
  const override = overrides[kind];
  const make = defaults[kind];
  if (override?.delay_ms) {
    await new Promise((resolve) => setTimeout(resolve, override.delay_ms));
  }
  send(
    override?.response ??
      (make ? make() : {status: 'failed', message: `Stub has no reply for ${kind}`})
  );
}

// The browser closes stdin when the extension disconnects.
process.stdin.on('end', () => process.exit(0));
