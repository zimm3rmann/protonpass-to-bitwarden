import { createPrivateKey, createPublicKey, webcrypto } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_ITEMS = 100_000;
const MAX_TOTAL_CREDENTIALS = 10_000;
const MAX_CREDENTIAL_ID_BYTES = 1_023;
const MAX_USER_HANDLE_BYTES = 64;
const MAX_KEY_VALUE_BYTES = 256;
const MAX_RP_ID_BYTES = 253;
const MAX_LABEL_BYTES = 4 * 1024;
const MAX_COUNTER = 4_294_967_295n;
const VALIDATION_MESSAGE = Buffer.from(
  "protonpass-to-bitwarden validation",
  "utf8",
);

const args = process.argv.slice(2);
const [input, expectedFlag, expectedValue] = args;
if (
  args.length !== 3 ||
  !input ||
  expectedFlag !== "--expected-count" ||
  !/^[1-9]\d*$/.test(expectedValue ?? "") ||
  !Number.isSafeInteger(Number(expectedValue)) ||
  Number(expectedValue) > MAX_TOTAL_CREDENTIALS
) {
  process.stderr.write(
    "usage: node scripts/validate-bitwarden-output.mjs BITWARDEN_JSON --expected-count N\n",
  );
  process.exit(2);
}
const expectedCount = Number(expectedValue);

const canonicalBase64url = (value, maxBytes) => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((maxBytes * 4) / 3)
  ) {
    return false;
  }
  const decoded = Buffer.from(value, "base64url");
  return decoded.length <= maxBytes && decoded.toString("base64url") === value;
};

const boundedString = (value, maxBytes, allowEmpty = false) =>
  typeof value === "string" &&
  (allowEmpty || value.length > 0) &&
  Buffer.byteLength(value, "utf8") <= maxBytes;

const canonicalTimestamp = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;

const sameIdentity = (left, right) =>
  left.dev === right.dev && left.ino === right.ino;

const sameSnapshot = (left, right) =>
  sameIdentity(left, right) &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

const validRegularFile = (metadata) =>
  metadata.isFile() && metadata.size <= BigInt(MAX_FILE_BYTES);

const readBoundedFile = async (path) => {
  const before = await lstat(path, { bigint: true });
  if (!validRegularFile(before)) {
    throw new Error();
  }

  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat({ bigint: true });
    if (!validRegularFile(opened) || !sameSnapshot(before, opened)) {
      throw new Error();
    }

    const chunks = [];
    let length = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(64 * 1024);
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) {
        break;
      }
      length += bytesRead;
      if (length > MAX_FILE_BYTES) {
        throw new Error();
      }
      chunks.push(chunk.subarray(0, bytesRead));
    }

    const afterHandle = await handle.stat({ bigint: true });
    const afterPath = await lstat(path, { bigint: true });
    if (
      BigInt(length) !== opened.size ||
      !sameSnapshot(opened, afterHandle) ||
      !sameSnapshot(afterHandle, afterPath)
    ) {
      throw new Error();
    }

    return new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks, length),
    );
  } finally {
    await handle.close();
  }
};

const validateCredentialFields = (credential) => {
  if (
    credential === null ||
    typeof credential !== "object" ||
    Array.isArray(credential) ||
    typeof credential.credentialId !== "string" ||
    !credential.credentialId.startsWith("b64.") ||
    !canonicalBase64url(
      credential.credentialId.slice(4),
      MAX_CREDENTIAL_ID_BYTES,
    ) ||
    !canonicalBase64url(credential.userHandle, MAX_USER_HANDLE_BYTES) ||
    !canonicalBase64url(credential.keyValue, MAX_KEY_VALUE_BYTES) ||
    !boundedString(credential.rpId, MAX_RP_ID_BYTES) ||
    !boundedString(credential.rpName, MAX_LABEL_BYTES) ||
    !boundedString(credential.userName, MAX_LABEL_BYTES, true) ||
    !boundedString(credential.userDisplayName, MAX_LABEL_BYTES, true) ||
    credential.keyType !== "public-key" ||
    credential.keyAlgorithm !== "ECDSA" ||
    credential.keyCurve !== "P-256" ||
    credential.discoverable !== "true" ||
    !/^(0|[1-9]\d{0,9})$/.test(credential.counter) ||
    BigInt(credential.counter) > MAX_COUNTER ||
    !canonicalTimestamp(credential.creationDate)
  ) {
    throw new Error();
  }
};

const validateKeyMaterial = async (credential) => {
  const keyBytes = Buffer.from(credential.keyValue, "base64url");
  try {
    const privateKeyObject = createPrivateKey({
      key: keyBytes,
      format: "der",
      type: "pkcs8",
    });
    if (
      privateKeyObject.asymmetricKeyType !== "ec" ||
      privateKeyObject.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    ) {
      throw new Error();
    }
    const privateKey = await webcrypto.subtle.importKey(
      "pkcs8",
      keyBytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const publicDer = createPublicKey(privateKeyObject).export({
      format: "der",
      type: "spki",
    });
    const publicKey = await webcrypto.subtle.importKey(
      "spki",
      publicDer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const algorithm = { name: "ECDSA", hash: "SHA-256" };
    const signature = await webcrypto.subtle.sign(
      algorithm,
      privateKey,
      VALIDATION_MESSAGE,
    );
    if (!(await webcrypto.subtle.verify(algorithm, publicKey, signature, VALIDATION_MESSAGE))) {
      throw new Error();
    }
  } finally {
    keyBytes.fill(0);
  }
};

try {
  const vault = JSON.parse(await readBoundedFile(input));
  if (
    vault === null ||
    typeof vault !== "object" ||
    Array.isArray(vault) ||
    vault.encrypted !== false ||
    !Array.isArray(vault.items) ||
    vault.items.length > MAX_ITEMS
  ) {
    throw new Error();
  }

  const credentials = [];
  for (const item of vault.items) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new Error();
    }
    if (item.login === undefined) {
      continue;
    }
    if (
      item.login === null ||
      typeof item.login !== "object" ||
      Array.isArray(item.login)
    ) {
      throw new Error();
    }
    const itemCredentials = item.login.fido2Credentials ?? [];
    if (!Array.isArray(itemCredentials) || itemCredentials.length > 1) {
      throw new Error();
    }
    if (credentials.length + itemCredentials.length > MAX_TOTAL_CREDENTIALS) {
      throw new Error();
    }
    credentials.push(...itemCredentials);
  }

  if (credentials.length !== expectedCount) {
    throw new Error();
  }
  for (const credential of credentials) {
    validateCredentialFields(credential);
    await validateKeyMaterial(credential);
  }

  process.stdout.write(
    `validated cryptographic key material for ${credentials.length} passkey${credentials.length === 1 ? "" : "s"}\n`,
  );
} catch {
  process.stderr.write("validation failed without displaying vault contents\n");
  process.exit(1);
}
