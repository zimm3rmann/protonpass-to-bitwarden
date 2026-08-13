import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

import { BitwardenJsonImporter } from "./bitwarden-json-importer";

class BridgeImporter extends BitwardenJsonImporter {
  constructor() {
    super();
  }
}

describe("protonpass-to-bitwarden bridge", () => {
  it("loads generated native JSON through the pinned Bitwarden importer", async () => {
    const path = process.env.BITWARDEN_BRIDGE_JSON;
    if (path == null) {
      throw new Error("BITWARDEN_BRIDGE_JSON is required");
    }

    const result = await new BridgeImporter().parse(readFileSync(path, "utf8"));
    expect(result.success).toBe(true);

    if (process.env.BITWARDEN_BRIDGE_MODE === "passkeys_only") {
      const expectedCount = Number(process.env.BITWARDEN_BRIDGE_EXPECTED_COUNT);
      const accepted =
        Number.isSafeInteger(expectedCount) &&
        expectedCount > 0 &&
        result.ciphers.length === expectedCount &&
        result.folders.length === 0 &&
        result.ciphers.every((cipher) => {
          const credentials = cipher.login?.fido2Credentials ?? [];
          const credential = credentials[0];
          return (
            cipher.type === 1 &&
            typeof cipher.name === "string" &&
            cipher.name.trim().length > 0 &&
            cipher.favorite === false &&
            cipher.folderId == null &&
            cipher.notes == null &&
            (cipher.fields?.length ?? 0) === 0 &&
            cipher.login?.username == null &&
            cipher.login?.password == null &&
            cipher.login?.totp == null &&
            (cipher.login?.uris?.length ?? 0) === 0 &&
            credentials.length === 1 &&
            credential != null &&
            typeof credential.credentialId === "string" &&
            credential.credentialId.startsWith("b64.") &&
            credential.keyType === "public-key" &&
            credential.keyAlgorithm === "ECDSA" &&
            credential.keyCurve === "P-256" &&
            typeof credential.keyValue === "string" &&
            credential.keyValue.length > 0 &&
            typeof credential.rpId === "string" &&
            credential.rpId.length > 0 &&
            typeof credential.userHandle === "string" &&
            credential.userHandle.length > 0 &&
            typeof credential.counter === "number" &&
            credential.discoverable === true &&
            credential.creationDate instanceof Date &&
            !Number.isNaN(credential.creationDate.getTime())
          );
        });
      expect(accepted).toBe(true);
      return;
    }

    expect(result.ciphers).toHaveLength(7);
    expect(result.folders).toHaveLength(3);

    const credentials = result.ciphers.flatMap(
      (cipher) => cipher.login?.fido2Credentials ?? [],
    );
    expect(credentials).toHaveLength(1);
    const credential = credentials[0];
    const keyHash = createHash("sha256")
      .update(Buffer.from(credential.keyValue, "base64url"))
      .digest("hex");
    expect(
      credential.credentialId === "b64.YRdyij7Rsqmc8EEfrY6u3A" &&
        credential.keyType === "public-key" &&
        credential.keyAlgorithm === "ECDSA" &&
        credential.keyCurve === "P-256" &&
        keyHash === "b11a2fba5dfff80cdfd9ee13004599393a28b2edcb2ee2986aec73eb33908c9a" &&
        credential.rpId === "webauthn.io" &&
        credential.userHandle ===
          "akVXbUxOR1Z3bWF6M3ZNeWFXekltenoxRUVsTlA1b1F4Vkp5ZXd4bm4zRQ" &&
        credential.userName === "yo" &&
        credential.counter === 0 &&
        credential.rpName === "webauthn.io" &&
        credential.userDisplayName === "yo" &&
        credential.discoverable === true &&
        credential.creationDate.toISOString() === "2024-05-06T08:06:45.000Z",
    ).toBe(true);
  });
});
