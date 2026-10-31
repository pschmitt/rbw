import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../extension/passkey-shim.js", import.meta.url), "utf8");

function load(PublicKeyCredential = class {}) {
  const context = vm.createContext({
    PublicKeyCredential, AuthenticatorAssertionResponse: class {}, AuthenticatorAttestationResponse: class {},
    Uint8Array, ArrayBuffer,
    atob: value => Buffer.from(value, "base64").toString("binary"),
  });
  vm.runInContext(source, context);
  return context.rbwPasskeyShim;
}

const assertion = {
  id: "AAEC", rawId: "AAEC",
  response: {clientDataJSON: "AAEC", authenticatorData: "AAEC", signature: "AAEC", userHandle: null},
};

test("the credential's toJSON and getClientExtensionResults can be assigned", () => {
  const credential = load().credential(assertion, "get");
  // GitHub assigns toJSON; on a read-only property that throws in strict mode.
  assert.doesNotThrow(() => { "use strict"; credential.toJSON = () => ({}); });
  assert.doesNotThrow(() => { "use strict"; credential.getClientExtensionResults = () => ({}); });
});

test("the credential carries the assertion", () => {
  const credential = load().credential(assertion, "get");
  assert.equal(credential.id, "AAEC");
  assert.equal(credential.type, "public-key");
  assert.deepEqual([...new Uint8Array(credential.rawId)], [0, 1, 2]);
  assert.equal(credential.response.userHandle, null);
});

test("platform-authenticator checks follow the availability answer", async () => {
  const PublicKeyCredential = class {
    static async isUserVerifyingPlatformAuthenticatorAvailable() { return false; }
    static async getClientCapabilities() { return {userVerifyingPlatformAuthenticator: false, hybridTransport: true}; }
  };
  const shim = load(PublicKeyCredential);
  shim.patchPlatformAuthenticator(async () => true);
  assert.equal(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), true);
  const caps = await PublicKeyCredential.getClientCapabilities();
  assert.equal(caps.userVerifyingPlatformAuthenticator, true);
  assert.equal(caps.passkeyPlatformAuthenticator, true);
  assert.equal(caps.hybridTransport, true);
});
