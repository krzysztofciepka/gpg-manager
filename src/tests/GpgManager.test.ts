import { GpgManager } from "../gpg/GpgManager";

test("encrypt and decrypt data with generated key", async () => {
  const manager = new GpgManager({ rsaKeyBits: 4096 });

  const SECRET_MESSAGE = "secret message";
  const PASSPHRASE = "test1234";
  const NAME = "AA";
  const EMAIL = "test@example.tld";

  const { privateKey, publicKey } = await manager.generateKeyPair({
    passphrase: PASSPHRASE,
    user: {
      name: NAME,
      email: EMAIL
    }
  });

  console.log(privateKey);
  console.log(publicKey);

  const encrypted = await manager.encrypt({
    message: SECRET_MESSAGE,
    signMessage: true,
    publicKey,
    privateKey,
    passphrase: "test1234"
  });

  console.log(encrypted);

  const decrypted = await manager.decrypt({
    encryptedMessage: encrypted,
    privateKey,
    verify: true,
    publicKey,
    passphrase: PASSPHRASE
  });

  console.log(decrypted);

  expect(decrypted).toEqual(SECRET_MESSAGE);
});
