import * as openpgp from "openpgp";

export type GpgManagerOptions = {
  rsaKeyBits: 2048 | 4096;
};

export type KeyData = {
  passphrase: string;
  user: {
    name: string;
    email: string;
  };
};

export type KeyPair = {
  privateKey: string;
  publicKey: string;
  revocationCert: string;
};

export type EncryptionData = {
  privateKey?: string;
  signMessage?: boolean;
  publicKey: string;
  passphrase?: string;
  message: string;
};

export type DecryptionData = {
  encryptedMessage: string;
  publicKey?: string;
  verify?: boolean;
  privateKey: string;
  passphrase: string;
};

export class GpgManager {
  constructor(private opts: GpgManagerOptions) {}

  async generateKeyPair(data: KeyData): Promise<KeyPair> {
    const {
      privateKeyArmored,
      publicKeyArmored,
      revocationCertificate
    } = await openpgp.generateKey({
      userIds: [{ name: data.user.name, email: data.user.email }],
      numBits: this.opts.rsaKeyBits,
      passphrase: data.passphrase
    });

    return {
      privateKey: privateKeyArmored,
      publicKey: publicKeyArmored,
      revocationCert: revocationCertificate
    };
  }

  async encrypt(data: EncryptionData): Promise<string> {
    let privateKey;
    if (data.signMessage) {
      if (!data.passphrase) {
        throw Error("Missing passphrase");
      }

      if (!data.privateKey) {
        throw Error("Missing private key");
      }

      const privateKeys = await openpgp.key.readArmored(data.privateKey);

      if (!privateKeys || !privateKeys.keys || !privateKeys.keys.length) {
        throw Error("Invalid private key");
      }

      privateKey = privateKeys.keys[0];

      await privateKey.decrypt(data.passphrase);
    }

    const {
      keys: [publicKey]
    } = await openpgp.key.readArmored(data.publicKey);

    const { data: encrypted } = await openpgp.encrypt({
      message: openpgp.message.fromText(data.message),
      publicKeys: [publicKey],
      privateKeys: data.signMessage ? [privateKey] : undefined
    });

    return encrypted;
  }

  async decrypt(data: DecryptionData): Promise<string> {
    if (data.verify && !data.publicKey) {
      throw Error("Missing public key");
    }

    const {
      keys: [privateKey]
    } = await openpgp.key.readArmored(data.privateKey);

    await privateKey.decrypt(data.passphrase);

    const { data: decrypted } = await openpgp.decrypt({
      message: await openpgp.message.readArmored(data.encryptedMessage),
      publicKeys:
        data.verify && data.publicKey
          ? (await openpgp.key.readArmored(data.publicKey)).keys
          : undefined,
      privateKeys: [privateKey]
    });

    return decrypted.toString();
  }
}
