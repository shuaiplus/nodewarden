import { User, UserDecryptionOptions, WebAuthnPrfDecryptionOption } from '../types';

export function buildAccountKeys(user: Pick<User, 'privateKey' | 'publicKey'>): Record<string, unknown> | null {
  if (!user.privateKey) {
    return null;
  }

  const publicKey = user.publicKey == null ? '' : String(user.publicKey);

  return {
    publicKeyEncryptionKeyPair: {
      wrappedPrivateKey: user.privateKey,
      publicKey,
      signedPublicKey: null,
      object: 'publicKeyEncryptionKeyPair',
      Object: 'publicKeyEncryptionKeyPair',
    },
    securityState: null,
    signatureKeyPair: null,
    object: 'privateKeys',
    Object: 'privateKeys',
  };
}

export function buildMasterPasswordUnlock(
  user: Pick<User, 'email' | 'key' | 'kdfType' | 'kdfIterations' | 'kdfMemory' | 'kdfParallelism'>
): UserDecryptionOptions['MasterPasswordUnlock'] {
  return {
    Kdf: {
      KdfType: user.kdfType,
      Iterations: user.kdfIterations,
      Memory: user.kdfMemory ?? null,
      Parallelism: user.kdfParallelism ?? null,
    },
    MasterKeyEncryptedUserKey: user.key,
    MasterKeyWrappedUserKey: user.key,
    Salt: user.email.toLowerCase(),
    Object: 'masterPasswordUnlock',
  };
}

export function buildUserDecryptionOptions(
  user: Pick<User, 'email' | 'key' | 'kdfType' | 'kdfIterations' | 'kdfMemory' | 'kdfParallelism'>,
  webAuthnPrfOption: WebAuthnPrfDecryptionOption | null = null
): UserDecryptionOptions {
  return {
    HasMasterPassword: true,
    Object: 'userDecryptionOptions',
    MasterPasswordUnlock: buildMasterPasswordUnlock(user),
    TrustedDeviceOption: null,
    KeyConnectorOption: null,
    WebAuthnPrfOption: webAuthnPrfOption,
  };
}

export function buildUserDecryptionCompat(
  user: Pick<User, 'email' | 'key' | 'kdfType' | 'kdfIterations' | 'kdfMemory' | 'kdfParallelism' | 'userKeyId'>
): Record<string, unknown> {
  return {
    masterPasswordUnlock: {
      kdf: {
        kdfType: user.kdfType,
        iterations: user.kdfIterations,
        memory: user.kdfMemory ?? null,
        parallelism: user.kdfParallelism ?? null,
      },
      masterKeyWrappedUserKey: user.key,
      masterKeyEncryptedUserKey: user.key,
      salt: user.email.toLowerCase(),
    },
    userKeyId: user.userKeyId,
  };
}
