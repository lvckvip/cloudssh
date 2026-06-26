import { concat, encodeUint32 } from './utils';

export class SSHAESGCMCipher {
  private key: CryptoKey | null = null;
  private iv: Uint8Array;
  private rawKey: Uint8Array;

  constructor(rawKey: Uint8Array, iv: Uint8Array) {
    // Copy the IV so we own it; this is the mutable nonce state
    this.iv = new Uint8Array(iv);
    this.rawKey = rawKey;
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-GCM', length: this.rawKey.length * 8 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Increment the 64-bit invocation counter stored in IV bytes [4..11]
   * using big-endian carry-over logic, per RFC 5647 §7.1.
   */
  private incIV(): void {
    for (let i = 11; i >= 4; i--) {
      this.iv[i]++;
      if (this.iv[i] !== 0) {
        break;
      }
    }
  }

  async encrypt(plaintext: Uint8Array, _seqNum?: number, aad?: Uint8Array, _commit: boolean = true): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const nonce = new Uint8Array(this.iv);

    const alg: Record<string, unknown> = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(alg as unknown as SubtleCryptoEncryptAlgorithm, this.key, plaintext)
    );

    this.incIV();
    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, _seqNum?: number, aad?: Uint8Array, _commit: boolean = true): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const nonce = new Uint8Array(this.iv);

    const alg: Record<string, unknown> = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) alg.additionalData = aad;

    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(alg as unknown as SubtleCryptoEncryptAlgorithm, this.key, ciphertext)
      );
      this.incIV();
      return decrypted;
    } catch (e) {
      console.error('[CRYPTO] Decrypt failed, ciphertextLen:', ciphertext.length, 'error:', e instanceof Error ? e.message : String(e));
      return null;
    }
  }
}

export class SSHAESCTRCipher {
  private key: CryptoKey | null = null;
  private counter: Uint8Array;
  private rawKey: Uint8Array;

  constructor(rawKey: Uint8Array, iv: Uint8Array) {
    if (iv.length !== 16) {
      throw new Error(`AES-CTR requires a 16-byte IV, got ${iv.length}`);
    }
    this.counter = new Uint8Array(iv);
    this.rawKey = rawKey;
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-CTR', length: this.rawKey.length * 8 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private incCounter(blocks: number): void {
    for (let block = 0; block < blocks; block++) {
      for (let i = 15; i >= 0; i--) {
        this.counter[i]++;
        if (this.counter[i] !== 0) break;
      }
    }
  }

  async encrypt(plaintext: Uint8Array, _seqNum?: number, _aad?: Uint8Array, commit: boolean = true): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const counter = new Uint8Array(this.counter);
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-CTR', counter, length: 128 } as SubtleCryptoEncryptAlgorithm,
        this.key,
        plaintext
      )
    );
    if (commit) {
      this.incCounter(Math.ceil(plaintext.length / 16));
    }
    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, _seqNum?: number, _aad?: Uint8Array, commit: boolean = true): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const counter = new Uint8Array(this.counter);
    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-CTR', counter, length: 128 } as SubtleCryptoEncryptAlgorithm,
          this.key,
          ciphertext
        )
      );
      if (commit) {
        this.incCounter(Math.ceil(ciphertext.length / 16));
      }
      return decrypted;
    } catch (e) {
      console.error('[CRYPTO] AES-CTR decrypt failed, ciphertextLen:', ciphertext.length, 'error:', e instanceof Error ? e.message : String(e));
      return null;
    }
  }
}

export class SSHHMAC {
  private key: CryptoKey | null = null;
  private rawKey: Uint8Array;
  private hash: 'SHA-1' | 'SHA-256' | 'SHA-512';
  readonly length: number;

  constructor(algorithm: string, rawKey: Uint8Array) {
    this.rawKey = rawKey;
    if (algorithm === 'hmac-sha1') {
      this.hash = 'SHA-1';
      this.length = 20;
    } else if (algorithm === 'hmac-sha2-256') {
      this.hash = 'SHA-256';
      this.length = 32;
    } else if (algorithm === 'hmac-sha2-512') {
      this.hash = 'SHA-512';
      this.length = 64;
    } else {
      throw new Error(`Unsupported MAC algorithm: ${algorithm}`);
    }
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'HMAC', hash: this.hash },
      false,
      ['sign', 'verify']
    );
  }

  async sign(packet: Uint8Array, seqNum: number): Promise<Uint8Array> {
    if (!this.key) throw new Error('MAC not initialized');
    const data = concat(encodeUint32(seqNum), packet);
    return new Uint8Array(await crypto.subtle.sign('HMAC', this.key, data));
  }

  async verify(packet: Uint8Array, seqNum: number, expected: Uint8Array): Promise<boolean> {
    if (!this.key) throw new Error('MAC not initialized');
    const data = concat(encodeUint32(seqNum), packet);
    return crypto.subtle.verify('HMAC', this.key, expected, data);
  }
}

export const REKEY_THRESHOLD = 1 << 30;

export function shouldRekey(seqNum: number): boolean {
  return seqNum >= REKEY_THRESHOLD;
}
