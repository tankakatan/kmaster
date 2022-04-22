declare global {
    type Digest = 'sha256';
    type GenerateSecretArgs = {
        seed?: string | Buffer;
        salt?: string | Buffer;
        saltLength?: number;
        length: number;
        iterations: number;
        digest: Digest;
        alphabet: string;
        ignoreChars: string;
    };
    type GenerateSecretReturn = {
        seed: string;
        salt: string;
        iterations: number;
        length: number;
        digest: Digest;
        alphabet: string;
        secret: string;
    }
}

export {};
