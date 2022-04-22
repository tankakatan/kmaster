declare module global {
    export type Digest = 'sha256';
    export type GenerateSecretArgs = {
        seed?: string;
        salt?: string;
        saltLength?: number;
        length: number;
        iterations: number;
        digest: Digest;
    };
}

export {};
