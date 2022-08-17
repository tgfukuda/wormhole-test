declare module 'base58-js' {
    export const base58_to_binary: (base58: string) => Uint8Array;
    export const binary_to_base58: (bin: Uint8Array) => string;
};
