import {
    getSignedVAAWithRetry,
    attestFromEth,
    createWrappedOnSolana,
    postVaaSolana,
    createWrappedOnEth,
    CHAINS,
    CONTRACTS,
    parseSequencesFromLogEth,
    getEmitterAddressEth,
    setDefaultWasm,
    getForeignAssetSolana,
    getForeignAssetEth,
    tryNativeToUint8Array,
    transferFromEth,
    redeemOnSolana,
    attestFromSolana,
    parseSequenceFromLogSolana,
    getEmitterAddressSolana,
    transferFromSolana,
    redeemOnEth,
    tryUint8ArrayToNative,

} from '@certusone/wormhole-sdk';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { NodeHttpTransport } from '@improbable-eng/grpc-web-node-http-transport';
import { Connection, Keypair, PublicKey, TokenAccountsFilter, Transaction } from '@solana/web3.js';
import { ASSOCIATED_TOKEN_PROGRAM_ID, Token, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { GetSignedVAAResponse } from '@certusone/wormhole-sdk-proto-web/lib/cjs/publicrpc/v1/publicrpc';
import { base58_to_binary } from 'base58-js';
import erc20 from '../erc20.json';

/** need to use solana sdk lib on node runtime. */
setDefaultWasm('node');

/** public rpcs */
const wormholeRpcUrl = 'https://wormhole-v2-testnet-api.certus.one';
const defaultRpcs: Partial<Record<SupportedChain, string>> = {
    'solana': 'https://api.devnet.solana.com',
    'avalanche': 'https://api.avax-test.network/ext/bc/C/rpc',
    'polygon': 'https://rpc-mumbai.matic.today',
    'bsc': 'https://data-seed-prebsc-1-s1.binance.org:8545/',
};

/**
 * Beacon Upgraded event
 * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/ERC1967/ERC1967Upgrade.sol#L33
 */
const BEACON_UPGRADE_HASH = '0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e';

/** node hates rpc, to avoid xhr implementation error. */
const nodeTransport = {
    transport: NodeHttpTransport()
};

const DEFAULT_RETRY_TIMEOUT = 1000;
const DEFAULT_RETRY_LIMIT = 1000;

const ETHEREUMISH = ['ethereum', 'avalanche', 'polygon', 'bsc'] as const;
export type Ethereumish = typeof ETHEREUMISH[number];
export type Solana = 'solana';
export type SupportedChain = Ethereumish | Solana;
const SUPPORTED_CHAINS = [...ETHEREUMISH, 'solana'] as const;

export type SignerConfig = {
    keystorePath: string,
    passwordPath: string,
};

export type EthereumConfig = Partial<Record<Ethereumish, string>> & SignerConfig;

export type SolanaConfig = {
    rpcUri?: string,
    privKeyPath: string,
};

type Attestation = {
    hash: string,
    sequence: string[]
};

type SrcChainTxResult = {
    hash: string,
    vaas: GetSignedVAAResponse[],
};

type DestChainTxResult = {
    hash: string,
};

type BridgeInitResult = {
    src: { hash: string },
    dst: ((DestChainTxResult | { error: string }) & { chain: SupportedChain })[],
};

type TeleportResult = {
    src: { hash: string },
    dst: { hash: string },
};

type EthAddr = { chain: Ethereumish, addr: string | null };
type SolAddr = { chain: Solana, addr: string | null };
type GlobalAddr = EthAddr | SolAddr;

export type NetworkType = 'MAINNET' | 'TESTNET';

export type Asset = Record<string, Partial<Record<SupportedChain, string>>>;

abstract class BaseTransactor {
    network: NetworkType;

    constructor(network: NetworkType) {
        this.network = network;
    }

    abstract getSeqFromTxHash(hash: string): Promise<string[]>;
    abstract getTokenAddr(originChain: SupportedChain, originTokenAddr: Uint8Array): Promise<string | null>;
    abstract attestToken(tokenAddress: string): Promise<Attestation>;
    abstract createWrapped({ vaaBytes }: GetSignedVAAResponse): Promise<DestChainTxResult>;
}

class EthereumishTransactor extends BaseTransactor {
    /**
     * base signer, keep in mind that it has no connection to rpc provider
     * use `connectedEthSigner`
     */
     signer: ethers.Wallet;
     rpcProvider: ethers.providers.JsonRpcProvider;
     chain: Ethereumish;

    constructor(provider: ethers.providers.JsonRpcProvider, signer: ethers.Wallet, chain: Ethereumish, network: NetworkType) {
        super(network);
        this.rpcProvider = provider;
        this.signer = signer;
        this.chain = chain;
    }

    connectedEthSigner(): ethers.Signer {
        return this.signer.connect(this.rpcProvider);
    }

    async getTxEvents(hash: string): Promise<ethers.providers.Log[]> {
        const tx = await this.rpcProvider.getTransactionReceipt(hash);

        return tx.logs;
    }
    
    async getWrappedAddressByLog(logs: ethers.providers.Log[]) {
        for (const log of logs) {
            if (log.topics[0] === BEACON_UPGRADE_HASH) {
                return log.address;
            }
        }

        return undefined;
    }

    async getSeqFromTxHash(hash: string): Promise<string[]> {
        const receipt = await this.rpcProvider.getTransactionReceipt(hash);
        return parseSequencesFromLogEth(receipt, CONTRACTS[this.network][this.chain].core);
    }

    async getTokenAddr(originChain: SupportedChain, originTokenAddr: Uint8Array): Promise<string | null> {
        if (originChain === this.chain) return tryUint8ArrayToNative(originTokenAddr, this.chain);

        const addr = await getForeignAssetEth(
            CONTRACTS[this.network][this.chain].token_bridge,
            this.rpcProvider,
            originChain,
            originTokenAddr,
        );

        if (!addr || addr === ethers.constants.AddressZero) {
            return null;
        } else {
            return addr;
        }
    }

    async getTokenBalance(tokenAddr: string): Promise<ethers.BigNumber> {
        const token = new ethers.Contract(tokenAddr, erc20, this.rpcProvider);
        return ethers.BigNumber.from(await token.balanceOf(this.signer.address));
    }

    async getAllowance(tokenAddr: string, spender: string): Promise<ethers.BigNumber> {
        const token = new ethers.Contract(tokenAddr, erc20, this.rpcProvider);
        return ethers.BigNumber.from(await token.allowance(this.signer.address, spender));
    }

    async approveToken(tokenAddr: string, amount: ethers.BigNumber) {
        const token = new ethers.Contract(tokenAddr, erc20, this.connectedEthSigner());
        return await token.approve(CONTRACTS[this.network][this.chain].token_bridge, amount);
    }

    async lockToken(src: Ethereumish, dst: SupportedChain, to: Uint8Array, tokenAddr: string, amount: ethers.BigNumber): Promise<Attestation> {
        const allowance = await this.getAllowance(
            tokenAddr,
            CONTRACTS[this.network][src].token_bridge,
        );

        const diff = amount.toBigInt() - allowance.toBigInt();
        
        if (0n < diff) {
            const approval = await this.approveToken(CONTRACTS[this.network][src].token_bridge, ethers.BigNumber.from(diff));
            console.log("approval", approval.hash);
        }

        const receipt = await transferFromEth(
            CONTRACTS[this.network][src].token_bridge,
            this.connectedEthSigner(),
            tokenAddr,
            amount,
            CHAINS[dst],
            to,
        );
        const sequence = parseSequencesFromLogEth(receipt, CONTRACTS[this.network][src].token_bridge);

        return {
            hash: receipt.transactionHash,
            sequence,
        };
    }

    async redeemToken({ vaaBytes }: GetSignedVAAResponse): Promise<DestChainTxResult> {
        const receipt = await redeemOnEth(
            CONTRACTS[this.network][this.chain].token_bridge,
            this.connectedEthSigner(),
            vaaBytes,
        );
        const hash = receipt.transactionHash;

        return {
            hash,
        };
    }

    async attestToken(tokenAddress: string): Promise<Attestation> {
        const receipt = await attestFromEth(
            CONTRACTS[this.network][this.chain].token_bridge,
            this.connectedEthSigner(),
            tokenAddress,
        );
        return {
            hash: receipt.transactionHash,
            sequence: parseSequencesFromLogEth(receipt, CONTRACTS[this.network][this.chain].core)
        };
    }

    async createWrapped({ vaaBytes }: GetSignedVAAResponse): Promise<DestChainTxResult> {
        const tx = await createWrappedOnEth(
            CONTRACTS[this.network][this.chain].token_bridge,
            this.connectedEthSigner(),
            vaaBytes,
        );

        const wrapped = await this.getWrappedAddressByLog(tx.logs);
        if (!wrapped) {
            console.log("WARN: creating wrapped asset may fail");
        }

        return {
            hash: tx.transactionHash,
        };
    }
}

export const printSolkeyFromBase58 = (base58: string) => {
    return base58_to_binary(base58);
}

class SolanaTransactor extends BaseTransactor {
    signer: Keypair;
    rpcProvider: Connection;

    constructor(solConf: SolanaConfig, network: NetworkType) {
        super(network)
        this.rpcProvider = new Connection(solConf.rpcUri || defaultRpcs.solana || "", 'confirmed');
        this.signer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(solConf.privKeyPath).toString())));
    }

    async getTxEvents(hash: string) {
        const tx = await this.rpcProvider.getTransaction(hash)

        console.log(tx?.transaction.message.accountKeys.map(p => p.toBase58()))

        if (tx?.transaction.message.accountKeys && tx.meta?.innerInstructions) {
            for (const instruction of tx.meta.innerInstructions) {
                instruction.instructions.forEach(i => {
                    console.log(i)
                })
            }
        }

        console.log(TOKEN_PROGRAM_ID.toBase58())
    }

    async getSeqFromTxHash(hash: string): Promise<string[]> {
        const info = await this.rpcProvider.getTransaction(hash);
        if (!info) {
            throw new Error("An error occurred while fetching the transaction info");
        }

        const sequence = parseSequenceFromLogSolana(info);

        return [sequence];
    }

    async signAndSend(transaction: Transaction): Promise<string> {
        transaction.partialSign(this.signer);
        const hash = await this.rpcProvider.sendRawTransaction(transaction.serialize());
        
        const { blockhash, lastValidBlockHeight } = await this.rpcProvider.getLatestBlockhash();

        const confirmation = await this.rpcProvider.confirmTransaction({
            blockhash,
            lastValidBlockHeight,
            signature: hash
        });

        if (confirmation.value.err) {
            throw new Error(`failed to confirm ${hash}`);
        }

        return hash;
    }

    /** create the associated account if it doesn't exist */
    async getAssociatedAccountInfo(tokenAddr: string) {
        const mintKey = new PublicKey(tokenAddr);
        const receipient = await Token.getAssociatedTokenAddress(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
            mintKey,
            this.signer.publicKey
        );
        const associatedInfo = await this.rpcProvider.getAccountInfo(receipient);
        if (!associatedInfo) {
            const transaction = new Transaction().add(
                Token.createAssociatedTokenAccountInstruction(
                    ASSOCIATED_TOKEN_PROGRAM_ID,
                    TOKEN_PROGRAM_ID,
                    mintKey,
                    receipient,
                    this.signer.publicKey,
                    this.signer.publicKey
                )
            );

            const { blockhash, lastValidBlockHeight } = await this.rpcProvider.getLatestBlockhash();
            transaction.recentBlockhash = blockhash;
            transaction.feePayer = this.signer.publicKey;
            transaction.partialSign(this.signer);
            const txId = await this.rpcProvider.sendRawTransaction(transaction.serialize());
            await this.rpcProvider.confirmTransaction({
                blockhash,
                lastValidBlockHeight,
                signature: txId,
            });
        }

        return {
            receipient,
            associatedInfo,
        };
    }

    async getTokenBalance(tokenAddr: string) {
        const tokenFilter: TokenAccountsFilter = {
            programId: TOKEN_PROGRAM_ID,
        };
        const result = await this.rpcProvider.getParsedTokenAccountsByOwner(this.signer.publicKey, tokenFilter);

        console.log(result);

        for (const { account, pubkey } of result.value) {
            const tokenInfo = account.data.parsed.info;
            console.log(account.data.parsed);
            const address = tokenInfo.mint as string;
            const amount = tokenInfo.tokenAmount.uiAmount as number;
            if (address === tokenAddr) {
                return amount;
            }
        }

        return 0;
    }

    async lockToken(dst: SupportedChain, to: Uint8Array, tokenAddr: string, amount: BigInt): Promise<Attestation> {
        const fromAddr = (
            await Token.getAssociatedTokenAddress(
                ASSOCIATED_TOKEN_PROGRAM_ID,
                TOKEN_PROGRAM_ID,
                new PublicKey(tokenAddr),
                this.signer.publicKey,
            )
        ).toBase58();
        
        const transaction = await transferFromSolana(
            this.rpcProvider,
            CONTRACTS[this.network].solana.core,
            CONTRACTS[this.network].solana.token_bridge,
            this.signer.publicKey.toBase58(),
            fromAddr,
            tokenAddr,
            amount,
            to,
            dst
        );
        const hash = await this.signAndSend(transaction);
        
        const sequence = await this.getSeqFromTxHash(hash);

        return {
            hash,
            sequence,
        };
    }

    async redeemToken({ vaaBytes }: GetSignedVAAResponse): Promise<DestChainTxResult> {
        const transaction = await redeemOnSolana(
            this.rpcProvider,
            CONTRACTS[this.network].solana.core,
            CONTRACTS[this.network].solana.token_bridge,
            this.signer.publicKey.toBase58(),
            vaaBytes,
        );
        const hash = await this.signAndSend(transaction);

        return {
            hash,
        };
    }

    async attestToken(tokenAddress: string): Promise<Attestation> {
        const transaction = await attestFromSolana(
            this.rpcProvider,
            CONTRACTS[this.network].solana.core,
            CONTRACTS[this.network].solana.token_bridge,
            this.signer.publicKey.toString(),
            tokenAddress,
        );
        const hash = await this.signAndSend(transaction);

        const sequence = await this.getSeqFromTxHash(hash);

        return {
            hash,
            sequence,
        };
    }

    async createWrapped({ vaaBytes }: GetSignedVAAResponse): Promise<DestChainTxResult> {
        const payerAddr = this.signer.publicKey.toBase58();

        await postVaaSolana(this.rpcProvider,
            async (transaction) => {
                transaction.partialSign(this.signer);
                return transaction;
            },
            CONTRACTS[this.network].solana.core,
            payerAddr,
            Buffer.from(vaaBytes),
        );

        const transaction = await createWrappedOnSolana(
            this.rpcProvider,
            CONTRACTS[this.network].solana.core,
            CONTRACTS[this.network].solana.token_bridge,
            payerAddr,
            vaaBytes,
        );
        
        const hash = await this.signAndSend(transaction);
        return {
            hash,
        };
    }

    async getTokenAddr(originChain: SupportedChain, originTokenAddr: Uint8Array) {
        if (originChain === 'solana') return tryUint8ArrayToNative(originTokenAddr, 'solana');

        /** solana returns null for non-bridged address */
        return await getForeignAssetSolana(
            this.rpcProvider,
            CONTRACTS[this.network].solana.token_bridge,
            originChain,
            originTokenAddr,
        );
    }
}

export class BridgeTransactor {
    wormholeRpcUri: string;
    ethTransactors: Record<Ethereumish, EthereumishTransactor>;
    solTransactor: SolanaTransactor;
    network: NetworkType;

    constructor(ethConf: EthereumConfig, solConf: SolanaConfig, network: NetworkType = 'TESTNET', wormholeRpcUri?: string) {
        this.network = network;
        this.wormholeRpcUri = wormholeRpcUri || wormholeRpcUrl;
        const keystoreJsonFile = fs.readdirSync(ethConf.keystorePath).pop();
        if (!keystoreJsonFile) {
            throw new Error("keystore may have no account.");
        }
        try {
            const signer = ethers.Wallet.fromEncryptedJsonSync(
                fs.readFileSync(path.join(ethConf.keystorePath, keystoreJsonFile)).toString(),
                fs.readFileSync(ethConf.passwordPath)
            );
            this.ethTransactors = ETHEREUMISH.reduce((transactors, chain) => ({
                ...transactors, 
                [chain]: new EthereumishTransactor(new ethers.providers.JsonRpcProvider(ethConf[chain] || defaultRpcs[chain]), signer, chain, network),
            }), {} as Record<Ethereumish, EthereumishTransactor>);
        } catch (e) {
            throw e;
        }
        this.solTransactor = new SolanaTransactor(solConf, network);
    }

    async listTokens(origin: GlobalAddr): Promise<Partial<Record<SupportedChain, string>>> {
        let result: Partial<Record<SupportedChain, string>> = {};
        await Promise.all(SUPPORTED_CHAINS.map(async (chain) => {
            result[chain] = (await this.getTokenAddr(chain, origin)).addr || undefined;
        }));
        return result;
    }

    /** not atomic */
    async teleportERC20(origin: GlobalAddr, src: SupportedChain, dst: SupportedChain, amount: ethers.BigNumber): Promise<TeleportResult> {
        if (src === dst) {
            throw new Error("no need to bridge");
        }

        const srcAddr = await this.getTokenAddr(src, origin);
        const dstAddr = await this.getTokenAddr(dst, origin);

        if (!srcAddr.addr || !dstAddr.addr) {
            throw new Error("given address may not deployed on the source or destination chain");
        }

        const srcRes = await this.lockToken(srcAddr.chain, dstAddr.chain, srcAddr.addr, amount);
        if (srcRes.vaas.length !== 1) console.log('expected vaa is one, but getting more or less');

        const vaa = srcRes.vaas.pop();
        if (!vaa) {
            console.log(srcRes);
            throw new Error("vaa is stil not signed by guardians. try again later.");
        };

        try {
            const destRes = await this.redeemToken(dstAddr.chain, vaa);

            return {
                src: srcRes,
                dst: destRes,
            };
        } catch (e) {
            console.log(srcRes);
            throw e;
        }
    }

    async lockToken(src: SupportedChain, dst: SupportedChain, tokenAddr: string, amount: ethers.BigNumber): Promise<SrcChainTxResult> {
        if (src === dst) {
            throw new Error("no need to lock");
        }

        const fallThrough = (e: any) => {
            console.error(e);
            return Promise.resolve([]);
        };

        if (src === 'solana') {
            const { hash, sequence } = await this.solTransactor.lockToken(
                dst,
                tryNativeToUint8Array(this.ethTransactors[dst as Ethereumish].signer.address, dst), //dst must be ethereumish
                tokenAddr,
                amount.toBigInt(),
            );
            const vaas = await this.getVAAWithSeq(sequence, src, CONTRACTS[this.network][src].token_bridge)
                .catch(fallThrough);

            return { hash, vaas };
        } else if (ETHEREUMISH.includes(src)) {
            const { hash, sequence } = await this.ethTransactors[src].lockToken(
                src,
                dst,
                this.solTransactor.signer.publicKey.toBuffer(),
                tokenAddr,
                amount,
            );
            const vaas = await this.getVAAWithSeq(sequence, src, CONTRACTS[this.network][src].token_bridge)
                .catch(fallThrough);
            
            return { hash, vaas };
        } else {
            throw new Error(`unreachable: ${src}`);
        }
    }

    redeemToken(dst: SupportedChain, vaa: GetSignedVAAResponse): Promise<DestChainTxResult>;
    redeemToken(dst: SupportedChain, txhash: string, src: SupportedChain): Promise<DestChainTxResult>;
    async redeemToken(dst: SupportedChain, info: unknown, src?: SupportedChain): Promise<DestChainTxResult> {
        if (typeof info === 'object') {
            const vaa = info as GetSignedVAAResponse;
            if (!vaa) throw new Error("unknow error occurred");
            switch(dst) {
                case 'solana': return await this.solTransactor.redeemToken(vaa);
                default: return await this.ethTransactors[dst].redeemToken(vaa);
            }
        } else if (typeof info === 'string') {
            const txHash = info;
            let seq;
            switch (src) {
                case undefined: throw new Error("source chain not provided");
                case 'solana': {
                    seq = await this.solTransactor.getSeqFromTxHash(txHash);
                    break;
                }
                default: seq = await this.ethTransactors[src].getSeqFromTxHash(txHash);
            }
            if (!seq) throw new Error("unknow error occurred");

            const vaas = await this.getVAAWithSeq(seq, src, CONTRACTS[this.network][src].token_bridge);
            const vaa = vaas.pop();
            if (!vaa) throw new Error("vaa is stil not signed by guardians");
            switch (dst) {
                case 'solana': return await this.solTransactor.redeemToken(vaa);
                default: return await this.ethTransactors[dst].redeemToken(vaa);
            }
        } else {
            throw new Error("unreachable");
        }
    }

    async getVAAWithSeq(sequence: string[], chain: SupportedChain, vaaEmitterAddr: string): Promise<GetSignedVAAResponse[]> {
        return Promise.all(sequence.map(async (log) => getSignedVAAWithRetry(
            [this.wormholeRpcUri],
            CHAINS[chain],
            chain === 'solana' ? await getEmitterAddressSolana(vaaEmitterAddr) : getEmitterAddressEth(vaaEmitterAddr),
            log,
            nodeTransport,
            DEFAULT_RETRY_TIMEOUT,
            DEFAULT_RETRY_LIMIT
        )));
    }

    async getTokenAddr(chain: SupportedChain, origin: GlobalAddr): Promise<GlobalAddr> {
        if (chain === origin.chain) {
            return origin;
        }

        const originTokenAddr = tryNativeToUint8Array(origin.addr || "", origin.chain);

        if (chain === 'solana') {
            return { chain, addr: await this.solTransactor.getTokenAddr(origin.chain, originTokenAddr) };
        } else if (ETHEREUMISH.includes(chain) && this.ethTransactors[chain]) {
            return { chain, addr: await this.ethTransactors[chain].getTokenAddr(origin.chain, originTokenAddr) };
        } else {
            throw new Error(`unreachable: ${chain}`);
        }
    }

    createWrapped(vaa: GetSignedVAAResponse, dst: SupportedChain): Promise<DestChainTxResult>;
    createWrapped(txHash: string, dst: SupportedChain, src: SupportedChain): Promise<DestChainTxResult>;
    async createWrapped(info: unknown, dst: SupportedChain, src?: SupportedChain): Promise<DestChainTxResult> {
        if (typeof info === 'object') {
            const vaa = info as GetSignedVAAResponse;
            if (!vaa) throw new Error("unknow error occurred");
            switch (dst) {
                case 'solana': return this.solTransactor.createWrapped(vaa);
                default: return this.ethTransactors[dst].createWrapped(vaa);
            }
        } else if (typeof info === 'string') {
            const txHash = info;
            let seq;
            switch (src) {
                case undefined: throw new Error("source chain not provided");
                case 'solana': {
                    seq = await this.solTransactor.getSeqFromTxHash(txHash);
                    break;
                }
                default: seq = await this.ethTransactors[src].getSeqFromTxHash(txHash);
            }
            if (!seq) throw new Error("unknow error occurred");

            const vaas = await this.getVAAWithSeq(seq, src, CONTRACTS[this.network][src].token_bridge);
            const vaa = vaas.pop();
            if (!vaa) throw new Error("vaa is stil not signed by guardians");
            switch (dst) {
                case 'solana': return this.solTransactor.createWrapped(vaa);
                default: return this.ethTransactors[dst].createWrapped(vaa);
            }
        } else {
            throw new Error("unreachable");
        }
    }

    async attestToken(tokenAddr: string, from: SupportedChain): Promise<SrcChainTxResult> {
        if (from === 'solana') {
            throw new Error("not implemented");
        } else if (ETHEREUMISH.includes(from)) {
            const {hash, sequence} = await this.ethTransactors[from].attestToken(tokenAddr);
            const vaas = await this.getVAAWithSeq(
                sequence,
                from,
                getEmitterAddressEth(CONTRACTS[this.network][from].token_bridge),
            );
            
            return { hash, vaas }
        } else {
            throw new Error(`unreachable ${from}`);
        }
    }

    async attestAndWrap(token: string, src: Ethereumish, dsts: SupportedChain[]): Promise<BridgeInitResult> {
        /** attesting token and get Vaa */
        const target = [...new Set(dsts)].filter((dst) => dst !== src);
        if (target.length === 0) {
            throw new Error("no valid destination");
        }

        const { hash: srcHash, vaas } = await this.attestToken(token, src);

        if (vaas.length !== 1) console.log('expected vaa is one, but getting more or less');

        const vaa = vaas.pop();
        if (!vaa) throw new Error("vaa is stil not signed by guardians");

        /** create wrapped token on each chain */
        const deployResult = await Promise.all(target.map(
            (dst) => this.createWrapped(vaa, dst)
                .catch((e: Error) => Promise.resolve({ error: `failed to wrap on ${dst} for ${e.message}` }))
                .then((res) => ({ ...res, chain: dst }))
        ));

        return {
            src: { hash: srcHash },
            dst: deployResult,
        };
    }
}
