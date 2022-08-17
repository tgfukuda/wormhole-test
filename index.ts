import { getSignedVAAWithRetry, attestFromEth, createWrappedOnSolana, postVaaSolana, createWrappedOnEth, CHAINS, CONTRACTS, parseSequencesFromLogEth, getEmitterAddressEth, setDefaultWasm } from '@certusone/wormhole-sdk';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { NodeHttpTransport } from '@improbable-eng/grpc-web-node-http-transport';
import { Connection, Keypair, PublicKey, TokenAccountsFilter, Transaction } from '@solana/web3.js';
import { ASSOCIATED_TOKEN_PROGRAM_ID, Token, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { GetSignedVAAResponse } from '@certusone/wormhole-sdk-proto-web/lib/cjs/publicrpc/v1/publicrpc';
import { base58_to_binary } from 'base58-js';

setDefaultWasm('node');

const wormhorleRpcUrl = 'https://wormhole-v2-testnet-api.certus.one';
const solanaRpcUrl = 'https://api.devnet.solana.com';
const fujiCChainRpcUrl = 'https://api.avax-test.network/ext/bc/C/rpc';
const mumbaiRocUrl = 'https://rpc-mumbai.matic.today';
const bscRpcUrl = 'https://data-seed-prebsc-1-s1.binance.org:8545/';

const nodeTransport = {
    transport: NodeHttpTransport()
};
const defaultRetryTimeout = 1000;
const defaultRetryLimit = 10;

class KeystoreNotFoundError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "KeystoreNotFoundError";
    }
}

class InitWalletError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "InitWalletError";
    }
}

class SolTxError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "SolanaTxError";
    }
}

type Ethereumish = 'ethereum' | 'avalanche' | 'polygon' | 'bsc';

type SignerConfig = {
    keystorePath: string,
    passwordPath: string,
};

type EthereumConfig = Partial<Record<Exclude<Ethereumish, 'ethereum'>, string>> & { infuraApiKey: string } & SignerConfig;

type SolanaConfig = {
    rpcUri?: string,
    privKeyPath: string,
};

type SrcChainTxResult = {
    hash: string,
    vaas: GetSignedVAAResponse[],
};

type DestChainTxResult = {
    hash: string,
};

class BridgeTransactor {
    wormholeRpcUri: string;
    ethSigner: ethers.Wallet;
    solRpcProvider: Connection;
    solSigner: Keypair;
    ethereumishRpcProviders: Record<Exclude<Ethereumish, 'ethereum'>, ethers.providers.JsonRpcProvider> & {
        ethereum: ethers.providers.InfuraProvider,
    };
    

    constructor(wormholeRpcUri: string, ethConf: EthereumConfig, solConf: SolanaConfig) {
        const keystoreJsonFile = fs.readdirSync(ethConf.keystorePath).pop();
        this.wormholeRpcUri = wormholeRpcUri;
        try {
            if (!keystoreJsonFile) {
                throw new KeystoreNotFoundError("keystore may have no account.");
            }

            this.ethereumishRpcProviders = {
                ethereum: new ethers.providers.InfuraProvider('goerli', ethConf.infuraApiKey),
                avalanche: new ethers.providers.JsonRpcProvider(ethConf.avalanche || fujiCChainRpcUrl),
                polygon: new ethers.providers.JsonRpcProvider(ethConf.polygon || mumbaiRocUrl),
                bsc: new ethers.providers.JsonRpcProvider(ethConf.bsc || bscRpcUrl),
            };

            this.ethSigner = ethers.Wallet.fromEncryptedJsonSync(
                fs.readFileSync(path.join(ethConf.keystorePath, keystoreJsonFile)).toString(),
                fs.readFileSync(ethConf.passwordPath)
            );
            this.solRpcProvider = new Connection(solConf.rpcUri || solanaRpcUrl, 'confirmed');
            this.solSigner = Keypair.fromSecretKey(base58_to_binary(fs.readFileSync(solConf.privKeyPath).toString()));
        } catch (e) {
            throw new InitWalletError((e as Error).message);
        }
    }

    async getVAAFromEthereumishTxHash(hash: string, bridgeAddr: string, ethereumish: Ethereumish = 'ethereum') {
        const receipt = await this.ethereumishRpcProviders[ethereumish].getTransactionReceipt(hash);
        const sequence = parseSequencesFromLogEth(receipt, CONTRACTS.TESTNET[ethereumish].core);
        const vaas = [];

        for (const log of sequence) {
            vaas.push(await getSignedVAAWithRetry(
                [this.wormholeRpcUri],
                CHAINS[ethereumish],
                getEmitterAddressEth(bridgeAddr),
                log,
                nodeTransport,
                defaultRetryTimeout,
                defaultRetryLimit
            ));
        }
        
        return vaas;
    }

    async attestERC20FromEthereumish(tokenAddress: string, ethereumish: Ethereumish = 'ethereum'): Promise<SrcChainTxResult> {
        const signer = this.ethSigner.connect(this.ethereumishRpcProviders[ethereumish]);
        const receipt = await attestFromEth(CONTRACTS.TESTNET[ethereumish].token_bridge, signer, tokenAddress);
        const sequence = parseSequencesFromLogEth(receipt, CONTRACTS.TESTNET[ethereumish].core);
        const vaas = [];
        for (const log of sequence) {
            vaas.push(await getSignedVAAWithRetry(
                [this.wormholeRpcUri],
                CHAINS[ethereumish],
                getEmitterAddressEth(CONTRACTS.TESTNET[ethereumish].token_bridge),
                log,
                nodeTransport,
                defaultRetryTimeout,
                defaultRetryLimit
            ));
        }

        return {
            hash: receipt.transactionHash,
            vaas
        };
    }

    async createWrappedOnEthereumish({ vaaBytes }: GetSignedVAAResponse, ethereumish: Ethereumish): Promise<DestChainTxResult> {
        const signer = this.ethSigner.connect(this.ethereumishRpcProviders[ethereumish]);
        const tx = await createWrappedOnEth(CONTRACTS.TESTNET[ethereumish].token_bridge, signer, vaaBytes);

        return {
            hash: tx.transactionHash,
        };
    }

    async createWrappedOnSolana({ vaaBytes }: GetSignedVAAResponse): Promise<DestChainTxResult> {
        const payerAddr = this.solSigner.publicKey.toString();

        const postTx = await postVaaSolana(this.solRpcProvider,
            async (transaction) => {
                transaction.partialSign(this.solSigner);
                return transaction;
            },
            CONTRACTS.TESTNET.solana.core,
            payerAddr,
            Buffer.from(vaaBytes)
        );

        const transaction = await createWrappedOnSolana(
            this.solRpcProvider,
            CONTRACTS.TESTNET.solana.core,
            CONTRACTS.TESTNET.solana.token_bridge,
            payerAddr,
            vaaBytes
        );
        
        try {
            transaction.partialSign(this.solSigner);
            const hash = await this.solRpcProvider.sendRawTransaction(transaction.serialize());
            
            const latestBlockHash = await this.solRpcProvider.getLatestBlockhash();

            const receipt = await this.solRpcProvider.confirmTransaction({
                blockhash: latestBlockHash.blockhash,
                lastValidBlockHeight: latestBlockHash.lastValidBlockHeight,
                signature: hash
            });
            if (receipt.value.err) {
                console.error(receipt.value.err);
            }
            return {
                hash
            };
        } catch (e) {
            console.error(e);
            throw new SolTxError((e as Error).message);
        }
    }
}

const attestHash = '0x7fdcdd34ab07560a6b8d7423b598bc47a5ee80d78c270eaae957aa49f379d7d2';

const transactor = new BridgeTransactor(wormhorleRpcUrl, {
    keystorePath: process.env.KEYSTORE || "",
    passwordPath: process.env.PASSWORD || "",
    infuraApiKey: process.env.INFURA_API_KEY || "",
}, {
    privKeyPath: process.env.SOL_PRIV_KEY || "",
});

const exaToken = "0x4319D92C172acaE5D37724C139f86179F37C29CC";

(async () => {
    const [vaa, ..._] = await transactor.getVAAFromEthereumishTxHash(attestHash, CONTRACTS.TESTNET.ethereum.token_bridge);
    const createTx = await transactor.createWrappedOnEthereumish(vaa, 'avalanche');

    console.log(createTx);
})()
