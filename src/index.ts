import { BridgeTransactor, GlobalAddr } from './bridge';
import ASSETS from '../assets.testnet.json';
import { ethers } from 'ethers';

const ethDefaultConf = {
    keystorePath: process.env.KEYSTORE || "",
    passwordPath: process.env.PASSWORD || "",
    ethereum: process.env.ETH_PROVIDER|| "",
};
const solDefaultConf = {
    privKeyPath: process.env.SOL_PRIV_KEY || "",
};

const transactor = new BridgeTransactor(ethDefaultConf, solDefaultConf);

const attestHash = ASSETS.ExampleToken.attestHash;

const origin: GlobalAddr = {
    chain: 'ethereum',
    addr: ASSETS.ExampleToken.ethereum,
};

// EX.
// transactor.teleportToken(origin, 'solana', 'ethereum', ethers.utils.parseUnits("1", 7).toBigInt())
//     .then(console.log);