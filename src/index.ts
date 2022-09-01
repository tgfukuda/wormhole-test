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
// send 1 token from solana to ethereum
// transactor.teleportToken(origin, 'solana', 'ethereum', ethers.utils.parseUnits("1", 8).toBigInt())
//     .then(console.log);
//send 1 token from ethereum to solana
// transactor.teleportToken(origin, 'ethereum', 'solana', ethers.utils.parseEther("1").toBigInt())
//     .then(console.log)
