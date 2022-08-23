import { BridgeTransactor, Asset, printSolkeyFromBase58, GlobalAddr } from './bridge';
import ASSETS from '../assets.testnet.json';
import { ethers } from 'ethers';

const attestHash = '0x7fdcdd34ab07560a6b8d7423b598bc47a5ee80d78c270eaae957aa49f379d7d2';
const teleportHashSolana = '0xb612a6d7b654c45f0e9b9e77732de6641d594ec9e8d53e3e6a8c64262a2383eb';
const teleportHashAvalanche = '0xb6cea7bb5a79407bcb3eb4a019e5621413c95a0c4f836ed7118b4ab4d475a05d';

const ethDefaultConf = {
    keystorePath: process.env.KEYSTORE || "",
    passwordPath: process.env.PASSWORD || "",
    ethereum: process.env.ETH_PROVIDER|| "",
};
const solDefaultConf = {
    privKeyPath: process.env.SOL_PRIV_KEY || "",
};

const transactor = new BridgeTransactor(ethDefaultConf, solDefaultConf);

const amount = ethers.BigNumber.from(ethers.utils.parseEther('1'));
const origin: GlobalAddr = {
    chain: 'ethereum',
    addr: ASSETS.ExampleToken.ethereum,
};

transactor.lockToken('ethereum', 'avalanche', ASSETS.ExampleToken.ethereum, amount)
    .then(console.log)
    