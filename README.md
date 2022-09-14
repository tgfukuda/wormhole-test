# wormhole bridge client

## requirements

1. basic knowledge of ERC20, blockchain
2. nodejs runtime
3. valid ethereum wallet as a keystore and its password
4. valid solana wallet as a byte array. printSolkeyFromBase58 is exported from bridge.ts. if you have a base58 privatekey, convert it. 

## contents

`src/bridge.ts`:

wormhole bridge wrapper. basic methods for ERC20 included.
if no configuration, testnet one used.

`assets.testnet.json`:

test token data. attestation have already been done.

```
npm i
npx ts-node index.ts
```

to get any constant, refer to https://github.com/certusone/wormhole/blob/dev.v2/bridge_ui/src/utils/consts.ts
or ask on an official discord
