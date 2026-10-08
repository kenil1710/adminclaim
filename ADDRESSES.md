# Addresses

Network: GenLayer Studio Dev (chain id 61997), RPC `https://studio-dev.genlayer.com/api`, explorer https://explorer-studio-dev.genlayer.com/

| Deployment | Address | Constructor | Commit | Deploy | contracts/AdminClaim.py sha256 |
|---|---|---|---|---|---|
| CANONICAL | [`0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8`](https://explorer-studio-dev.genlayer.com/address/0x13cb760E534A5edA7e383cd9A0f6E1b0b84f23E8) | `["CANONICAL",21600,3600]` | [`df32b0eac7`](https://github.com/kenil1710/adminclaim/commit/df32b0eac7ffc4d09f7688a0a188404013f1ae5c) | [deploy tx](https://explorer-studio-dev.genlayer.com/tx/0x53fc3c31f0d2b5794b30e230d9f3cc66e4d04a86ec5c6df71b004c2f24e5c44c) | `475d84e43af4fa7016003499b7cb6fe810aef626787c801ab24f795f0b0167db` |
| DEMO | [`0x4974407d9611a979677E3203CA2f95e283907554`](https://explorer-studio-dev.genlayer.com/address/0x4974407d9611a979677E3203CA2f95e283907554) | `["DEMO",60,600]` | [`df32b0eac7`](https://github.com/kenil1710/adminclaim/commit/df32b0eac7ffc4d09f7688a0a188404013f1ae5c) | [deploy tx](https://explorer-studio-dev.genlayer.com/tx/0x41a2fec2687d8f920b1190e1cec37cef3c117b222821214ceeac04b596205ff4) | `475d84e43af4fa7016003499b7cb6fe810aef626787c801ab24f795f0b0167db` |

Both deployments are the same file from the same commit; only the constructor differs (cooldown seconds, freshness seconds). `node tools/verify_source.mjs` reads the code back with `gen_getContractCode` and compares it byte for byte with `contracts/` at HEAD.

Previous deployments: [docs/superseded/README.md](docs/superseded/README.md).
