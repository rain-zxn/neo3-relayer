# Relayer

A relayer between Poly and Neo N3.

## Build From Source

### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.14 or later

### Build

```shell
git clone https://github.com/polynetwork/neo3-relayer.git
cd neo3-relayer
go build -o neo3-relayer main.go
```

After successfully building the source code, you should see the executable program `neo-relayer`.

## Run

Before running the relayer, you need to create a wallet file of PolyNetwork.
Then you need to register the account as a Relayer of the Poly net and let the consensus nodes approve your registration.
Finally, you can start relaying transactions between Poly and Neo.

Before running, you need feed the configuration file `config.json`.

```json
{
  "RelayJsonRpcUrl": "http://40.115.182.238:20336",                 // poly node rpc port
  "RelayChainID": 0,                                                // poly chain id
  "WalletFile": "./poly_test.dat",                                  // poly chain wallet file
  "NeoMagic": 5195066,                                              // Neo N3 network magic number
  "NeoWalletFile": "neo_test.json",                                 // Neo N3 wallet file
  "NeoJsonRpcUrl": "http://seed1t.neo.org:21332",                   // Neo N3 node rpc port
  "NeoChainID": 11,                                                 // Neo N3 chain id
  "NeoCCMC": "0x233e50e8f9c22563dc4873230a49d6931c2adebe",          // neo ccmc script hash in big endian
  "SpecificContract": "",                                           // the specific contract you want to monitor, eg. lock proxy, if empty, everything will be relayed
  "ScanInterval": 2,                                                // interval for scanning chains
  "RetryInterval": 2,                                               // interval for retrying sending tx to poly
  "DBPath": "boltdb",                                               // path for bolt db
  "ChangeBookkeeper": false,                                        // change bookkeeper or not
  "PolyStartHeight": 284956,                                        // start scanning height of poly
  "NeoStartHeight": 4790618                                         // start scanning height of neo
}
```

Now, you can start the relayer using the following command:

```shell
./neo3-relayer --neopwd pwd --relaypwd pwd
```

Flag `neopwd` is the password for your neo wallet and `relaypwd` is the password for your Poly wallet.
The relayer will generate logs under `./Logs` and you can check relayer status by view log file.
