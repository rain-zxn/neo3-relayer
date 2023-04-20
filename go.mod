module github.com/polynetwork/neo3-relayer

go 1.14

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/joeqian10/EasyLogger v1.0.0
	github.com/joeqian10/neo3-gogogo v1.1.2
	github.com/ontio/ontology v1.14.4 // indirect
	github.com/ontio/ontology-crypto v1.2.1
	github.com/polynetwork/bridge-common v0.0.38-alpha
	github.com/polynetwork/poly v1.8.3
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.4
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/tendermint/tm-db/064 => github.com/tendermint/tm-db v0.6.4
