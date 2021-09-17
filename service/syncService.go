package service

import (
	rpc2 "github.com/joeqian10/neo-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/wallet"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/db"
	"github.com/polynetwork/neo3-relayer/log"
	rsdk "github.com/polynetwork/poly-go-sdk"
	"os"
)

var Log = log.Log

// SyncService ...
type SyncService struct {
	relayAccount    *rsdk.Account
	relaySdk        *rsdk.PolySdk
	relaySyncHeight uint32
	relayPubKeys    [][]byte

	nwh                *wallet.WalletHelper
	neoSdk             *rpc.RpcClient
	neoSyncHeight      uint32
	neoNextConsensus   string
	neoStateRootHeight uint32

	neo2Sdk *rpc2.RpcClient

	db     *db.BoltDB
	config *config.Config
}

// NewSyncService ...
func NewSyncService(acct *rsdk.Account, relaySdk *rsdk.PolySdk, neoAccount *wallet.WalletHelper, client *rpc.RpcClient, client2 *rpc2.RpcClient) *SyncService {
	if !checkIfExist(config.DefConfig.DBPath) {
		os.Mkdir(config.DefConfig.DBPath, os.ModePerm)
	}
	boltDB, err := db.NewBoltDB(config.DefConfig.DBPath)
	if err != nil {
		Log.Errorf("db.NewWaitingDB error:%s", err)
		os.Exit(1)
	}
	syncSvr := &SyncService{
		relayAccount:       acct,
		relaySdk:           relaySdk,
		neoSdk:             client,
		neoStateRootHeight: 0,
		nwh:                neoAccount,
		neo2Sdk:            client2,
		db:                 boltDB,
		config:             config.DefConfig,
	}
	return syncSvr
}

// Run ...
func (this *SyncService) Run() {
	go this.RelayToNeo()
	go this.RelayToNeoCheckAndRetry()
	//go this.NeoToRelay()
	//go this.NeoToRelayCheckAndRetry()
}

func checkIfExist(dir string) bool {
	_, err := os.Stat(dir)
	if err != nil && !os.IsExist(err) {
		return false
	}
	return true
}
