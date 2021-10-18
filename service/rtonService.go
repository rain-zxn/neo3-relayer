package service

import (
	"encoding/json"
	"fmt"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	autils "github.com/polynetwork/poly/native/service/utils"
	"time"
)

// RelayToNeo sync headers from relay chain to neo
func (this *SyncService) RelayToNeo() {
	this.neoSyncHeight = this.config.PolyStartHeight
	for {
		currentRelayChainHeight, err := this.relaySdk.GetCurrentBlockHeight()
		if err != nil {
			Log.Errorf("[RelayToNeo] GetCurrentBlockHeight error: ", err)
		}
		err = this.relayToNeo(this.neoSyncHeight, currentRelayChainHeight)
		if err != nil {
			Log.Errorf("[RelayToNeo] relayToNeo error: ", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) relayToNeo(m, n uint32) error {
	for i := m; i < n; i++ {
		Log.Infof("[relayToNeo] start parse block %d", i)

		block, err := this.relaySdk.GetBlockByHeight(i)
		if err != nil {
			return fmt.Errorf("[relayToNeo] GetBlockByHeight error: %s", err)
		}
		txs := block.Transactions
		for _, tx := range txs {
			txHash := tx.Hash()
			event, err := this.relaySdk.GetSmartContractEvent(txHash.ToHexString())
			if err != nil {
				return fmt.Errorf("[relayToNeo] relaySdk.GetSmartContractEvent error:%s", err)
			}
			for _, notify := range event.Notify {
				states, ok := notify.States.([]interface{})
				if !ok {
					continue
				}
				if notify.ContractAddress != autils.CrossChainManagerContractAddress.ToHexString() { // relay chain CCMC
					continue
				}
				name := states[0].(string)
				if name == "makeProof" {
					toChainID := uint64(states[2].(float64))
					if toChainID == this.config.NeoChainID {
						key := states[5].(string)
						// get current neo chain sync height, which is the reliable header height
						currentNeoChainSyncHeight, err := this.GetCurrentNeoChainSyncHeight()
						if err != nil {
							Log.Errorf("[relayToNeo] GetCurrentNeoChainSyncHeight error: ", err)
						}
						err = this.syncProofToNeo(key, i, uint32(currentNeoChainSyncHeight))
						if err != nil {
							Log.Errorf("--------------------------------------------------")
							Log.Errorf("[relayToNeo] syncProofToNeo error: %s", err)
							Log.Errorf("polyHeight: %d, key: %s", i, key)
							Log.Errorf("--------------------------------------------------")
						}
					}
				}
			}
		}

		if this.config.ChangeBookkeeper {
			// sync key header, change book keeper
			// but should be done after all cross chain tx in this block are handled for verification purpose.

			blkInfo := &vconfig.VbftBlockInfo{}
			if err := json.Unmarshal(block.Header.ConsensusPayload, blkInfo); err != nil {
				return fmt.Errorf("[relayToNeo] unmarshal blockInfo error: %s", err)
			}
			if blkInfo.NewChainConfig != nil {
				//this.waitForNeoBlock() // wait for neo block
				err = this.changeBookKeeper(block)
				if err != nil {
					Log.Errorf("--------------------------------------------------")
					Log.Errorf("[relayToNeo] syncHeaderToNeo error: %s", err)
					Log.Errorf("polyHeight: %d", i)
					Log.Errorf("--------------------------------------------------")
				}
			}
		}

		this.neoSyncHeight++
	}
	return nil
}

func (this *SyncService) RelayToNeoCheckAndRetry() {
	for {
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second) // 15 seconds a block
		err := this.neoCheckTx()
		if err != nil {
			Log.Errorf("[RelayToNeoCheckAndRetry] this.neoCheckTx error: %s", err)
		}
		err = this.neoRetryTx()
		if err != nil {
			Log.Errorf("[RelayToNeoCheckAndRetry] this.neoRetryTx error: %s", err)
		}
	}
}
