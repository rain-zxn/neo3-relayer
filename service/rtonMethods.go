package service

import (
	"bytes"
	goc "crypto"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"github.com/joeqian10/neo3-gogogo/sc"
	"github.com/joeqian10/neo3-gogogo/tx"
	"github.com/polynetwork/neo3-relayer/db"
	"github.com/polynetwork/neo3-relayer/log"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	"strconv"
	"strings"
	"time"

	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
)

const (
	VERIFY_AND_EXECUTE_TX = "verifyAndExecuteTx"
	CHANGE_BOOK_KEEPER    = "changeBookKeeper"
	GET_BOOK_KEEPERS       = "getBookKeepers"
)

// GetCurrentNeoChainSyncHeight
func (this *SyncService) GetCurrentNeoChainSyncHeight(relayChainID uint64) (uint64, error) {
	response := this.neoSdk.GetStorage(this.config.NeoCCMC, "AgE=")
	if response.HasError() {
		return 0, fmt.Errorf("[GetCurrentNeoChainSyncHeight] GetCurrentHeight error: %s", "Engine faulted! "+response.Error.Message)
	}
	var height uint64
	s := response.Result
	if s == "" {
		return 0, nil
	}
	b, err := crypto.Base64Decode(s)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		height = 0
	} else {
		height = helper.BytesToUInt64(b)
		height++ // means the next block header needs to be synced
	}
	return height, nil
}

func (this *SyncService) changeBookKeeper(block *types.Block) error {
	headerBytes := block.Header.GetMessage()
	// raw header
	cp1 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerBytes,
	}
	log.Infof("raw header: %s", helper.BytesToHex(headerBytes))

	// public keys
	bs := []byte{}
	blkInfo := &vconfig.VbftBlockInfo{}
	_ = json.Unmarshal(block.Header.ConsensusPayload, blkInfo) // already checked before
	if blkInfo.NewChainConfig != nil {
		var bookkeepers []keypair.PublicKey
		for _, peer := range blkInfo.NewChainConfig.Peers {
			keyBytes, _ := hex.DecodeString(peer.ID)
			key, _ := keypair.DeserializePublicKey(keyBytes) // compressed
			bookkeepers = append(bookkeepers, key)
		}

		// unsorted pub keys----------------------------------------
		for _, pubKey := range bookkeepers {
			uncompressed := getRelayUncompressedKey(pubKey) // length 67
			bs = append(bs, uncompressed...)
		}

		log.Infof("unsorted pub keys: %s", helper.BytesToHex(bs))
		//bs = []byte{}
		// ---------------------------------------------------------

		//// sort the new public keys
		//bookkeepers = keypair.SortPublicKeys(bookkeepers)
		//for _, pubKey := range bookkeepers {
		//	uncompressed := getRelayUncompressedKey(pubKey) // length 67
		//	//log.Infof(helper.BytesToHex(uncompressed)) // sorted
		//	bs = append(bs, uncompressed...)
		//}
		//log.Infof("sorted pub keys: %s", helper.BytesToHex(bs))
	}
	cp2 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: bs,
	}

	// signatures
	var bs2 []byte
	if len(block.Header.SigData) == 0 {
		bs2 = []byte{}
	} else {
		var err error
		headerHash := block.Header.Hash()
		hasher := goc.SHA256.New()
		hasher.Write(headerHash.ToArray())
		digest := hasher.Sum(nil)
		bs2, err = this.sortSignatures(block.Header.SigData, digest)
		if err != nil {
			return fmt.Errorf("[changeBookKeeper] sort signatures error: %s", err)
		}
	}

	cp3 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: bs2,
	}
	log.Infof("signature: %s", helper.BytesToHex(bs2))

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoCCMC) // hex string in little endian
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, CHANGE_BOOK_KEEPER, []interface{}{cp1, cp2, cp3})
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] sc.MakeScript error: %s", err)
	}

	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] WalletHelper.GetAccountAndBalance error: %s", err)
	}
	trx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] WalletHelper.MakeTransaction error: %s", err)
	}
	// sign transaction
	trx, err = this.nwh.SignTransaction(trx, this.config.NeoMagic)
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] WalletHelper.SignTransaction error: %s", err)
	}

	rawTxString := crypto.Base64Encode(trx.ToByteArray())
	log.Infof(rawTxString)
	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		return fmt.Errorf("[changeBookKeeper] SendRawTransaction error: %s, "+
			"unsigned header hex string: %s, "+
			"public keys hex string: %s, "+
			"signatures hex string: %s"+
			"script hex string: %s, "+
			"changeBookKeeper RawTransactionString: %s",
			response.ErrorResponse.Error.Message,
			helper.BytesToHex(headerBytes),
			helper.BytesToHex(bs),
			helper.BytesToHex(bs2),
			helper.BytesToHex(script),
			rawTxString)
	}

	log.Infof("[changeBookKeeper] txHash is: %s", trx.GetHash().String())

	//// add new public keys to db, update relayPubkeys
	//this.relayPubKeys = recoverPublicKeys(bs)
	//err = this.db.PutPPKS(bs)
	//if err != nil {
	//	return fmt.Errorf("[changeBookKeeper] db.PutPPKS error: %s", err)
	//}
	return nil
}

func (this *SyncService) syncProofToNeo(key string, txHeight, lastSynced uint32) error {
	blockHeightReliable := lastSynced + 1
	// get the proof of the cross chain tx
	crossStateProof, err := this.relaySdk.ClientMgr.GetCrossStatesProof(txHeight, key)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] GetCrossStatesProof error: %s", err)
	}
	path, err := hex.DecodeString(crossStateProof.AuditPath)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] DecodeString error: %s", err)
	}
	txProof := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: path,
	}
	log.Infof("txProof: " + helper.BytesToHex(path))

	// get the next block header since it has the stateroot for the cross chain tx
	blockHeightToBeVerified := txHeight + 1
	headerToBeVerified, err := this.relaySdk.GetHeaderByHeight(blockHeightToBeVerified)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] GetHeaderByHeight error: %s", err)
	}
	txProofHeader := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerToBeVerified.GetMessage(),
	}
	log.Infof("txProofHeader: " + helper.BytesToHex(headerToBeVerified.GetMessage()))

	// check constraints
	if this.config.SpecificContract != "" { // if empty, relay everything
		stateRootValue, err := MerkleProve(path, headerToBeVerified.CrossStateRoot.ToArray())
		if err != nil {
			return fmt.Errorf("[syncProofToNeo] MerkleProve error: %s", err)
		}
		toMerkleValue, err := DeserializeMerkleValue(stateRootValue)

		if err != nil {
			return fmt.Errorf("[syncProofToNeo] DeserializeMerkleValue error: %s", err)
		}
		if helper.BytesToHex(toMerkleValue.TxParam.ToContract) != this.config.SpecificContract {
			log.Infof(helper.BytesToHex(toMerkleValue.TxParam.ToContract))
			log.Infof("This cross chain tx is not for this specific contract.")
			return nil
		}
	}

	var headerProofBytes []byte
	var currentHeaderBytes []byte
	var sigData [][]byte
	var headerHash common.Uint256
	var signListBytes []byte
	if txHeight >= lastSynced {
		// cross chain tx is in current epoch, no need for headerProof and currentHeader
		headerProofBytes = []byte{}
		currentHeaderBytes = []byte{}
		// the signList should be the signature of the header at txHeight + 1
		sigData = headerToBeVerified.SigData
		headerHash = headerToBeVerified.Hash()
	} else {
		// txHeight < lastSynced, so blockHeightToBeVerified < blockHeightReliable
		// get the merkle proof of the block containing the stateroot
		merkleProof, err := this.relaySdk.GetMerkleProof(blockHeightToBeVerified, blockHeightReliable)
		if err != nil {
			return fmt.Errorf("[syncProofToNeo] GetMerkleProof error: %s", err)
		}
		headerProofBytes, err = hex.DecodeString(merkleProof.AuditPath)
		if err != nil {
			return fmt.Errorf("[syncProofToNeo] merkleProof DecodeString error: %s", err)
		}

		// get the raw current header
		headerReliable, err := this.relaySdk.GetHeaderByHeight(blockHeightReliable)
		if err != nil {
			return fmt.Errorf("[syncProofToNeo] GetHeaderByHeight error: %s", err)
		}
		currentHeaderBytes = headerReliable.GetMessage()

		// get the sign list of the current header
		sigData = headerReliable.SigData
		headerHash = headerReliable.Hash()
	}

	headerProof := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerProofBytes,
	}
	log.Infof("headerProof: " + helper.BytesToHex(headerProofBytes))

	currentHeader := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: currentHeaderBytes,
	}
	log.Infof("currentHeader: " + helper.BytesToHex(currentHeaderBytes))

	log.Infof("headerHash: 0x" + headerHash.ToHexString())

	hasher := goc.SHA256.New()
	hasher.Write(headerHash.ToArray())
	digest := hasher.Sum(nil)

	signListBytes, err = this.sortSignatures(sigData, digest)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] sort signatures error: %s", err)
	}
	signList := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: signListBytes,
	}
	log.Infof("signList: " + helper.BytesToHex(signListBytes))

	stateRootValue, err := MerkleProve(path, headerToBeVerified.CrossStateRoot.ToArray())
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] MerkleProve error: %s", err)
	}
	toMerkleValue, err := DeserializeMerkleValue(stateRootValue)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] DeserializeMerkleValue error: %s", err)
	}
	log.Infof("fromChainId: " + strconv.Itoa(int(toMerkleValue.FromChainID)))
	log.Infof("polyTxHash: " + helper.BytesToHex(toMerkleValue.TxHash))
	log.Infof("fromContract: " + helper.BytesToHex(toMerkleValue.TxParam.FromContract))
	log.Infof("toChainId: " + strconv.Itoa(int(toMerkleValue.TxParam.ToChainID)))
	log.Infof("sourceTxHash: " + helper.BytesToHex(toMerkleValue.TxParam.TxHash))
	log.Infof("toContract: " + helper.BytesToHex(toMerkleValue.TxParam.ToContract))
	log.Infof("method: " + helper.BytesToHex(toMerkleValue.TxParam.Method))
	log.Infof("TxParamArgs: " + helper.BytesToHex(toMerkleValue.TxParam.Args))

	//toAssetHash, toAddress, amount, err := DeserializeArgs(toMerkleValue.TxParam.Args)
	//if err != nil {
	//	return fmt.Errorf("[syncProofToNeo] DeserializeArgs error: %s", err)
	//}
	//log.Infof("toAssetHash: " + helper.BytesToHex(toAssetHash))
	//log.Infof("toAddress: " + helper.BytesToHex(toAddress))
	//log.Infof("amount: " + amount.String())

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoCCMC)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, VERIFY_AND_EXECUTE_TX, []interface{}{txProof, txProofHeader, headerProof, currentHeader, signList})
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] sc.MakeScript error: %s", err)
	}
	log.Infof("script: " + helper.BytesToHex(script))
	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] WalletHelper.GetAccountAndBalance error: %s", err)
	}

	retry := &db.Retry{
		Height: txHeight,
		Key:    key,
	}
	sink := common.NewZeroCopySink(nil)
	retry.Serialization(sink)

	trx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient GAS") {
			err = this.db.PutNeoRetry(sink.Bytes())
			if err != nil {
				return fmt.Errorf("[syncProofToNeo] this.db.PutNeoRetry error: %s", err)
			}
			log.Infof("[syncProofToNeo] put tx into retry db, height %d, key %s, db key %s", txHeight, key, helper.BytesToHex(sink.Bytes()))
			return nil
		}
		return fmt.Errorf("[syncProofToNeo] WalletHelper.MakeTransaction error: %s", err)
	}

	// sign transaction
	trx, err = this.nwh.SignTransaction(trx, this.config.NeoMagic)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] WalletHelper.SignTransaction error: %s", err)
	}

	rawTxString := crypto.Base64Encode(trx.ToByteArray())
	log.Infof(rawTxString)

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		err = this.db.PutNeoRetry(sink.Bytes())
		if err != nil {
			return fmt.Errorf("[syncProofToNeo] this.db.PutNeoRetry error: %s", err)
		}
		log.Errorf("[syncProofToNeo] put tx into retry db, height %d, key %s, db key %s", txHeight, key, helper.BytesToHex(sink.Bytes()))
		return fmt.Errorf("[syncProofToNeo] SendRawTransaction error: %s, path(cp1): %s, cp2: %d, syncProofToNeo RawTransactionString: %s",
			response.ErrorResponse.Error.Message, helper.BytesToHex(path), int64(blockHeightReliable), rawTxString)
	}
	log.Infof("[syncProofToNeo] syncProofToNeo txHash is: %s", trx.GetHash().String())

	return nil
}

func (this *SyncService) retrySyncProofToNeo(v []byte, lastSynced uint32) error {
	retry := new(db.Retry)
	err := retry.Deserialization(common.NewZeroCopySource(v))
	if err != nil {
		return fmt.Errorf("[retrySyncProofToNeo] retry.Deserialization error: %s", err)
	}
	txHeight := retry.Height
	key := retry.Key

	blockHeightReliable := lastSynced + 1
	// get the proof of the cross chain tx
	crossStateProof, err := this.relaySdk.ClientMgr.GetCrossStatesProof(txHeight, key)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToNeo] GetCrossStatesProof error: %s", err)
	}
	path, err := hex.DecodeString(crossStateProof.AuditPath)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToNeo] DecodeString error: %s", err)
	}
	txProof := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: path,
	}
	//log.Infof("path: " + helper.BytesToHex(path))

	// get the next block header since it has the stateroot for the cross chain tx
	blockHeightToBeVerified := txHeight + 1
	headerToBeVerified, err := this.relaySdk.GetHeaderByHeight(blockHeightToBeVerified)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToNeo] GetHeaderByHeight error: %s", err)
	}
	txProofHeader := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerToBeVerified.GetMessage(),
	}

	//log.Infof("txProofHeader: " + helper.BytesToHex(headerToBeVerified.GetMessage()))

	var headerProofBytes []byte
	var currentHeaderBytes []byte
	var sigData [][]byte
	var headerHash common.Uint256
	var signListBytes []byte
	if txHeight >= lastSynced {
		// cross chain tx is in current epoch, no need for headerProof and currentHeader
		headerProofBytes = []byte{}
		currentHeaderBytes = []byte{}
		// the signList should be the signature of the header at txHeight + 1
		sigData = headerToBeVerified.SigData
		headerHash = headerToBeVerified.Hash()
	} else {
		// txHeight < lastSynced, so blockHeightToBeVerified < blockHeightReliable
		// get the merkle proof of the block containing the stateroot
		merkleProof, err := this.relaySdk.GetMerkleProof(blockHeightToBeVerified, blockHeightReliable)
		if err != nil {
			return fmt.Errorf("[retrySyncProofToNeo] GetMerkleProof error: %s", err)
		}
		headerProofBytes, err = hex.DecodeString(merkleProof.AuditPath)
		if err != nil {
			return fmt.Errorf("[retrySyncProofToNeo] merkleProof DecodeString error: %s", err)
		}
		log.Infof("headerPath: " + helper.BytesToHex(headerProofBytes))

		// get the raw current header
		headerReliable, err := this.relaySdk.GetHeaderByHeight(blockHeightReliable)
		if err != nil {
			return fmt.Errorf("[retrySyncProofToNeo] GetHeaderByHeight error: %s", err)
		}
		currentHeaderBytes = headerReliable.GetMessage()

		// get the sign list of the current header
		sigData = headerReliable.SigData
		headerHash = headerReliable.Hash()
	}

	headerProof := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerProofBytes,
	}
	//log.Infof("headProof: " + helper.BytesToHex(headerProofBytes))

	currentHeader := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: currentHeaderBytes,
	}
	//log.Infof("currentHeader: " + helper.BytesToHex(currentHeaderBytes))

	hasher := goc.SHA256.New()
	hasher.Write(headerHash.ToArray())
	digest := hasher.Sum(nil)
	signListBytes, err = this.sortSignatures(sigData, digest)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToNeo] sort signatures error: %s", err)
	}
	signList := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: signListBytes,
	}
	//log.Infof("signList: " + helper.BytesToHex(signListBytes))

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoCCMC) // hex string in little endian
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, VERIFY_AND_EXECUTE_TX, []interface{}{txProof, txProofHeader, headerProof, currentHeader, signList})
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] sc.MakeScript error: %s", err)
	}
	log.Infof("script: " + helper.BytesToHex(script))
	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] WalletHelper.GetAccountAndBalance error: %s", err)
	}
	trx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] WalletHelper.MakeTransaction error: %s", err)
	}

	// sign transaction
	trx, err = this.nwh.SignTransaction(trx, this.config.NeoMagic)
	if err != nil {
		return fmt.Errorf("[syncProofToNeo] WalletHelper.SignTransaction error: %s", err)
	}
	rawTxString := crypto.Base64Encode(trx.ToByteArray())
	log.Infof(rawTxString)

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		if strings.Contains(response.ErrorResponse.Error.Message, "Block or transaction validation failed") {
			log.Infof("[retrySyncProofToNeo] remain tx in retry db, SendRawTransaction: height %d, key %s, db key %s", txHeight, key, helper.BytesToHex(v))
			return nil
		}

		err := this.db.DeleteNeoRetry(v)
		if err != nil {
			return fmt.Errorf("[retrySyncProofToNeo] this.db.DeleteNeoRetry error: %s", err)
		}
		log.Infof("[retrySyncProofToNeo] delete tx from retry db, height %d, key %s, db key %s", txHeight, key, helper.BytesToHex(v))
		return fmt.Errorf("[retrySyncProofToNeo] SendRawTransaction error: %s, path(cp1): %s, cp2: %d, syncProofToNeo RawTransactionString: %s",
			response.ErrorResponse.Error.Message, helper.BytesToHex(path), int64(blockHeightReliable), rawTxString)
	}
	log.Infof("[retrySyncProofToNeo] syncProofToNeo txHash is: %s", trx.GetHash().String())

	err = this.db.DeleteNeoRetry(v)
	if err != nil {
		err := this.db.DeleteNeoRetry(v)
		log.Infof("[retrySyncProofToNeo] delete tx from retry db, height %d, key %s, db key %s", txHeight, key, helper.BytesToHex(v))
		return fmt.Errorf("[retrySyncProofToNeo] this.db.DeleteNeoRetry error: %s", err)
	}
	return nil
}

func (this *SyncService) neoRetryTx() error {
	retryList, err := this.db.GetAllNeoRetry()
	if err != nil {
		return fmt.Errorf("[neoRetryTx] this.db.GetAllRetry error: %s", err)
	}
	for _, v := range retryList {
		// get current neo chain sync height, which is the reliable header height
		currentNeoChainSyncHeight, err := this.GetCurrentNeoChainSyncHeight(this.relaySdk.ChainId)
		if err != nil {
			log.Errorf("[neoRetryTx] GetCurrentNeoChainSyncHeight error: ", err)
		}
		err = this.retrySyncProofToNeo(v, uint32(currentNeoChainSyncHeight))
		if err != nil {
			log.Errorf("[neoRetryTx] this.retrySyncProofToNeo error:%s", err)
		}
		time.Sleep(time.Duration(this.config.RetryInterval) * time.Second)
	}

	return nil
}

func (this *SyncService) waitForNeoBlock() {
	response := this.neoSdk.GetBlockCount()
	currentNeoHeight := uint32(response.Result - 1)
	newNeoHeight := currentNeoHeight
	for currentNeoHeight == newNeoHeight {
		time.Sleep(time.Duration(15) * time.Second)
		newResponse := this.neoSdk.GetBlockCount()
		newNeoHeight = uint32(newResponse.Result - 1)
	}
}

func (this *SyncService) getCurrentPolyBookKeeps() error {
	scriptHash, err := helper.UInt160FromString(this.config.NeoCCMC) // hex string in little endian
	if err != nil {
		return fmt.Errorf("[getBookKeeps] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, GET_BOOK_KEEPERS, []interface{}{})
	if err != nil {
		return fmt.Errorf("[getBookKeeps] sc.MakeScript error: %s", err)
	}
	response := this.neoSdk.InvokeScript(crypto.Base64Encode(script), nil)
	if response.HasError() {
		return fmt.Errorf("[getBookKeeps] InvokeScript error: %s", response.GetErrorInfo())
	}
	if len(response.Result.Stack) == 0 {
		return fmt.Errorf("[getBookKeeps] InvokeScript response stack incorrect length")
	}
	stack0 := response.Result.Stack[0] // Array of ByteArray
	stack0.Convert()
	if stack0.Type != "Array" {
		return fmt.Errorf("[getBookKeeps] InvokeScript response stack incorrect type")
	}
	values := stack0.Value.([]models.InvokeStack)

	pubKeys := make([][]byte, len(values))
	for i, v := range values {
		if v.Type != "ByteString" {
			return fmt.Errorf("[getBookKeeps] InvokeScript response inside stack incorrect type")
		}
		s, err := crypto.Base64Decode(v.Value.(string))
		if err != nil {
			return fmt.Errorf("[getBookKeeps] crypto.Base64Decode error: %s", err)
		}
		//pubKey, err := crypto.FromBytes(s, btcec.S256())
		pubKey, err := btcec.ParsePubKey(s, btcec.S256())
		if err != nil {
			return fmt.Errorf("[getBookKeeps] crypto.NewECPointFromString error: %s", err)
		}
		pubKeys[i] = pubKey.SerializeUncompressed() // length 65
		//log.Infof(helper.BytesToHex(pubKeys[i]))
	}
	this.relayPubKeys = pubKeys
	return nil
}

// sort signatures according to public key order, append sorted signatures together
func (this *SyncService) sortSignatures(sigs [][]byte, hash []byte) ([]byte, error) {
	// ----------------------------------------------------------------
	//// get pubKeys from db if nil
	//if len(this.relayPubKeys) == 0 {
	//	pubKeys, err := this.db.GetPPKS()
	//	if err != nil {
	//		return nil, err
	//	}
	//	if len(pubKeys) == 0 {
	//		return nil, fmt.Errorf("relay public keys not found in db")
	//	}
	//	if len(pubKeys)%65 != 0 {
	//		return nil, fmt.Errorf("wrong length for relay public keys in db")
	//	}
	//	this.relayPubKeys = recoverPublicKeys(pubKeys)
	//}
	// ------------------------------------------------------------------

	// get pubKeys from ccmc
	err := this.getCurrentPolyBookKeeps()
	if err != nil {
		return nil, fmt.Errorf("[sortSignatures] getCurrentPolyBookKeeps error: %s", err)
	}
	return sortSignatures(this.relayPubKeys, sigs, hash)
}

func sortSignatures(pubKeys, sigs [][]byte, hash []byte) ([]byte, error) {
	// sig length should >= 2/3 * len(pubKeys) + 1
	if len(sigs) < len(pubKeys)*2/3+1 {
		return nil, fmt.Errorf("[sortSignatures] not enough signatures")
	}
	sortedSigs := make([][]byte, len(pubKeys)) // len(relayPubKeys)?
	log.Infof("before sorting sig: ")
	for _, sig := range sigs {
		//log.Infof(helper.BytesToHex(sig))
		pubKey, err := recoverPublicKeyFromSignature(sig, hash) // sig in BTC format
		//log.Infof(helper.BytesToHex(pubKey))
		if err != nil {
			return nil, fmt.Errorf("[sortSignatures] recoverPublicKeyFromSignature error: %s", err)
		}
		//newPubKey := append([]byte{0x12, 0x05}, pubKey...)
		//log.Infof(helper.BytesToHex(newPubKey))
		index := -1
		for i, _ := range pubKeys {
			if bytes.Equal(pubKeys[i], pubKey) {
				index = i
				break
			}
		}
		if index == -1 {
			return nil, fmt.Errorf("[sortSignatures] signature (%s) recovered public key (%s) not found", helper.BytesToHex(sig), helper.BytesToHex(pubKey))
		}
		sortedSigs[index] = sig
	}
	sigListBytes := []byte{}
	log.Infof("sorted sig: ")
	for _, sortedSig := range sortedSigs {
		// convert to eth format
		if len(sortedSig) != 0 {
			//log.Infof(helper.BytesToHex(sortedSig))
			newSig, _ := signature.ConvertToEthCompatible(sortedSig)
			sigListBytes = append(sigListBytes, newSig...)
		}
	}
	return sigListBytes, nil
}

const PolyPublicKeyLength int = 67

func recoverPublicKeys(pubKeys []byte) [][]byte {
	count := len(pubKeys) / PolyPublicKeyLength
	relayPubKeys := make([][]byte, count)
	for i := 0; i < count; i++ {
		relayPubKeys[i] = pubKeys[i*PolyPublicKeyLength : i*PolyPublicKeyLength+PolyPublicKeyLength]
	}
	return relayPubKeys
}

func getRelayUncompressedKey(key keypair.PublicKey) []byte {
	var buff bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buff.WriteByte(byte(0x12))
		case ec.SM2:
			buff.WriteByte(byte(0x13))
		}
		label, err := getCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buff.WriteByte(label)
		buff.Write(ec.EncodePublicKey(t.PublicKey, false))
	default:
		panic("err")
	}
	return buff.Bytes()
}

func getCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}

func recoverPublicKeyFromSignature(sig, hash []byte) ([]byte, error) {
	s, err := signature.Deserialize(sig)
	if err != nil {
		return nil, err
	}
	t, ok := s.Value.([]byte)
	if !ok {
		return nil, errors.New("invalid signature type")
	}
	if len(t) != 65 {
		return nil, errors.New("invalid signature length")
	}

	pubKey, _, err := btcec.RecoverCompact(btcec.S256(), t, hash) // S256 is secp256k1, P256 is secp256r1,
	if err != nil {
		return nil, err
	}
	return pubKey.SerializeUncompressed(), nil // length in 65
}

func recoverPublicKeyFromSignature1(sig, hash []byte) ([]byte, error) {
	s, err := signature.Deserialize(sig)
	if err != nil {
		return nil, err
	}
	t, ok := s.Value.([]byte)
	if !ok {
		return nil, errors.New("invalid signature type")
	}
	if len(t) != 65 {
		return nil, errors.New("invalid signature length")
	}

	pubKey, _, err := btcec.RecoverCompact(btcec.S256(), t, hash) // S256 is secp256k1, P256 is secp256r1,
	if err != nil {
		return nil, err
	}
	return pubKey.SerializeCompressed(), nil // length in 65
}
