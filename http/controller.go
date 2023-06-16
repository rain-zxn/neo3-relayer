package main

import (
	"bytes"
	goc "crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"github.com/joeqian10/neo3-gogogo/sc"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/service"
	rsdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	autils "github.com/polynetwork/poly/native/service/utils"
	"net/http"
	"strconv"
)

const (
	VERIFY_AND_EXECUTE_TX = "verifyAndExecuteTx"
	GET_BOOK_KEEPERS      = "getBookKeepers"
	METHOD_UNLOCK         = "unlock"
	METHOD_BRIDGEIN       = "bridgeIn"
)

type Controller struct {
	syncService  *service.SyncService
	neoSdk       *rpc.RpcClient
	relaySdk     *rsdk.PolySdk
	relayPubKeys [][]byte
}

type DstTx struct {
	Data   string `json:"data"`
	DstCCM string `json:"dst_ccm"`
}

var controller *Controller

func (c *Controller) ComposeDstTx(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	if hash == "" {
		http.Error(w, "request not invalid", http.StatusBadRequest)
		return
	}
	Log.Infof("Composing dst tx poly_hash: %v", hash)
	data, err := c.composeDstTx(hash)
	dstTx := &DstTx{
		Data:   hex.EncodeToString(data),
		DstCCM: config.DefConfig.NeoCCMC,
	}
	if err != nil {
		Log.Errorf("Failed to compose dst tx err: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		bytes, err := json.Marshal(dstTx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	}
}

func (c *Controller) composeDstTx(hash string) (data []byte, err error) {
	txHeight, err := c.relaySdk.GetBlockHeightByTxHash(hash)
	event, err := c.relaySdk.GetSmartContractEvent(hash)
	if err != nil {
		return nil, fmt.Errorf("composeDstTx GetSmartContractEvent error:%s", err)
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
			if toChainID == config.DefConfig.NeoChainID {
				key := states[5].(string)
				// get current neo chain sync height, which is the reliable header height
				currentNeoChainSyncHeight, err := c.syncService.GetCurrentNeoChainSyncHeight()
				if err != nil {
					Log.Errorf("[relayToNeo] GetCurrentNeoChainSyncHeight error: ", err)
					return nil, err
				}
				return c.getScript(key, txHeight, uint32(currentNeoChainSyncHeight))
			}
		}
	}
	return nil, fmt.Errorf("no tx")
}

func (c *Controller) getScript(key string, txHeight, lastSynced uint32) ([]byte, error) {
	blockHeightReliable := lastSynced + 1
	// get the proof of the cross chain tx
	crossStateProof, err := c.relaySdk.ClientMgr.GetCrossStatesProof(txHeight, key)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] GetCrossStatesProof error: %s", err)
	}
	path, err := hex.DecodeString(crossStateProof.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] DecodeString error: %s", err)
	}
	txProof := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: path,
	}
	//Log.Infof("txProof: " + helper.BytesToHex(path))

	// get the next block header since it has the stateroot for the cross chain tx
	blockHeightToBeVerified := txHeight + 1
	headerToBeVerified, err := c.relaySdk.GetHeaderByHeight(blockHeightToBeVerified)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] GetHeaderByHeight error: %s", err)
	}
	txProofHeader := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerToBeVerified.GetMessage(),
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
		merkleProof, err := c.relaySdk.GetMerkleProof(blockHeightToBeVerified, blockHeightReliable)
		if err != nil {
			return nil, fmt.Errorf("[syncProofToNeo] GetMerkleProof error: %s", err)
		}
		headerProofBytes, err = hex.DecodeString(merkleProof.AuditPath)
		if err != nil {
			return nil, fmt.Errorf("[syncProofToNeo] merkleProof DecodeString error: %s", err)
		}

		// get the raw current header
		headerReliable, err := c.relaySdk.GetHeaderByHeight(blockHeightReliable)
		if err != nil {
			return nil, fmt.Errorf("[syncProofToNeo] GetHeaderByHeight error: %s", err)
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
	//Log.Infof("headerProof: " + helper.BytesToHex(headerProofBytes))

	currentHeader := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: currentHeaderBytes,
	}
	//Log.Infof("currentHeader: " + helper.BytesToHex(currentHeaderBytes))
	//Log.Infof("headerHash: 0x" + headerHash.ToHexString())

	hasher := goc.SHA256.New()
	hasher.Write(headerHash.ToArray())
	digest := hasher.Sum(nil)

	signListBytes, err = c.sortSignatures(sigData, digest)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] sort signatures error: %s", err)
	}
	signList := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: signListBytes,
	}
	//Log.Infof("signList: " + helper.BytesToHex(signListBytes))

	stateRootValue, err := service.MerkleProve(path, headerToBeVerified.CrossStateRoot.ToArray())
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] MerkleProve error: %s", err)
	}
	toMerkleValue, err := service.DeserializeMerkleValue(stateRootValue)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] DeserializeMerkleValue error: %s", err)
	}

	polyHash := helper.BytesToHex(util.Reverse(toMerkleValue.TxHash))
	srcHash := helper.BytesToHex(toMerkleValue.TxParam.TxHash)
	Log.Infof("fromChainId: " + strconv.Itoa(int(toMerkleValue.FromChainID)))
	Log.Infof("polyTxHash: " + polyHash)
	Log.Infof("fromContract: " + helper.BytesToHex(toMerkleValue.TxParam.FromContract))
	Log.Infof("toChainId: " + strconv.Itoa(int(toMerkleValue.TxParam.ToChainID)))
	Log.Infof("sourceTxHash: " + srcHash)
	Log.Infof("toContract: " + helper.BytesToHex(toMerkleValue.TxParam.ToContract))
	Log.Infof("method: " + helper.BytesToHex(toMerkleValue.TxParam.Method))
	Log.Infof("TxParamArgs: " + helper.BytesToHex(toMerkleValue.TxParam.Args))
	toAssetHash, toAddress, amount, err := service.DeserializeArgs(toMerkleValue.TxParam.Args)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] DeserializeArgs error: %s", err)
	}
	Log.Infof("toAssetHash: " + helper.BytesToHex(toAssetHash))
	Log.Infof("toAddress: " + helper.BytesToHex(toAddress))
	Log.Infof("amount: " + amount.String())

	// limit the method to "unlock" or "bridgeIn"
	if helper.BytesToHex(toMerkleValue.TxParam.Method) != hex.EncodeToString([]byte(METHOD_UNLOCK)) &&
		helper.BytesToHex(toMerkleValue.TxParam.Method) != hex.EncodeToString([]byte(METHOD_BRIDGEIN)) { // unlock
		return nil, fmt.Errorf("[syncProofToNeo] called method is invalid, height %d, key %s", txHeight, key)
	}

	// build script
	scriptHash, err := helper.UInt160FromString(config.DefConfig.NeoCCMC)
	if err != nil {
		return nil, fmt.Errorf("[syncProofToNeo] neo ccmc conversion error: %s", err)
	}
	return sc.MakeScript(scriptHash, VERIFY_AND_EXECUTE_TX, []interface{}{txProof, txProofHeader, headerProof, currentHeader, signList})
}

// sort signatures according to public key order, append sorted signatures together
func (c *Controller) sortSignatures(sigs [][]byte, hash []byte) ([]byte, error) {
	// get pubKeys from ccmc
	err := c.getCurrentPolyBookKeeps()
	if err != nil {
		return nil, fmt.Errorf("[sortSignatures] getCurrentPolyBookKeeps error: %s", err)
	}
	return sortSignatures(c.relayPubKeys, sigs, hash)
}
func (c *Controller) getCurrentPolyBookKeeps() error {
	scriptHash, err := helper.UInt160FromString(config.DefConfig.NeoCCMC) // hex string in little endian
	if err != nil {
		return fmt.Errorf("[getBookKeeps] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, GET_BOOK_KEEPERS, []interface{}{})
	if err != nil {
		return fmt.Errorf("[getBookKeeps] sc.MakeScript error: %s", err)
	}
	response := c.neoSdk.InvokeScript(crypto.Base64Encode(script), nil)
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
		//Log.Infof(helper.BytesToHex(pubKeys[i]))
	}
	c.relayPubKeys = pubKeys
	return nil
}

func sortSignatures(pubKeys, sigs [][]byte, hash []byte) ([]byte, error) {
	// sig length should >= 2/3 * len(pubKeys) + 1
	if len(sigs) < len(pubKeys)*2/3+1 {
		return nil, fmt.Errorf("[sortSignatures] not enough signatures")
	}
	sortedSigs := make([][]byte, len(pubKeys))
	//Log.Infof("before sorting sig: ")
	for _, sig := range sigs {
		//Log.Infof(helper.BytesToHex(sig))
		pubKey, err := recoverPublicKeyFromSignature(sig, hash) // sig in BTC format
		//Log.Infof(helper.BytesToHex(pubKey))
		if err != nil {
			return nil, fmt.Errorf("[sortSignatures] recoverPublicKeyFromSignature error: %s", err)
		}
		//newPubKey := append([]byte{0x12, 0x05}, pubKey...)
		//Log.Infof(helper.BytesToHex(newPubKey))
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
	//Log.Infof("sorted sig: ")
	for _, sortedSig := range sortedSigs {
		// convert to eth format
		if len(sortedSig) != 0 {
			//Log.Infof(helper.BytesToHex(sortedSig))
			newSig, _ := signature.ConvertToEthCompatible(sortedSig)
			sigListBytes = append(sigListBytes, newSig...)
		}
	}
	return sigListBytes, nil
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
