package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	mainAddr  = "SPTvzNhFYFaFuhoRbXMgsgUMtUcS2NxrhM"
	aliceAddr = "SaqEQbsDwgRm7ZQJboELwUWGAqMYrv8Uif"
	bobAddr   = "SfUoYaMDeAjmYNLxpAHFT3adDxmQyUCa4m"
)

type BtcdClient struct {
	chainClient     *rpcclient.Client
	walletClient    *rpcclient.Client
	btcdConnConfig  *rpcclient.ConnConfig
	btcdChainConfig *chaincfg.Params
}

var (
	reg        SimBitcoinProcess
	btcdClient BtcdClient
)

func main() {
	// start a bitcoin simnet network
	reg.RunBitcoinProcess(false)

	time.Sleep(3 * time.Second)

	// start a wallet process
	reg.RunWalletProcess()

	defer func() {
		// stop wallet process
		reg.StopWallet()
		// stop bitcoin process
		reg.StopBitcoin()
	}()

	var err error

	btcdClient.btcdConnConfig = &rpcclient.ConnConfig{
		Host:         BtcdHost,
		Endpoint:     "ws",
		User:         BtcdUser,
		Pass:         BtcdPass,
		HTTPPostMode: false,
		DisableTLS:   true,
	}
	btcdClient.btcdChainConfig = &chaincfg.SimNetParams
	btcdClient.btcdChainConfig.DefaultPort = BtcdHost

	btcdClient.chainClient, err = rpcclient.New(btcdClient.btcdConnConfig, nil)
	if err != nil {
		fmt.Println("chain client: ", err)
		return
	}

	err = btcdClient.chainClient.NotifyBlocks()
	if err != nil {
		fmt.Println("notify blocks: ", err)
		return
	}

	// open main wallet
	walletConnConfig := &rpcclient.ConnConfig{
		Host:         WalletHost,
		Endpoint:     "ws",
		User:         BtcdUser,
		Pass:         BtcdPass,
		HTTPPostMode: false,
		DisableTLS:   true,
	}
	btcdClient.walletClient, err = rpcclient.New(walletConnConfig, nil)
	if err != nil {
		fmt.Println("wallet client: ", err)
		return
	}

	// open wallet for 10 mins
	err = btcdClient.walletClient.WalletPassphrase(WalletPass, 10*60)
	if err != nil {
		fmt.Println(err)
		return
	}

	mainAmt, err := btcdClient.walletClient.GetBalance("default")
	fmt.Println("Main account balance: ", mainAmt.ToBTC())
	aliceAmt, err := btcdClient.walletClient.GetBalance("alice")
	fmt.Println("Alice account balance: ", aliceAmt.ToBTC())
	bobAmt, err := btcdClient.walletClient.GetBalance("bob")
	fmt.Println("Bob account balance: ", bobAmt.ToBTC())

	addr, err := btcutil.DecodeAddress(mainAddr, btcdClient.btcdChainConfig)
	privKey, err := btcdClient.walletClient.DumpPrivKey(addr)
	fmt.Println("Main account private key: ", privKey.String())
	addrAlice, err := btcutil.DecodeAddress(aliceAddr, btcdClient.btcdChainConfig)
	privKeyAlice, err := btcdClient.walletClient.DumpPrivKey(addrAlice)
	fmt.Println("Alice account private key: ", privKeyAlice.String())
	addrBob, err := btcutil.DecodeAddress(bobAddr, btcdClient.btcdChainConfig)
	privKeyBob, err := btcdClient.walletClient.DumpPrivKey(addrBob)
	fmt.Println("Bob account private key: ", privKeyBob.String())

	// result hash of the game between VN and TL
	vn := sha256.Sum256([]byte("VN wins"))
	tl := sha256.Sum256([]byte("TL wins"))

	// Alice bets that VN wins
	// Bob bets that TL wins
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_SHA256)
	builder.AddOp(txscript.OP_DUP)
	builder.AddData(vn[:])
	builder.AddOp(txscript.OP_EQUAL)
	builder.AddOp(txscript.OP_IF)
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(privKeyAlice.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ELSE)
	builder.AddData(tl[:])
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(privKeyBob.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ENDIF)
	builder.AddOp(txscript.OP_TRUE)
	pkScript, err := builder.Script()
	if err != nil {
		fmt.Println("build script: ", err)
		return
	}

	// create a P2WSH address
	witnessScriptCommitment := sha256.Sum256(pkScript)
	address, err := btcutil.NewAddressWitnessScriptHash(witnessScriptCommitment[:], btcdClient.btcdChainConfig)
	if err != nil {
		fmt.Println("witness address: ", err)
		return
	}
	fmt.Println("P2SH address: ", address.EncodeAddress())

	// P2WSH script
	builder = txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(witnessScriptCommitment[:])
	p2wshScript, err := builder.Script()
	fmt.Println("P2WSH script: ", hex.EncodeToString(p2wshScript))

	/* txHash, err := chainhash.NewHashFromStr("c753ba5d420f03cef265002e5b713566d9499cab66f1eca75a37986d40882035")
	txRaw, err := btcdClient.chainClient.GetRawTransaction(txHash)
	txSpent := txRaw.MsgTx().TxOut[0]

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: 490000000, PkScript: p2wshScript,
	}
	tx.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx, 0, txSpent.PkScript, txscript.SigHashSingle, privKey.PrivKey, true)
	tx.TxIn[0].SignatureScript = sig

	hash, err := btcdClient.chainClient.SendRawTransaction(tx, false)
	if err != nil {
		fmt.Println("send tx: ", err)
		return
	}
	fmt.Println("TX hash: ", hash.String())

	time.Sleep(10 * time.Second) */

	// CREATE SPENT script
	txHash, err := chainhash.NewHashFromStr("9fdb07b34c79ac6b2ed6531e506664ef8aedf2e208b0315084243a602336de13")
	txRaw, err := btcdClient.chainClient.GetRawTransaction(txHash)
	txSpent := txRaw.MsgTx().TxOut[0]
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	builder = txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	// verify data signer to prove that this data package is submitted by the signer
	builder.AddData(btcutil.Hash160(privKeyAlice.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript2, err := builder.Script()
	if err != nil {
		fmt.Println("build script: ", err)
		return
	}
	txOut := &wire.TxOut{
		Value: 480000000, PkScript: pkScript2,
	}
	tx.AddTxOut(txOut)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		txSpent.PkScript,
		txSpent.Value,
	)
	_ = txscript.NewTxSigHashes(tx, inputFetcher)

	//sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, 0, txOut.Value, txSpent.PkScript, txscript.SigHashSingle, privKeyAlice.PrivKey)
	sig, err := txscript.RawTxInSignature(tx, 0, txSpent.PkScript, txscript.SigHashSingle, privKeyAlice.PrivKey)

	witness := wire.TxWitness{
		sig, privKeyAlice.SerializePubKey(), []byte("VN wins"), pkScript,
	}
	tx.TxIn[0].Witness = witness
	fmt.Println("witness: ", witness.SerializeSize())
	hash, err := btcdClient.chainClient.SendRawTransaction(tx, false)
	if err != nil {
		fmt.Println("send tx: ", err)
		return
	}
	fmt.Println("TX hash: ", hash.String())

	time.Sleep(10 * time.Second)

	/*         default SPENT 4.9 BTC to
	txHash, err := chainhash.NewHashFromStr("4b095af8d0245dc39a8acd1a3a922328c51a2866233f4772c3b36a40c18ce471")
	txRaw, err := btcdClient.chainClient.GetRawTransaction(txHash)
	txSpent := txRaw.MsgTx().TxOut[0]

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	// verify data signer to prove that this data package is submitted by the signer
	builder.AddData(btcutil.Hash160(privKeyAlice.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript, err := builder.Script()
	if err != nil {
		fmt.Println("build script: ", err)
		return
	}
	fmt.Println("script: ", hex.EncodeToString(pkScript))
	txOut := &wire.TxOut{
		Value: 490000000, PkScript: pkScript,
	}
	tx.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx, 0, txSpent.PkScript, txscript.SigHashSingle, privKey.PrivKey, true)
	tx.TxIn[0].SignatureScript = sig

	hash, err := btcdClient.chainClient.SendRawTransaction(tx, false)
	if err != nil {
		fmt.Println("send tx: ", err)
		return
	}
	fmt.Println("TX hash: ", hash.String()) */

	/* //// ******************** Create Taproot Address ******************** \\\\
	fmt.Println("//// ******************** Create Taproot Address ********************  \\\\\\\\")
	internalKeyPriv := "5JGgKfRy6vEcWBpLJV5FXUfMGNXzvdWzQHUM1rVLEUJfvZUSwvS"
	pubKey := privKey.PrivKey.PubKey()

	embeddedData := []byte("this is test embedded data for tapsscript")

	// Step 1: Create the Taproot script tree.
	tapScriptTree, _, _, err := CreateTapScriptTree(embeddedData, pubKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	// internal private key as key path spend
	internalPrivKey, err := btcutil.DecodeWIF(internalKeyPriv)
	if err != nil {
		fmt.Println(err)
		return
	}

	internalPubKey := internalPrivKey.PrivKey.PubKey()

	// Step 2: Generate the Taproot tree.
	tapScriptRootHash := tapScriptTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(
		internalPubKey, tapScriptRootHash[:],
	)

	// Step 3: Generate the Bech32m address.
	address, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), btcdClient.btcdChainConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Taproot address: ", address.String())

	//// ******************** sends 1 BTC to Taproot Address ******************** \\\\
	fmt.Println("//// ******************** sends 0.001 BTC to Taproot Address ******************** \\\\\\\\")
	amount, err := btcutil.NewAmount(0.001)
	if err != nil {
		fmt.Println(err)
		return
	}

	hash, err := btcdClient.walletClient.SendFrom("default", address, amount)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("TX hash: ", hash.String())

	reg.mintBlock(1)

	rawCommitTx, err := btcdClient.chainClient.GetRawTransaction(hash)
	if err != nil {
		fmt.Println(err)
		return
	}
	// TODO: use a better way to find our output
	var commitIndex int
	var commitOutput *wire.TxOut
	for i, out := range rawCommitTx.MsgTx().TxOut {
		if out.Value == 100000 {
			commitIndex = i
			commitOutput = out
			break
		}
	}
	println("TxOut index: ", commitIndex)
	println("TxOut: ", commitOutput)

	aliceAmt, err = btcdClient.walletClient.GetBalance("alice")
	fmt.Println("Alice account remaining balance: ", aliceAmt.ToBTC()) */

	return
}

// Construct the Taproot script with one leaf, Taproot can have many leafs
func CreateTapScriptTree(embeddedData []byte, pubKey *btcec.PublicKey) (*txscript.IndexedTapScriptTree, *txscript.TapLeaf, []byte, error) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddOp(txscript.OP_IF)
	// chunk our data into digestible 520 byte chunks
	chunks := chunkSlice(embeddedData, 520)
	for _, chunk := range chunks {
		builder.AddData(chunk)
	}
	builder.AddOp(txscript.OP_ENDIF)
	// verify data signer to prove that this data package is submitted by the signer
	builder.AddData(schnorr.SerializePubKey(pubKey))
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript, err := builder.Script()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building script: %v", err)
	}

	// aggregate leafs to create a Taproot output key
	tapLeaf := txscript.NewBaseTapLeaf(pkScript)
	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaf)

	return tapScriptTree, &tapLeaf, pkScript, nil
}

// chunkSlice splits input slice into max chunkSize length slices
func chunkSlice(slice []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}
