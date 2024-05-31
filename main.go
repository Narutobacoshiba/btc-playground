package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	mainAddr  = "SdaE8ZpvAeVxjbvGgUWg58zsLayyG7MAGW"
	aliceAddr = "SfwqvzyrYfeZkuQxp3jVEuGVsC96Gm8hyy"
	bobAddr   = "Sf3t2Pc7ZuEYT6WZsBh2Q88mwdPm3rF4Aq"
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

	////// ******************* GENERATE witness script hash ******************* \\\\\\

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
	builder.AddOp(txscript.OP_ELSE)
	builder.AddData(tl[:])
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(privKeyBob.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_ENDIF)
	builder.AddOp(txscript.OP_CHECKSIG)
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

	////// ******************* Send 49BTC to witness script hash ******************* \\\\\\

	// P2WSH script
	builder = txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(witnessScriptCommitment[:])
	p2wshScript, err := builder.Script()
	fmt.Println("P2WSH script: ", hex.EncodeToString(p2wshScript))

	/// get txhash from listunspent tx of default account
	txHash, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b")
	txRaw, err := btcdClient.chainClient.GetRawTransaction(txHash)
	txSpent := txRaw.MsgTx().TxOut[0]

	// create tx
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
	fmt.Println("TX1 hash: ", hash.String())

	time.Sleep(10 * time.Second)

	////// ******************* ALICE SPENT FROM witness script hash ******************* \\\\\\

	txRaw, err = btcdClient.chainClient.GetRawTransaction(hash)
	txSpent = txRaw.MsgTx().TxOut[0]
	tx = wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *hash,
			Index: uint32(0),
		},
	})

	// build script lock
	// only alice can spent
	builder = txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(privKeyAlice.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript2, err := builder.Script()
	if err != nil {
		fmt.Println("build script: ", err)
		return
	}
	txOut = &wire.TxOut{
		Value: 480000000, PkScript: pkScript2,
	}
	tx.AddTxOut(txOut)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		txSpent.PkScript,
		txSpent.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, inputFetcher)

	sig, err = txscript.RawTxInWitnessSignature(tx, sigHashes, 0, txSpent.Value, pkScript, txscript.SigHashAll, privKeyAlice.PrivKey)

	witness := wire.TxWitness{
		sig, privKeyAlice.SerializePubKey(), []byte("VN wins"), pkScript,
	}
	tx.TxIn[0].Witness = witness
	if err != nil {
		fmt.Println("send tx: ", err)
		return
	}

	hash, err = btcdClient.chainClient.SendRawTransaction(tx, false)
	if err != nil {
		fmt.Println("send tx: ", err)
		return
	}
	fmt.Println("TX2 hash: ", hash.String())

	time.Sleep(10 * time.Second)

	reg.mintBlock(10)

	return
}
