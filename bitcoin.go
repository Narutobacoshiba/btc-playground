package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	seed          = "3a1accd3616d71a2c7b1f576b4a50d0bad427628af7a207afdbc5c878d5ad975"
	BtcdHost      = "localhost:18556"
	BtcdUser      = "aTu8e04uPlE7yYoLU3o7pD6FplQ="
	BtcdPass      = "qQcvrVZf0AtiA1Ta/NtX34Xmvsk="
	BlockTime     = 3 * time.Second
	MiningAddress = "SPTvzNhFYFaFuhoRbXMgsgUMtUcS2NxrhM"
	WalletHost    = "localhost:18554"
	WalletPass    = "hello"
)

// managing bitcoin simnet process
type SimBitcoinProcess struct {
	BitcoinCmd *exec.Cmd
	WalletCmd  *exec.Cmd
}

func (reg *SimBitcoinProcess) RunWalletProcess() {
	// setup wallet running in simnet mode
	reg.WalletCmd = exec.Command(
		"btcwallet",
		"--simnet",
		"--noclienttls",
		"--noservertls",
		"--btcdusername", BtcdUser,
		"--btcdpassword", BtcdPass,
		"-u", BtcdUser,
		"-P", BtcdPass,
		"&",
	)
	// set child process group id to the same as parent process id, so that KILL signal can kill both parent and child processes
	reg.WalletCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// determine if there is already a running btcwallet process
	if !isProcessRunning("btcwallet") {
		fmt.Println("run btcwallet process")
		if err := reg.WalletCmd.Start(); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("btcwallet process already running")
	}

	// wait for wallet to start
	time.Sleep(3 * time.Second)
}

func (reg *SimBitcoinProcess) StopWallet() {
	if reg.WalletCmd != nil && reg.WalletCmd.Process != nil {
		err := reg.WalletCmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("stop btcwallet process")
}

func (reg *SimBitcoinProcess) LogWalletError() {
	stderr, _ := reg.WalletCmd.StderrPipe()
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func (reg *SimBitcoinProcess) RunBitcoinProcess(genBlock bool) {
	// setup bitcoin node running in simnet mode
	rpcUser := fmt.Sprintf("--rpcuser=%s", BtcdUser)
	rpcPass := fmt.Sprintf("--rpcpass=%s", BtcdPass)
	reg.BitcoinCmd = exec.Command(
		"btcd",
		"--simnet",
		"--txindex",
		"--notls",
		"--logdir",
		"simnet/btcd/logs",
		"--miningaddr", MiningAddress,
		rpcUser,
		rpcPass,
		"&",
	)
	// set child process group id to the same as parent process id, so that KILL signal can kill both parent and child processes
	reg.BitcoinCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// determine if there is already a running btcd process
	if !isProcessRunning("btcd") {
		fmt.Println("run btcd process")
		if err := reg.BitcoinCmd.Start(); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("btcd process already running")
	}

	// wait for bitcoin node to start
	time.Sleep(3 * time.Second)

	// generate blocks
	// if newly created bitcoin regtest, need to generate 101 blocks to finalize coinbase rewards. This is for insufficient funds
	if genBlock {
		go func() {
			for {
				err := exec.Command("btcctl", "--simnet", "--notls", rpcUser, rpcPass, "generate", "1").Run()
				if err != nil {
					panic(err)
				}
				time.Sleep(BlockTime)
			}
		}()
	}
}

func (reg *SimBitcoinProcess) mintBlock(num int) {
	rpcUser := fmt.Sprintf("--rpcuser=%s", BtcdUser)
	rpcPass := fmt.Sprintf("--rpcpass=%s", BtcdPass)
	err := exec.Command("btcctl", "--simnet", "--notls", rpcUser, rpcPass, "generate", fmt.Sprintf("%d", num)).Run()
	if err != nil {
		panic(err)
	}
}

func (reg *SimBitcoinProcess) StopBitcoin() {
	if reg.BitcoinCmd != nil && reg.BitcoinCmd.Process != nil {
		err := reg.BitcoinCmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("stop btcd process")
}

func (reg *SimBitcoinProcess) LogBitcoinError() {
	stderr, _ := reg.BitcoinCmd.StderrPipe()
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func isProcessRunning(name string) bool {
	cmd := exec.Command("pgrep", name)
	out, err := cmd.Output()

	if err != nil {
		return false
	}

	if len(strings.TrimSpace(string(out))) == 0 {
		return false
	}

	return true
}
