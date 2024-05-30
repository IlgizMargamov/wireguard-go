//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"os"
	"os/signal"
	"runtime"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func printUsage() {
	fmt.Printf("Usage: %s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
			return
		}
	default:
		return
	}

	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "│   Running wireguard-go is not required because this  │")
	fmt.Fprintln(os.Stderr, "│   kernel has first class support for WireGuard. For  │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,       │")
	fmt.Fprintln(os.Stderr, "│   please visit:                                      │")
	fmt.Fprintln(os.Stderr, "│         https://www.wireguard.com/install/           │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

func main() {
	// if not elevated, relaunch by shellexecute with runas verb set
	if !amAdmin() {
		runMeElevated()
	}
	if len(os.Args) != 3 {
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	//reader := bufio.NewReader(os.Stdin)
	//fmt.Print("Enter text: ")
	//text, _ := reader.ReadString('\n')
	//fmt.Println(text)

	fmt.Fprintln(os.Stderr, "Warning: this is a test program for Windows, mainly used for debugging this Go package. For a real WireGuard for Windows client, the repo you want is <https://git.zx2c4.com/wireguard-windows/>, which includes this code as a module.")

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	//logger.Verbosef("Starting wireguard-go version %s", Version)

	tun, err := tun.CreateTUN(interfaceName, 0)

	//bufio.NewReader(os.Stdin)
	//fmt.Print("Enter text: ")
	//reader.ReadString('\n')
	//fmt.Println(text)

	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	var key1, key2 NoisePrivateKey
	pub1, pub2 := key1.publicKey(), key2.publicKey()
	fmt.Println(pub1)
	fmt.Println(pub2)
	bind := conn.NewDefaultBind()
	//src := key1[:]
	private_key_134 := "e8bf9434607d58e871ac085b6dcea57ba186dbccc9d3582f334514ff65ac8e48" //hex.EncodeToString(src)
	public_key_134 := "388c8529007a5406cd096abd871905fda3cda82b2940cd7d6f9cdff4ddcf8929"  //hex.EncodeToString(src)
	enpoint_134 := "134.122.47.142:5353"
	/*private_key_5 := "10bd3cfcbcbff74bfd9e86a5d6728a542cb646124ad637406492aba953931e76" //hex.EncodeToString(src)
	public_key_5 := "81c1a30a2316582fa1ff99ef583f0ae474e082e213fff6bd680874d3dcdf0315"    //hex.EncodeToString(src)
	enpoint_5 := "5.181.252.167:5353"
	*/cfg := uapiCfg(
		"private_key", private_key_134,
		//"listen_port", "0",
		//"replace_peers", "true",
		"public_key", public_key_134, //hex.EncodeToString(pub2[:]),
		//"protocol_version", "1",
		//"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
		"endpoint", enpoint_134,
	)
	/*	cfg := uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32")*/

	device := device.NewDevice(tun, bind, logger)
	/*if len(cfg) > 0 {

	}
	confPath := os.Args[2]
	fi, err := os.ReadFile(confPath) // in file generated public and private keys are in base64 encoding
	// so u need to just read the string convert to bytes and get its representation in hex
	cfg = string(fi)
	*/
	/*`private_key=087ec6e14bbed210e7215cdc73468dfa23f080a1bfb8665b2fd809bd99d28379
	public_key=c4c8e984c5322c8184c72265b92b250fdb63688705f504ba003c88f03393cf28
	allowed_ip=0.0.0.0/0
	endpoint=127.0.0.1:58120`
	*/if err := device.IpcSet(cfg); err != nil {
		device.Close()
		os.Exit(ExitSetupFailed)
	}
	if err := device.Up(); err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		device.Close()
		os.Exit(ExitSetupFailed)
	}
	/*	endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	 */bufio.NewReader(os.Stdin)
	//fmt.Print("Enter text: ")
	//reader.ReadString('\n')
	//fmt.Println(text)
	logger.Verbosef("Device started")

	uapi, err := ipc.UAPIListen(interfaceName)
	/*bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	*/ //reader.ReadString('\n')
	//fmt.Println(text)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	logger.Verbosef("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, windows.SIGTERM)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}

func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("admin no")
		return false
	}
	fmt.Println("admin yes")
	return true
}

func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

/*
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	var foreground bool
	var interfaceName string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		interfaceName = os.Args[2]

	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		interfaceName = os.Args[1]
	}

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	// open TUN device (or use supplied fd)

	tdev, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = unix.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tdev.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
*/
