package main

import (
	"fmt"
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/log"
	"github.com/polynetwork/neo3-relayer/service"
	relaySdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/core/types"
	"github.com/urfave/cli"
	"net/http"
	"os"
	"runtime"
	"time"
)

var Log = log.Log

func setupApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "poly-bridge Service"
	app.Action = StartHttp
	app.Version = "1.0.0"
	app.Copyright = "Copyright in 2019 The Ontology Authors"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Usage: "http config file `<path>`",
			Value: "config_testnet.json",
		},
		cli.StringFlag{
			Name:  "host",
			Usage: "http host",
			Value: "0.0.0.0",
		},
		cli.Int64Flag{
			Name:  "port",
			Usage: "http port",
			Value: 8080,
		},
	}
	app.Commands = []cli.Command{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}
	return app
}

func StartHttp(ctx *cli.Context) (err error) {
	configpath := ctx.GlobalString("config")
	host := ctx.GlobalString("host")
	port := ctx.GlobalInt64("port")
	if configpath == "" || port == 0 {
		panic(fmt.Errorf("configpath is: %v, port is: %v", configpath, port))
	}

	err = config.DefConfig.Init(configpath)
	if err != nil {
		fmt.Println("DefConfig.Init error: ", err)
		return
	}

	//create Relay Chain RPC Client
	relaySdk := relaySdk.NewPolySdk()
	err = SetUpPoly(relaySdk, config.DefConfig.RelayJsonRpcUrl)
	if err != nil {
		panic(fmt.Errorf("failed to set up poly: %v", err))
	}

	// create a NEO RPC client
	neoRpcClient := rpc.NewClient(config.DefConfig.NeoJsonRpcUrl)

	syncService := service.NewSyncService(nil, relaySdk, nil, neoRpcClient, nil)

	controller = &Controller{
		syncService: syncService,
		neoSdk:      neoRpcClient,
		relaySdk:    relaySdk,
	}
	Log.Infof("start ....")
	Log.Infof("listen %v:%v", host, port)
	http.HandleFunc("/api/v1/composedsttx", controller.ComposeDstTx)
	http.ListenAndServe(fmt.Sprintf("%v:%v", host, port), nil)
	return
}

func SetUpPoly(poly *relaySdk.PolySdk, rpcAddr string) error {
	poly.NewRpcClient().SetAddress(rpcAddr)
	c1 := make(chan *types.Header, 1)
	c2 := make(chan error, 1)

	// use another routine to check time out and error
	go func() {
		hdr, err := poly.GetHeaderByHeight(0)
		if err != nil {
			c2 <- err
		}
		c1 <- hdr
	}()

	select {
	case hdr := <-c1:
		poly.SetChainId(hdr.ChainID)
	case err := <-c2:
		return err
	case <-time.After(time.Second * 5):
		return fmt.Errorf("poly rpc port timeout")
	}

	return nil
}

func main() {
	if err := setupApp().Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
