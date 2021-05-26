package main

import (
	"fmt"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSetUpPoly(t *testing.T) {
	err := Init()
	assert.Nil(t, err)
}

func Init() error {
	poly := poly_go_sdk.NewPolySdk()
	poly.NewRpcClient().SetAddress("http://40.87.40.70:20336")
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return fmt.Errorf("GetHeader err : %v", err)
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}