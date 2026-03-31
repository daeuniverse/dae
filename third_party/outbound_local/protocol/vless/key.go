package vless

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/common"
)

func Password2Key(password string) (id []byte, err error) {
	// UUID mapping
	if l := len([]byte(password)); l < 32 || l > 36 {
		password = common.StringToUUID5(password)
	}
	password = strings.ReplaceAll(password, "-", "")
	if len(password) != 32 {
		return nil, fmt.Errorf("invalid UUID: %s", password)
	}
	id = make([]byte, 16)
	if _, err := hex.Decode(id[:], []byte(password)); err != nil {
		return nil, err
	}
	return id, nil
}
