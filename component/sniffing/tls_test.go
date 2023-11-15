/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

var tlsStreamGoogle, _ = hex.DecodeString("1603010200010001fc0303d90fdf25b0c7a11c3eb968604a065157a149407c139c22ed32f5c6f486ed2c04206c51c32da7f83c3c19766be60d45d264e898c77504e34915c44caa69513c2221003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000013001100000e7777772e676f6f676c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d00207fe08226bdc4fb1715e477506b6afe8f3abe2d20daa1f8c78c5483f1a90a9b19001500af00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
var tlsStreamWindowsOdinGame, _ = hex.DecodeString("16030300b8010000b403036484b04b0f87a95364166094aa611bb989a6886b4ca4f23480cfd31a1c683e8400002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a010000610000001700150000126f64696e2e67616d652e6461756d2e6e6574000500050100000000000a00080006001d00170018000b00020100000d001a00180804080508060401050102010403050302030202060106030023000000170000ff01000100")
var tlsCurlIpsb, _ = hex.DecodeString("1603010200010001fc030331503d966014db2c7034d289c3ee31bcbfcfcffa4219a7b6971bbdec86144b5120ecc056cb75ae5d49ad9a89d82d2b43fe7b8c66d1c4e631e66a80fa273ebb25ae003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000000a000800000569702e7362000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020bd75abd51a882eeff6a462d1fb12aa7f01ee830c4e6589d6d14e3bcf507e5802001500b800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

func TestSniffer_SniffTls(t *testing.T) {
	tests := []struct {
		Domain string
		Stream []byte ""
	}{{
		Domain: "www.google.com",
		Stream: tlsStreamGoogle,
	}, {
		Domain: "odin.game.daum.net",
		Stream: tlsStreamWindowsOdinGame,
	}, {
		Domain: "ip.sb",
		Stream: tlsCurlIpsb,
	}}
	logrus.SetLevel(logrus.DebugLevel)
	for _, test := range tests {
		sniffer := NewPacketSniffer(test.Stream, 300*time.Millisecond)
		d, err := sniffer.SniffTls()
		if err != nil {
			t.Fatal(err)
		}
		if d != test.Domain {
			t.Fatal(d)
		}
		t.Log(d)
	}
}
