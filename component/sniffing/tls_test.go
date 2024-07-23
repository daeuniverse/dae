/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

var tlsStreamGoogle, _ = hex.DecodeString("1603010200010001fc0303d90fdf25b0c7a11c3eb968604a065157a149407c139c22ed32f5c6f486ed2c04206c51c32da7f83c3c19766be60d45d264e898c77504e34915c44caa69513c2221003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000013001100000e7777772e676f6f676c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d00207fe08226bdc4fb1715e477506b6afe8f3abe2d20daa1f8c78c5483f1a90a9b19001500af00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
var tlsStreamWindowsOdinGame, _ = hex.DecodeString("16030300b8010000b403036484b04b0f87a95364166094aa611bb989a6886b4ca4f23480cfd31a1c683e8400002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a010000610000001700150000126f64696e2e67616d652e6461756d2e6e6574000500050100000000000a00080006001d00170018000b00020100000d001a00180804080508060401050102010403050302030202060106030023000000170000ff01000100")
var tlsCurlIpsb, _ = hex.DecodeString("1603010200010001fc030331503d966014db2c7034d289c3ee31bcbfcfcffa4219a7b6971bbdec86144b5120ecc056cb75ae5d49ad9a89d82d2b43fe7b8c66d1c4e631e66a80fa273ebb25ae003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000000a000800000569702e7362000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020bd75abd51a882eeff6a462d1fb12aa7f01ee830c4e6589d6d14e3bcf507e5802001500b800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
var tlsWebTelegramOrm, _ = hex.DecodeString("1603010848010008440303ced524db6d5c3a5d5f480cc5a603c18ecefd7ebcf518842d04ba0ec3527f55ff2019644bb362609b3473df92c1f8e714e51a56f0229e1bf30b41637d1c63f60d3e0020caca130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007db4a4a0000002b000706baba03040303002d00020101000b00020100001b00030200020000001500130000107765622e74656c656772616d2e6f7267446900050003026832ff01000100000500050100000000003304ef04edaaaa000100639904c0497fd380cf791168b32c3d804502df8d0c4dd8e6a55e1466b67bb408f5c119111521a525b638da5a7591d5317a9152cd8753c24a03f456ad43378f68b5c9624c15276513779ab7d3a0c497c14f724337d0d32a54dc7ca86a1975f374db476e0db1ce6b655b8d46300d348095ebca2390629840b95a816f9fea50d056ce1658286fe50ddf636587096c00e88eee973e9b4c27ff805d92763406a5338174cd3df0ca92337010f97753916be2ab05ffe966a863a48d429d85512ef5874b838941f9d910bf000d9daab88fc765d3d24c23138026b937d63c0eca7cadad52aead052bead4bedf5518aa779481611202f781fb034e289c1fca387a7c9c518e37cc46d488b7b0a3a45c4c06958998298ea6951234b8bed768974cd521d6b8a4c46233bf828b3a543bf644a1aaa27bf8f23659d9744c8285248ab264e1365d750c14e080acea45373553f1710351a667018615e08b9587275494564df1cb7f3a907897617069372e43b2470a7c499cb5ac84500a85d882af720422a94292c41ed2b659dd22a6e2849db72685c970a649e05220779991d6b14769a322a135d7c2bd2ea3584576c227093e2fc7a317781c8533566c2cb9a522bb91ba03395c863b59139ec764104293ff6a29309712b156bea74443469c866e6922b9708426583f4ea30f0acac37de68faf911eb02543c02b4166b21875374f4b477a7db34e0ad07d5f26b0302ac3b0635baf8c932d23c63c095f6cccc112097d53e5099410926e6561ade8b6208b33311827d7cb921c96733fd574a0a5c160b11361a39ee64b5fefd9cc62938e1cfa88dbcb1cf04753750581288cb135a9ab025894e2e18191c33f13554bf195b781297dcddc5e37949e1d565d88764f96e0578a81014dac33f6d5b355ca1bb1368917cc36027b4c38ba8a73884ab120b94ca47f6b1b34dde71bc96a8ac95306d89311a3270bccd53c2973bc785b7efa611284e96f1b91410ed041147920f02940f00619622c22b434b61cd91dab3757d7dab7e5d0ce81436c66984a76786d9aa13f0162848c4c0b34fc130e7c77c4b3a3fb41c2a5fa52e6e21750f25ec29b2b25a120a2e76f99f917b2d0c8d749a2b77816ce2853f234a9ebf4157d0603d00b8ea4f8765187c2ed541b7f6b485a50a413d366e1b5cdb4233f388289e230a58d087ba6531bc6bbcd36136176065d0ef47922f1a17865539e862bf54c69a27cc0a8635722f2c00d82461fba5bf35b44569a36faa45353e950f499766bd9c65d03186ae0580d28242ea0b83e52cac8847313e907d6b3104d2c06480bd09805c99c40122b949207520ae65794f6371226551aba29993cd347989a254655032b25af6bf4b6b82ac8e1657004c71587013746834c0dd995a936add5a188c85342d622b50b34618837267ae726d621cb2701257aab119e72229926ab249516e91bab9e81b490a059a132893c952b441c54deeba48cc08440607efff9396eb7bbdcf224c3cb3225bb71034b9db9bb770ca5038b90349fc9ab4086760b690455b886415c64fa5458a49781a5b8af1d92930fb6330160b09714454c59380440aa35aa673e8c2c75206dbed8971ac38495468d66504ea5b55e6265cbc5c6ac6005085b54978c916bd61ac37986a0b5334b6207c58f2364c2753d4fe5364513124f1b4bcfbbd9fbd8522a169d556fc11e6df7ab69e380711fc97b29d07935ac80eb232b001d0020ed8b382def2224509760f16ba76243b62de7f374762e4ee0562cf5b867")
var tlsWebTelegramOrm2, _ = hex.DecodeString("cd752f000a000c000aaaaa6399001d0017001800230000fe0d011a0000010001e30020217edb72810ca195f950839d754921794abbcc7eeb27b165daef4245f23c433b00f0c0634e48ea494b4b8c09ae9b161be96554b593d74f52642fc0ec919bbdd56b97cf428f09d23924f02bb587326b17c610aa045cb240827120d0d9e445014046c0d172684f93be9318bf7990cc5b1844742ed11533feabeaea427b17a0a3b1ed13f31007df29137d05a9f91a6fc1f7dab2bc559779d005331d81a0a256f03ae1bfb0f89c2ed1ec81a2b9f89e8344615351ced8de6f5c5e4a305dd964b0eb4623dc438f368028882757ffdb098c327be43c0b825e1fe939a57b52a503ea4f7cf0393eb3e5c0cf0edd743fc1ce8d580d80d738b4d72bef6a2242095e18f52915bc210f76b3957cf6c089cf288dd78361f0f8001700000010000e000c02683208687474702f312e31000d0012001004030804040105030805050108060601001200005a5a0001000029012b00f600f01635dab1dfb1753ee089778cbcfa5a9a35bc3cf2306441bd5d8cc99cccc3273aba9c488292429fd2e55e4c67635f9aa487b7febe8b7d1148050c49df37925e44b236aadebcaf86a3d5cdf385fb8aa448254bc57f0ac2ed806b5faaf669e4fc1b04b1d045e40fdc8ab31c94539bbcda1486c0dbd79354b691e977cf57576b8e9e497c198da81dac26f5240ab449e04dc511b7e7c81c264d7b03b4a14ebe5e011356bbd7febe6b20a4608385b3328e8de3716b184cb60c7e65d9b55fc8a1adf57af6db5b10e609b000fc3abb391a3fad1bda426e1b6179d4f6e1328b301a144f9c6e85dcc256fd79fe0c92339597e85d08c6b5810d0031301bb0d0a9adb7a4ea4d421a46a1aeaad42ebed1710661de8545a9e93745d04e7c5be760090f852ac549c5864936851264")

func TestSniffer_SniffTls(t *testing.T) {
	tests := []struct {
		Domain string
		Stream io.Reader
	}{{
		Domain: "www.google.com",
		Stream: bytes.NewReader(tlsStreamGoogle),
	}, {
		Domain: "odin.game.daum.net",
		Stream: bytes.NewReader(tlsStreamWindowsOdinGame),
	}, {
		Domain: "ip.sb",
		Stream: bytes.NewReader(tlsCurlIpsb),
	}, {
		Domain: "web.telegram.org",
		Stream: io.MultiReader(bytes.NewReader(tlsWebTelegramOrm), bytes.NewReader(tlsWebTelegramOrm2)),
	}}
	logrus.SetLevel(logrus.DebugLevel)
	for _, test := range tests {
		sniffer := NewStreamSniffer(test.Stream, 300*time.Millisecond)
		d, err := sniffer.SniffTcp()
		if err != nil {
			t.Fatal(err)
		}
		if d != test.Domain {
			t.Fatal(d)
		}
		t.Log(d)
	}
}
