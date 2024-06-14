module github.com/daeuniverse/dae

go 1.21.0

toolchain go1.21.3

require (
	github.com/adrg/xdg v0.4.0
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df
	github.com/bits-and-blooms/bloom/v3 v3.5.0
	github.com/cilium/ebpf v0.12.3
	github.com/daeuniverse/dae-config-dist/go/dae_config v0.0.0-20230604120805-1c27619b592d
	github.com/daeuniverse/outbound v0.0.0-20240614055625-64f4b8c35aa6
	github.com/fsnotify/fsnotify v1.7.0
	github.com/json-iterator/go v1.1.12
	github.com/miekg/dns v1.1.55
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/okzk/sdnotify v0.0.0-20180710141335-d9becc38acbd
	github.com/safchain/ethtool v0.3.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/v2rayA/ahocorasick-domain v0.0.0-20231231085011-99ceb8ef3208
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.4
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	golang.org/x/crypto v0.18.0
	golang.org/x/exp v0.0.0-20230728194245-b0cb94b80691
	golang.org/x/sys v0.16.0
	google.golang.org/protobuf v1.31.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/daeuniverse/quic-go v0.0.0-20240413031024-943f218e0810 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20230705174524-200ffdc848b8 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/onsi/ginkgo/v2 v2.11.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/tools v0.11.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230807174057-1744710a1577 // indirect
)

require (
	github.com/bits-and-blooms/bitset v1.8.0 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-idea v0.0.0-20170306091226-d2fb45a411fb // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/dgryski/go-rc2 v0.0.0-20150621095337-8a9021637152 // indirect
	github.com/dlclark/regexp2 v1.11.0
	github.com/eknkc/basex v1.0.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mzz2017/disk-bloom v1.0.1 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/refraction-networking/utls v1.6.4 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	gitlab.com/yawning/chacha20.git v0.0.0-20230427033715-7877545b1b37 // indirect
	golang.org/x/term v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/grpc v1.57.0 // indirect
)

// replace github.com/daeuniverse/outbound => ../outbound

// replace github.com/daeuniverse/quic-go => ../quic-go

//replace github.com/cilium/ebpf => /home/mzz/goProjects/ebpf
//replace github.com/daeuniverse/dae-config-dist/go/dae_config => /home/mzz/antlrProjects/dae-config/build/go/dae_config
