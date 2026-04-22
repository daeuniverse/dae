# dae 重构验证计划

本文档用于把“重构路线”落到可执行的验证清单上，避免后续改动只停留在架构讨论层面。

目标有三点：

- 在真正重构前，先用契约测试固定高风险边界。
- 把新增测试和现有测试映射到具体阶段，降低回归风险。
- 给每个阶段提供最小可运行的测试命令，便于逐步推进。

## 验证原则

- 先验证错误边界，再验证生命周期边界，最后验证模型边界。
- 每个阶段至少保留一组可以独立运行的 targeted tests，不依赖全量 `go test ./...`。
- 新增测试优先覆盖重构前后都必须保持稳定的行为，不覆盖一次性实现细节。
- 行为重构和结构重构不要混在同一个阶段；先用测试锁住行为，再移动代码。

## Phase 1: Config 边界收紧

目标：

- 把高层 `panic` 路径改成 `error` 返回。
- 固定 `FunctionOrString` / `FunctionListOrString` 的契约行为。
- 让 builder / policy 在接收到非法 union 值时返回错误，而不是崩溃。

新增测试：

- [config/function_union_test.go](/root/dae/config/function_union_test.go)
  - `TestFunctionOrStringToFunction`
  - `TestFunctionListOrStringToFunctionList`
  - `TestPatchMustOutboundFallback`
- [component/dns/fallback_contract_test.go](/root/dae/component/dns/fallback_contract_test.go)
  - `TestRequestMatcherBuilderRejectsInvalidFallbackType`
  - `TestResponseMatcherBuilderRejectsInvalidFallbackType`
- [component/outbound/dialer_selection_policy_test.go](/root/dae/component/outbound/dialer_selection_policy_test.go)
  - `TestNewDialerSelectionPolicyFromGroupParamRejectsInvalidPolicyType`
- [control/routing_matcher_builder_test.go](/root/dae/control/routing_matcher_builder_test.go)
  - `TestRoutingMatcherBuilderRejectsInvalidFallbackType`

现有辅助测试：

- [config/marshal_test.go](/root/dae/config/marshal_test.go)
- [pkg/config_parser/config_parser_test.go](/root/dae/pkg/config_parser/config_parser_test.go)

建议命令：

```bash
go test ./config/... ./pkg/config_parser/... ./component/dns/... ./component/outbound/... ./control/... -run 'FunctionOrString|FunctionListOrString|FallbackType|SelectionPolicy'
```

通过标准：

- 所有非法 union 输入都返回 `error`。
- 不再依赖 `panic` 来表示配置层高阶错误。

## Phase 2: DNS 长短状态分离

目标：

- 把 `DnsController` 中的长期状态和 generation runtime 分开。
- 继续支持 reload 期间复用 DNS cache / forwarder warm state。
- 避免旧 generation 上下文取消后，复用的 worker 异常退出。

现有关键测试：

- [control/dns_controller_reload_test.go](/root/dae/control/dns_controller_reload_test.go)
  - `TestDnsController_RuntimeWorkersSurviveContextCancel`
- [control/dns_forwarder_cache_test.go](/root/dae/control/dns_forwarder_cache_test.go)
- [control/dns_singleflight_test.go](/root/dae/control/dns_singleflight_test.go)
- [control/dns_control_cache_cleanup_test.go](/root/dae/control/dns_control_cache_cleanup_test.go)
- [control/dns_cache_scope_test.go](/root/dae/control/dns_cache_scope_test.go)

建议命令：

```bash
go test ./control/... -run 'DnsController|dns.*reload|dns.*forwarder|dns.*singleflight|dns.*cache'
```

通过标准：

- DNS runtime 更新后，旧 context 取消不会杀死共享 worker。
- DNS cache / forwarder 生命周期语义保持不变。

## Phase 3: ControlPlane 降级为 facade

目标：

- 把 datapath janitor 和 DNS runtime handoff 从 `ControlPlane` 中抽离。
- 保持 reload / retirement / drain 语义不变。

现有关键测试：

- [control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go)
  - `TestReuseDNSControllerFromUpdatesRuntime`
  - `TestReuseDNSListenerFromTransfersOwnership`
  - `TestReuseDNSListenerFromRejectsProtocolMismatch`
- [control/control_plane_janitor_test.go](/root/dae/control/control_plane_janitor_test.go)
- [control/control_plane_shutdown_udp_test.go](/root/dae/control/control_plane_shutdown_udp_test.go)
- [control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go)

建议命令：

```bash
go test ./control/... ./cmd/... -run 'ReuseDNS|Drain|Janitor|Shutdown|Retirement'
```

通过标准：

- `ControlPlane` 拆分后，旧/new generation handoff 语义不变。
- janitor 停止和 retirement cleanup 仍然能按预期完成。

## Phase 4: cmd/run 下沉 Runner / ReloadManager

目标：

- 把 staged reload、handoff、retirement 排队逻辑从 CLI 入口下沉。
- 保持外部 CLI 行为不变。

现有关键测试：

- [cmd/run_shutdown_test.go](/root/dae/cmd/run_shutdown_test.go)
- [cmd/reload_progress_test.go](/root/dae/cmd/reload_progress_test.go)
- [control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go)

建议命令：

```bash
go test ./cmd/... ./control/... -run 'Reload|Progress|Shutdown|Handoff'
```

通过标准：

- CLI 行为不变。
- reload busy / handoff / retirement 的状态转换不变。

## Phase 5: Routing IR

目标：

- 引入统一的 normalized rule IR。
- 各 matcher / backend 从 IR 降低，而不是直接从 parser 规则各自解释。

现有关键测试：

- [component/routing/optimizer_contract_test.go](/root/dae/component/routing/optimizer_contract_test.go)
- [component/dns/request_rule_split_test.go](/root/dae/component/dns/request_rule_split_test.go)
- [component/daedns/router_test.go](/root/dae/component/daedns/router_test.go)
- [control/routing_matcher_builder_test.go](/root/dae/control/routing_matcher_builder_test.go)

建议命令：

```bash
go test ./component/routing/... ./component/dns/... ./component/daedns/... ./control/... -run 'Routing|Rule|Matcher|Optimizer'
```

通过标准：

- 规则规范化后，DNS/request/response/control backend 的语义不漂移。
- 同一个规则输入，在不同 backend 上的 fallback / outbound 行为保持一致。

## Phase 6: Dialer 健康模型显式化

目标：

- 用显式 health domain API 包裹内部索引模型。
- 保持 UDP data fallback、reload snapshot、recovery backoff 语义不变。

现有关键测试：

- [component/outbound/dialer/recovery_bugs_test.go](/root/dae/component/outbound/dialer/recovery_bugs_test.go)
- [component/outbound/dialer_group_test.go](/root/dae/component/outbound/dialer_group_test.go)
- [control/dial_family_fallback_test.go](/root/dae/control/dial_family_fallback_test.go)
- [control/udp_dial_guard_test.go](/root/dae/control/udp_dial_guard_test.go)

建议命令：

```bash
go test ./component/outbound/... ./component/outbound/dialer/... ./control/... -run 'Recovery|Snapshot|DialerGroup|UDP.*fallback|dial.*guard'
```

通过标准：

- `ReloadHealthSnapshot` / `RestoreHealthSnapshot` 语义不变。
- UDP data-plane fallback 仍然能回落到 DNS UDP / TCP 健康域。

## 建议执行顺序

建议按以下顺序推进，每完成一个阶段都保留一个可长期停留的稳定点：

1. Phase 1: Config 边界收紧
2. Phase 2: DNS 长短状态分离
3. Phase 3: ControlPlane facade 化
4. Phase 4: Runner / ReloadManager 下沉
5. Phase 5: Routing IR
6. Phase 6: Dialer 健康模型显式化

## 评审检查表

每个重构 PR 在评审时至少回答以下问题：

- 这次改动是否引入了新的状态所有者？
- 如果有复用对象，复用的是“对象”还是“状态”？
- 现有 targeted tests 是否覆盖到了改动边界？
- 是否把行为改动和结构改动混在了一个提交中？
- 是否留下了新的双状态源或新的隐式生命周期耦合？

## 当前已落地的第一步

本次已完成：

- 把 config union helper 从 `panic` 改为返回 `error`
- 给 fallback / policy / routing builder 添加非法 union 输入的契约测试
- 建立本验证文档，作为后续重构的执行与回归基线

## 当前已落地的第二步

本次继续完成：

- 删除 `DnsController` 的 legacy runtime 字段与 fallback 读取路径，统一以 `runtimeState` 作为单一真相来源
- 新增 [control/dns_runtime_test_helpers_test.go](/root/dae/control/dns_runtime_test_helpers_test.go) 作为测试期 runtime 构造辅助，避免测试继续依赖被移除的 legacy 字段
- 将 DNS 相关测试迁移到 `runtimeState` 构造方式，并通过 `go test ./control/...` 验证行为未回归

## 当前已落地的第三步

本次继续完成：

- 在 [control/dns_control.go](/root/dae/control/dns_control.go) 中抽出 `dnsControllerStore`，把 `dnsCache`、`dnsForwarderCache`、janitor/evictor 状态、BPF update worker 状态以及 preference wait registry 统一收口为长期状态所有者
- 调整 [control/dns_preference_wait_test.go](/root/dae/control/dns_preference_wait_test.go)、[control/dns_lru_e2e_test.go](/root/dae/control/dns_lru_e2e_test.go)、[control/dns_control_cache_cleanup_test.go](/root/dae/control/dns_control_cache_cleanup_test.go)、[control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go) 和 [control/control_plane_real_domain_test.go](/root/dae/control/control_plane_real_domain_test.go) 等测试，使其显式初始化 `dnsControllerStore`，固定长期状态归属迁移后的构造方式
- 新增 [control/dns_runtime_test_helpers_test.go](/root/dae/control/dns_runtime_test_helpers_test.go) 中的 `newTestDnsControllerStore`，为后续继续拆分 DNS 长期状态和 generation runtime 提供统一测试入口
- 通过以下命令验证这一步仅改变状态归属，不改变行为：

```bash
go test ./control/...
go test ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

## 当前已落地的第四步

本次继续完成：

- 在 [control/dns_control.go](/root/dae/control/dns_control.go) 中把 `DnsController` 对 `dnsControllerStore` 的持有从值语义切换为共享指针语义，并新增 `sharedStoreFacade()`，让后续 reload 可以创建新的 controller facade，同时继续复用长期 DNS state
- 在 [control/control_plane.go](/root/dae/control/control_plane.go) 中将 `ReuseDNSControllerFrom` 改为“刷新旧 facade runtime，再创建共享 store 的新 facade 并交给新 generation”，不再继续把同一个 `DnsController` 对象在新旧 generation 间直接转移
- 在 [control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go) 中固定新的 handoff 契约：
  - 新旧 generation 共享 active DNS controller facade
  - 新 facade 与旧 facade 不是同一个对象
  - 两者共享同一个 `dnsControllerStore`
  - 旧 facade 的 runtime 也会先更新到新 generation，避免 reload 交接窗口内的旧引用继续持有旧 runtime
- 调整 [control/dns_runtime_test_helpers_test.go](/root/dae/control/dns_runtime_test_helpers_test.go) 的默认测试 store 为最小化形态，避免测试默认构造误引入未启动的 evictor queue，保持原有同步 callback 语义
- 通过以下命令验证 facade 分离后行为未回归：

```bash
go test ./control/...
go test ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

本轮补充验证：

```bash
go test ./...
go test -race ./control/... ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

## 当前已落地的第五步

本次继续完成：

- 在 [control/dns_control.go](/root/dae/control/dns_control.go) 中把 `DnsController` 的 generation-local 行为配置刷新纳入 `UpdateRuntime` / `ReuseForReload`：
  - `qtypePrefer`
  - `optimisticCacheEnabled`
  - `optimisticCacheTtl`
  - `maxCacheSize`
- 将上述行为配置改为原子读写，修复 reload 更新与 janitor / lookup 并发访问时的 data race，避免“runtime 指针已切换，但行为配置仍沿用旧 generation 值”的隐性不一致
- 让 `UpdateRuntime` 和 `ReuseForReload` 对非法 `IpVersionPrefer` 显式返回 `error`，而不是静默接受无效运行时配置
- 为此补充并更新以下测试：
  - [control/dns_controller_reload_test.go](/root/dae/control/dns_controller_reload_test.go)：新增 reload 后行为配置同步刷新的契约测试，以及非法 `IpVersionPrefer` 的失败契约测试
  - [control/dns_cache_race_test.go](/root/dae/control/dns_cache_race_test.go)：把 `singleflight` 并发场景收敛成确定性 barrier，固定 `-race` 下的单飞契约，避免测试本身因时序过松而误报
  - [control/dns_preference_wait_test.go](/root/dae/control/dns_preference_wait_test.go)、[control/dns_lru_e2e_test.go](/root/dae/control/dns_lru_e2e_test.go)、[control/dns_control_cache_cleanup_test.go](/root/dae/control/dns_control_cache_cleanup_test.go)：更新为原子字段访问方式，保证测试构造与运行时实现一致

本轮最终验证：

```bash
go test ./control/...
go test ./...
go test -race ./control/... ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

结论：

- 当前这轮围绕 config 边界、`DnsController` 状态分层、reload facade handoff 与 runtime 行为配置同步的重构已经完成闭环。
- 普通回归与 `-race` 回归均已通过，可以作为下一批 `ControlPlane` facade 化或更深层 routing / dialer 重构之前的稳定基线。

## 当前已落地的第六步

本次继续完成：

- 新增 [control/dns_runtime.go](/root/dae/control/dns_runtime.go)，把原先散落在 `ControlPlane` 根对象上的 DNS orchestration 状态正式收拢为 `controlPlaneDNSRuntime`：
  - `dnsController`
  - `dnsRouting`
  - `dnsFixedDomainTtl`
  - `dnsListener`
  - prepared start/reuse hook
  - upstream ready/available channel 与 once
  - deferred DNS listener start 状态
- 在 [control/control_plane.go](/root/dae/control/control_plane.go) 中把以下 DNS 生命周期方法改为委托到 runtime：
  - `CloneDnsCache`
  - `ActiveDnsController`
  - `DetachDnsController`
  - `StopDNSListener`
  - `RestartDNSListener`
  - `ReuseDNSListenerFrom`
  - `ReuseDNSControllerFrom`
  - `SetPreparedDNSStartHook`
  - `SetPreparedDNSReuseHook`
  - `WaitDNSUpstreamsReady`
  - `WaitDNSUpstreamAvailable`
  - `StartPreparedDNSListener`
- 将 `releaseRetainedState` 里的 DNS 相关清理切换为 runtime 统一释放，减少 `ControlPlane` 根对象直接持有和逐项回收 DNS 子系统状态
- 保持外部行为不变，只调整状态 owner 与方法归属，为后续继续把 `ControlPlane` 降级为 facade 做准备

本次同步调整的测试：

- [control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go)：更新为显式构造 `controlPlaneDNSRuntime`，固定 DNS listener/controller handoff 与 prepared start/reuse hook 的新 owner 边界

本轮验证：

```bash
go test ./control/...
go test ./...
go test -race ./control/... ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

结论：

- `ControlPlane` 已经开始从“直接持有所有 DNS 细节”的大对象，转向“组合一个内部 DNS runtime 并委托生命周期操作”的形态。
- 这一步仍然是纯边界重排，没有引入新的 DNS 运行语义；普通回归和 `-race` 回归均通过。

## 当前已落地的第七步

本次继续完成：

- 新增 [config/decode.go](/root/dae/config/decode.go)，把 `Config.New()` 根部的 section 分发从“反射遍历整个 `Config` 结构体”改成显式 decoder registry：
  - `global`
  - `subscription`
  - `node`
  - `group`
  - `routing`
  - `dns`
- 在 [config/config.go](/root/dae/config/config.go) 中把根部必选 section 校验和 parse 顺序显式化，让后续逐节替换反射 parser 时，不再需要先动 `Config.New()` 的主控制流
- 保留现有 section 级 `SectionParser` / `ParamParser` 行为，因此这一步只是在根入口收紧边界，不改 DSL 语义
- 新增 [config/decode_test.go](/root/dae/config/decode_test.go)，固定显式 section decoder 分发路径和 unknown section 错误边界

本轮验证：

```bash
go test ./config/...
go test ./...
go test -race ./control/... ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

结论：

- `Config.New()` 已不再依赖根部反射扫描来决定 section 解析入口。
- 关键 section 的 decoder 边界已经显式化，为后续继续替换 `routing` / `dns` / `group` 的内部反射解析打下基础。

## 当前已落地的第八步

本次继续完成：

- 新增 [control/generation_state.go](/root/dae/control/generation_state.go)，把 `ControlPlane` 中明显属于 generation 生命周期的状态收口为 `controlPlaneGenerationState`：
  - `outbounds`
  - `referencedOutbounds`
  - `dialMode`
  - `routingMatcher`
  - `bootstrapResolvers`
- 新增 [control/datapath_janitor.go](/root/dae/control/datapath_janitor.go)，把 datapath janitor 的 owner 状态收口为 `controlPlaneDatapathJanitor`：
  - stop/done/once/started 状态
  - cleanup mutex
  - janitor scratch buffers
- 在 [control/control_plane.go](/root/dae/control/control_plane.go) 中将上述状态改为内部对象持有，并让 `releaseRetainedState()`、scratch 获取与初始化路径统一委托到新 owner
- 更新 [control/control_plane_drain_test.go](/root/dae/control/control_plane_drain_test.go)、[control/control_plane_janitor_test.go](/root/dae/control/control_plane_janitor_test.go)、[control/control_plane_real_domain_test.go](/root/dae/control/control_plane_real_domain_test.go)、[control/dscp_routing_test.go](/root/dae/control/dscp_routing_test.go)、[control/mac_routing_test.go](/root/dae/control/mac_routing_test.go)、[control/metadata_routing_chain_test.go](/root/dae/control/metadata_routing_chain_test.go)、[control/dial_family_fallback_test.go](/root/dae/control/dial_family_fallback_test.go)、[control/udp_reuse_simulation_test.go](/root/dae/control/udp_reuse_simulation_test.go) 的构造方式，使测试显式体现新的 owner 边界

本轮验证：

```bash
go test ./config/... ./control/...
go test ./...
go test -race ./control/... ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

结论：

- `ControlPlane` 已进一步从“所有 generation / datapath 状态都直接堆在根对象上”的形态，推进到“根对象组合 generation state、dns runtime、datapath janitor” 的形态。
- 这一步仍然是所有权与生命周期边界重排，没有引入新的 datapath 清理语义；普通回归和 `-race` 回归均通过。

## 当前已落地的第九步

本次继续完成：

- 新增 [cmd/reload_manager.go](/root/dae/cmd/reload_manager.go)，把 `cmd/run.go` 中原先散落的 reload 排队、staged handoff、retirement、progress/pprof 刷新逻辑收口为 `reloadManager`
- 新增 [cmd/runner.go](/root/dae/cmd/runner.go)，让入口层从“一个超大 `Run` 函数”转为 `Runner + ReloadManager` 的组合；[cmd/run.go](/root/dae/cmd/run.go) 现在只负责组装 `Runner` 并委托执行
- 更新 [cmd/run_shutdown_test.go](/root/dae/cmd/run_shutdown_test.go) 的 reload manager 契约测试，固定：
  - shutdown handoff 会优先消费 pending staged handoff
  - queued reload request 只保留最新请求时间戳

本轮验证：

```bash
go test ./cmd/... ./control/...
go test ./...
go test -race ./cmd/... ./control/... ./component/dns/... ./component/outbound/... ./config/... ./pkg/config_parser/...
```

结论：

- `cmd/run` 的生命周期状态机已经不再完全寄居在入口函数本体里。
- staged reload / handoff / retirement 的 owner 边界已经转为 `Runner` 与 `ReloadManager` 组合，后续继续下沉时不必再从 CLI 控制流直接拆。

## 当前已落地的第十步

本次继续完成：

- 新增 [component/routing/ir.go](/root/dae/component/routing/ir.go) 和 [component/routing/normalize.go](/root/dae/component/routing/normalize.go)，引入共享的 `routing.NormalizedProgram`
- 新增 [component/dns/routing_program.go](/root/dae/component/dns/routing_program.go)，把 DNS request routing 的“优化 + internal selector split” 收口为 `NormalizedRequestRoutingProgram`
- 在以下 builder 中新增 `FromProgram` 入口，使 backend 从共享 program 降低，而不是各自直接解释 parser 规则：
  - [component/dns/request_routing.go](/root/dae/component/dns/request_routing.go)
  - [component/dns/response_routing.go](/root/dae/component/dns/response_routing.go)
  - [control/routing_matcher_builder.go](/root/dae/control/routing_matcher_builder.go)
- 将以下调用点迁移到 program 入口：
  - [component/dns/dns.go](/root/dae/component/dns/dns.go)
  - [component/daedns/router.go](/root/dae/component/daedns/router.go)
  - [control/control_plane.go](/root/dae/control/control_plane.go)
- 新增 [component/routing/normalize_test.go](/root/dae/component/routing/normalize_test.go) 和 [component/dns/routing_program_test.go](/root/dae/component/dns/routing_program_test.go)，固定：
  - program 构造会 clone 原始规则，不反向污染输入
  - request routing program 会稳定拆分 DNS / sub / node / subnode 规则

本轮验证：

```bash
go test ./component/routing/... ./component/dns/... ./control/... ./component/outbound/... ./cmd/...
go test ./...
```

结论：

- routing 层已经有了共享的 normalize/program 边界。
- DNS request、DNS response、control matcher 三个 backend 已经从“各自拿 parser rules 解释”推进到“从共同的 normalized program lowering”。

## 当前已落地的第十一步

本次继续完成：

- 新增 [component/outbound/dialer/health_domain.go](/root/dae/component/outbound/dialer/health_domain.go)，引入显式 `HealthDomain` / `HealthKey` API，并在以下路径开始替代散落的硬编码 index：
  - [component/outbound/dialer/connectivity_check.go](/root/dae/component/outbound/dialer/connectivity_check.go)：`NetworkType.Index()` 现在通过 `HealthKey` 归一化映射
  - [component/outbound/dialer_group.go](/root/dae/component/outbound/dialer_group.go)：标准 selection network types 与 alive set 构建改为基于 `StandardHealthKeys()`
- 新增 [component/outbound/dialer/recovery_state.go](/root/dae/component/outbound/dialer/recovery_state.go)，把 recovery/backoff/timer/punishment 状态机提为 `dialerRecoveryManager`
- 在 [component/outbound/dialer/dialer.go](/root/dae/component/outbound/dialer/dialer.go) 中保留 `Dialer` 作为 facade，健康快照、restore、recovery trigger/cancel/backoff/stability 相关方法统一委托到 recovery manager
- 新增 [component/outbound/dialer/health_domain_test.go](/root/dae/component/outbound/dialer/health_domain_test.go)，固定：
  - TCP DNS 语义仍然映射到共享 TCP 健康域
  - canonical health keys 仍覆盖现有 6 个标准 collection

本轮验证：

```bash
go test ./component/outbound/... ./component/outbound/dialer/... ./control/...
go test ./...
```

结论：

- dialer 健康模型已经从“外围调用者直接依赖内部 idx 约定”推进到“有显式 health domain API 和 recovery manager owner”的形态。
- 现有 recovery snapshot / restore / backoff 行为由既有测试持续覆盖，新增 API 只是显式化边界，没有改变既有语义。

## 审阅修复记录

本次根据未提交修改审阅结果补充修复：

- 恢复 [config/config.go](/root/dae/config/config.go) 中 `FunctionOrStringToFunction` 与 `FunctionListOrStringToFunctionList` 的历史导出签名，避免破坏外部 API；新增 `ParseFunctionOrString` 与 `ParseFunctionListOrString` 供内部 error-return 调用链使用。
- 为 [cmd/reload_manager.go](/root/dae/cmd/reload_manager.go) 中跨 goroutine 读写的 reload 状态加锁，包括 `reloadingErr`、pending staged handoff、pending retirement channel 与 reload 时间戳，并让 [cmd/run.go](/root/dae/cmd/run.go) 统一走 `finishReloadSuccess()` 清理成功路径。
- 在 [control/dns_control.go](/root/dae/control/dns_control.go) 与 [control/dns_runtime.go](/root/dae/control/dns_runtime.go) 补充 DNS reload ownership model 注释，明确“独立 facade + 共享 store + handoff bridge”关系。
- 调整 [component/dns/routing_program.go](/root/dae/component/dns/routing_program.go)，`NormalizedRequestRoutingProgram` 构造不再先创建再丢弃中间 program，而是一次优化后拆分 DNS / sub / node / subnode 规则。
- 将 DNS controller 业务路径的 store 检查从静默创建空 store 改为显式断言，避免测试或手工构造 controller 时掩盖初始化错误；reload 兼容桥仍会显式初始化缺失 store。
- 补充 [component/routing/normalize_test.go](/root/dae/component/routing/normalize_test.go) 的 `Lower` 边界测试，覆盖空规则、nil parser、fallback 错误传播。
- 删除 [component/outbound/dialer/dialer.go](/root/dae/component/outbound/dialer/dialer.go) 中与 `triggerRecoveryDetection` 完全等价的 `triggerRecoveryDetectionInternal` 死代码。

本轮验证：

```bash
go test ./config/... ./component/dns/... ./component/routing/... ./component/outbound/... ./control/... ./cmd/...
go test ./...
go test -race ./...
make ebpf
```

结论：

- 普通全量测试与 race 全量测试均通过。
- 这轮修复消除了审阅中指出的导出 API 破坏、reload manager 未同步共享字段、重复清理入口、routing program 中间包装浪费、`Lower` 边界测试不足和 dialer 死代码问题。

## 后续审阅修复记录

本次根据新增审阅点继续修复：

- 为 [cmd/reload_manager.go](/root/dae/cmd/reload_manager.go) 的 `startControlPlaneRetirement` 补充单元测试，覆盖 retirement channel 发布、退休协程完成以及旧 generation cancel 调用。
- 将 DNS 配置比较从 `reflect.DeepEqual` 改为稳定 fingerprint 比较，避免在 [cmd/reload_manager.go](/root/dae/cmd/reload_manager.go) 的 staged DNS reuse 判断中依赖反射深比较。
- 调整 [component/dns/routing_program.go](/root/dae/component/dns/routing_program.go)，仅在无 optimizer 时执行 `DeepCloneRules`；有 optimizer 时直接使用 `ApplyRulesOptimizers` 内部 clone 结果，避免重复深拷贝。
- 在 [component/outbound/dialer/health_domain.go](/root/dae/component/outbound/dialer/health_domain.go) 新增 `HealthKeyFromCollectionIndex`，并让 [component/outbound/dialer/dialer.go](/root/dae/component/outbound/dialer/dialer.go) 的 collection index 反查不再遍历 6 个标准 key。

本轮验证：

```bash
go test ./cmd/... ./component/dns/... ./component/outbound/...
go test ./...
go test -race ./...
```

结论：

- 新增 retirement 单元测试通过。
- 普通全量测试与 race 全量测试均通过。

## DNS Fingerprint 覆盖修复记录

本次根据新增审阅点继续修复：

- 在 [cmd/reload_manager.go](/root/dae/cmd/reload_manager.go) 的 `dnsConfigFingerprint` 上补充维护注释，明确该函数必须与 `config.Dns` 顶层字段保持同步。
- 在 [cmd/run_shutdown_test.go](/root/dae/cmd/run_shutdown_test.go) 新增 `TestDNSConfigFingerprintCoversAllDnsFields`，通过反射校验 `config.Dns` 顶层字段覆盖率。后续新增 DNS 配置字段但未更新 fingerprint 时，测试会失败。

本轮验证：

```bash
go test ./cmd/...
go test ./...
go test -race ./...
```

结论：

- 普通全量测试与 race 全量测试均通过。
