# Changelogs

Also seen in [GitHub Releases](https://github.com/daeuniverse/dae/releases)

HTML version available at https://dae.v2raya.org/docs/current/changelogs

## Query history releases

```bash
curl --silent "https://api.github.com/repos/daeuniverse/dae/releases" | jq -r '.[] | {tag_name,created_at,prerelease}'
```

## Releases

<!-- BEGIN NEW TOC ENTRY -->
- [v0.6.0 (Latest)](#v060-latest)
- [v0.5.1](#v051)
- [v0.5.0](#v050)
- [v0.4.0](#v040)
- [v0.3.0](#v030)
- [v0.2.4](#v024)
- [v0.2.3](#v023)
- [v0.2.2](#v022)
- [v0.2.1](#v021)
- [v0.2.0](#v020)
- [v0.1.10.p1](#v0110p1)
- [v0.1.10](#v0110)
- [v0.1.9-patch.1](#v019-patch1)
- [v0.1.9](#v019)
- [v0.1.8](#v018)
- [v0.1.7](#v017)
- [v0.1.6](#v016)
- [v0.1.5](#v015)
- [v0.1.4](#v014)
- [v0.1.3](#v013)
- [v0.1.2](#v012)
- [v0.1.1](#v011)
- [v0.1.0](#v010)
<!-- BEGIN NEW CHANGELOGS -->

### v0.6.0 (Latest)

> Release date: 2024/06/11

#### Breaking Changes

> [!NOTE]
> Please read the following PRs for details

- feat(bpf): implement stack bypass in [#458](https://github.com/daeuniverse/dae/pull/458) by (@jschwinger233)
- patch/optimize(bpf): improve lan hijack datapath performance in [#466](https://github.com/daeuniverse/dae/pull/466) by (@jschwinger233)
- patch/optimize(bpf): improve wan tcp hijack datapath performance in [#481](https://github.com/daeuniverse/dae/pull/481) by (@jschwinger233)

#### Features

- feat: dae trace in [#435](https://github.com/daeuniverse/dae/pull/435) by (@jschwinger233)
- feat(bpf): implement stack bypass in [#458](https://github.com/daeuniverse/dae/pull/458) by (@jschwinger233)
- feat: add httpupgrade in [#472](https://github.com/daeuniverse/dae/pull/472) by (@AkinoKaede)
- feat: support reloading progress and error for `dae reload` in [#470](https://github.com/daeuniverse/dae/pull/470) by (@mzz2017)
- feat: add .clang-format file from torvalds/linux in [#492](https://github.com/daeuniverse/dae/pull/492) by (@mzz2017)
- feat: support to maintain udp conn state in [#493](https://github.com/daeuniverse/dae/pull/493) by (@mzz2017)

#### Bug Fixes

- fix: Create DaeNetns instance strictly once on reload in [#446](https://github.com/daeuniverse/dae/pull/446) by (@jschwinger233)
- patch/optimize(bpf): improve lan hijack datapath performance in [#466](https://github.com/daeuniverse/dae/pull/466) by (@jschwinger233)
- fix: Fix bpf CO-RE issue on 6.9 in [#483](https://github.com/daeuniverse/dae/pull/483) by (@jschwinger233)
- fix(bpf): revert using bpf_redirect_peer in [#480](https://github.com/daeuniverse/dae/pull/480) by (@jschwinger233)
- patch/optimize(bpf): improve wan tcp hijack datapath performance in [#481](https://github.com/daeuniverse/dae/pull/481) by (@jschwinger233)
- fix: shoot ipv6 icmp redirects in [#494](https://github.com/daeuniverse/dae/pull/494) by (@mzz2017)
- fix: cannot use must in bracket in fallback in [#495](https://github.com/daeuniverse/dae/pull/495) by (@mzz2017)
- fix: Don't enable net.ipv6.conf.all.forwarding in [#496](https://github.com/daeuniverse/dae/pull/496) by (@jschwinger233)
- fix: auto_config_kernel_parameter sets net.ipv6.conf.all.forwarding=1 when binding lan interfaces in [#499](https://github.com/daeuniverse/dae/pull/499) by (@jschwinger233)
- fix/chore: update submodule outbound to fix panic in some edge cases in [#503](https://github.com/daeuniverse/dae/pull/503) by (@mzz2017)
- fix: maintain udp conn direction to fix possible dns leaking in [#505](https://github.com/daeuniverse/dae/pull/505) by (@mzz2017)
- fix: sysctl net.ipv4.conf.dae0peer.accept_local=1 in [#512](https://github.com/daeuniverse/dae/pull/512) by (@jschwinger233)
- fix: Opt out TCP sockmap bypass by default in [#518](https://github.com/daeuniverse/dae/pull/518) by (@jschwinger233)
- fix: set accept_ra=2 to fix missing ipv6 address on WAN interface if necessary in [#504](https://github.com/daeuniverse/dae/pull/504) by (@mzz2017)

#### Others

- docs(protocols): delete redundant line in [#452](https://github.com/daeuniverse/dae/pull/452) by (@bradfordzhang)
- ci(Makefile): enable trace module by default in [#455](https://github.com/daeuniverse/dae/pull/455) by (@hero-intelligent)
- ci: update actions/checkout@v3 to actions/checkout@v4 in [#461](https://github.com/daeuniverse/dae/pull/461) by (@MarksonHon)
- ci: update ci modules using nodejs to latest in [#465](https://github.com/daeuniverse/dae/pull/465) by (@MarksonHon)
- style: format bpf c code using kernel checkpatch.pl in [#477](https://github.com/daeuniverse/dae/pull/477) by (@jschwinger233)
- chore: bump submodule dae_bpf_headers in [#487](https://github.com/daeuniverse/dae/pull/487) by (@jschwinger233)
- chore: Replace regexp with regexp2 for better filtering in [#467](https://github.com/daeuniverse/dae/pull/467) by (@xishang0128)
- docs(example): add '# Multiple filters indicate 'or' logic.' in [#488](https://github.com/daeuniverse/dae/pull/488) by (@akiooo45)
- ci(generate-changelogs.yml): generate auth token on the fly in [#489](https://github.com/daeuniverse/dae/pull/489) by (@sumire88)
- ci(release): draft release v0.6.0rc1 in [#491](https://github.com/daeuniverse/dae/pull/491) by (@dae-prow)
- docs(readme): remove unnecessary lines in [#500](https://github.com/daeuniverse/dae/pull/500) by (@sumire88)
- chore: upgrade quic-go to 0.42.0 and utls to 1.6.4 in [#497](https://github.com/daeuniverse/dae/pull/497) by (@mzz2017)
- ci(release): draft release v0.6.0rc2 in [#502](https://github.com/daeuniverse/dae/pull/502) by (@dae-prow)
- chore(dae.service): set TimeoutStartSec=120 instead of 10 in [#510](https://github.com/daeuniverse/dae/pull/510) by (@hiifeng)
- chore(issue_template): update template params in [#514](https://github.com/daeuniverse/dae/pull/514) by (@sumire88)
- docs: update dae-with-opnsense.md in [#517](https://github.com/daeuniverse/dae/pull/517) by (@linglilongyi)
- chore: right the wrong gateway config in opnsense document in [#520](https://github.com/daeuniverse/dae/pull/520) by (@troubadour-hell)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.6.0/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.5.1...v0.6.0

#### New Contributors

- @xishang0128 made their first contribution in [#467](https://github.com/daeuniverse/dae/pull/467)
- @akiooo45 made their first contribution in [#488](https://github.com/daeuniverse/dae/pull/488)
- @hiifeng made their first contribution in [#510](https://github.com/daeuniverse/dae/pull/510)
- @linglilongyi made their first contribution in [#517](https://github.com/daeuniverse/dae/pull/517)

### v0.5.1

> Release date: 2024/01/23

#### Features

- feat: support to auto config firewall (firewalld) in [#420](https://github.com/daeuniverse/dae/pull/420) by (@mzz2017)
- optimize: avoid conflict with potential local dns server in [#422](https://github.com/daeuniverse/dae/pull/422) by (@mzz2017)

#### Bug Fixes

- fix: Workaround UDP port conflicts when another local process binds 53 in [#414](https://github.com/daeuniverse/dae/pull/414) by (@jschwinger233)
- fix/docs: fix the first check failure and possible dns leaking in [#418](https://github.com/daeuniverse/dae/pull/418) by (@mzz2017)
- fix: Watch sysctl changes to ensure expected values in [#426](https://github.com/daeuniverse/dae/pull/426) by (@jschwinger233)

#### Others

- ci(release): draft release v0.5.0 in [#409](https://github.com/daeuniverse/dae/pull/409) by (@dae-prow-robot)
- chore(changelogs): fix changelogs corruption in [#410](https://github.com/daeuniverse/dae/pull/410) by (@sumire88)
- chore(issue_template): demise telegram support in [#425](https://github.com/daeuniverse/dae/pull/425) by (@sumire88)
- docs(tutorials): add run-on-centos7 in [#434](https://github.com/daeuniverse/dae/pull/434) by (@kuseee)
- chore(cmd/version): update print info in [#417](https://github.com/daeuniverse/dae/pull/417) by (@sumire88)
- refactor/optimize: remove dead code in [#411](https://github.com/daeuniverse/dae/pull/411) by (@jschwinger233)
- docs(tutorials): add dae-with-opnsense(en/zh) in [#438](https://github.com/daeuniverse/dae/pull/438) by (@troubadour-hell)

#### 特性支持

- 特性: 支持自动配置防火墙 (firewalld) in [#420](https://github.com/daeuniverse/dae/pull/420) 由 (@mzz2017)
- 优化: 避免与潜在的本地 DNS 服务器冲突 in [#422](https://github.com/daeuniverse/dae/pull/422) 由 (@mzz2017)

#### 问题修复

- 修复: 解决另一个本地进程绑定 53 时的 UDP 端口冲突 in [#414](https://github.com/daeuniverse/dae/pull/414) 由 (@jschwinger233)
- 修复/文档: 修复第一次检查失败和可能的 DNS 泄漏 in [#418](https://github.com/daeuniverse/dae/pull/418) 由 (@mzz2017)
- 修复: 观察 sysctl 更改以确保预期的值 in [#426](https://github.com/daeuniverse/dae/pull/426) 由 (@jschwinger233)

#### 其他变更

- 自动化(release): 起草版本 v0.5.0 in [#409](https://github.com/daeuniverse/dae/pull/409) 由 (@dae-prow-robot)
- 杂项(changelogs): 修复变更日志损坏 in [#410](https://github.com/daeuniverse/dae/pull/410) 由 (@sumire88)
- 杂项(issue_template): 暂时移除 Telegram 支持 in [#425](https://github.com/daeuniverse/dae/pull/425) 由 (@sumire88)
- 文档(tutorials): 添加在 CentOS 7 上运行指南 in [#434](https://github.com/daeuniverse/dae/pull/434) 由 (@kuseee)
- 杂项(cmd/version): 更新打印信息 in [#417](https://github.com/daeuniverse/dae/pull/417) 由 (@sumire88)
- 重构/优化: 移除无用代码 in [#411](https://github.com/daeuniverse/dae/pull/411) 由 (@jschwinger233)
- 文档(tutorials): 添加 dae-with-opnsense(en/zh) in [#438](https://github.com/daeuniverse/dae/pull/438) 由 (@troubadour-hell)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.5.1/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.5.0...v0.5.1

#### New Contributors

- @kuseee made their first contribution in [#434](https://github.com/daeuniverse/dae/pull/434)

### v0.5.0

> Release date: 2024/01/04

#### Features

- feat/refactor: refactor outbound and support v2ray-plugin in [#390](https://github.com/daeuniverse/dae/pull/390) by (@mzz2017)
- feat: use bpf_sk_assign at tproxy_wan_ingress in [#383](https://github.com/daeuniverse/dae/pull/383) by (@jschwinger233)

#### Bug Fixes

- fix/chore: disable gso on client by default and upgrade softwind/quic-go in [#391](https://github.com/daeuniverse/dae/pull/391) by (@mzz2017)
- fix: add \_ into valid charset of ac machine in [#388](https://github.com/daeuniverse/dae/pull/388) by (@mzz2017)
- fix: running issue and no network on android in [#264](https://github.com/daeuniverse/dae/pull/264) by (@mzz2017)
- fix: ip rule is not added when only binding to wan in [#399](https://github.com/daeuniverse/dae/pull/399) by (@mzz2017)
- fix(bpf): sk_lookup_udp for listener only in [#401](https://github.com/daeuniverse/dae/pull/401) by (@jschwinger233)
- patch: rewrite bpf spec before loading to avoid bpf map lookup during runtime in [#376](https://github.com/daeuniverse/dae/pull/376) by (@jschwinger233)
- patch(bpf): Don't clear checksum on wan_egress in [#393](https://github.com/daeuniverse/dae/pull/393) by (@jschwinger233)

#### Others

- docs: add guide to separate configuration files in [#389](https://github.com/daeuniverse/dae/pull/389) by (@epmtyicu)
- ci: Add more kernel tests in [#386](https://github.com/daeuniverse/dae/pull/386) by (@jschwinger233)
- ci(docker): remove support for armv6 in [#392](https://github.com/daeuniverse/dae/pull/392) by (@mzz2017)
- ci(release): draft release v0.5.0rc1 in [#396](https://github.com/daeuniverse/dae/pull/396) by (@dae-prow-robot)
- chore: add fish completion in [#398](https://github.com/daeuniverse/dae/pull/398) by (@zzzsyyy)
- chore: Build statically linked binary in [#402](https://github.com/daeuniverse/dae/pull/402) by (@jschwinger233)
- docs(troubleshooting.md): add firewalld related docs in [#403](https://github.com/daeuniverse/dae/pull/403) by (@mzz2017)
- ci(release): draft release v0.5.0rc2 in [#405](https://github.com/daeuniverse/dae/pull/405) by (@dae-prow-robot)
- chore(license): update license signature in [#406](https://github.com/daeuniverse/dae/pull/406) by (@sumire88)

#### 特性支持

- 特性/重构: 重构出站并支持 v2ray-plugin in [#390](https://github.com/daeuniverse/dae/pull/390) by (@mzz2017)
- 特性: 在 #383 的 tproxy_wan_ingress 中使用 bpf_sk_assign by (@jschwinger233)

#### 问题修复

- 修复/杂项: 默认情况下禁用客户端的 gso 并升级 softwind/quic-go in [#391](https://github.com/daeuniverse/dae/pull/391) by (@mzz2017)
- 修复: 在 ac 机器的有效字符集中添加 \_ in [#388](https://github.com/daeuniverse/dae/pull/388) by (@mzz2017)
- 修复: Android 上的运行问题和无网络 in [#264](https://github.com/daeuniverse/dae/pull/264) by (@mzz2017)
- 修复: 只绑定到 wan 时未添加 ip 规则 in [#399](https://github.com/daeuniverse/dae/pull/399) by (@mzz2017)
- 修复(bpf): 仅针对监听器执行 sk_lookup_udp in [#401](https://github.com/daeuniverse/dae/pull/401) by (@jschwinger233)
- 补丁: 重写 bpf 规范，以避免在运行时进行 bpf 映射查找 in #376 by (@jschwinger233)
- 补丁(bpf): 不要在 #393 的 wan_egress 上清除校验和 by (@jschwinger233)

#### 其他变更

- 文档: 添加分离配置文件的指南 in [#389](https://github.com/daeuniverse/dae/pull/389) by (@epmtyicu)
- 自动化: 在 [#386](https://github.com/daeuniverse/dae/pull/386) 中添加更多内核测试 by (@jschwinger233)
- 自动化(docker): 移除对 armv6 的支持 in [#392](https://github.com/daeuniverse/dae/pull/392) by (@mzz2017)
- 自动化(release): 在 [#396](https://github.com/daeuniverse/dae/pull/396) 中起草发布 v0.5.0rc1 by (@dae-prow-robot)
- 杂项: 在 [#398](https://github.com/daeuniverse/dae/pull/398) 中添加 fish 补全 by (@zzzsyyy)
- 杂项: 在 [#402](https://github.com/daeuniverse/dae/pull/402) 中构建静态链接二进制 by (@jschwinger233)
- 文档(troubleshooting.md): 在 [#403](https://github.com/daeuniverse/dae/pull/403) 中添加与 firewalld 相关的文档 by (@mzz2017)
- 自动化(release): 在 [#405](https://github.com/daeuniverse/dae/pull/405) 中起草发布 v0.5.0rc2 by (@dae-prow-robot)
- 杂项(license): 在 [#406](https://github.com/daeuniverse/dae/pull/406) 中更新许可证签名 by (@sumire88)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.5.0/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.4.0...v0.5.0

#### New Contributors

- @epmtyicu made their first contribution in [#389](https://github.com/daeuniverse/dae/pull/389)
- @zzzsyyy made their first contribution in [#398](https://github.com/daeuniverse/dae/pull/398)
- @sumire88 made their first contribution in [#406](https://github.com/daeuniverse/dae/pull/406)

### v0.4.0

> Release date: 2023/12/26

#### Features

- feat(cmd): extend --version print info in [#356](https://github.com/daeuniverse/dae/pull/356) by (@yqlbu)
- feat: support --abort for reload and suspend in [#346](https://github.com/daeuniverse/dae/pull/346) by (@mzz2017)
- feat/optimize: print SubscriptionTag in AliveDialerSet::printLatencies() in [#319](https://github.com/daeuniverse/dae/pull/319) by (@luochen1990)
- optimize: latencyString shows realLatency(+offset) in [#307](https://github.com/daeuniverse/dae/pull/307) by (@luochen1990)
- optimize(udp)/fix(quicSniffer): optimize performance of udp and fix a potential panic of quic in [#301](https://github.com/daeuniverse/dae/pull/301) by (@mzz2017)
- feat: support ToS routing rule in [#292](https://github.com/daeuniverse/dae/pull/292) by (@mzz2017)

#### Bug Fixes

- fix: add \_ to valid domain chars set in [#365](https://github.com/daeuniverse/dae/pull/365) by (@mzz2017)

#### Others

- ci: Test against various kernels on PR in [#373](https://github.com/daeuniverse/dae/pull/373) by (@jschwinger233)
- docs: add guide for ufw 'binding to LAN' in [#372](https://github.com/daeuniverse/dae/pull/372) by (@st0nie)
- chore: upgrade softwind in [#359](https://github.com/daeuniverse/dae/pull/359) by (@mzz2017)
- chore: add zsh completion in [#353](https://github.com/daeuniverse/dae/pull/353) by (@st0nie)
- chore: add bash completion in [#352](https://github.com/daeuniverse/dae/pull/352) by (@shenghuang147)
- docs: improve docs about reload in [#347](https://github.com/daeuniverse/dae/pull/347) by (@bradfordzhang)
- docs: tweak archlinux installation guide in [#333](https://github.com/daeuniverse/dae/pull/333) by (@Integral-Tech)
- docs: refine DNS example in [#329](https://github.com/daeuniverse/dae/pull/329) by (@EkkoG)
- chore(Dockerfile): upgrade golang and clang (https://github.com/daeuniverse/daed/issues/250) in [#320](https://github.com/daeuniverse/dae/pull/320) by (@hero-intelligent)
- docs(readme): refine project description in [#317](https://github.com/daeuniverse/dae/pull/317) by (@yqlbu)
- ci(generate-changelogs): update default assignees list in [#314](https://github.com/daeuniverse/dae/pull/314) by (@yqlbu)
- ci(release): draft release v0.4.0rc1 in [#313](https://github.com/daeuniverse/dae/pull/313) by (@daebot)
- chore(release): add changelogs entry for v0.3.0 in [#311](https://github.com/daeuniverse/dae/pull/311) by (@mzz2017,@yqlbu)
- docs: improve docs about pppoe and mark in [#305](https://github.com/daeuniverse/dae/pull/305) by (@mzz2017)
- chore: close file descriptor & remove duplicated error handle in [#303](https://github.com/daeuniverse/dae/pull/303) by (@douglarek)
- docs(en): update how-it-works in [#300](https://github.com/daeuniverse/dae/pull/300) by (@yqlbu)
- chore: bump quic-go to v0.38.0 in [#297](https://github.com/daeuniverse/dae/pull/297) by (@mzz2017)
- refactor/fix: match dscp instead of tos in [#294](https://github.com/daeuniverse/dae/pull/294) by (@mzz2017)
- chore: honk with sound in [#289](https://github.com/daeuniverse/dae/pull/289) by (@troubadour-hell)

#### 特性

- 特性(cmd): 在 [#356](https://github.com/daeuniverse/dae/pull/356) 中扩展 --version 打印信息 by (@yqlbu)
- 特性: 为重载和挂起支持 --abort in [#346](https://github.com/daeuniverse/dae/pull/346) by (@mzz2017)
- 特性/优化: 在 [#319](https://github.com/daeuniverse/dae/pull/319) 中打印 SubscriptionTag 到 AliveDialerSet::printLatencies() by (@luochen1990)
- 优化: latencyString 在 [#307](https://github.com/daeuniverse/dae/pull/307) 中显示 realLatency(+offset) by (@luochen1990)
- 优化(udp)/修复(quicSniffer): 优化 udp 性能并修复 quic 潜在的 panic in [#301](https://github.com/daeuniverse/dae/pull/301) by (@mzz2017)
- 特性: 在 [#292](https://github.com/daeuniverse/dae/pull/292) 中支持 ToS 路由规则 by (@mzz2017)

#### 问题修复

- 修复: 在 [#365](https://github.com/daeuniverse/dae/pull/365) 中将 \_ 添加到有效域字符集合 by (@mzz2017)

#### 其他

- ci: 在 [#373](https://github.com/daeuniverse/dae/pull/373) 中对 PR 测试不同内核 by (@jschwinger233)
- docs: 在 [#372](https://github.com/daeuniverse/dae/pull/372) 中添加 ufw 'binding to LAN' 指南 by (@st0nie)
- 杂项: 在 [#359](https://github.com/daeuniverse/dae/pull/359) 中升级 softwind by (@mzz2017)
- 杂项: 在 [#353](https://github.com/daeuniverse/dae/pull/353) 中添加 zsh 完成 by (@st0nie)
- 杂项: 在 [#352](https://github.com/daeuniverse/dae/pull/352) 中添加 bash 完成 by (@shenghuang147)
- docs: 在 [#347](https://github.com/daeuniverse/dae/pull/347) 中改进关于重载的文档 by (@bradfordzhang)
- docs: 在 [#333](https://github.com/daeuniverse/dae/pull/333) 中微调 Arch Linux 安装指南 by (@Integral-Tech)
- docs: 在 [#329](https://github.com/daeuniverse/dae/pull/329) 中完善 DNS 示例 by (@EkkoG)
- 杂项(Dockerfile): 在 [#320](https://github.com/daeuniverse/dae/pull/320) 中升级 golang 和 clang (https://github.com/daeuniverse/daed/issues/250) by (@hero-intelligent)
- docs(readme): 在 [#317](https://github.com/daeuniverse/dae/pull/317) 中改进项目描述 by (@yqlbu)
- ci(generate-changelogs): 在 [#314](https://github.com/daeuniverse/dae/pull/314) 中更新默认分配人列表 by (@yqlbu)
- ci(release): 在 [#313](https://github.com/daeuniverse/dae/pull/313) 中起草发布 v0.4.0rc1 by (@daebot)
- 杂项(release): 在 [#311](https://github.com/daeuniverse/dae/pull/311) 中为 v0.3.0 添加变更日志条目 by (@mzz2017,@yqlbu)
- docs: 在 [#305](https://github.com/daeuniverse/dae/pull/305) 中改进关于 pppoe 和 mark 的文档 by (@mzz2017)
- 杂项: 在 [#303](https://github.com/daeuniverse/dae/pull/303) 中关闭文件描述符并删除重复的错误处理 by (@douglarek)
- docs(en): 在 [#300](https://github.com/daeuniverse/dae/pull/300) 中更新 how-it-works by (@yqlbu)
- 杂项: 在 [#297](https://github.com/daeuniverse/dae/pull/297) 中升级 quic-go 到 v0.38.0 by (@mzz2017)
- 重构/修复: 在 [#294](https://github.com/daeuniverse/dae/pull/294) 中匹配 DSCP 而不是 TOS by (@mzz2017)
- 杂项: 在 [#289](https://github.com/daeuniverse/dae/pull/289) 中用声音 honk by (@troubadour-hell)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.4.0/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.3.0...v0.4.0

#### New Contributors

- @jschwinger233 made their first contribution in https://github.com/daeuniverse/dae/pull/373

## v0.4.0rc1 (Pre-release)

> Release date: 2023/09/02

#### Features

- optimize: latencyString shows realLatency(+offset) in [#307](https://github.com/daeuniverse/dae/pull/307) by (@luochen1990)
- feat: support ToS routing rule in [#292](https://github.com/daeuniverse/dae/pull/292) by (@mzz2017)
- feat: dae can call now in [#288](https://github.com/daeuniverse/dae/pull/288) by (@troubadour-hell)

#### Others

- chore(release): add changelogs entry for v0.3.0 in [#311](https://github.com/daeuniverse/dae/pull/311) by (@mzz2017,@yqlbu)
- docs: improve docs about pppoe and mark in [#305](https://github.com/daeuniverse/dae/pull/305) by (@mzz2017)
- chore: close file descriptor & remove duplicated error handle in [#303](https://github.com/daeuniverse/dae/pull/303) by (@douglarek)
- docs(en): update how-it-works in [#300](https://github.com/daeuniverse/dae/pull/300) by (@yqlbu)
- chore: bump quic-go to v0.38.0 in [#297](https://github.com/daeuniverse/dae/pull/297) by (@mzz2017)
- refactor/fix: match dscp instead of tos in [#294](https://github.com/daeuniverse/dae/pull/294) by (@mzz2017)
- chore: honk with sound in [#289](https://github.com/daeuniverse/dae/pull/289) by (@troubadour-hell)

#### 特性支持

- 优化: latencyString 现在显示实际延迟(+偏移) in [#307](https://github.com/daeuniverse/dae/pull/307) 由 (@luochen1990)
- 特性: 支持 ToS 路由规则 in [#292](https://github.com/daeuniverse/dae/pull/292) 由 (@mzz2017)
- 特性: 现在 dae 可以 honk honk 叫 in [#288](https://github.com/daeuniverse/dae/pull/288) 由 (@troubadour-hell)

#### 其他

- 杂项(release): 为 v0.3.0 添加变更记录入口 in [#311](https://github.com/daeuniverse/dae/pull/311) 由 (@mzz2017,@yqlbu)
- 文档: 改进关于 pppoe 和 mark 的文档 in [#305](https://github.com/daeuniverse/dae/pull/305) 由 (@mzz2017)
- 杂项: 关闭文件描述符并移除重复的错误处理 in [#303](https://github.com/daeuniverse/dae/pull/303) 由 (@douglarek)
- 文档(en): 更新 how-it-works in [#300](https://github.com/daeuniverse/dae/pull/300) 由 (@yqlbu)
- 杂项: 将 quic-go 升级到 v0.38.0 in [#297](https://github.com/daeuniverse/dae/pull/297) 由 (@mzz2017)
- 重构/修复: 匹配 DSCP 而不是 ToS in [#294](https://github.com/daeuniverse/dae/pull/294) 由 (@mzz2017)
- 杂项: 带声音 honk in [#289](https://github.com/daeuniverse/dae/pull/289) 由 (@troubadour-hell)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.4.0rc1/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.3.0...v0.4.0rc1

#### New Contributors

- @luochen1990 made their first contribution in https://github.com/daeuniverse/dae/pull/307

## v0.3.0 (Latest)

> Release date: 2023/09/03

> **Note**
> Adopt new release strategy.

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.3.0/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.4...v0.3.0

### v0.2.5rc2

> Release date: 2023/08/14

#### Bug Fix

- ci/hotfix: demise buildarg=pie in [#282](https://github.com/daeuniverse/dae/pull/282) by (@yqlbu)

#### 问题修复

- 修复: 不再使用 buildarg=pie in [#271](https://github.com/daeuniverse/dae/pull/282) by (@yqlbu)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.5rc2/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.5rc1...v0.2.5rc2

### v0.2.5rc1

> Release date: 2023/08/13

#### Features

- optimize(juicity): support Base64URLEncoding for PinnedCertchainSha256 in [#265](https://github.com/daeuniverse/dae/pull/265) by (@mzz2017)
- feat: add meek in [#258](https://github.com/daeuniverse/dae/pull/258) by (@AkinoKaede)

#### Bug Fixes

- fix: rebinding wg/tun not work in [#271](https://github.com/daeuniverse/dae/pull/271) by (@mzz2017)
- fix: caddy cannot accept connections in [#262](https://github.com/daeuniverse/dae/pull/262) by (@mzz2017)

#### Others

- ci(release): draft release v0.2.4 in [#277](https://github.com/daeuniverse/dae/pull/277) by (@yqlbu)
- ci/chore: remove the buildmode specified in CI in [#273](https://github.com/daeuniverse/dae/pull/273) by (@shenghuang147)
- chore: amd64 and arm64 use PIE build mode by default in [#272](https://github.com/daeuniverse/dae/pull/272) by (@shenghuang147)
- chore: upgrade quic-go to 0.37.4 to support go1.21 in [#270](https://github.com/daeuniverse/dae/pull/270) by (@mzz2017)
- chore(pr_template): update headers in [#269](https://github.com/daeuniverse/dae/pull/269) by (@yqlbu)
- chore/refactor: rework issue_templates in [#267](https://github.com/daeuniverse/dae/pull/267) by (@yqlbu)
- chore: add -buildmode=pie in [#266](https://github.com/daeuniverse/dae/pull/266) by (@shenghuang147)
- ci(release): draft release v0.2.4rc2 in [#260](https://github.com/daeuniverse/dae/pull/260) by (@daebot)

#### 特性支持

- 优化(juicity): 支持 PinnedCertchainSha256 的 Base64URLEncoding in [#265](https://github.com/daeuniverse/dae/pull/265) by (@mzz2017)
- 特性: 添加 meek in [#258](https://github.com/daeuniverse/dae/pull/258) by (@AkinoKaede)

#### 问题修复

- 修复: 重新绑定 wg/tun 无效的问题 in [#271](https://github.com/daeuniverse/dae/pull/271) by (@mzz2017)
- 修复: caddy 无法接受连接的问题 in [#262](https://github.com/daeuniverse/dae/pull/262) by (@mzz2017)

#### 其他变更

- 自动化(发布): 起草发布 v0.2.4 版本 in [#277](https://github.com/daeuniverse/dae/pull/277) by (@yqlbu)
- 自动化/杂项: 在 CI 中移除指定的 buildmode in [#273](https://github.com/daeuniverse/dae/pull/273) by (@shenghuang147)
- 杂项: amd64 和 arm64 默认使用 PIE 构建模式 in [#272](https://github.com/daeuniverse/dae/pull/272) by (@shenghuang147)
- 杂项: 升级 quic-go 到 0.37.4 以支持 go1.21 in [#270](https://github.com/daeuniverse/dae/pull/270) by (@mzz2017)
- 杂项(pr_template): 更新标题 in [#269](https://github.com/daeuniverse/dae/pull/269) by (@yqlbu)
- 杂项/重构: 重新设计 issue_templates in [#267](https://github.com/daeuniverse/dae/pull/267) by (@yqlbu)
- 杂项: 添加 -buildmode=pie in [#266](https://github.com/daeuniverse/dae/pull/266) by (@shenghuang147)
- 自动化(发布): 起草发布 v0.2.4rc2 版本 in [#260](https://github.com/daeuniverse/dae/pull/260) by (@daebot)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.5rc1/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.4...v0.2.5rc1

#### New Contributors

- @shenghuang147 made their first contribution in https://github.com/daeuniverse/dae/pull/266

## v0.2.4

> Release date: 2023/08/13

#### Features

- feat(juicity): support certificate pinning in [#256](https://github.com/daeuniverse/dae/pull/256) by (@mzz2017)
- optimize: force to choose one if there is only one node in the group in [#251](https://github.com/daeuniverse/dae/pull/251) by (@mzz2017)
- feat: support juicity in [#248](https://github.com/daeuniverse/dae/pull/248) by (@mzz2017)

#### Bug Fixes

- fix: bad ipversion selection caused by #251 in [#257](https://github.com/daeuniverse/dae/pull/257) by (@mzz2017)

#### Others

- ci(release): add entry for release-v0.2.3 in [#253](https://github.com/daeuniverse/dae/pull/253) by (@yqlbu)
- chore: upgrade go mod in [#249](https://github.com/daeuniverse/dae/pull/249) by (@mzz2017)
- docs: create zh routing docs in [#247](https://github.com/daeuniverse/dae/pull/247) by (@bradfordzhang)
- docs: create zh global and dns docs in [#243](https://github.com/daeuniverse/dae/pull/243) by (@troubadour-hell)
- docs: refine protocol support and alpine installation in [#241](https://github.com/daeuniverse/dae/pull/241) by (@mzz2017)
- ci(release): draft release v0.2.3rc1 in [#240](https://github.com/daeuniverse/dae/pull/240) by (@daebot)

#### 特性支持

- 特性(juicity): 支持证书固定 (Certificate Pinning) in [#256](https://github.com/daeuniverse/dae/pull/256) by (@mzz2017)
- 优化: 在组中只有一个节点时强制选择该节点 in [#251](https://github.com/daeuniverse/dae/pull/251) by (@mzz2017)
- 特性: 支持 juicity in [#248](https://github.com/daeuniverse/dae/pull/248) by (@mzz2017)

#### 问题修复

- 修复: 由 #251 导致的错误的 IP 版本选择 in [#257](https://github.com/daeuniverse/dae/pull/257) by (@mzz2017)

#### 其他变更

- 自动化(release): 添加发布版本 v0.2.3 的条目 in [#253](https://github.com/daeuniverse/dae/pull/253) by (@yqlbu)
- 杂项: 升级 Go 模块 in [#249](https://github.com/daeuniverse/dae/pull/249) by (@mzz2017)
- 文档: 创建中文路由文档 in [#247](https://github.com/daeuniverse/dae/pull/247) by (@bradfordzhang)
- 文档: 创建中文全局和 DNS 文档 in [#243](https://github.com/daeuniverse/dae/pull/243) by (@troubadour-hell)
- 文档: 完善协议支持和 Alpine 安装 in [#241](https://github.com/daeuniverse/dae/pull/241) by (@mzz2017)
- 自动化(release): 撰写发布版本 v0.2.3rc1 in [#240](https://github.com/daeuniverse/dae/pull/240) by (@daebot)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.4/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.3...v0.2.4

#### New Contributors

- @bradfordzhang made their first contribution in #247

## v0.2.3

> Release date: 2023/08/02

#### Features

- feat/refactor: support the node-level proxy chain in [#235](https://github.com/daeuniverse/dae/pull/235) by (@mzz2017)
- optimize: pull subscriptions using custom UA in [#233](https://github.com/daeuniverse/dae/pull/233) by (@mzz2017)
- optimize(vmess): auto choose cipher instead of aes-128-gcm in [#232](https://github.com/daeuniverse/dae/pull/232) by (@mzz2017)
- feat(vmess/vless): support network h2 in [#229](https://github.com/daeuniverse/dae/pull/229) by (@mzz2017)

#### Bug Fixes

- hotfix: fix subscription pulling panic caused by #233 in [#237](https://github.com/daeuniverse/dae/pull/237) by (@mzz2017)

#### Others

- chore: update codeowners in [#234](https://github.com/daeuniverse/dae/pull/234) by (@yqlbu)
- ci(seed-build): checkout codebase based on ref in [#230](https://github.com/daeuniverse/dae/pull/230) by (@yqlbu)
- ci(release): draft release v0.2.2rc1 in [#228](https://github.com/daeuniverse/dae/pull/228) by (@daebot)
- ci(pr-build): add pr.ready_for_review trigger in [#226](https://github.com/daeuniverse/dae/pull/226) by (@yqlbu)

#### 特性支持

- 特性/重构: 支持节点级代理链 in [#235](https://github.com/daeuniverse/dae/pull/235) 由 (@mzz2017) 提交
- 优化: 使用自定义 UA 拉取订阅 in [#233](https://github.com/daeuniverse/dae/pull/233) 由 (@mzz2017) 提交
- 优化(vmess): 自动选择加密方式，而不是 aes-128-gcm in [#232](https://github.com/daeuniverse/dae/pull/232) 由 (@mzz2017) 提交
- 特性(vmess/vless): 支持网络类型 h2 in [#229](https://github.com/daeuniverse/dae/pull/229) 由 (@mzz2017) 提交

#### 问题修复

- 紧急修复: 修复由 #233 引起的订阅拉取问题 in [#237](https://github.com/daeuniverse/dae/pull/237) 由 (@mzz2017) 提交

#### 其他变更

- 杂项: 更新 codeowners in [#234](https://github.com/daeuniverse/dae/pull/234) 由 (@yqlbu) 提交
- 自动化(seed-build): 基于 ref 检出代码库 in [#230](https://github.com/daeuniverse/dae/pull/230) 由 (@yqlbu) 提交
- 自动化(release): 起草版本 v0.2.2rc1 in [#228](https://github.com/daeuniverse/dae/pull/228) 由 (@daebot) 提交
- 自动化(pr-build): 添加 pr.ready_for_review 触发器 in [#226](https://github.com/daeuniverse/dae/pull/226) 由 (@yqlbu) 提交

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.3/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.2...v0.2.3

## v0.2.2

> Release date: 2023/07/17

#### Features

- feat/chore: add log file/refine code/add tip for no-load in [#219](https://github.com/daeuniverse/dae/pull/219) by (@mzz2017)
- feat: latency-based failover [#119](https://github.com/daeuniverse/dae/pull/119) by (@mzz2017)

#### Bug Fixes

- fix(ebpf): udp problem caused by #221 by accident in [#225](https://github.com/daeuniverse/dae/pull/225) by (@mzz2017)
- fix: support to bind dae to wg lan (and other tun) in [#221](https://github.com/daeuniverse/dae/pull/221) by (@mzz2017)
- fix: No AddrPort presented in [#207](https://github.com/daeuniverse/dae/pull/207) by (@mzz2017)
- fix/optimize/refactor(udp): fix potential stuck UDP and optimize reroute logic in [#204](https://github.com/daeuniverse/dae/pull/204) by (@mzz2017)
- fix: truncated dns resp in [#203](https://github.com/daeuniverse/dae/pull/203) by (@mzz2017)
- fix(dns): should reject with nx instead of 0.0.0.0 [#141](https://github.com/daeuniverse/dae/pull/141) by (@mzz2017)

#### Others

- ci/hotfix(build): inherit secret in [#223](https://github.com/daeuniverse/dae/pull/223) by (@yqlbu)
- ci/hotfix(seed-build): add condition to run report-result in [#222](https://github.com/daeuniverse/dae/pull/222) by (@yqlbu)
- ci/fix(daily-build): add missing ref input in [#220](https://github.com/daeuniverse/dae/pull/220) by (@yqlbu)
- ci/feat(build,pr-build,seed-build): integrate check runs to report build status in [#218](https://github.com/daeuniverse/dae/pull/218) by (@yqlbu)
- ci/fix(build): add ref input (required) in [#216](https://github.com/daeuniverse/dae/pull/216) by (@yqlbu)
- ci(pr-build): don't trigger workflow for draft PRs in [#215](https://github.com/daeuniverse/dae/pull/215) by (@yqlbu)
- ci(pr-build): fix default branch for seed workflow in [#214](https://github.com/daeuniverse/dae/pull/214) by (@yqlbu)
- ci(build,pr-build): watch changes made to seed-build.yml in [#211](https://github.com/daeuniverse/dae/pull/211) by (@yqlbu)
- ci/fix(seed-build): catch non-pr condition in [#210](https://github.com/daeuniverse/dae/pull/210) by (@yqlbu)
- ci(pr-build): use pr.head.sha as default ref in [#209](https://github.com/daeuniverse/dae/pull/209) by (@yqlbu)
- ci(build,daily-build.yml): adhere to naming convention in [#208](https://github.com/daeuniverse/dae/pull/208) by (@yqlbu)
- docs(run-on-alpine.md)Add Alpine guide in [#206](https://github.com/daeuniverse/dae/pull/206) by (@MarksonHon)
- docs: demise dae.v2raya.org in [#205](https://github.com/daeuniverse/dae/pull/205) by (@yqlbu)
- chore(pr_template): add test result section in [#202](https://github.com/daeuniverse/dae/pull/202) by (@yqlbu)
- ci(generate-changelogs): set dry_run as true in [#201](https://github.com/daeuniverse/dae/pull/201) by (@yqlbu)
- ci(daily-build): update cron schedule in [#198](https://github.com/daeuniverse/dae/pull/198) by (@yqlbu)
- ci(release): draft release v0.2.1rc1 in [#197](https://github.com/daeuniverse/dae/pull/197) by (@daebot)

#### 特性支持

- 特性/杂项: 添加写入到 log 文件，添加更友好的空载提示 in [#219](https://github.com/daeuniverse/dae/pull/219) by (@mzz2017)
- 特性: 基于时延的故障转移 [#119](https://github.com/daeuniverse/dae/pull/119) by (@mzz2017)

#### 问题修复

- 修复(ebpf): 由 #221 导致的 udp 问题 in [#225](https://github.com/daeuniverse/dae/pull/225) by (@mzz2017)
- 修复: 支持绑定 wg lan (以及其他 tun) in [#221](https://github.com/daeuniverse/dae/pull/221) by (@mzz2017)
- 修复: 报错 No AddrPort presented 的问题 in [#207](https://github.com/daeuniverse/dae/pull/207) by (@mzz2017)
- 修复/优化/重构(udp): 修复潜在的 UDP 阻塞并优化重路由逻辑 in [#204](https://github.com/daeuniverse/dae/pull/204) by (@mzz2017)
- 修复: dns 回包过大被截断的问题 in [#203](https://github.com/daeuniverse/dae/pull/203) by (@mzz2017)
- 修复(dns): 应当使用 NX 而不是 0.0.0.0 来进行 reject [#141](https://github.com/daeuniverse/dae/pull/141) by (@mzz2017)

#### 其他变更

- 自动化/修复(build): 继承 secret 问题 in [#223](https://github.com/daeuniverse/dae/pull/223) by (@yqlbu)
- 自动化/修复(seed-build): 添加运行 report-result 的条件 in [#222](https://github.com/daeuniverse/dae/pull/222) by (@yqlbu)
- 自动化/修复(daily-build): 添加丢失的 ref input in [#220](https://github.com/daeuniverse/dae/pull/220) by (@yqlbu)
- 自动化/特性(build,pr-build,seed-build): 持续检查运行来报告构建状态 in [#218](https://github.com/daeuniverse/dae/pull/218) by (@yqlbu)
- 自动化/修复(build): 添加必须的 ref input in [#216](https://github.com/daeuniverse/dae/pull/216) by (@yqlbu)
- 自动化(pr-build): 不要为 draft PRs 触发 actions in [#215](https://github.com/daeuniverse/dae/pull/215) by (@yqlbu)
- 自动化(pr-build): 修复 seed 工作流的默认分支 in [#214](https://github.com/daeuniverse/dae/pull/214) by (@yqlbu)
- 自动化(build,pr-build): 观察并响应 seed-build.yml 的变更 in [#211](https://github.com/daeuniverse/dae/pull/211) by (@yqlbu)
- 自动化/修复(seed-build): 捕获 non-pr 条件 in [#210](https://github.com/daeuniverse/dae/pull/210) by (@yqlbu)
- 自动化(pr-build): 使用 pr.head.sha 作为默认 ref in [#209](https://github.com/daeuniverse/dae/pull/209) by (@yqlbu)
- 自动化(build,daily-build.yml): 遵守命名约定 in [#208](https://github.com/daeuniverse/dae/pull/208) by (@yqlbu)
- 文档(run-on-alpine.md): 添加 Alpine 安装指南 in [#206](https://github.com/daeuniverse/dae/pull/206) by (@MarksonHon)
- 文档: 暂时从 README 移除 dae.v2raya.org in [#205](https://github.com/daeuniverse/dae/pull/205) by (@yqlbu)
- 杂项(pr_template): 添加测试结果一节 in [#202](https://github.com/daeuniverse/dae/pull/202) by (@yqlbu)
- 自动化(generate-changelogs): 设置 dry_run 为 true in [#201](https://github.com/daeuniverse/dae/pull/201) by (@yqlbu)
- 自动化(daily-build): 更新自动执行时间 in [#198](https://github.com/daeuniverse/dae/pull/198) by (@yqlbu)

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.2/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.1...v0.2.2

## v0.2.1

> Release date: 2023/07/17

#### Features

- feat: support unknown qtype and upgrade go mod in [#180](https://github.com/daeuniverse/dae/pull/180) by (@mzz2017)
- feat: support tuic v5 in [#176](https://github.com/daeuniverse/dae/pull/176) by (@mzz2017)
- optimize(dns): cache all qtype (not only a/aaaa) in [#167](https://github.com/daeuniverse/dae/pull/167) by (@mzz2017)
- feat: support to bind to lan lazily and re-bind to lan in [#166](https://github.com/daeuniverse/dae/pull/166) by (@mzz2017)

#### Bug Fixes

- fix(wss): allow_insecure and sni not work in [#165](https://github.com/daeuniverse/dae/pull/165) by (@mzz2017)

#### Others

- ci: add modularity support for build, daily-build, and pr-build in [#190](https://github.com/daeuniverse/dae/pull/190) by (@yqlbu)
- ci: add daily-build workflow in [#189](https://github.com/daeuniverse/dae/pull/189) by (@yqlbu)
- ci: update workflow naming standards in [#186](https://github.com/daeuniverse/dae/pull/186) by (@yqlbu)
- docs(readme/badges): make release-badge updated on the fly in [#185](https://github.com/daeuniverse/dae/pull/185) by (@yqlbu)
- ci(trigger): separate pr_build from build in [#183](https://github.com/daeuniverse/dae/pull/183) by (@yqlbu)
- chore: suppress LinkSubscribe error in [#181](https://github.com/daeuniverse/dae/pull/181) by (@mzz2017)
- refactor(/docs): rework documentation structure layout in [#179](https://github.com/daeuniverse/dae/pull/179) by (@yqlbu @earrmouth)
- refactor(dns): replace dnsmessage with miekg/dns in [#188](https://github.com/daeuniverse/dae/pull/188) by (@mzz2017)

#### 特性支持

- 特性(dns): 支持未知的 qtype，允许使用数字 in [#180](https://github.com/daeuniverse/dae/pull/180) by (@mzz2017)
- 特性: 支持新协议 tuic v5 in [#176](https://github.com/daeuniverse/dae/pull/176) by (@mzz2017)
- 优化(dns): 缓存所有 qtype 类型 (不只是 a/aaaa) in [#167](https://github.com/daeuniverse/dae/pull/167) by (@mzz2017)
- 特性: 支持到 lan 接口的懒绑定和重新绑定 in [#166](https://github.com/daeuniverse/dae/pull/166) by (@mzz2017)

#### 问题修复

- 修复(wss): `allow_insecure` 和 `sni` 无法正常工作的问题 in [#165](https://github.com/daeuniverse/dae/pull/165) by (@mzz2017)

#### 其他变更

- 自动化: 为 build, daily-build, and pr-build 添加模块化工作流支持 in [#190](https://github.com/daeuniverse/dae/pull/190) by (@yqlbu)
- 自动化: 添加 daily-build 工作流 in [#189](https://github.com/daeuniverse/dae/pull/189) by (@yqlbu)
- 自动化: 更新 workflow 命名标准 in [#186](https://github.com/daeuniverse/dae/pull/186) by (@yqlbu)
- 文档(readme/badges): 更新 release-badge on the fly in [#185](https://github.com/daeuniverse/dae/pull/185) by (@yqlbu)
- 自动化(trigger): 将 pr_build 从 build 分离出来 in [#183](https://github.com/daeuniverse/dae/pull/183) by (@yqlbu)
- 杂项: 降低 LinkSubscribe 报错级别 in [#181](https://github.com/daeuniverse/dae/pull/181) by (@mzz2017)
- 重构/文档: 重构文档结构布局 in [#179](https://github.com/daeuniverse/dae/pull/179) by (@yqlbu @earrmouth)
- 重构(dns): 使用 miekg/dns 替换 dnsmessage in [#188](https://github.com/daeuniverse/dae/pull/188) by (@mzz2017)

#### New Contributors

- @earrmouth made their first contribution in #179

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.1/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.2.0...v0.2.1

## v0.2.0

> Release date: 2023/07/02

#### Features

- optimize(routing): fix slow domain++ ip routing in [#133](https://github.com/daeuniverse/dae/pull/133) by (@mzz2017)
- feat: support iptables tproxy by @mzz2017 in https://github.com/daeuniverse/dae/pull/80
- feat: add uTLS support by @AkinoKaede in https://github.com/daeuniverse/dae/pull/94
- feat: support geosite attr by @mzz2017 in https://github.com/daeuniverse/dae/pull/98
- feat(dns): support fixed domain ttl by @mzz2017 in https://github.com/daeuniverse/dae/pull/100

#### Bug Fixes

- fix: samba not work in [#173](https://github.com/daeuniverse/dae/pull/173) by (@mzz2017)
- fix: should allow fallbacking ip version if dialing domain in [#164](https://github.com/daeuniverse/dae/pull/164) by (@mzz2017)
- fix: bad connectivity check of dns(tcp) caused by #80 in [#155](https://github.com/daeuniverse/dae/pull/155) by (@mzz2017)
- fix/chore(grpc): allow insecure caused no connection in [#151](https://github.com/daeuniverse/dae/pull/151) by (@mzz2017)
- fix: new control plane should reset grpc conn pool cache in [#150](https://github.com/daeuniverse/dae/pull/150) by (@mzz2017)
- fix(group): policy 'fixed' parsing in [#149](https://github.com/daeuniverse/dae/pull/149) by (@mzz2017)
- fix(socks5): udp problem in [#148](https://github.com/daeuniverse/dae/pull/148) by (@mzz2017)
- fix: should gracefully exit if failed to listen when reloading in [#138](https://github.com/daeuniverse/dae/pull/138) by (@mzz2017)
- fix: change default `tcp_check_http_method` from CONNECT to `HEAD` in [#137](https://github.com/daeuniverse/dae/pull/137) by (@mzz2017)
- fix: failed to sniff tls1.2 traffic in some cases in [#135](https://github.com/daeuniverse/dae/pull/135) by (@mzz2017)
- fix: enlarge kernel geoip size limit in [#130](https://github.com/daeuniverse/dae/pull/130) by (@mzz2017)
- fix(config): problem that always append values to default list in [#128](https://github.com/daeuniverse/dae/pull/128) by (@mzz2017)
- fix/ci: fix argument list too long due to packed and use clang-15 in [#162](https://github.com/daeuniverse/dae/pull/162) by (@mzz2017)
- fix(dns): mismatched qname matching rules by @mzz2017 in https://github.com/daeuniverse/dae/pull/99
- fix: rand seed for network check by @mzz2017 in https://github.com/daeuniverse/dae/pull/106
- fix(config_parser): potential panic due to out of index by @mzz2017 in https://github.com/daeuniverse/dae/pull/108
- fix(trojan): potential panic due to incorrect n returned by ReadFrom by @mzz2017 in https://github.com/daeuniverse/dae/pull/109

#### Others

- chore: expose the routable dialer for dae-wing in [#172](https://github.com/daeuniverse/dae/pull/172) by (@mzz2017)
- ci(generate-changelogs): add control on whether to write to issue page in [#170](https://github.com/daeuniverse/dae/pull/170) by (@yqlbu)
- chore(geodata): change back to v2fly geodata in [#168](https://github.com/daeuniverse/dae/pull/168) by (@mzz2017)
- ci: add generate-changelogs workflow in [#159](https://github.com/daeuniverse/dae/pull/159) by (@yqlbu)
- chore/docs: support to unroll route loop and update troubleshooting.md in [#158](https://github.com/daeuniverse/dae/pull/158) by (@mzz2017)
- ci: separate release build from main build in [#157](https://github.com/daeuniverse/dae/pull/157) by (@yqlbu)
- docs(getting-started): add ref to run-as-daemon in [#147](https://github.com/daeuniverse/dae/pull/147) by (@yqlbu)
- chore(pr_template): correct a typo in [#146](https://github.com/daeuniverse/dae/pull/146) by (@yqlbu)
- chore: allow to modify app name and assets dir name in [#144](https://github.com/daeuniverse/dae/pull/144) by (@mzz2017)
- chore(Dockerfile): change geodata upstream in [#140](https://github.com/daeuniverse/dae/pull/140) by (@mzz2017)
- chore: fix incorrect number of routing rule stringer in [#131](https://github.com/daeuniverse/dae/pull/131) by (@mzz2017)
- chore: fix make with /bin/sh in [#129](https://github.com/daeuniverse/dae/pull/129) by (@mzz2017)
- chore(Makefile): support submodules in [#126](https://github.com/daeuniverse/dae/pull/126) by (@mzz2017)
- chore(changelogs-v0.2.0rc1): apply minor fix in [#125](https://github.com/daeuniverse/dae/pull/125) by (@yqlbu)
- chore(config): support IgnoreZero option for config.Marhsaller in [#153](https://github.com/daeuniverse/dae/pull/153) by (@mzz2017)
- ci: add check-docs workflow by @yqlbu in https://github.com/daeuniverse/dae/pull/93
- refactor: move insert.sh to ./hack/test by @yqlbu in https://github.com/daeuniverse/dae/pull/95
- ci(hack): add config-doc-generator by @yqlbu in https://github.com/daeuniverse/dae/pull/101
- fix(test): domain_matcher/benchmark_test.go @mzz2017 in https://github.com/daeuniverse/dae/pull/107
- ci: docs synchronization by @yqlbu in https://github.com/daeuniverse/dae/pull/103
- docs(routing.md): revise fwmark section by @mzz2017 in https://github.com/daeuniverse/dae/pull/113

#### 特性支持

- 优化(routing): 修复 domain++ 的 ip 规则匹配缓慢的问题 in [#133](https://github.com/daeuniverse/dae/pull/133) by (@mzz2017)
- 特性: 支持 iptables/nftables 的 mangle 表 tproxy by @mzz2017 in https://github.com/daeuniverse/dae/pull/80
- 特性: 支持 uTLS by @AkinoKaede in https://github.com/daeuniverse/dae/pull/94
- 特性: 支持在 geosite 使用属性标签 `@` 符号 by @mzz2017 in https://github.com/daeuniverse/dae/pull/98
- 特性(dns): 支持为特定域名设定固定的 ttl，这对 DDNS 场景较为有用 by @mzz2017 in https://github.com/daeuniverse/dae/pull/100

#### 问题修复

- 修复: samba 无法正常工作的问题 in [#173](https://github.com/daeuniverse/dae/pull/173) by (@mzz2017)
- 修复: 当 dial_mode 为 domain 族时，现在允许从 ipv6 回落到 ipv4，以及从 ipv4 回落到 ipv6 in [#164](https://github.com/daeuniverse/dae/pull/164) by (@mzz2017)
- 修复: 由 #80 导致的无法正常工作的 TCP DNS 检查 in [#155](https://github.com/daeuniverse/dae/pull/155) by (@mzz2017)
- 修复(grpc): allow insecure 会导致的无法连接 in [#151](https://github.com/daeuniverse/dae/pull/151) by (@mzz2017)
- 修复: grpc 连接池缓存应当在 reload 时候重置 in [#150](https://github.com/daeuniverse/dae/pull/150) by (@mzz2017)
- 修复(group): 策略 'fixed' 的解析问题 in [#149](https://github.com/daeuniverse/dae/pull/149) by (@mzz2017)
- 修复(socks5): udp 无法正常工作的问题 in [#148](https://github.com/daeuniverse/dae/pull/148) by (@mzz2017)
- 修复: 重载时无法监听 tproxy 端口，应当做好清理工作后退出 in [#138](https://github.com/daeuniverse/dae/pull/138) by (@mzz2017)
- 修复: 将 `tcp_check_http_method` 的默认值从 `CONNECT` 改为 `HEAD` in [#137](https://github.com/daeuniverse/dae/pull/137) by (@mzz2017)
- 修复: 一些情况下无法嗅探 tls1.2 流量的问题 in [#135](https://github.com/daeuniverse/dae/pull/135) by (@mzz2017)
- 修复: 扩大内核程序中可放置的 geoip 大小限制 in [#130](https://github.com/daeuniverse/dae/pull/130) by (@mzz2017)
- 修复(config): 总是将用户设置的值添加到默认列表的后面的问题，例如 tcp_check_url 列表 in [#128](https://github.com/daeuniverse/dae/pull/128) by (@mzz2017)
- 修复/自动化: 修复 packed 导致的 argument list too long 并使用 clang-15 构建 in [#162](https://github.com/daeuniverse/dae/pull/162) by (@mzz2017)
- 修复(dns): 修复 DNS 中 qname 匹配规则失效的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/99
- 修复: 修复启动时网络检查链接列表的随机排布问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/106
- 修复(config_parser): 修复配置文件格式错误时潜在的崩溃问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/108
- 修复(trojan): 修复 trojan 崩溃问题，该问题由 ReadFrom 返回的 n 可能不正确导致 by @mzz2017 in https://github.com/daeuniverse/dae/pull/109

#### 其他变更

- 杂项: 提供代理 dialer 给 dae-wing，以允许在拉取订阅时经过代理 in [#172](https://github.com/daeuniverse/dae/pull/172) by (@mzz2017)
- 自动化(generate-changelogs): 添加发版时是否写 issue page 的控制项 in [#170](https://github.com/daeuniverse/dae/pull/170) by (@yqlbu)
- 杂项(geodata): 换回 v2fly 源的 geodata in [#168](https://github.com/daeuniverse/dae/pull/168) by (@mzz2017)
- 自动化: 添加生成 changelogs 工作流 in [#159](https://github.com/daeuniverse/dae/pull/159) by (@yqlbu)
- 杂项/文档: 支持编译时 unroll route loop，更新 troubleshooting.md in [#158](https://github.com/daeuniverse/dae/pull/158) by (@mzz2017)
- 自动化: 从 main build 中分离 release build in [#157](https://github.com/daeuniverse/dae/pull/157) by (@yqlbu)
- 文档(getting-started): 添加到 run-as-daemon 的引用 in [#147](https://github.com/daeuniverse/dae/pull/147) by (@yqlbu)
- 杂项(pr_template): 修正错别字 in [#146](https://github.com/daeuniverse/dae/pull/146) by (@yqlbu)
- 杂项: 允许修改 app name 和 assets dir name in [#144](https://github.com/daeuniverse/dae/pull/144) by (@mzz2017)
- 杂项(Dockerfile): 更改 geodata 上游 in [#140](https://github.com/daeuniverse/dae/pull/140) by (@mzz2017)
- 杂项: 修复不正确的 routing rule 条目数的打印 in [#131](https://github.com/daeuniverse/dae/pull/131) by (@mzz2017)
- 杂项: 修复使用 /bin/sh 会导致 make 失败的问题 in [#129](https://github.com/daeuniverse/dae/pull/129) by (@mzz2017)
- 杂项(Makefile): 支持 submodules in [#126](https://github.com/daeuniverse/dae/pull/126) by (@mzz2017)
- 杂项(changelogs-v0.2.0rc1): 修复格式问题 in [#125](https://github.com/daeuniverse/dae/pull/125) by (@yqlbu)
- 杂项(config): 为 config.Marhsaller 添加 IgnoreZero 选项支持 in [#153](https://github.com/daeuniverse/dae/pull/153) by (@mzz2017)
- 自动化: 添加文档格式检查工作流 by @yqlbu in https://github.com/daeuniverse/dae/pull/93
- 重构: 将 insert.sh 移动至 ./hack/test by @yqlbu in https://github.com/daeuniverse/dae/pull/95
- 自动化(hack): 添加 config-doc-generator by @yqlbu in https://github.com/daeuniverse/dae/pull/101
- 修复(test): 修复 domain_matcher/benchmark_test.go by @mzz2017 in https://github.com/daeuniverse/dae/pull/107
- 自动化: 添加文档自动同步至 dae-docs 项目 by @yqlbu in https://github.com/daeuniverse/dae/pull/103
- 文档(routing.md): 修订 fwmark 一节的文档 by @mzz2017 in https://github.com/daeuniverse/dae/pull/113

##### New Contributors

- @AkinoKaede made their first contribution in https://github.com/daeuniverse/dae/pull/94

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.2.0/example.dae

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.10.p1...v0.2.0

## v0.1.10.p1

> Release date: 2023/06/05

##### 功能变更

- fix(trojan): 修复因无效的 trojan 协议控制字段而导致的程序崩溃 by @mzz2017 in https://github.com/daeuniverse/dae/pull/120

##### Changes

- fix(dns): potential panic due to invalid packet control data by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/120

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.9...v0.1.10.p1

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.1.10.p1/example.dae

## v0.1.10

> Release date: 2023/06/04

##### 功能变更

- feat: 支持 `tcp_check_http_method` by @mzz2017 in https://github.com/daeuniverse/dae/pull/77
- patch: 现在会优先在配置文件同目录搜索 geodata by @mzz2017 in https://github.com/daeuniverse/dae/pull/84
- fix(dns): 修复 0.1.8 版本中 PR #63 导致的 DNS 缓存不会过期的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/87
- patch(geodata): 修复由 #84 导致的错误的 geodata 搜索路径 `/etc/dae/dae` by @mzz2017 in https://github.com/daeuniverse/dae/pull/90

##### 其他变更

- chore(Makefile): 添加 export GOOS=linux 以修复在 macos 上的构建 by @mzz2017 in https://github.com/daeuniverse/dae/pull/78
- chore: 添加 editorconfig 文件以美化 github 上对 go 文件的展示 by @yqlbu in https://github.com/daeuniverse/dae/pull/85
- chore: 添加 PR 模板 by @yqlbu in https://github.com/daeuniverse/dae/pull/86

##### Changes

- feat: support `tcp_check_http_method` by @mzz2017 in https://github.com/daeuniverse/dae/pull/77
- patch: search geodata at same dir with config first by @mzz2017 in https://github.com/daeuniverse/dae/pull/84
- fix(dns): cache would never expire caused by #63 by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/87
- patch(geodata): fix incorrect geodata search path `/etc/dae/dae` caused by #84 by @mzz2017 in https://github.com/daeuniverse/dae/pull/90

##### Other Changes

- chore(Makefile): add export GOOS=linux to build on macos by @mzz2017 in https://github.com/daeuniverse/dae/pull/78
- chore: add editorconfig by @yqlbu in https://github.com/daeuniverse/dae/pull/85
- chore: add pull_request_template by @yqlbu in https://github.com/daeuniverse/dae/pull/86

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.9...v0.1.10

**Example Config**: https://github.com/daeuniverse/dae/blob/v0.1.10/example.dae

## v0.1.9-patch.1

> Release date: 2023/05/14

##### 功能变更

- 修复(dns): 修复 0.1.8 版本中 PR #63 导致的 DNS 缓存不会过期的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/87

##### Changes

- fix(dns): cache would never expire caused by #63 by accident by @mzz2017 in https://github.com/daeuniverse/dae/pull/87

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.9...v0.1.9patch1

## v0.1.9

> Release date: 2023/05/09

##### 功能变更

- 修复 trojan UDP 不通的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/71
- 修复 `curl http://[ipv6]:port` 不通的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/70

##### 其他变更

- 修复 docker 镜像构建的 CI 会在特定名称的分支提交时意外地运行的问题 by @mzz2017 in https://github.com/daeuniverse/dae/pull/72

##### Changes

- fix(trojan): udp problem by @mzz2017 in https://github.com/daeuniverse/dae/pull/71
- fix(sniffing): fail to `curl http://[ipv6]:port` by @mzz2017 in https://github.com/daeuniverse/dae/pull/70

##### Other Changes

- fix(ci): PR runs docker action in some cases by @mzz2017 in https://github.com/daeuniverse/dae/pull/72

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.8...v0.1.9

## v0.1.8

> Release date: 2023/04/30

##### 功能变更

- optimize: DNS 缓存空解析和非 A/AAAA 查询，以及 reject 使用 0.0.0.0 和 :: by @mzz2017 in https://github.com/daeuniverse/dae/pull/63
- feat: 支持为 `tcp_check_url` 和 `udp_check_dns` 设定固定 IP 以防止 DNS 污染对 ipv4/ipv6 的支持带来影响 by @mzz2017 in https://github.com/daeuniverse/dae/commit/9493b9a0aa82573fed934bf62cc836f0fe148607

##### 其他变更

- chore: 增加 changelogs by @yqlbu in https://github.com/daeuniverse/dae/pull/55
- chore: 增加 pre-commit 钩子来格式化代码 by @yqlbu in https://github.com/daeuniverse/dae/pull/59
- style: 格式化 golang 代码风格 by @czybjtu in https://github.com/daeuniverse/dae/pull/58
- chore: 增加 issue 模板 by @yqlbu in https://github.com/daeuniverse/dae/pull/62
- chore(codeowner): 更新 ownership by @yqlbu in https://github.com/daeuniverse/dae/pull/64

##### New Contributors

- @czybjtu made their first contribution in https://github.com/daeuniverse/dae/pull/58

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.7...v0.1.8

## v0.1.7

> Release date: 2023/04/16

##### 特性

支持 `global.sniffing_timeout` 来设定嗅探的超时时间，调大这个值对于时延较高的局域网来说较为有用。

##### 修复

1. 修复无法解析小火箭 shadowrocket 的 vmess+ws+tls 分享链接的问题。
2. 修复域名嗅探失败的问题。

##### PR

- chore: fix doamin regex example by @troubadour-hell in https://github.com/daeuniverse/dae/pull/53
- doc: add badges and contribution guide by @yqlbu in https://github.com/daeuniverse/dae/pull/54

##### New Contributors

- @troubadour-hell made their first contribution in https://github.com/daeuniverse/dae/pull/53

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.6...v0.1.7

## v0.1.6

> Release date: 2023/04/09

##### 特性

- 支持在 dns 的 request 路由中使用 reject 出站。
- 支持在 routing 中使用 `must_组名` 的出站，该规则将强制作用于 DNS 请求，直接通过特定组发出，而绕过 dns 模块，提供给有特殊用途的用户使用。
- 支持在 routing 中使用 `must_rules` 的出站，命中该出站的 DNS 请求将绕过 dns 模块，直接进行路由并发出，提供给有特殊用途的用户使用。
- 支持 v2rayN 格式的 vmess 分享格式中的不标准 bool 值解析。
- 支持在 dns 中使用 `ipversion_prefer`，设定当域名是双栈时，只返回 ipv4 还是只返回 ipv6。

##### 修复

- 修复在 dns 的 response 路由中对无序 ip 序列的支持问题。
- 修复 trojan 可能的 panic 问题。
- dns 缓存丢失且 dial_mode 为 domain 时将尝试重路由，以缓解 dns 缓存丢失时无法使用 domain 进行路由的问题。
- 修复部分游戏无法进入的问题，该问题是由于 tcp 建立连接时，dae 总是等待客户端发包，但一些游戏场景中，首包是由服务端 push 的，因此陷入无限等待。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.5...v0.1.6

## v0.1.5

> Release date: 2023/03/29

##### 更新内容

- 修复 wan_interface 填入 auto 时可能出现的无法启动的问题。
- 修复 https 协议（naiveproxy）的支持问题，新增对 h2 的长连接和多路复用。
- 移除 DNS 抢答检测器，因为它不总是在所有地区都有效，而且在失效时会减慢查询速度。
- 文档（example.dae）：增加通过节点标签精确筛选节点的示例 @yqlbu in https://github.com/daeuniverse/dae/pull/44
- 文档（example.dae）：新增一个 tcp 健康检测 url by @yqlbu in https://github.com/daeuniverse/dae/pull/46

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.4...v0.1.5

## v0.1.4

> Release date: 2023/03/25

##### 更新内容

- domain routing 给出不标准的域名时将忽略而不是报错。
- 将 config 所在目录加入到 geodata 的搜索路径。
- 优化 udp 的内存占用。
- 忽略 sighup 而使用 sigusr2 作为 suspend 的信号。
- 支持自动配置 sysctl 参数。
- 文档: 更新 debian-kernel-upgrade by @yqlbu in https://github.com/daeuniverse/dae/pull/39

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.3...v0.1.4

## v0.1.3

> Release date: 2023/03/24

##### 用户相关

- 新增 amd64_v2_sse 和 amd64_v3_avx 的可执行文件构建，使用更高的版本理论上可提高一定性能（这次 Release 的 CI 失败了，等下次吧） by @MarksonHon in https://github.com/daeuniverse/dae/pull/38
- 支持自动侦测 WAN 接口，在 wan_interface 填入 auto 即可。
- 修复热重载失败时的不正确的回滚行为，以及在一定条件下更改 group 配置时可能无法连接新组的问题。
- 修复在有 MAC 地址路由的情况下 bind to WAN 将导致无网络的问题。
- 修改启动时网络联通性检查使用的链接 https://github.com/daeuniverse/dae/commit/c2e02482d0588823d2a3d9cae6998b9a7a5a1fae 。
- 修复在一定条件下可能的针对 DNS upstream 的域名分流失败的问题。

##### 开发者相关

- 打包了包括 go vendor 和 git submodules 在内的源码并随 releases 发布。
- 增加了 export 命令的描述。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.2...v0.1.3

## v0.1.2

> Release date: 2023/03/22

1. 优化热重载时的 DNS 缓存行为，解决热重载时 outbound out of range 的问题。
2. 增加高通的 generate_204 作为网络联通性检查的链接，以解决部分用户无法访问`www.msftconnecttest.com`的问题。
3. 支持龙芯 loong64 架构。
4. 修复大并发下可能的崩溃问题。

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.1...v0.1.2

## v0.1.1

> Release date: 2023/03/16

##### What's Changed

- feat: shorten docker command arguments by leveraging CMD by @kunish in https://github.com/daeuniverse/dae/pull/35

##### New Contributors

- @kunish made their first contribution in https://github.com/daeuniverse/dae/pull/35

**Full Changelog**: https://github.com/daeuniverse/dae/compare/v0.1.0...v0.1.1

## v0.1.0

> Release date: 2023/03/14

Goose out of shell.
