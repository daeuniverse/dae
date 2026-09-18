# 贡献指南

如果你想为项目作出贡献、帮助改进项目，欢迎参与。参与贡献也是了解 GitHub 协作开发、新技术及其生态系统的好方法。你还可以学习如何提交有建设性、能提供帮助的 bug 报告和功能请求，以及其中最可贵的贡献：高质量、整洁的 Pull Request。

## bug 报告和功能请求

如果发现了 bug 或想请求新功能，请先搜索是否已有类似的 issue。如果没有，请在本仓库中创建 [issue](https://github.com/daeuniverse/dae/issues/new)。

## 代码

如果想修复 bug 或实现功能，请 fork 本仓库并创建 Pull Request。

在创建 Pull Request 前，如果对需求或实现有疑问，建议先创建 issue 进行讨论。这样可以确认维护者同意改动的内容和方式，也有望让后续合并更快。

只有所有状态检查都通过后，Pull Request 才能合并。

## pre-commit 钩子

本仓库使用 [pre-commit 钩子](https://github.com/pre-commit/pre-commit-hooks)，在提交写入本地 Git 历史之前执行 lint 检查。按以下步骤设置 pre-commit：

```bash
# install pre-commit
pip3 install pre-commit
# install pre-commit hooks
pre-commit install
```

## 如何创建整洁的 Pull Request

- 在 GitHub 上创建项目的个人 fork。
- 将 fork 克隆到本地机器。你在 GitHub 上的远程仓库名为 `origin`。
- 将原始仓库添加为名为 `upstream` 的远程仓库。
- 如果 fork 创建已有一段时间，请务必将上游改动拉取到本地仓库。
- 从 `main` 创建一个新分支，用于本次开发。
- 实现或修复功能，并为代码添加注释。
- 遵循项目的代码风格，包括缩进。
- 如果项目有测试，请执行测试。常规单元测试使用 `go test -tags dae_stub_ebpf ./...`，eBPF 测试使用 `make ebpf-test`。
- 按需编写或调整测试。
- 按需添加或修改文档。
- 使用 Git 的[交互式 rebase](https://help.github.com/articles/interactive-rebase) 将多次提交合并为一次提交。必要时创建一个新分支。
- 将分支推送到你在 GitHub 上的 fork，即远程仓库 `origin`。
- 从你的 fork 向正确的分支创建 Pull Request。目标分支为项目的 `main`。
- Pull Request 获批并合并后，可以将 `upstream` 的改动拉取到本地仓库，并删除多余的分支。

最后还有同样重要的一点：始终使用现在时编写提交信息。提交信息应描述这次提交应用后会对代码产生什么作用，而不是你对代码做了什么。

## 重新请求审查

请勿在新评论中通过提及审查者来提醒他们，而应使用重新请求审查功能。详情见 [GitHub 文档：重新请求审查](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request#re-requesting-a-review)。
