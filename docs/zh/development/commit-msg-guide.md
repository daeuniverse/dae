# 语义化提交信息

## 采用这些约定的原因

- 自动生成更新日志
- 便于浏览 Git 历史（例如，忽略代码风格改动）

了解如何通过小幅调整提交信息的风格，成为更好的开发者。

## 格式

```
`<type>(<scope>): <subject>`

`<scope>` is optional
```

## 示例

```
feat: add hat wobble
^--^  ^------------^
|     |
|     +-> Summary in present tense.
|
+-------> Type: chore, docs, feat, fix, refactor, style, or test.
```

`<type>` 的取值示例：

| 类型 | 含义 |
| --- | --- |
| `feat` | 面向用户的新功能，而非构建脚本的新功能 |
| `fix` | 面向用户的 bug 修复，而非构建脚本的修复 |
| `docs` | 文档改动 |
| `style` | 格式调整、补充缺失的分号等；不改动生产代码 |
| `refactor` | 重构生产代码，例如重命名变量 |
| `test` | 添加缺失的测试、重构测试；不改动生产代码 |
| `chore` | 更新 grunt 任务等；不改动生产代码，例如升级依赖 |
| `perf` | 改善性能，例如提高并发性能 |
| `ci` | 更新 CI 配置文件和脚本，例如 `.gitHub/workflows/*.yml` |

`<Scope>` 的取值示例：

- `init`
- `runner`
- `watcher`
- `config`
- `web-server`
- `proxy`

`<scope>` 可以为空（例如，改动是全局性的，或难以归属于单个组件），此时省略圆括号。在 Karma 插件等较小的项目中，`<scope>` 为空。

## 提交信息主题（首行）

首行不得超过 `72` 个字符，其后应留一个空行。类型和范围始终使用小写，如下所示。

## 提交信息正文

与 `<subject>` 一样，使用祈使语气和现在时：用 `change`，而不是 `changed` 或 `changes`。正文应说明改动的动机，以及与此前行为的对比。

## 提交信息页脚

### 引用 issue

应在页脚中单独一行列出要关闭的 issue，并以 `Closes` 关键字开头，如下所示：

```
Closes #234
```

如果有多个 issue：

```
Closes #123, #245, #992
```

## 参考资料

- <https://www.conventionalcommits.org/>
- <https://seesparkbox.com/foundry/semantic_commit_messages>
- <http://karma-runner.github.io/1.0/dev/git-commit-msg.html>
- <https://wadehuanglearning.blogspot.com/2019/05/commit-commit-commit-why-what-commit.html>
