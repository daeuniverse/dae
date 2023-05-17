# Semantic Commit Messages

## The reasons for these conventions

- automatic generating of the changelog
- simple navigation through Git history (e.g. ignoring the style changes)

See how a minor change to your commit message style can make you a better developer.

## Format

```
`<type>(<scope>): <subject>`

`<scope>` is optional
```

## Example

```
feat: add hat wobble
^--^  ^------------^
|     |
|     +-> Summary in present tense.
|
+-------> Type: chore, docs, feat, fix, refactor, style, or test.
```

Example `<type>` values:

- `feat`: (new feature for the user, not a new feature for build script)
- `fix`: (bug fix for the user, not a fix to a build script)
- `docs`: (changes to the documentation)
- `style`: (formatting, missing semi colons, etc; no production code change)
- `refactor`: (refactoring production code, eg. renaming a variable)
- `test`: (adding missing tests, refactoring tests; no production code change)
- `chore`: (updating grunt tasks etc; no production code change, e.g. dependencies upgrade)
- `perf`: (perfomance improvement change, e.g. better concurrency performance)
- `ci`: (updating CI configuration files and scripts e.g. .GitHub/workflows/\*.yml )

Example `<Scope>` values:

- `init`
- `runner`
- `watcher`
- `config`
- `web-server`
- `proxy`

The `<scope>` can be empty (e.g. if the change is a global or difficult to assign to a single component), in which case the parentheses are omitted. In smaller projects such as Karma plugins, the `<scope>` is empty.

## Message Subject (First Line)

The first line cannot be longer than `72` characters and should be followed by a blank line. The type and scope should always be lowercase as shown below

## Message Body

use as in the `<subject>`, use the imperative, present tense: "change" not "changed" nor "changes". Message body should include motivation for the change and contrasts with previous behavior.

## Message footer

##### Referencing issues

Closed issues should be listed on a separate line in the footer prefixed with "Closes" keyword as the following:

```
Closes #234
```

or in the case of multiple issues:

```
Closes #123, #245, #992
```

## References

- <https://www.conventionalcommits.org/>
- <https://seesparkbox.com/foundry/semantic_commit_messages>
- <http://karma-runner.github.io/1.0/dev/git-commit-msg.html>
- <https://wadehuanglearning.blogspot.com/2019/05/commit-commit-commit-why-what-commit.html>
