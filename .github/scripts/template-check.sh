#!/usr/bin/env bash
# Usage: template-check.sh NUMBER; offline: template-check.sh --dry-run issue|pr < body.md
set -euo pipefail

search='I searched existing issues'
trap_box='I checked the boxes above without reading them'
agent_box='I am an AI agent, and this content was submitted without human review'
understand='I understand this change and answer for every line'
main='This branch is based on the current main'
gates="I ran the repository's gates and recorded the results in Verified"
commits='Each commit is one coherent change'

check_body() {
    jq -Rs --arg kind "$1" --arg search "$search" --arg trap "$trap_box" \
        --arg agent "$agent_box" --arg understand "$understand" --arg main "$main" \
        --arg gates "$gates" --arg commits "$commits" '
        def trim: gsub("^\\s+|\\s+$"; "");
        def boxes($text): [split("\n")[] |
            capture("^\\s*[-*] \\[(?<mark>[ x])\\] " + $text + "(?:\\s*/[^\\n]*)?\\s*$"; "i") | .mark | ascii_downcase];
        def checked($text): boxes($text) | any(. == "x");
        def kept($text): boxes($text) | length > 0 and all(. == "x");
        gsub("<!--[\\s\\S]*?-->"; "") |
        gsub("(?:^|\\n)```[^\\n]*\\n[\\s\\S]*?\\n```[^\\n]*"; "") | . as $body |
        # Issues opened from other forms or blank issues carry no human-responsible field.
        if $kind == "issue" and (test("(?:^|\\n)### Human responsible"; "i") | not) then [] else
        # Pull requests carry no name field; the first required box makes the author answer for the change.
        ([capture("(?:^|\\n)### Human responsible(?: /[^\\n]*)?\\n(?<human>[\\s\\S]*?)(?:\\n#{1,6} |\\z)"; "i") | .human][0]
            // "" | trim | ascii_downcase) as $human |
        [
            {test: checked($trap), en: "The unread-checkbox trap is checked.", zh: "勾选了“我没有阅读上面的选项就直接勾选了”。"},
            {test: checked($agent), en: "The AI-agent box says there was no human review.", zh: "勾选了“我是 AI 代理”，表示内容没有经过人工审核。"},
            {test: ($kind == "issue" and ($human == "" or $human == "_no response_" or
                ($human | test("^@?your-name(?:\\s*/.*)?$|^your github username$")))),
                en: "Name the human responsible with a GitHub username.", zh: "请填写负责人的 GitHub 用户名。"},
            {test: ($kind == "pr" and ([$understand, $main, $gates, $commits] |
                any(. as $box | $body | kept($box) | not))),
                en: "Keep and check all four unconditional PR boxes.", zh: "请保留并勾选 PR 的四项必选选项。"},
            {test: ($kind == "issue" and (kept($search) | not)),
                en: "Keep and check the existing-issue search box.", zh: "请保留并勾选“我已搜索过现有 issue”。"}
        ] | map(select(.test) | {en, zh}) end'
}

if [[ ${1:-} == --dry-run ]]; then
    [[ ${2:-} == issue || ${2:-} == pr ]] || exit 2
    check_body "$2"
    exit
fi

number=${1:?issue or pull request number}
repo="repos/${GITHUB_REPOSITORY:?}"
item=$(gh api "$repo/issues/$number")
if jq -e '.user.type == "Bot" or (["OWNER", "MEMBER", "COLLABORATOR"] | index($ARGS.named.association)) != null' \
    --arg association "$(jq -r .author_association <<< "$item")" <<< "$item" >/dev/null; then
    exit
fi
kind=$(jq -r 'if .pull_request then "pr" else "issue" end' <<< "$item")
failures=$(jq -r '.body // ""' <<< "$item" | check_body "$kind")
label=template-violation
marker='<!-- template-violation -->'
failed=$(jq length <<< "$failures")
labelled=$(jq --arg label "$label" 'any(.labels[]; .name == $label)' <<< "$item")
if [[ $failed == 0 && ( ${GITHUB_EVENT_ACTION:-} != edited || $labelled != true ) ]]; then
    exit
fi

comment=$(gh api --paginate --slurp "$repo/issues/$number/comments" | jq --arg marker "$marker" \
    '[.[][] | select(.user.type == "Bot" and .user.login == "github-actions[bot]" and (.body | startswith($marker)))][0] // null')
if [[ $failed != 0 ]]; then
    message=$(jq -r --arg marker "$marker" '
        $marker + "\n内容不符合模板要求，已关闭。请修改以下各项，正文改好后会自动重新打开：\n" +
        (map("- " + .zh) | join("\n")) +
        "\n\nFix these template violations; this item will reopen automatically once its body is fixed:\n" +
        (map("- " + .en) | join("\n"))' <<< "$failures")
else
    message="$marker
已按模板改好，现已重新打开。

Template violations fixed; reopened."
fi
if [[ $comment == null ]]; then
    gh api "$repo/issues/$number/comments" -f body="$message" --silent
elif [[ $(jq -r .body <<< "$comment") != "$message" ]]; then
    gh api "$repo/issues/comments/$(jq -r .id <<< "$comment")" -X PATCH -f body="$message" --silent
fi

if [[ $failed != 0 ]]; then
    if ! gh api "$repo/labels/$label" --silent; then
        gh label create "$label" --repo "$GITHUB_REPOSITORY" --color D93F0B \
            --description 'Issue or PR template needs correction' || gh api "$repo/labels/$label" --silent
    fi
    gh api "$repo/issues/$number/labels" -f "labels[]=$label" --silent
    if [[ $(jq -r .state <<< "$item") == open ]]; then
        if [[ $kind == issue ]]; then
            gh issue close "$number" --repo "$GITHUB_REPOSITORY" --reason 'not planned'
        else
            gh pr close "$number" --repo "$GITHUB_REPOSITORY"
        fi
    fi
else
    if [[ $(jq -r .state <<< "$item") == closed ]]; then
        gh "$kind" reopen "$number" --repo "$GITHUB_REPOSITORY"
    fi
    gh api "$repo/issues/$number/labels/$label" -X DELETE --silent
fi
