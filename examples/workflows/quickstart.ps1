param(
    [string]$Target = "coinbase/<IN_SCOPE_REPO_1>",
    [string]$RepoPath = ".",
    [string]$Config = "openclaw.localstub.yaml"
)

python -m openclaw `
    --config $Config `
    --target $Target `
    --repo-path $RepoPath `
    --print-json
