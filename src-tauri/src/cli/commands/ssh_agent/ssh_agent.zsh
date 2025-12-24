# if our ssh agent is running, make sure we set SSH_AUTH_SOCK accordingly
function ap_ssh_agent_preexec() {
    AP_SSH_AUTH_SOCK="$HOME/Library/Application Support/Axo Pass/ssh-agent.sock"
    lsof "$AP_SSH_AUTH_SOCK" >/dev/null 2>&1

    if [[ $? -ne 0 ]]; then
        # ap ssh-agent is not running.
        # if we have ORIGINAL_SSH_AUTH_SOCK set, restore it
        if [[ -n "$ORIGINAL_SSH_AUTH_SOCK" ]]; then
            export SSH_AUTH_SOCK=$ORIGINAL_SSH_AUTH_SOCK
            unset ORIGINAL_SSH_AUTH_SOCK
        fi
    else
        # ap ssh-agent is running.
        # if SSH_AUTH_SOCK is not AP_SSH_AUTH_SOCK, set it accordingly
        if [[ "$SSH_AUTH_SOCK" != "$AP_SSH_AUTH_SOCK" ]]; then
            export ORIGINAL_SSH_AUTH_SOCK="$SSH_AUTH_SOCK"
            export SSH_AUTH_SOCK="$AP_SSH_AUTH_SOCK"
        fi
    fi
}

typeset -a preexec_functions

# NOTE: Prepend to preexec_functions. Because some shells treat the
# last precmd position as privileged [0], so prepending generally seems safer.
# [0] e.g. ghostty and kitty:
# 1. https://github.com/ghostty-org/ghostty/blob/main/src/shell-integration/zsh/ghostty-integration#L121
# 2. https://github.com/ghostty-org/ghostty/blob/d4d8cbd1537292ea1a0f207757503de54fe1cb3b/src/shell-integration/zsh/ghostty-integration
preexec_functions=(ap_ssh_agent_preexec $preexec_functions)
