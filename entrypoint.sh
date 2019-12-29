#!/bin/bash
set -e

SA_JWT_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token";

log_info () {
    echo "[$(date)] INFO  $1" 1>&2;
}

log_error () {
    echo "[$(date)] ERROR $1" 1>&2;
}

log_fatal () {
    echo "[$(date)] FATAL $1" 1>&2;
}

check_errors () {
    local json=$1;
    local errors;
    errors=$(jq -ecMj '.errors' <<< $json) && log_error "errors: $errors" && return 1;
    return 0;
}

lease_sleep () {
    local lease_duration=$1;
    local wait_time=$(expr $lease_duration / 3 - 1);
    wait_time=$(( $wait_time > 1 ? $wait_time : 1 ));
    log_info "sleeping for ${wait_time}s...";
    sleep $wait_time;
}

BACKOFF_DELAY_INIT=5;
BACKOFF_DELAY_MAX=300;
reset_backoff () {
    BACKOFF_DELAY=$BACKOFF_DELAY_INIT;
}
reset_backoff;

backoff () {
    log_info "backing off; sleeping for ${BACKOFF_DELAY}s...";
    sleep $BACKOFF_DELAY;
    # decorrelated jitter (https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/)
    # mean delay increases more slowly than with full jitter (i.e., est_mean_delay(i) = init * (3/2)^i)
    BACKOFF_DELAY=$(min $BACKOFF_DELAY_MAX $(random_between $BACKOFF_DELAY_INIT $(( BACKOFF_DELAY * 3 ))));
}

min () {
    echo -nE $(( $1 < $2 ? $1 : $2 ));
}

random_between () {
    echo -nE $(( RANDOM * ($2 - $1) / 2**15 + $1 ));
}

write_client_token () {
    local resp=$1;

    local token;
    if token="$(jq -ecj '.auth.client_token' <<< $resp)"; then
        mkdir -p ${VAULT_TOKEN_PATH%/*};
        echo -nE "$token" > "$VAULT_TOKEN_PATH~";
        mv "$VAULT_TOKEN_PATH~" "$VAULT_TOKEN_PATH";
    else
        log_error "missing client_token in vault response";
        return 1;
    fi
}

current_lease_duration () {
    local session;
    session=$(cat "$VAULT_SESSION_PATH" 2>/dev/null) || return 1;

    local lease_duration;
    lease_duration=$(jq -eMj '.auth.lease_duration' <<< $session) || return 1;
    echo -nE "$lease_duration";
}

handle_auth_response () {
    local resp=$1;

    check_errors "$resp" || return 1;
    mkdir -p ${VAULT_SESSION_PATH%/*};
    echo -nE "$resp" > "$VAULT_SESSION_PATH~";
    mv "$VAULT_SESSION_PATH~" "$VAULT_SESSION_PATH";

    write_client_token "$resp" || return 1;

    local message_filter=$(printf '%s' \
        'if .auth.lease_duration then '\
        '  "new vault token leased for "+(.auth.lease_duration|tostring)+"s: request_id "+.request_id '\
        'else null end');

    local message;
    message="$(jq -ecj "$message_filter" <<< $resp)" || { log_error "new lease duration missing" && return 1; }
    log_info "$message";
}

k8s_login () {
    log_info "trying kubernetes service account login...";

    [ ! -f "$SA_JWT_PATH" ] && log_fatal "missing service account token: $SA_JWT_PATH" && exit 1;
    local jwt=$(cat "$SA_JWT_PATH");

    local login_data=$(jq -n --arg jwt "$jwt" --arg role "$APP_ROLE" '{jwt: $jwt, role: $role}');
    local resp=$(curl -sS --request POST --data "$login_data" "${VAULT_ADDR}/v1/auth/kubernetes/login");
    
    handle_auth_response "$resp" || { log_error "kubernetes login failed" && return 1; }
}

renew_token () {
    log_info "trying client token renewal...";

    [ ! -f "$VAULT_SESSION_PATH" ] && log_error "missing vault session: $VAULT_SESSION_PATH" && return 1;

    local prev_session=$(cat "$VAULT_SESSION_PATH");

    local token;
    token=$(jq -eMj '.auth.client_token' <<< $prev_session) || { log_error "missing previous client token" && return 1; }

    local lease_duration;
    if ! lease_duration=$(jq -eMj '.auth.lease_duration' <<< $prev_session); then
        log_error "missing previous lease duration; requesting 120s...";
        lease_duration=120;
    fi

    local renewal_request=$(jq -n --arg increment "$lease_duration" '{"increment": $increment}');
    local resp=$(curl -sS --request PUT --header "X-Vault-Token: $token" --data "$renewal_request" "${VAULT_ADDR}/v1/auth/token/renew-self");

    handle_auth_response "$resp" || { log_error "token refresh failed" && return 1; }
}

auto_refresh () {
    sleep 5;

    while true; do
        if renew_token; then
            reset_backoff;
            lease_sleep "$(current_lease_duration)";
        elif k8s_login; then
            reset_backoff;
            lease_sleep "$(current_lease_duration)";
        else
            backoff;
        fi
    done
}

[ -z "$APP_ROLE" ] && log_fatal "missing or empty APP_ROLE" && exit 1;
[ -z "$VAULT_ADDR" ] && log_fatal "missing or empty VAULT_ADDR" && exit 1;
[ -z "$VAULT_SESSION_PATH" ] && log_fatal "missing or empty VAULT_SESSION_PATH" && exit 1;
[ -z "$VAULT_TOKEN_PATH" ] && log_fatal "missing or empty VAULT_TOKEN_PATH" && exit 1;

eval "$@"