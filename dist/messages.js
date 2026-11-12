export const NOT_INSTALLED = "qbit-vault was not found; install it from https://github.com/qbitdevz/qbit-vault and make sure it is on PATH";
export const LOCKED = "vault is locked; QBit Vault asks for the passphrase when a tool or a /vault command needs it";
export const OUTDATED_BINARY = "qbit-vault-pi needs qbit-vault 1.4.0 or newer; run 'qbit-vault update'";
export const NOT_INITIALIZED = "no vault here; run 'qbit-vault init'";
export const TIMEOUT = "qbit-vault did not answer in time";
export const USAGE = "usage: /vault list [global|project|all] | set NAME [global|project] | rm NAME [global|project] | revoke NAME|--all | audit [--tail N] | doctor";
export const BAD_NAME = "invalid name: use capital letters, digits and _ (up to 64), starting with a letter";
/** Secret names as the contract defines them. */
export const NAME_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
/** The one line shown for a failed call. Only fixed texts and the CLI's own error message. */
export function failureText(failure) {
    if (failure.reason === "not_installed")
        return NOT_INSTALLED;
    if (failure.reason === "timeout")
        return TIMEOUT;
    const error = failure.error;
    if (error?.code === "vault_locked")
        return LOCKED;
    if (error?.code === "not_initialized")
        return NOT_INITIALIZED;
    if (error)
        return error.message;
    return typeof failure.code === "number" ? `qbit-vault failed (exit ${failure.code})` : "qbit-vault failed";
}
