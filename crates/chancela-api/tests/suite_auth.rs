#[path = "common/mod.rs"]
mod common;

#[path = "active_sessions.rs"]
mod active_sessions;
#[path = "apikey_auth.rs"]
mod apikey_auth;
#[path = "auth_settings_slice.rs"]
mod auth_settings_slice;
#[path = "create_user_role.rs"]
mod create_user_role;
#[path = "first_admin_bootstrap.rs"]
mod first_admin_bootstrap;
#[path = "permission_enforcement_parity.rs"]
mod permission_enforcement_parity;
#[path = "recovery_rbac.rs"]
mod recovery_rbac;
#[path = "self_service_account.rs"]
mod self_service_account;
#[path = "signup_and_invites.rs"]
mod signup_and_invites;
#[path = "step_up_totp.rs"]
mod step_up_totp;
#[path = "totp_and_account_policy.rs"]
mod totp_and_account_policy;
#[path = "two_step_signin.rs"]
mod two_step_signin;
