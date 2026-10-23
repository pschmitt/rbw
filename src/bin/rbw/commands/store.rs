// The account the current operation targets: the one selected via
// --account / RBW_ACCOUNT (or, in the TUI, set per-entry via
// `set_active_account`), else the primary account. Keeps the local db path
// (server + email) aligned with whichever account the agent request targeted.
pub(super) fn active_account() -> anyhow::Result<rbw::config::Account> {
    let config = rbw::config::Config::load()?;
    config
        .account(crate::actions::current_account().as_deref())
        .map_err(anyhow::Error::new)
}

pub(super) fn account_email(
    account: &rbw::config::Account,
) -> anyhow::Result<String> {
    let email = account.email.as_ref().ok_or_else(|| {
        anyhow::anyhow!("failed to find email address in config")
    })?;
    Ok(email.resolve()?)
}

pub fn load_db() -> anyhow::Result<rbw::db::Db> {
    let account = active_account()?;
    rbw::db::Db::load(&account.server_name()?, &account_email(&account)?)
        .map_err(anyhow::Error::new)
}

pub fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let account = active_account()?;
    db.save(&account.server_name()?, &account_email(&account)?)
        .map_err(anyhow::Error::new)
}

pub(super) fn remove_db() -> anyhow::Result<()> {
    let account = active_account()?;
    rbw::db::Db::remove(&account.server_name()?, &account_email(&account)?)
        .map_err(anyhow::Error::new)
}
