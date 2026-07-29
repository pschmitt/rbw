use crate::prelude::*;

pub async fn register(
    email: &str,
    apikey: crate::locked::ApiKey,
) -> Result<()> {
    let (client, _account) = api_client_async().await?;
    let config = crate::config::Config::load_async().await?;

    client
        .register(email, &crate::config::device_id(&config).await?, &apikey)
        .await?;

    Ok(())
}

pub async fn login(
    email: &str,
    password: crate::locked::Password,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(
    String,
    String,
    crate::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (client, account) = api_client_async().await?;
    let config = crate::config::Config::load_async().await?;
    let (kdf, iterations, memory, parallelism) =
        client.prelogin(email).await?;

    let identity = crate::identity::Identity::new(
        email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;
    let (access_token, refresh_token, protected_key) = client
        .login(
            email,
            account.sso_id.as_deref(),
            &crate::config::device_id(&config).await?,
            &identity.master_password_hash,
            two_factor_token,
            two_factor_provider,
        )
        .await?;

    Ok((
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ))
}

pub async fn send_two_factor_email(
    email: &str,
    sso_email_2fa_session_token: &str,
) -> Result<()> {
    let (client, _account) = api_client_async().await?;
    let config = crate::config::Config::load_async().await?;
    client
        .send_email_login(
            email,
            &crate::config::device_id(&config).await?,
            sso_email_2fa_session_token,
        )
        .await
}

pub fn unlock<S: std::hash::BuildHasher>(
    email: &str,
    password: &crate::locked::Password,
    kdf: crate::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
    crate::locked::PrivateKey,
)> {
    let identity = crate::identity::Identity::new(
        email,
        password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(&identity.keys) {
        Ok(master_keys) => crate::locked::Keys::new(master_keys),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            })
        }
        Err(e) => return Err(e),
    };

    let protected_private_key =
        crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key = crate::locked::PrivateKey::new(
        protected_private_key.decrypt_locked_symmetric(&key)?,
    );

    let org_keys = decrypt_org_keys(&private_key, protected_org_keys)?;

    Ok((key, org_keys, private_key))
}

// Decrypts every org key in `protected_org_keys` using `private_key` (the
// account's own RSA private key, itself only decryptable with the master
// password -- see `unlock`). Also called after every `sync`, using the
// private key retained in the agent's in-memory state from the original
// unlock, so a newly created/joined org's key becomes usable immediately
// instead of only after the next full lock+unlock cycle.
pub fn decrypt_org_keys<S: std::hash::BuildHasher>(
    private_key: &crate::locked::PrivateKey,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<std::collections::HashMap<String, crate::locked::Keys>> {
    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let protected_org_key =
            crate::cipherstring::CipherString::new(protected_org_key)?;
        let org_key = crate::locked::Keys::new(
            protected_org_key.decrypt_locked_asymmetric(private_key)?,
        );
        org_keys.insert(org_id.clone(), org_key);
    }
    Ok(org_keys)
}

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(
    Option<String>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
        Vec<crate::db::Collection>,
        Vec<crate::db::Organization>,
    ),
)> {
    with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        |access_token| {
            let access_token = access_token.to_string();
            Box::pin(async move { sync_once(&access_token).await })
        },
    )
    .await
}

async fn sync_once(
    access_token: &str,
) -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
    Vec<crate::db::Collection>,
    Vec<crate::db::Organization>,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub async fn purge_vault(
    access_token: &str,
    refresh_token: &str,
    master_password_hash: &crate::locked::PasswordHash,
) -> Result<Option<String>> {
    let hash = crate::base64::encode(master_password_hash.hash());
    let (new_access_token, ()) = with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        move |access_token| {
            let access_token = access_token.to_string();
            let hash = hash.clone();
            Box::pin(
                async move { purge_vault_once(&access_token, &hash).await },
            )
        },
    )
    .await?;
    Ok(new_access_token)
}

async fn purge_vault_once(
    access_token: &str,
    master_password_hash: &str,
) -> Result<()> {
    let (client, _) = api_client_async().await?;
    client.purge_vault(access_token, master_password_hash).await
}

pub async fn delete_org(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    master_password_hash: &crate::locked::PasswordHash,
) -> Result<Option<String>> {
    let hash = crate::base64::encode(master_password_hash.hash());
    let (new_access_token, ()) = with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        move |access_token| {
            let access_token = access_token.to_string();
            let org_id = org_id.to_string();
            let hash = hash.clone();
            Box::pin(async move {
                delete_org_once(&access_token, &org_id, &hash).await
            })
        },
    )
    .await?;
    Ok(new_access_token)
}

async fn delete_org_once(
    access_token: &str,
    org_id: &str,
    master_password_hash: &str,
) -> Result<()> {
    let (client, _) = api_client_async().await?;
    client
        .delete_org(access_token, org_id, master_password_hash)
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_org(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    billing_email: &str,
    encrypted_key: &str,
    encrypted_collection_name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        move |access_token| {
            let access_token = access_token.to_string();
            let name = name.to_string();
            let billing_email = billing_email.to_string();
            let encrypted_key = encrypted_key.to_string();
            let encrypted_collection_name =
                encrypted_collection_name.to_string();
            Box::pin(async move {
                create_org_once(
                    &access_token,
                    &name,
                    &billing_email,
                    &encrypted_key,
                    &encrypted_collection_name,
                )
                .await
            })
        },
    )
    .await
}

async fn create_org_once(
    access_token: &str,
    name: &str,
    billing_email: &str,
    encrypted_key: &str,
    encrypted_collection_name: &str,
) -> Result<String> {
    let (client, _) = api_client_async().await?;
    client
        .create_org(
            access_token,
            name,
            billing_email,
            encrypted_key,
            encrypted_collection_name,
        )
        .await
}

pub fn add(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        add_once(access_token, name, data, fields, notes, folder_id)
    })
}

fn add_once(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.add(access_token, name, data, fields, notes, folder_id)?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    refresh_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_once(
            access_token,
            id,
            org_id,
            name,
            data,
            fields,
            notes,
            folder_uuid,
            history,
        )
    })
}

fn edit_once(
    access_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit(
        access_token,
        id,
        org_id,
        name,
        data,
        fields,
        notes,
        folder_uuid,
        history,
    )?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        remove_once(access_token, id)
    })
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.remove(access_token, id)?;
    Ok(())
}

pub fn delete_permanently(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        delete_permanently_once(access_token, id)
    })
}

fn delete_permanently_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.delete_permanently(access_token, id)?;
    Ok(())
}

pub fn archive(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        archive_once(access_token, id)
    })
}

fn archive_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.archive(access_token, id)?;
    Ok(())
}

pub fn unarchive(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        unarchive_once(access_token, id)
    })
}

fn unarchive_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.unarchive(access_token, id)?;
    Ok(())
}

pub fn archive_multiple(
    access_token: &str,
    refresh_token: &str,
    ids: &[String],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        archive_multiple_once(access_token, ids)
    })
}

fn archive_multiple_once(access_token: &str, ids: &[String]) -> Result<()> {
    let (client, _) = api_client()?;
    client.archive_multiple(access_token, ids)?;
    Ok(())
}

pub fn unarchive_multiple(
    access_token: &str,
    refresh_token: &str,
    ids: &[String],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        unarchive_multiple_once(access_token, ids)
    })
}

fn unarchive_multiple_once(access_token: &str, ids: &[String]) -> Result<()> {
    let (client, _) = api_client()?;
    client.unarchive_multiple(access_token, ids)?;
    Ok(())
}

pub fn restore(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        restore_once(access_token, id)
    })
}

fn restore_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.restore(access_token, id)?;
    Ok(())
}

pub fn restore_multiple(
    access_token: &str,
    refresh_token: &str,
    ids: &[String],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        restore_multiple_once(access_token, ids)
    })
}

fn restore_multiple_once(access_token: &str, ids: &[String]) -> Result<()> {
    let (client, _) = api_client()?;
    client.restore_multiple(access_token, ids)?;
    Ok(())
}

pub fn edit_collections(
    access_token: &str,
    refresh_token: &str,
    id: &str,
    collection_ids: &[String],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_collections_once(access_token, id, collection_ids)
    })
}

fn edit_collections_once(
    access_token: &str,
    id: &str,
    collection_ids: &[String],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit_collections(access_token, id, collection_ids)?;
    Ok(())
}

pub fn attachment_url(
    access_token: &str,
    refresh_token: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        attachment_url_once(access_token, cipher_id, attachment_id)
    })
}

fn attachment_url_once(
    access_token: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<String> {
    let (client, _) = api_client()?;
    client.attachment_url(access_token, cipher_id, attachment_id)
}

pub fn download_attachment(url: &str) -> Result<Vec<u8>> {
    let (client, _) = api_client()?;
    client.download_attachment(url)
}

pub fn delete_attachment(
    access_token: &str,
    refresh_token: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        delete_attachment_once(access_token, cipher_id, attachment_id)
    })
}

fn delete_attachment_once(
    access_token: &str,
    cipher_id: &str,
    attachment_id: &str,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.delete_attachment(access_token, cipher_id, attachment_id)
}

pub fn create_attachment(
    access_token: &str,
    refresh_token: &str,
    cipher_id: &str,
    encrypted_filename: &str,
    encrypted_key: &str,
    encrypted_data: &[u8],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_attachment_once(
            access_token,
            cipher_id,
            encrypted_filename,
            encrypted_key,
            encrypted_data.to_vec(),
        )
    })
}

fn create_attachment_once(
    access_token: &str,
    cipher_id: &str,
    encrypted_filename: &str,
    encrypted_key: &str,
    encrypted_data: Vec<u8>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.create_attachment(
        access_token,
        cipher_id,
        encrypted_filename,
        encrypted_key,
        encrypted_data,
    )?;
    Ok(())
}

pub fn rename_collection(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    collection_id: &str,
    encrypted_name: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        rename_collection_once(
            access_token,
            org_id,
            collection_id,
            encrypted_name,
        )
    })
}

fn rename_collection_once(
    access_token: &str,
    org_id: &str,
    collection_id: &str,
    encrypted_name: &str,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.rename_collection(
        access_token,
        org_id,
        collection_id,
        encrypted_name,
    )?;
    Ok(())
}

pub fn create_collection(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    encrypted_name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_collection_once(access_token, org_id, encrypted_name)
    })
}

fn create_collection_once(
    access_token: &str,
    org_id: &str,
    encrypted_name: &str,
) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_collection(access_token, org_id, encrypted_name)
}

pub fn delete_collection(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    collection_id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        delete_collection_once(access_token, org_id, collection_id)
    })
}

fn delete_collection_once(
    access_token: &str,
    org_id: &str,
    collection_id: &str,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.delete_collection(access_token, org_id, collection_id)
}

pub fn org_users(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
) -> Result<(Option<String>, Vec<crate::api::OrgUser>)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        org_users_once(access_token, org_id)
    })
}

fn org_users_once(
    access_token: &str,
    org_id: &str,
) -> Result<Vec<crate::api::OrgUser>> {
    let (client, _) = api_client()?;
    client.org_users(access_token, org_id)
}

pub fn invite_org_user(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    email: &str,
    role: i32,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        invite_org_user_once(access_token, org_id, email, role)
    })
}

fn invite_org_user_once(
    access_token: &str,
    org_id: &str,
    email: &str,
    role: i32,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.invite_org_user(access_token, org_id, email, role)
}

pub fn remove_org_user(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    user_id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        remove_org_user_once(access_token, org_id, user_id)
    })
}

fn remove_org_user_once(
    access_token: &str,
    org_id: &str,
    user_id: &str,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.remove_org_user(access_token, org_id, user_id)
}

pub fn accept_org_invite(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    user_id: &str,
    token: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        accept_org_invite_once(access_token, org_id, user_id, token)
    })
}

fn accept_org_invite_once(
    access_token: &str,
    org_id: &str,
    user_id: &str,
    token: &str,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.accept_org_invite(access_token, org_id, user_id, token)
}

pub fn user_public_key(
    access_token: &str,
    refresh_token: &str,
    user_id: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        user_public_key_once(access_token, user_id)
    })
}

fn user_public_key_once(access_token: &str, user_id: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.user_public_key(access_token, user_id)
}

pub async fn confirm_org_user(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    user_id: &str,
    encrypted_key: &str,
) -> Result<Option<String>> {
    let (new_access_token, ()) = with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        move |access_token| {
            let access_token = access_token.to_string();
            let org_id = org_id.to_string();
            let user_id = user_id.to_string();
            let encrypted_key = encrypted_key.to_string();
            Box::pin(async move {
                confirm_org_user_once(
                    &access_token,
                    &org_id,
                    &user_id,
                    &encrypted_key,
                )
                .await
            })
        },
    )
    .await?;
    Ok(new_access_token)
}

async fn confirm_org_user_once(
    access_token: &str,
    org_id: &str,
    user_id: &str,
    encrypted_key: &str,
) -> Result<()> {
    let (client, _) = api_client_async().await?;
    client
        .confirm_org_user(access_token, org_id, user_id, encrypted_key)
        .await
}

pub fn collections_details(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
) -> Result<(Option<String>, Vec<crate::api::CollectionDetail>)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        collections_details_once(access_token, org_id)
    })
}

fn collections_details_once(
    access_token: &str,
    org_id: &str,
) -> Result<Vec<crate::api::CollectionDetail>> {
    let (client, _) = api_client()?;
    client.collections_details(access_token, org_id)
}

pub fn set_collection_users(
    access_token: &str,
    refresh_token: &str,
    org_id: &str,
    collection_id: &str,
    encrypted_name: &str,
    external_id: Option<&str>,
    groups: &[serde_json::Value],
    users: &[crate::api::CollectionUser],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        set_collection_users_once(
            access_token,
            org_id,
            collection_id,
            encrypted_name,
            external_id,
            groups,
            users,
        )
    })
}

fn set_collection_users_once(
    access_token: &str,
    org_id: &str,
    collection_id: &str,
    encrypted_name: &str,
    external_id: Option<&str>,
    groups: &[serde_json::Value],
    users: &[crate::api::CollectionUser],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.set_collection_users(
        access_token,
        org_id,
        collection_id,
        encrypted_name,
        external_id,
        groups,
        users,
    )
}

pub fn list_folders(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, Vec<(String, String)>)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        list_folders_once(access_token)
    })
}

fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let (client, _) = api_client()?;
    client.folders(access_token)
}

pub fn create_folder(
    access_token: &str,
    refresh_token: &str,
    name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_folder(access_token, name)
}

fn with_exchange_refresh_token<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(&str) -> Result<T>,
{
    match f(access_token) {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            let t = f(&access_token)?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

async fn with_exchange_refresh_token_async<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T>> + Send>,
        > + Send
        + Sync,
    T: Send,
{
    match f(access_token).await {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let t = f(&access_token).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_refresh_token(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token(refresh_token)
}

async fn exchange_refresh_token_async(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token_async(refresh_token).await
}

tokio::task_local! {
    // Set by the agent around each request (via `AGENT_ACCOUNT.scope`) so that
    // `api_client`/`api_client_async` target the right account's server. It is
    // readable from both async and sync code running within that task.
    pub static AGENT_ACCOUNT: crate::config::Account;
}

// Set by the CLI (from --account / RBW_ACCOUNT, or per-operation by the
// multi-account TUI) so that the synchronous api calls it makes target the
// right account's server. `None` falls back to the primary account.
static CLIENT_ACCOUNT: std::sync::RwLock<Option<crate::config::Account>> =
    std::sync::RwLock::new(None);

pub fn set_client_account(account: crate::config::Account) {
    *CLIENT_ACCOUNT.write().unwrap() = Some(account);
}

// Clear the CLI-selected account, reverting api calls to the primary account.
pub fn clear_client_account() {
    *CLIENT_ACCOUNT.write().unwrap() = None;
}

// Which account the current api call targets: the agent's per-request account,
// else the CLI's selected account, else the primary account.
fn resolve_account(config: &crate::config::Config) -> crate::config::Account {
    if let Ok(account) = AGENT_ACCOUNT.try_with(Clone::clone) {
        return account;
    }
    // Clone out of the lock before matching so the read guard is dropped
    // immediately (clippy::significant_drop_in_scrutinee).
    let selected = CLIENT_ACCOUNT.read().unwrap().clone();
    if let Some(account) = selected {
        return account;
    }
    config.primary()
}

fn api_client() -> Result<(crate::api::Client, crate::config::Account)> {
    let config = crate::config::Config::load()?;
    let account = resolve_account(&config);
    let client = crate::api::Client::new(
        &account.base_url(),
        &account.identity_url(),
        &account.ui_url(),
        account.client_cert_path.as_deref(),
    );
    Ok((client, account))
}

async fn api_client_async(
) -> Result<(crate::api::Client, crate::config::Account)> {
    let config = crate::config::Config::load_async().await?;
    let account = resolve_account(&config);
    let client = crate::api::Client::new(
        &account.base_url(),
        &account.identity_url(),
        &account.ui_url(),
        account.client_cert_path.as_deref(),
    );
    Ok((client, account))
}
