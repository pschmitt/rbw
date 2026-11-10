use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
use signature_2::Signer as _;

async fn record_ssh_agent_event(
    operation: &'static str,
    success: bool,
    meta: Option<crate::actions::SshKeyAuditMeta>,
) {
    let Ok(config) = rbw::config::Config::load_async().await else {
        log::warn!("audit event could not read rbw configuration");
        return;
    };
    let config = config.audit;
    let mut event = rbw::audit::Event::new(
        "ssh-agent",
        operation,
        if success { "success" } else { "failure" },
    );
    if let Some(meta) = meta {
        event = event
            .with_account(&meta.account)
            .with_item_id(&meta.item_id)
            .with_field("ssh_private_key");
        if let Some(name) = meta.item_name.as_deref() {
            event = event.with_item_name(name);
        }
    }
    rbw::audit::record_async_best_effort(config, event).await;
}

fn rsa_private_key(
    p_bytes: &[u8],
    q_bytes: &[u8],
    e_bytes: &[u8],
) -> Result<rsa::PrivateKey, ssh_agent_lib::error::AgentError> {
    let bits = u32::try_from(
        p_bytes
            .len()
            .max(q_bytes.len())
            .max(e_bytes.len())
            .saturating_mul(8),
    )
    .map_err(ssh_agent_lib::error::AgentError::other)?;
    let parse = |bytes: &[u8]| {
        rsa::BoxedUint::from_be_slice(bytes, bits)
            .map_err(ssh_agent_lib::error::AgentError::other)
    };
    rsa::PrivateKey::from_p_q(
        parse(p_bytes)?,
        parse(q_bytes)?,
        parse(e_bytes)?,
    )
    .map_err(ssh_agent_lib::error::AgentError::other)
}

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

fn rsa_signature(
    rsa_key: rsa::PrivateKey,
    data: &[u8],
    flags: u32,
) -> Result<ssh_agent_lib::ssh_key::Signature, ssh_agent_lib::error::AgentError>
{
    let mut rng = rand::rng();

    let (algorithm, sig_bytes) = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        let signing_key =
            rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha512>::new(rsa_key);
        let signature = signing_key
            .try_sign_with_rng(&mut rng, data)
            .map_err(ssh_agent_lib::error::AgentError::other)?;

        ("rsa-sha2-512", signature.to_bytes())
    } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        let signing_key =
            rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(rsa_key);
        let signature = signing_key
            .try_sign_with_rng(&mut rng, data)
            .map_err(ssh_agent_lib::error::AgentError::other)?;

        ("rsa-sha2-256", signature.to_bytes())
    } else {
        let signing_key =
            rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(rsa_key);
        let signature = signing_key
            .try_sign_with_rng(&mut rng, data)
            .map_err(ssh_agent_lib::error::AgentError::other)?;

        ("ssh-rsa", signature.to_bytes())
    };

    ssh_agent_lib::ssh_key::Signature::new(
        ssh_agent_lib::ssh_key::Algorithm::new(algorithm)
            .map_err(ssh_agent_lib::error::AgentError::other)?,
        sig_bytes,
    )
    .map_err(ssh_agent_lib::error::AgentError::other)
}

#[derive(Clone)]
pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl SshAgent {
    pub fn new(
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self { state }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = rbw::dirs::ssh_agent_socket_file();

        let _ = std::fs::remove_file(&socket); // Ignore error if it doesn't exist

        let listener = tokio::net::UnixListener::bind(socket)?;
        ssh_agent_lib::agent::listen(listener, self).await?;

        Ok(())
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshAgent {
    async fn request_identities(
        &mut self,
    ) -> Result<
        Vec<ssh_agent_lib::proto::Identity>,
        ssh_agent_lib::error::AgentError,
    > {
        let result = crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))
            .and_then(|keys| {
                keys.into_iter()
                    .map(|p| {
                        p.parse::<ssh_agent_lib::ssh_key::PublicKey>()
                            .map(|pk| ssh_agent_lib::proto::Identity {
                                credential: pk.key_data().clone().into(),
                                comment: String::new(),
                            })
                            .map_err(ssh_agent_lib::error::AgentError::other)
                    })
                    .collect()
            });
        record_ssh_agent_event("ssh_agent.identities", result.is_ok(), None)
            .await;
        result
    }

    async fn sign(
        &mut self,
        request: ssh_agent_lib::proto::SignRequest,
    ) -> Result<
        ssh_agent_lib::ssh_key::Signature,
        ssh_agent_lib::error::AgentError,
    > {
        let mut audit_meta = None;
        let result: Result<_, ssh_agent_lib::error::AgentError> = async {
            let pubkey = ssh_agent_lib::ssh_key::PublicKey::new(
                request.credential.key_data().clone(),
                "",
            );

            let (private_key, meta) = crate::actions::find_ssh_private_key(
                self.state.clone(),
                pubkey,
            )
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;
            audit_meta = Some(meta);

            match private_key.key_data() {
                ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(
                    key,
                ) => key
                    .try_sign(&request.data)
                    .map_err(ssh_agent_lib::error::AgentError::other),

                ssh_agent_lib::ssh_key::private::KeypairData::Rsa(key) => {
                    let rsa_key = rsa_private_key(
                        key.private.p.as_bytes(),
                        key.private.q.as_bytes(),
                        key.public.e.as_bytes(),
                    )?;

                    rsa_signature(rsa_key, &request.data, request.flags)
                }

                // TODO: Check which other key types are supported by bitwarden
                other => Err(ssh_agent_lib::error::AgentError::Other(
                    format!("Unsupported key type: {other:?}").into(),
                )),
            }
        }
        .await;
        record_ssh_agent_event("ssh_agent.sign", result.is_ok(), audit_meta)
            .await;
        result
    }
}

#[test]
fn rsa_components_preserve_the_ssh_public_key() {
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
    use signature_2::Verifier as _;

    let original = rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap();
    let primes = original.primes();
    let restored = rsa_private_key(
        &primes[0].to_be_bytes(),
        &primes[1].to_be_bytes(),
        &original.e_bytes(),
    )
    .unwrap();
    assert_eq!(original.n_bytes(), restored.n_bytes());
    assert_eq!(original.e_bytes(), restored.e_bytes());

    let public = ssh_agent_lib::ssh_key::public::RsaPublicKey {
        e: ssh_agent_lib::ssh_key::Mpint::from_positive_bytes(
            &original.e_bytes(),
        )
        .unwrap(),
        n: ssh_agent_lib::ssh_key::Mpint::from_positive_bytes(
            &original.n_bytes(),
        )
        .unwrap(),
    };
    let message = b"SSH signature compatibility";
    for flags in [SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512] {
        let signature =
            rsa_signature(restored.clone(), message, flags).unwrap();
        public.verify(message, &signature).unwrap();
        assert!(public.verify(b"different message", &signature).is_err());
    }

    // ssh-key 0.6 does not accept legacy ssh-rsa signatures. Keep the
    // existing failure explicit until the upstream type supports them.
    assert!(rsa_signature(restored, message, 0).is_err());
}
