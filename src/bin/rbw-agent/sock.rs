use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

pub struct Sock(tokio::net::UnixStream);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    // The underlying stream, so that pinentry prompts can watch for the client
    // disconnecting and cancel accordingly.
    pub fn inner(&mut self) -> &mut tokio::net::UnixStream {
        let Self(sock) = self;
        sock
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        if let rbw::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv_login_secret(
        &mut self,
    ) -> anyhow::Result<rbw::locked::Password> {
        use tokio::io::AsyncReadExt as _;
        let len = usize::from(self.0.read_u16().await?);
        anyhow::ensure!(
            (1..=rbw::locked::CAPACITY).contains(&len),
            "invalid login input length"
        );
        let mut bytes = rbw::locked::Vec::try_new()?;
        bytes.zero();
        self.0.read_exact(&mut bytes.data_mut()[..len]).await?;
        bytes.truncate(len);
        std::str::from_utf8(bytes.data())
            .context("login input is not UTF-8")?;
        Ok(rbw::locked::Password::new(bytes))
    }

    pub async fn recv(
        &mut self,
    ) -> anyhow::Result<std::result::Result<rbw::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_str(&line)
            .map_err(|_| "failed to parse agent request".to_owned()))
    }
}

pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let path = rbw::dirs::socket_file();
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_input_frames_are_bounded_and_read_individually() {
        let (mut client, agent) = tokio::net::UnixStream::pair().unwrap();
        let mut agent = Sock::new(agent);
        client
            .write_all(b"\0\x05first\0\x06second\xff\xff")
            .await
            .unwrap();

        assert!(
            agent.recv_login_secret().await.unwrap().password() == b"first"
        );
        assert!(
            agent.recv_login_secret().await.unwrap().password() == b"second"
        );
        assert!(agent.recv_login_secret().await.is_err());
    }
}
