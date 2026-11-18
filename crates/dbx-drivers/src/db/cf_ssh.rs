//! CF CLI integration. Each API/org/space has a private CF_HOME so login and
//! targeting never change the user's terminal session. No shell is invoked,
//! and SSO passcodes travel through stdin, not argv, config, or logs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration, Instant};

use super::ssh_prompt::{request_ssh_prompt, SshPromptAnswer, UserInputRequest};
use crate::models::connection::CfSshConfig;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_OUTPUT: u64 = 1024 * 1024;

pub fn validate_config(config: &CfSshConfig) -> Result<(), String> {
    let url = reqwest::Url::parse(config.api_endpoint.trim()).map_err(|_| "CF API endpoint must be an HTTPS URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("CF API endpoint must be an HTTPS origin without credentials, query, or path".into());
    }
    for (name, value) in [("organization", &config.org), ("space", &config.space), ("application", &config.app)] {
        if value.trim().is_empty() || value.trim().starts_with('-') || value.chars().any(char::is_control) {
            return Err(format!("CF {name} is required and must not start with '-' or contain control characters"));
        }
    }
    Ok(())
}

fn cf_executable() -> PathBuf {
    // GUI apps on macOS commonly have a minimal PATH without Homebrew.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(if cfg!(windows) { "cf.exe" } else { "cf" });
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    #[cfg(target_os = "macos")]
    for path in ["/opt/homebrew/bin/cf", "/usr/local/bin/cf"] {
        if Path::new(path).is_file() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(if cfg!(windows) { "cf.exe" } else { "cf" })
}

pub struct CfSession {
    home: TempDir,
    executable: PathBuf,
    login_lock: Mutex<bool>,
}

impl CfSession {
    fn new(executable: PathBuf, data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir).map_err(|_| "Unable to create private CF session directory")?;
        let home = tempfile::Builder::new()
            .prefix("cf-session-")
            .tempdir_in(data_dir)
            .map_err(|_| "Unable to create private CF session directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Unable to protect private CF session directory")?;
        }
        Ok(Self { home, executable, login_lock: Mutex::new(false) })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .env("CF_HOME", self.home.path())
            .env("CF_COLOR", "false")
            .env("CF_TRACE", "false")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command
    }

    async fn run(&self, args: &[&str], input: Option<&str>) -> Result<String, String> {
        let operation = args.first().copied().unwrap_or("command");
        let mut command = self.command();
        command.args(args);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|_| "Unable to start CF CLI. Install Cloud Foundry CLI and ensure 'cf' is executable")?;
        let result = timeout(COMMAND_TIMEOUT, async {
            if let Some(input) = input {
                let mut stdin = child.stdin.take().ok_or("CF login input is unavailable")?;
                stdin.write_all(input.as_bytes()).await.map_err(|_| "Unable to send CF SSO passcode")?;
                stdin.write_all(b"\n").await.map_err(|_| "Unable to send CF SSO passcode")?;
                stdin.shutdown().await.map_err(|_| "Unable to finish CF login input")?;
            }
            let mut output = Vec::new();
            child
                .stdout
                .take()
                .ok_or("CF command output is unavailable")?
                .take(MAX_OUTPUT + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| "Unable to read CF command output")?;
            if output.len() as u64 > MAX_OUTPUT {
                return Err("CF command output exceeded its limit".to_string());
            }
            if !child.wait().await.map_err(|_| "Unable to wait for CF command")?.success() {
                // Never surface CLI output: login failures may echo credentials.
                return Err(format!(
                    "CF {operation} failed. Check the API endpoint, SSO login, organization, space, and permissions"
                ));
            }
            Ok(String::from_utf8_lossy(&output).into_owned())
        })
        .await
        .map_err(|_| format!("CF {operation} timed out"))?;
        result
    }

    async fn login(&self, config: &CfSshConfig) -> Result<(), String> {
        let mut logged_in = self.login_lock.lock().await;
        if *logged_in {
            // `cf curl` refreshes an expired access token if the refresh token is
            // still valid. Unlike `cf oauth-token`, this verifies authentication.
            let valid = self
                .run(&["curl", "/v3/organizations?per_page=1"], None)
                .await
                .ok()
                .and_then(|output| serde_json::from_str::<serde_json::Value>(&output).ok())
                .is_some_and(|value| value.get("resources").is_some());
            if valid {
                return Ok(());
            }
            *logged_in = false;
        }
        self.run(&["api", config.api_endpoint.trim()], None).await?;
        let info = self.run(&["curl", "/v2/info"], None).await?;
        let info: serde_json::Value =
            serde_json::from_str(&info).map_err(|_| "CF API returned invalid discovery information")?;
        let authorization_endpoint =
            info["authorization_endpoint"].as_str().ok_or("CF API did not provide an SSO endpoint")?;
        let mut passcode_url =
            reqwest::Url::parse(authorization_endpoint).map_err(|_| "CF API returned an invalid SSO endpoint")?;
        if passcode_url.scheme() != "https"
            || passcode_url.host_str().is_none()
            || !passcode_url.username().is_empty()
            || passcode_url.password().is_some()
        {
            return Err("CF SSO endpoint must use HTTPS without embedded credentials".into());
        }
        passcode_url.set_path("/passcode");
        passcode_url.set_query(None);
        passcode_url.set_fragment(None);
        let request = UserInputRequest::new(format!(
            "Open this URL in your browser, sign in, then paste the one-time SSO passcode:\n{passcode_url}"
        ))
        .with_title(Some("Cloud Foundry SSO login".into()))
        .with_source(Some("Cloud Foundry".into()))
        .into_request(config.api_endpoint.trim(), 443);
        let receiver = request_ssh_prompt(request).ok_or("CF SSO login requires an interactive DBX session")?;
        let answer = timeout(LOGIN_TIMEOUT, receiver)
            .await
            .map_err(|_| "CF SSO login timed out")?
            .map_err(|_| "CF SSO login was cancelled")?;
        let SshPromptAnswer::Secret(passcode) = answer else {
            return Err("CF SSO login was cancelled".into());
        };
        let passcode = passcode.trim();
        if passcode.is_empty() || passcode.chars().any(char::is_control) {
            return Err("CF SSO passcode must be a non-empty single line".into());
        }
        self.run(&["login", "--sso", "-o", config.org.trim(), "-s", config.space.trim()], Some(passcode)).await?;
        *logged_in = true;
        Ok(())
    }
}

#[derive(Default)]
pub struct CfSessions {
    sessions: Mutex<HashMap<String, Arc<CfSession>>>,
}

impl CfSessions {
    pub async fn session(&self, config: &CfSshConfig, data_dir: &Path) -> Result<Arc<CfSession>, String> {
        validate_config(config)?;
        let key = serde_json::to_string(&(config.api_endpoint.trim(), config.org.trim(), config.space.trim()))
            .map_err(|_| "Invalid CF session configuration")?;
        let session = {
            let mut sessions = self.sessions.lock().await;
            if let Some(session) = sessions.get(&key) {
                session.clone()
            } else {
                let session = Arc::new(CfSession::new(cf_executable(), data_dir)?);
                sessions.insert(key, session.clone());
                session
            }
        };
        session.login(config).await?;
        Ok(session)
    }

    pub async fn clear(&self) {
        self.sessions.lock().await.clear();
    }
}

fn tunnel_args(config: &CfSshConfig, local_port: u16, remote_host: &str, remote_port: u16) -> Vec<String> {
    let host = if remote_host.contains(':') { format!("[{remote_host}]") } else { remote_host.to_string() };
    vec![
        "ssh".into(),
        config.app.trim().into(),
        "-N".into(),
        "-i".into(),
        config.instance_index.to_string(),
        "-L".into(),
        format!("127.0.0.1:{local_port}:{host}:{remote_port}"),
    ]
}

pub async fn start_forward(
    session: &CfSession,
    config: &CfSshConfig,
    remote_host: &str,
    remote_port: u16,
    requested_local_port: Option<u16>,
    connect_timeout_secs: u64,
) -> Result<(Child, u16), String> {
    if remote_host.trim().is_empty() || remote_host.chars().any(char::is_control) || remote_port == 0 {
        return Err("CF SSH forwarding requires a database hostname and port".into());
    }
    let listener = TcpListener::bind(("127.0.0.1", requested_local_port.unwrap_or(0)))
        .await
        .map_err(|_| "Unable to reserve the CF SSH local port. It may already be in use")?;
    let local_port = listener.local_addr().map_err(|_| "Unable to read CF SSH local port")?.port();
    let mut command = session.command();
    command.args(tunnel_args(config, local_port, remote_host, remote_port)).stdout(Stdio::null()).stderr(Stdio::null());
    // The CLI owns its listener. Release the reservation immediately before
    // spawning; any competing bind causes CF SSH to fail, never a LAN bind.
    drop(listener);
    let mut child = command.spawn().map_err(|_| "Unable to start CF SSH. Install Cloud Foundry CLI")?;
    let deadline = Instant::now() + Duration::from_secs(connect_timeout_secs.clamp(1, 300));
    loop {
        if child.try_wait().map_err(|_| "Unable to check CF SSH process")?.is_some() {
            return Err("CF SSH failed. Ensure the application is running, SSH is enabled for its space and app, and your user has SSH access".into());
        }
        if timeout(Duration::from_millis(100), TcpStream::connect(("127.0.0.1", local_port)))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            // Let an immediate bind/authentication failure surface instead of
            // mistaking another process on the chosen port for our listener.
            sleep(Duration::from_millis(100)).await;
            if child.try_wait().map_err(|_| "Unable to check CF SSH process")?.is_some() {
                return Err("CF SSH failed while opening its local forward".into());
            }
            return Ok((child, local_port));
        }
        if Instant::now() >= deadline {
            return Err("CF SSH timed out while opening its local forward".into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn config() -> CfSshConfig {
        CfSshConfig {
            api_endpoint: "https://api.cf.example.com".into(),
            org: "team org".into(),
            space: "dev".into(),
            app: "ssh-proxy".into(),
            instance_index: 2,
        }
    }

    #[test]
    fn validates_endpoint_and_required_target_without_shell_injection() {
        assert!(validate_config(&config()).is_ok());
        for endpoint in [
            "http://api.example.com",
            "https://user:secret@api.example.com",
            "https://api.example.com/path",
            "https://api.example.com?token=secret",
        ] {
            let mut config = config();
            config.api_endpoint = endpoint.into();
            assert!(validate_config(&config).is_err(), "{endpoint}");
        }
        for app in ["", "--skip-host-validation", " --skip-host-validation", "app\nother"] {
            let mut config = config();
            config.app = app.into();
            assert!(validate_config(&config).is_err());
        }
    }

    #[test]
    fn forward_is_loopback_only_and_preserves_remote_hostname() {
        assert_eq!(
            tunnel_args(&config(), 43123, "hana.example.com", 443),
            ["ssh", "ssh-proxy", "-N", "-i", "2", "-L", "127.0.0.1:43123:hana.example.com:443"]
        );
        assert!(tunnel_args(&config(), 43123, "::1", 443).last().unwrap().contains("[::1]"));
    }

    #[cfg(unix)]
    pub(crate) fn fake_session(dir: &Path) -> CfSession {
        use std::os::unix::fs::PermissionsExt;
        let executable = dir.join("fake-cf");
        let test_binary = std::env::current_exe().unwrap();
        // The listener runs this test executable, not Python or a real CF CLI.
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$@" >> "$CF_HOME/argv"
case "$1" in
  api) exit 0 ;;
  curl)
    if [ "$2" = '/v2/info' ]; then
      printf '%s' '{{"authorization_endpoint":"https://login.cf.example.com"}}'
    elif [ -f "$CF_HOME/auth" ]; then
      printf '%s' '{{"resources":[]}}'
    else
      printf '%s' '{{"errors":[{{"code":10002}}]}}'
    fi ;;
  login)
    read -r passcode
    printf '%s' "$passcode" > "$CF_HOME/passcode"
    if [ "$passcode" = 'reject-secret' ]; then
      printf '%s' "$passcode"
      exit 1
    fi
    touch "$CF_HOME/auth" ;;
  ssh)
    for arg do last="$arg"; done
    export CF_TEST_FORWARD="$last"
    exec '{}' --exact db::cf_ssh::tests::fake_cf_listener --nocapture --test-threads=1 ;;
esac
"#,
            test_binary.display()
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        CfSession::new(executable, dir).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn fake_cf_listener() {
        let Ok(spec) = std::env::var("CF_TEST_FORWARD") else { return };
        let mut parts = spec.split(':');
        let host = parts.next().unwrap();
        let port = parts.next().unwrap().parse::<u16>().unwrap();
        let listener = std::net::TcpListener::bind((host, port)).unwrap();
        for stream in listener.incoming() {
            drop(stream.unwrap());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sso_uses_private_home_and_stdin_and_reuses_login_until_expired() {
        use super::super::ssh_prompt::{
            clear_ssh_prompt_gateway, install_ssh_prompt_gateway, prompt_gateway_test_lock,
        };
        let _guard = prompt_gateway_test_lock().lock().await;
        let dir = tempfile::tempdir().unwrap();
        let session = Arc::new(fake_session(dir.path()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        install_ssh_prompt_gateway(tx);
        let task_session = session.clone();
        let task = tokio::spawn(async move { task_session.login(&config()).await });
        let prompt = timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert_eq!(prompt.request.source.as_deref(), Some("Cloud Foundry"));
        assert!(!prompt.request.echo);
        assert!(prompt.request.prompt.unwrap().contains("https://login.cf.example.com/passcode"));
        prompt.responder.send(SshPromptAnswer::Secret("one-time-secret".into())).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(session.home.path().join("passcode")).unwrap(), "one-time-secret");
        let args = std::fs::read_to_string(session.home.path().join("argv")).unwrap();
        assert!(args.contains("--sso\n-o\nteam org\n-s\ndev"));
        assert!(!args.contains("one-time-secret"));
        session.login(&config()).await.unwrap();
        assert!(rx.try_recv().is_err(), "valid sessions must not prompt again");
        std::fs::remove_file(session.home.path().join("auth")).unwrap();
        let task_session = session.clone();
        let task = tokio::spawn(async move { task_session.login(&config()).await });
        let prompt = timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        prompt.responder.send(SshPromptAnswer::Reject).unwrap();
        assert!(task.await.unwrap().unwrap_err().contains("cancelled"));
        clear_ssh_prompt_gateway();
        let home = session.home.path().to_path_buf();
        drop(session);
        assert!(!home.exists(), "dropping the session must clean up CF_HOME");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_login_never_exposes_passcode_in_error_or_argv() {
        let dir = tempfile::tempdir().unwrap();
        let session = fake_session(dir.path());
        let error = session.run(&["login", "--sso"], Some("reject-secret")).await.unwrap_err();
        assert!(!error.contains("reject-secret"));
        assert!(!std::fs::read_to_string(session.home.path().join("argv")).unwrap().contains("reject-secret"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sso_fails_closed_without_interactive_ui() {
        use super::super::ssh_prompt::{clear_ssh_prompt_gateway, prompt_gateway_test_lock};
        let _guard = prompt_gateway_test_lock().lock().await;
        clear_ssh_prompt_gateway();
        let dir = tempfile::tempdir().unwrap();
        let session = fake_session(dir.path());
        let error = session.login(&config()).await.unwrap_err();
        assert!(error.contains("interactive DBX session"));
        assert!(!std::fs::read_to_string(session.home.path().join("argv")).unwrap().contains("login\n"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn forward_releases_local_port_after_stop_and_rejects_occupied_port() {
        let dir = tempfile::tempdir().unwrap();
        let session = fake_session(dir.path());
        let (mut child, port) = start_forward(&session, &config(), "hana.example.com", 443, None, 5).await.unwrap();
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());
        child.kill().await.unwrap();
        let reservation = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let error = start_forward(&session, &config(), "hana.example.com", 443, Some(port), 5).await.err().unwrap();
        assert!(error.contains("already be in use"));
        drop(reservation);
    }
}
