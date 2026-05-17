//! End-to-end test against shadowsocks-rust using dns-tunnel as a SIP003
//! plugin. The test is skipped (with a printed reason) if `sslocal` or
//! `ssserver` are not on PATH, so it stays friendly on machines without
//! shadowsocks-rust installed.
//!
//! Topology:
//!
//!   [TCP client] -SOCKS5-> sslocal --plugin(client)--QUIC/doq--> ssserver --plugin(server)--> [TCP echo]
//!
//! The test writes shadowsocks config JSONs to a temp dir, spawns the four
//! processes, runs a SOCKS5 CONNECT to the in-process echo server, then
//! shuts everything down.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "dns-tunnel-test";
const METHOD: &str = "chacha20-ietf-poly1305";

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn write_json(path: &std::path::Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_echo(port: u16) -> std::thread::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut conn = match conn {
                Ok(c) => c,
                Err(_) => continue,
            };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    let n = match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    })
}

/// Minimal SOCKS5 CONNECT (no auth) to `target_port` on 127.0.0.1 through
/// the SOCKS proxy on `socks_port`. Returns the tunneled TcpStream.
fn socks5_connect(socks_port: u16, target_port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    // greeting: ver=5, nmethods=1, NO_AUTH
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp)?;
    assert_eq!(resp, [0x05, 0x00], "socks greeting");
    // request: ver=5, cmd=CONNECT, rsv=0, atyp=IPv4, addr, port
    let port_be = target_port.to_be_bytes();
    s.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port_be[0], port_be[1]])?;
    // reply: 4 bytes header + addr + port
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    assert_eq!(hdr[0], 0x05, "socks reply ver");
    assert_eq!(hdr[1], 0x00, "socks reply status (expected SUCCESS)");
    let addr_len = match hdr[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        other => panic!("unexpected atyp {other}"),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip)?;
    Ok(s)
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn end_to_end_with_shadowsocks_rust() {
    let sslocal = match which("sslocal") {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sslocal not on PATH; install shadowsocks-rust to run this test");
            return;
        }
    };
    let ssserver = match which("ssserver") {
        Some(p) => p,
        None => {
            eprintln!("SKIP: ssserver not on PATH");
            return;
        }
    };
    let plugin = PathBuf::from(env!("CARGO_BIN_EXE_dns-tunnel"));
    assert!(plugin.is_file(), "dns-tunnel bin not built at {plugin:?}");

    let tmp = tempdir();
    let echo_port = pick_free_port();
    let plugin_server_port = pick_free_port(); // dns-tunnel server listens here (UDP/QUIC)
    let socks_port = pick_free_port(); // sslocal SOCKS5

    let _echo = spawn_echo(echo_port);

    // ssserver config: listens on TCP 127.0.0.1:ss_server_port, plugin invocation
    // tells dns-tunnel to expose its public QUIC on plugin_server_port.
    let server_cfg = serde_json::json!({
        "server": "127.0.0.1",
        "server_port": plugin_server_port,
        "password": PASSWORD,
        "method": METHOD,
        "plugin": plugin.to_str().unwrap(),
        "plugin_opts": "mode=server;sni=test.local",
        "plugin_mode": "tcp_only"
    });
    // sslocal config: connects through plugin (which exposes plugin_client_port
    // locally), and forwards the resulting bytes to plugin_server_port.
    let client_cfg = serde_json::json!({
        "server": "127.0.0.1",
        "server_port": plugin_server_port,
        "local_address": "127.0.0.1",
        "local_port": socks_port,
        "password": PASSWORD,
        "method": METHOD,
        "plugin": plugin.to_str().unwrap(),
        "plugin_opts": "mode=client;sni=test.local;insecure",
        "plugin_mode": "tcp_only"
    });
    let server_cfg_path = tmp.path().join("server.json");
    let client_cfg_path = tmp.path().join("client.json");
    write_json(&server_cfg_path, &server_cfg);
    write_json(&client_cfg_path, &client_cfg);

    let mut server = Killer(
        Command::new(&ssserver)
            .arg("-c")
            .arg(&server_cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ssserver"),
    );
    let mut client = Killer(
        Command::new(&sslocal)
            .arg("-c")
            .arg(&client_cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sslocal"),
    );

    assert!(
        wait_for_port(socks_port, Duration::from_secs(10)),
        "sslocal SOCKS5 port {socks_port} never came up"
    );

    let mut conn = socks5_connect(socks_port, echo_port).expect("SOCKS5 CONNECT");
    let payload: Vec<u8> = (0..32_000u32).map(|i| (i & 0xff) as u8).collect();
    conn.write_all(&payload).expect("write payload");
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).expect("read echo");
    assert_eq!(got, payload, "echo round-trip differed");

    drop(conn);
    let _ = server.0.kill();
    let _ = client.0.kill();
}

// Minimal tempdir — `tempfile` would be cleaner but I want to keep deps out
// of the production graph; this is enough for one test.
fn tempdir() -> TempDir {
    let mut p = std::env::temp_dir();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("dns-tunnel-test-{stamp}"));
    std::fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

struct TempDir(PathBuf);
impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
