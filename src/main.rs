use std::error::Error;
use std::net::SocketAddr;
use tls_parser::{gen_tls_clienthello, gen_tls_extensions, parse_tls_client_hello_extension, parse_tls_extensions, parse_tls_plaintext, Serialize, TlsExtension, TlsMessage, TlsMessageHandshake};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use cookie_factory::{gen_simple};
use fast_socks5::client::{Config, Socks5Stream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:9443").await?;

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            process_socket(socket).await.unwrap();
        });
    }
}

async fn process_socket(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 1024];
    let n = stream.read_buf(&mut buffer.as_mut()).await?;
    let (rem, mut plaintext) = parse_tls_plaintext(&buffer[..n]).unwrap();
    let msg = match plaintext.msg.first_mut() {
        Some(msg) => msg,
        None => return Err("No TLS message found".into()),
    };
    let handshake = match msg {
        TlsMessage::Handshake(handshake) => handshake,
        _ => return Err("No TLS handshake found".into()),
    };
    let client_hello = match handshake {
        TlsMessageHandshake::ClientHello(client_hello) => client_hello,
        _ => return Err("No ClientHello found".into()),
    };
    let extensions = match client_hello.ext {
        Some(extensions) => extensions,
        None => return Err("No extensions found".into()),
    };


    let mut new_extensions = Vec::new();
    let mut buf = extensions;
    loop {
        let (reste, first) = parse_tls_client_hello_extension(buf).unwrap();
        if matches!(first, TlsExtension::ALPN(_)) {
            let end_of_stuff_before = extensions.len() - buf.len();
            new_extensions.extend_from_slice(&extensions[..end_of_stuff_before]);
            let test = extensions.len() - reste.len();
            //new_extensions.resize(test, 0);
            //new_extensions.extend_from_slice(&extensions[end_of_stuff_before..test]);
            new_extensions.extend_from_slice(reste);
            break;
        }
        buf = reste;
    }


    let (_, mut extensions) = parse_tls_extensions(extensions).unwrap();
    let sni = extensions
        .iter()
        .filter_map(|ext| match ext {
            TlsExtension::SNI(sni) => Some(sni),
            _ => None,
        })
        .next();

    let (_, sni) = match sni.and_then(|sni| sni.iter().next()) {
        Some(sni) => sni,
        None => return Err("No SNI found".into()),
    };

    let sni = std::str::from_utf8(sni)?;

    println!("SNI: {:?}", sni);

    client_hello.ext = Some(&new_extensions);

    let mut upstream = TcpStream::connect("76.76.21.21:443").await?;

    let mut msg = plaintext.serialize()?;
    upstream.write_all(&msg).await?;

    let res = copy_bidirectional(&mut stream, &mut upstream).await;
    println!("finished: {:?}", res);

    Ok(())
}
