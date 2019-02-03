#![feature(try_from)]
use argparse::ArgumentParser;
use argparse::Store;
use argparse::StoreTrue;
use bytes::Bytes;
use futures::sync::oneshot;
use futures::Future;
use futures::Sink;
use futures::Stream;
use mumble_protocol::control::msgs;
use mumble_protocol::control::ClientControlCodec;
use mumble_protocol::control::ControlPacket;
use mumble_protocol::crypt::ClientCryptState;
use mumble_protocol::voice::VoicePacket;
use mumble_protocol::voice::VoicePacketPayload;
use std::convert::Into;
use std::convert::TryInto;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tokio::net::UdpFramed;
use tokio::net::UdpSocket;
use tokio_codec::Decoder;
use tokio_tls::TlsConnector;

fn connect(
    server_addr: SocketAddr,
    server_host: String,
    user_name: String,
    accept_invalid_cert: bool,
    crypt_state_sender: oneshot::Sender<ClientCryptState>,
) -> impl Future<Item = (), Error = ()> {
    // Wrap crypt_state_sender in Option, so we can move it into a FnMut and only call it once
    let mut crypt_state_sender = Some(crypt_state_sender);

    // Connect to server via TCP
    TcpStream::connect(&server_addr)
        .map_err(|err| panic!("Failed to connect to server: {}", err))
        .and_then(move |stream| {
            println!("TCP connected..");
            // Wrap the connection in TLS
            let mut builder = native_tls::TlsConnector::builder();
            builder.danger_accept_invalid_certs(accept_invalid_cert);
            let connector: TlsConnector = builder
                .build()
                .expect("Failed to create TLS connector")
                .into();
            connector
                .connect(&server_host, stream)
                .map_err(|err| panic!("Failed to connect TLS: {}", err))
        })
        .and_then(move |tls_stream| {
            println!("TLS connected..");
            // Wrap the TLS stream with Mumble's client-side control-channel codec
            let (sink, stream) = ClientControlCodec::new().framed(tls_stream).split();

            // Handshake (omitting `Version` message for brevity)
            let mut msg = msgs::Authenticate::new();
            msg.set_username(user_name);
            msg.set_opus(true);
            sink.send(msg.into()).map(move |sink| (sink, stream))
        })
        .and_then(move |(sink, stream)| {
            println!("Logging in..");
            let mut crypt_state = None;
            stream
                // Handle incoming packets
                .filter_map(move |packet| match packet {
                    ControlPacket::TextMessage(mut msg) => {
                        println!(
                            "Got message from user with session ID {}: {}",
                            msg.get_actor(),
                            msg.get_message()
                        );
                        // Prepare reply
                        let mut response = msgs::TextMessage::new();
                        response.mut_session().push(msg.get_actor());
                        response.set_message(msg.take_message());
                        Some(response.into())
                    }
                    ControlPacket::CryptSetup(msg) => {
                        // Wait until we're fully connected before initiating UDP voice
                        crypt_state = Some(ClientCryptState::new_from(
                            msg.get_key()
                                .try_into()
                                .expect("Server sent private key with incorrect size"),
                            msg.get_client_nonce()
                                .try_into()
                                .expect("Server sent client_nonce with incorrect size"),
                            msg.get_server_nonce()
                                .try_into()
                                .expect("Server sent server_nonce with incorrect size"),
                        ));
                        None
                    }
                    ControlPacket::ServerSync(_) => {
                        println!("Logged in!");
                        if let Some(sender) = crypt_state_sender.take() {
                            let _ = sender.send(
                                crypt_state
                                    .take()
                                    .expect("Server didn't send us any CryptSetup packet!"),
                            );
                        }
                        None
                    }
                    ControlPacket::Reject(msg) => {
                        println!("Login rejected: {:?}", msg);
                        None
                    }
                    _ => None,
                })
                // Send replies back to server
                // Note: A normal application also has to send periodic Ping packets
                .forward(sink)
        })
        .map(|_| ())
        .map_err(|err| panic!(err))
}

fn handle_udp(
    server_addr: SocketAddr,
    crypt_state: oneshot::Receiver<ClientCryptState>,
) -> impl Future<Item = (), Error = ()> {
    // Bind UDP socket
    let udp_socket =
        UdpSocket::bind(&(Ipv6Addr::from(0u128), 0u16).into()).expect("Failed to bind UDP socket");

    // disconnected before we received the CryptSetup packet, oh well
    let crypt_state = crypt_state.map_err(|_| ());

    // Wait for initial CryptState
    crypt_state.and_then(move |crypt_state| {
        println!("UDP ready!");
        // Wrap the raw UDP packets in Mumble's crypto and voice codec (CryptState does both)
        let (sink, source) = UdpFramed::new(udp_socket, crypt_state).split();
        source
            // Handle incoming UDP packets
            .map(|(packet, src_addr)| match packet {
                VoicePacket::Ping { .. } => {
                    // Note: A normal application would handle these and only use UDP for voice
                    //       once it has received one.
                    None
                }
                VoicePacket::Audio {
                    seq_num,
                    payload,
                    position_info,
                    ..
                } => {
                    // Got audio, naively echo it back
                    let reply = VoicePacket::Audio {
                        _dst: std::marker::PhantomData,
                        target: 0,      // normal speech
                        session_id: (), // unused for server-bound packets
                        seq_num,
                        payload,
                        position_info,
                    };
                    Some((reply, src_addr))
                }
            })
            .or_else(|err| {
                eprintln!("Got an invalid UDP packet: {}", err);
                // To be expected, considering this is the internet, just ignore it
                Ok(None)
            })
            .filter_map(|it| it)
            // Note: A normal application would also send periodic Ping packets, and its own audio
            //       via UDP. We instead trick the server into accepting us by sending it one
            //       dummy voice packet.
            .select(futures::stream::once(Ok((
                VoicePacket::Audio {
                    _dst: std::marker::PhantomData,
                    target: 0,
                    session_id: (),
                    seq_num: 0,
                    payload: VoicePacketPayload::Opus(Bytes::from([0u8; 128].as_ref()), true),
                    position_info: None,
                },
                server_addr,
            ))))
            // Send replies back to server
            .forward(sink)
            .map_err(|err: std::io::Error| panic!("Error sending UDP packet: {}", err))
            .map(|_| ())
    })
}

fn main() {
    // Handle command line arguments
    let mut server_host = "".to_string();
    let mut server_port = 64738u16;
    let mut user_name = "EchoBot".to_string();
    let mut accept_invalid_cert = false;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Run the echo client example");
        ap.refer(&mut server_host)
            .add_option(&["--host"], Store, "Hostname of mumble server")
            .required();
        ap.refer(&mut server_port)
            .add_option(&["--port"], Store, "Port of mumble server");
        ap.refer(&mut user_name)
            .add_option(&["--username"], Store, "User name used to connect");
        ap.refer(&mut accept_invalid_cert).add_option(
            &["--accept-invalid-cert"],
            StoreTrue,
            "Accept invalid TLS certificates",
        );
        ap.parse_args_or_exit();
    }
    let server_addr = (server_host.as_ref(), server_port)
        .to_socket_addrs()
        .expect("Failed to parse server address")
        .next()
        .expect("Failed to resolve server address");

    // Oneshot channel for setting UDP CryptState from control task
    // For simplicity we don't deal with re-syncing, real applications would have to.
    let (crypt_state_sender, crypt_state_receiver) = oneshot::channel::<ClientCryptState>();

    // Run it
    tokio::run(
        connect(
            server_addr,
            server_host,
            user_name,
            accept_invalid_cert,
            crypt_state_sender,
        )
        .select(handle_udp(server_addr, crypt_state_receiver))
        .map_err(|_| ())
        .map(|_| ()),
    );
}
