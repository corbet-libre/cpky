//! Synthetic real Keyhole/libSQL acceptance peer for the HTTPS browser fixture.
//! The launch capability uses a private, ephemeral test-only file, never stdout.
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use ckyh::{CreationMonth, LibsqlStore, Passkeys, Url, Uuid};
    use cpky::{
        CeremonyKind, CeremonyRequest, CeremonyResult, Context, VaultOutcome,
        native::BrowserCeremony,
    };
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::{fs::OpenOptions, io::Write, path::PathBuf};
    let mut arguments = std::env::args().skip(1);
    let page = Url::parse(&arguments.next().expect("fixture page")).unwrap();
    let directory = PathBuf::from(arguments.next().expect("private fixture directory"));
    assert!(arguments.next().is_none());
    let origin = page.origin().ascii_serialization();
    let context = || Context::new(&origin, "localhost").unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let database = Url::from_file_path(directory.join("community.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(database.as_str(), "")))
        .unwrap();
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(
            1,
            "browser_loopback",
            ckyh::LIBSQL_SCHEMA,
        )]))
        .unwrap();
    let store = LibsqlStore::new(&db, "synthetic", runtime.handle().clone()).unwrap();
    let server = Passkeys::new(
        store,
        "synthetic",
        "localhost",
        &[Url::parse(&origin).unwrap()],
    )
    .unwrap();
    let launch = |ceremony: &BrowserCeremony, phase: u8| {
        let temporary = directory.join("launch.next");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary).unwrap();
        let value = serde_json::json!({"phase":phase,"url":ceremony.launch_url().as_str()});
        file.write_all(&serde_json::to_vec(&value).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        std::fs::rename(temporary, directory.join("launch.json")).unwrap();
    };
    let member = Uuid::from_u128(171);
    let (options, pending) = server.start_registration(member).unwrap();
    let ceremony = runtime
        .block_on(BrowserCeremony::start(
            context(),
            page.clone(),
            CeremonyRequest {
                kind: CeremonyKind::MemberRegistration,
                options: serde_json::to_value(options).unwrap(),
            },
        ))
        .unwrap();
    launch(&ceremony, 1);
    let CeremonyResult::MemberRegistration(result) = runtime.block_on(ceremony.wait()).unwrap()
    else {
        panic!("registration required")
    };
    let (public, secret) = result.into_parts();
    let original = secret.import(|bytes| blake3::hash(bytes));
    server
        .finish_registration(
            pending,
            &serde_json::from_value(public.into_json()).unwrap(),
            CreationMonth::new(2026, 10).unwrap(),
        )
        .unwrap();
    let (options, pending) = server.start_discoverable_authentication().unwrap();
    let ceremony = runtime
        .block_on(BrowserCeremony::start(
            context(),
            page,
            CeremonyRequest {
                kind: CeremonyKind::Authentication,
                options: serde_json::to_value(options).unwrap(),
            },
        ))
        .unwrap();
    launch(&ceremony, 2);
    let CeremonyResult::Authentication(result) = runtime.block_on(ceremony.wait()).unwrap() else {
        panic!("authentication required")
    };
    let (public, vault) = result.into_parts();
    let VaultOutcome::Ready(secret) = vault else {
        panic!("opaque PRF required")
    };
    assert!(original == secret.import(|bytes| blake3::hash(bytes)));
    assert_eq!(
        server
            .finish_discoverable_authentication(
                pending,
                &serde_json::from_value(public.into_json()).unwrap()
            )
            .unwrap()
            .member(),
        member
    );
    std::fs::remove_file(directory.join("launch.json")).unwrap();
    println!(
        "{{\"registration_verified\":true,\"authentication_verified\":true,\"same_prf\":true}}"
    );
}
#[cfg(target_arch = "wasm32")]
fn main() {}
