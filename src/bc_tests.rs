// Teste BancControl (Etapa 1). Rulează în GitHub Actions: crate-ul cere dependențe native (vcpkg).
use hbb_common::config::{RENDEZVOUS_SERVERS, RS_PUB_KEY};

#[test]
fn branded_defaults() {
    assert_eq!(crate::common::get_app_name(), "BancControl");
    assert!(crate::common::is_custom_client());
    assert!(!crate::common::is_rustdesk());
    assert!(RENDEZVOUS_SERVERS.iter().all(|s| !s.contains("rustdesk.com")));
    assert_ne!(RS_PUB_KEY, "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=");
    assert!(crate::common::get_rs_pk(RS_PUB_KEY).is_some());
}

// ---- Task 4/5: config semnat, stare blocată, rol ----
use crate::common::{
    apply_bc_locked_defaults, encode64, get_builtin_option, read_custom_client_with_key,
    BC_LOCKED_DEFAULTS,
};
use hbb_common::config::{is_disable_settings, is_incoming_only, is_outgoing_only};
use hbb_common::sodiumoxide::crypto::sign;
use std::sync::Mutex;

// Setările sunt statice globale: testele care le ating rulează pe rând.
static GLOBAL_SETTINGS: Mutex<()> = Mutex::new(());

fn reset_settings() {
    hbb_common::config::BUILTIN_SETTINGS.write().unwrap().clear();
    hbb_common::config::HARD_SETTINGS.write().unwrap().clear();
}

fn signed(json: &str, sk: &sign::SecretKey) -> String {
    encode64(sign::sign(json.as_bytes(), sk))
}

// Aceleași profiluri ca în res/bc/*.json (conținutul fișierelor se verifică în test separat).
const BENCH: &str = include_str!("../res/bc/bench.json");
const MASTER: &str = include_str!("../res/bc/master.json");
const RECEPTION: &str = include_str!("../res/bc/reception.json");

fn assert_locked() {
    for k in BC_LOCKED_DEFAULTS {
        assert_eq!(get_builtin_option(k), "Y", "{k} trebuie să fie blocat");
    }
    assert!(is_disable_settings());
    assert!(is_incoming_only());
}

#[test]
fn locked_by_default_without_config() {
    let _g = GLOBAL_SETTINGS.lock().unwrap_or_else(|e| e.into_inner());
    reset_settings();
    apply_bc_locked_defaults();
    assert_locked();
}

#[test]
fn custom_client_accepts_own_signature_bench_profile() {
    let _g = GLOBAL_SETTINGS.lock().unwrap_or_else(|e| e.into_inner());
    reset_settings();
    let (pk, sk) = sign::gen_keypair();
    read_custom_client_with_key(&signed(BENCH, &sk), &encode64(pk.0));
    assert_locked();
}

#[test]
fn custom_client_rejects_foreign_signature() {
    let _g = GLOBAL_SETTINGS.lock().unwrap_or_else(|e| e.into_inner());
    reset_settings();
    apply_bc_locked_defaults();
    let (pk_ours, _) = sign::gen_keypair();
    let (_, sk_other) = sign::gen_keypair();
    // profil „deblocant" semnat cu altă cheie: trebuie ignorat, starea rămâne blocată
    read_custom_client_with_key(&signed(MASTER, &sk_other), &encode64(pk_ours.0));
    assert_locked();
}

#[test]
fn custom_client_rejects_garbage() {
    let _g = GLOBAL_SETTINGS.lock().unwrap_or_else(|e| e.into_inner());
    reset_settings();
    apply_bc_locked_defaults();
    let (pk, _) = sign::gen_keypair();
    read_custom_client_with_key("nu-este-base64!!", &encode64(pk.0));
    read_custom_client_with_key(&encode64(b"gunoi"), &encode64(pk.0));
    assert_locked();
}

#[test]
fn master_profile_unlocks_and_is_outgoing() {
    let _g = GLOBAL_SETTINGS.lock().unwrap_or_else(|e| e.into_inner());
    reset_settings();
    apply_bc_locked_defaults();
    let (pk, sk) = sign::gen_keypair();
    read_custom_client_with_key(&signed(MASTER, &sk), &encode64(pk.0));
    for k in BC_LOCKED_DEFAULTS {
        assert_eq!(get_builtin_option(k), "N");
    }
    assert!(!is_disable_settings());
    assert!(is_outgoing_only());
    assert!(!is_incoming_only());
}

#[test]
fn reception_profile_is_both_roles_with_settings() {
    let _g = GLOBAL_SETTINGS.lock().unwrap_or_else(|e| e.into_inner());
    reset_settings();
    apply_bc_locked_defaults();
    let (pk, sk) = sign::gen_keypair();
    read_custom_client_with_key(&signed(RECEPTION, &sk), &encode64(pk.0));
    assert!(!is_incoming_only());
    assert!(!is_outgoing_only());
    assert!(!is_disable_settings());
}
