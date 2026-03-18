use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use rand::RngCore;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::AppState;

// ── Password Check ─────────────────────────────────────────────────────────

/// Constant-time password comparison to prevent timing attacks.
/// Pads/truncates both sides to a fixed 256-byte buffer so length
/// differences don't leak via timing.
pub fn verify_password(input: &str, expected: &str) -> bool {
    const LEN: usize = 256;
    let mut a = [0u8; LEN];
    let mut b = [0u8; LEN];
    let input_bytes = input.as_bytes();
    let expected_bytes = expected.as_bytes();
    a[..input_bytes.len().min(LEN)].copy_from_slice(&input_bytes[..input_bytes.len().min(LEN)]);
    b[..expected_bytes.len().min(LEN)].copy_from_slice(&expected_bytes[..expected_bytes.len().min(LEN)]);
    let lengths_match = subtle::Choice::from((input_bytes.len() == expected_bytes.len()) as u8);
    let bytes_match = a.ct_eq(&b);
    (lengths_match & bytes_match).into()
}

// ── Session Token ──────────────────────────────────────────────────────────

/// Generate a 32-byte cryptographically random hex token.
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Return an ISO datetime string 7 days from now.
pub fn session_expiry_at() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 7 * 24 * 3600;
    let dt = secs;
    let s = dt % 60;
    let m = (dt / 60) % 60;
    let h = (dt / 3600) % 24;
    let days_since_epoch = dt / 86400;
    format_unix_to_datetime(days_since_epoch, h, m, s)
}

fn format_unix_to_datetime(days: u64, h: u64, m: u64, s: u64) -> String {
    // https://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, m, s)
}

pub fn format_unix_to_datetime_pub(days: u64, h: u64, m: u64, s: u64) -> String {
    format_unix_to_datetime(days, h, m, s)
}

// ── Cookie Builder ─────────────────────────────────────────────────────────

pub fn build_session_cookie(token: &str, secure: bool) -> String {
    let mut cookie = format!(
        "session={}; HttpOnly; SameSite=Strict; Path=/",
        token
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_session_cookie() -> String {
    "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

// ── Axum Extractor ─────────────────────────────────────────────────────────

/// Authenticated session guard. Extract from request; redirects to /login if not valid.
pub struct AuthSession;

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = Arc::<AppState>::from_ref(state);
        let token = extract_session_cookie(&parts.headers);

        if let Some(token) = token {
            if is_valid_session(&state, &token).await {
                return Ok(AuthSession);
            }
        }

        Err(Redirect::to("/login").into_response())
    }
}

fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("session=") {
            let val = val.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

pub fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    extract_session_cookie(headers)
}

async fn is_valid_session(state: &AppState, token: &str) -> bool {
    match crate::db::get_session_expiry(&state.db, token) {
        Ok(Some(expires_at)) => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let now_str = {
                let days = now_secs / 86400;
                let h = (now_secs / 3600) % 24;
                let m = (now_secs / 60) % 60;
                let s = now_secs % 60;
                format_unix_to_datetime(days, h, m, s)
            };
            expires_at > now_str
        }
        _ => false,
    }
}
