use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::Duration as CookieDuration;

use crate::models::auth::{Claims, LoginRequest, LoginResponse};
use crate::routes::AppState;

/// Log in to the platform with an email and password.
/// Sets an HttpOnly cookie containing the JWT on success.
pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // 1. Find user by email
    let row = sqlx::query!(
        "SELECT id, password_hash, role FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&state.db)
    .await;

    let user = match row {
        Ok(Some(r)) => r,
        _ => return StatusCode::UNAUTHORIZED.into_response(), // Generic 401 on not found or DB error
    };

    // 2. Verify Argon2 password
    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        // Record failed login audit log? The ticket says:
        // "Every write in Tickets 12/14/15 inserts an audit_log row"
        // Let's record successful login for now.
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // 3. Issue JWT (~24h expiry)
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id.to_string(),
        role: user.role.clone(),
        exp: expiration,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to encode JWT: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 4. Audit Log entry
    let audit_id = Uuid::new_v4();
    let _ = sqlx::query!(
        "INSERT INTO audit_log (id, actor_id, action, target) VALUES ($1, $2, 'login', $3)",
        audit_id,
        user.id,
        user.id.to_string()
    )
    .execute(&state.db)
    .await;

    // 5. Set HttpOnly Cookie
    let cookie = Cookie::build(("jwt_token", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        // .secure(true) // Typically true in production for HTTPS
        .build();

    (
        StatusCode::OK,
        jar.add(cookie),
        Json(LoginResponse {
            message: "Login successful".to_string(),
        }),
    )
        .into_response()
}

/// Retrieve the currently authenticated user's claims.
pub async fn me_handler(claims: Claims) -> Json<Claims> {
    Json(claims)
}

/// Log out by expiring the JWT cookie.
pub async fn logout_handler(jar: CookieJar) -> impl IntoResponse {
    // Explicitly mirror the original cookie attributes so the browser
    // can match and overwrite it correctly, then expire it.
    let removal = Cookie::build(("jwt_token", ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(-1))
        .build();

    (
        StatusCode::OK,
        jar.add(removal),
        Json(LoginResponse {
            message: "Logged out".to_string(),
        }),
    )
        .into_response()
}
