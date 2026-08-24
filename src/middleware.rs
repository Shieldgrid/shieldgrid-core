use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use tracing::warn;

use crate::models::auth::Claims;
use crate::routes::AppState;

/// Extractor for JWT authentication.
///
/// Verifies the `Authorization: Bearer <token>` header, decodes the token
/// using the application's JWT secret, and extracts the claims.
/// Returns `401 Unauthorized` if the token is missing, invalid, or expired.
impl FromRequestParts<AppState> for Claims {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Check for a static API token in the Authorization header.
        if let Some(auth_header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if state.config.api_tokens.iter().any(|t| t == token) {
                        return Ok(Claims {
                            sub: "mcp-service-account".to_string(),
                            role: "admin".to_string(),
                            exp: 0,
                        });
                    }
                }
            }
        }

        // 2. Fall back to the session cookie.
        let jar = axum_extra::extract::cookie::CookieJar::from_headers(&parts.headers);

        let token = match jar.get("jwt_token").map(|c| c.value()) {
            Some(token) => token,
            None => {
                warn!("Missing jwt_token cookie");
                return Err(StatusCode::UNAUTHORIZED.into_response());
            }
        };

        let secret = &state.config.jwt_secret;
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| {
            warn!("JWT validation failed: {e}");
            StatusCode::UNAUTHORIZED.into_response()
        })?;

        Ok(token_data.claims)
    }
}

/// Extractor to enforce the `admin` role.
///
/// Wraps `Claims` to first validate the JWT, then asserts that the `role` is `"admin"`.
/// Returns `403 Forbidden` if the user is authenticated but not an admin.
#[allow(dead_code)]
pub struct RequireAdmin(pub Claims);

impl FromRequestParts<AppState> for RequireAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // First extract standard claims (which does JWT validation)
        let claims = Claims::from_request_parts(parts, state).await?;

        // Then verify the role
        if claims.role == "admin" {
            Ok(RequireAdmin(claims))
        } else {
            warn!(
                "User {} lacks admin role (role is '{}')",
                claims.sub, claims.role
            );
            Err(StatusCode::FORBIDDEN.into_response())
        }
    }
}

/// Extractor to enforce the `admin` or `mcp-read` role.
///
/// Returns `403 Forbidden` if the user is authenticated but has neither role.
#[allow(dead_code)]
pub struct RequireRead(pub Claims);

impl FromRequestParts<AppState> for RequireRead {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;

        if claims.role == "admin" || claims.role == "mcp-read" {
            Ok(RequireRead(claims))
        } else {
            warn!(
                "User {} lacks read access (role is '{}')",
                claims.sub, claims.role
            );
            Err(StatusCode::FORBIDDEN.into_response())
        }
    }
}
