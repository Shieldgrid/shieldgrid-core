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
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());

        let token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header["Bearer ".len()..],
            _ => {
                warn!("Missing or invalid Authorization header");
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
