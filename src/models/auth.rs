use serde::{Deserialize, Serialize};

/// Request body for the login endpoint.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Response body for the login endpoint on success.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

/// JWT claims embedded in the issued token.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (User ID)
    pub sub: String,
    /// User role (e.g. "admin")
    pub role: String,
    /// Expiration time (as UTC timestamp)
    pub exp: usize,
}
