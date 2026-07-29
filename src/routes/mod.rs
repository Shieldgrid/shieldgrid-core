/// Route definitions for the Shieldgrid API.
///
/// `build_router()` is the single construction point for the Axum [`Router`].
/// Subsequent tickets add routes here as they are implemented.

use axum::Router;

pub fn build_router() -> Router {
    Router::new()
}
