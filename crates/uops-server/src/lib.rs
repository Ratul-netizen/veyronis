//! The server, as a library.
//!
//! `main.rs` is the order these pieces happen in; this is the pieces. The split exists
//! so that the first-run path can be tested — a boot sequence whose only output is a
//! terminal is a boot sequence nothing can assert on, and "can the administrator we
//! just created actually log in" is the one question worth asking about it.

pub mod config;
pub mod firstrun;
pub mod headers;
pub mod shutdown;
pub mod web;

use std::path::Path;

use axum::Router;
use uops_api::routes::router;
use uops_api::state::AppState;

/// The whole application: the API, the web app when there is one, and the security
/// headers over both.
///
/// # Why this is a function and not three lines in `main`
///
/// It was three lines in `main`, and that is the shape that produces a guard nothing
/// applies. `boot.rs` built its own router to test the first-run login, so a header layer
/// added in `main` would have been invisible to every test in this repository — passing
/// unit tests for a policy no response carried. One assembly, used by the binary and by
/// the tests, is the only version of this that stays true.
///
/// Order matters twice. The web app's file service has to be attached before the headers,
/// because a layer applies to the fallback registered at the time it is added and not to
/// one replaced afterwards — the page would have been the one response without a policy.
/// And `uops_api` registers its own catch-all under `/api` before this, so a mistyped API
/// path still answers problem+json rather than a page of HTML.
///
/// # Errors
///
/// When `web_root` is given and has no `index.html`. `web::serve` explains why that is
/// worth refusing to start over.
pub fn application(state: AppState, web_root: Option<&Path>) -> Result<Router, String> {
    let mut app = router(state);
    if let Some(root) = web_root {
        app = web::serve(app, root)?;
    }
    Ok(headers::secured(app))
}
