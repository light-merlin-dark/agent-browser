//! An agent is not a reader: keep agent-browser out of the analytics of the
//! sites it visits.
//!
//! Every tab agent-browser opens or attaches to carries Umami's own opt-out,
//! `localStorage["umami.disabled"]`, set by an init script before any page
//! script runs. Umami's tracker reads that key before every send, wherever the
//! tracker is served from (a shared analytics origin or a site's first-party
//! proxy), so it works where a hostname block would miss.
//!
//! Umami's server-side bot check only catches headless Chrome
//! (`HeadlessChrome` in the user agent). A headed agent-browser, or a
//! CDP-attached real browser, presents an ordinary desktop Chrome user agent
//! and counts as a visitor without this.
//!
//! The key is set on every new document (navigations, redirects, popups, tabs
//! opened later) and, at launch, also on documents that are already loaded, so
//! attaching to a running browser covers its open tabs too. Origins without
//! storage (`about:blank`, `data:`, sandboxed frames) throw on access and are
//! skipped.
//!
//! `AGENT_BROWSER_SITE_ANALYTICS=live` opts a session back in for testing the
//! analytics itself. Live mode removes the key instead of leaving it alone, so
//! a persistent profile that earlier sessions opted out still counts.

use std::env;
use std::time::Duration;

use serde_json::json;

use super::cdp::client::CdpClient;

pub const UMAMI_DISABLED_KEY: &str = "umami.disabled";

/// Environment switch: `live` lets the sites' analytics count this session.
pub const SITE_ANALYTICS_ENV: &str = "AGENT_BROWSER_SITE_ANALYTICS";

const OPT_OUT_SCRIPT: &str =
    r#"try { window.localStorage.setItem("umami.disabled", "1"); } catch (e) {}"#;

const LIVE_SCRIPT: &str =
    r#"try { window.localStorage.removeItem("umami.disabled"); } catch (e) {}"#;

/// Bound for touching an already-loaded document at launch. A discarded or
/// frozen tab in an attached browser must not stall the launch.
const CURRENT_DOCUMENT_TIMEOUT: Duration = Duration::from_secs(2);

/// True when `value` (the environment switch) opts the session back in.
pub fn is_live(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.trim().eq_ignore_ascii_case("live"))
}

/// The init script for a session, by the environment switch.
pub fn script_for(value: Option<&str>) -> &'static str {
    if is_live(value) {
        LIVE_SCRIPT
    } else {
        OPT_OUT_SCRIPT
    }
}

/// The init script for this daemon, read from its environment.
pub fn script() -> &'static str {
    script_for(env::var(SITE_ANALYTICS_ENV).ok().as_deref())
}

/// Registers the script on every new document in `session_id`.
///
/// Queued without waiting for the reply, like `Runtime.runIfWaitingForDebugger`:
/// a popup that shares its opener's renderer answers only after it is resumed,
/// and the opener's pending input event waits on the popup, so awaiting here
/// stalls both until the command times out (measured: 30 s). `Page.enable`
/// goes first: without it a paused popup took the script after its first
/// document about half the time; with it, every time (measured over 24 runs).
pub async fn queue_on_new_documents(client: &CdpClient, session_id: &str) -> Result<(), String> {
    client
        .send_command_no_wait("Page.enable", None, Some(session_id))
        .await?;
    client
        .send_command_no_wait(
            "Page.addScriptToEvaluateOnNewDocument",
            Some(json!({ "source": script() })),
            Some(session_id),
        )
        .await
}

/// Registers the script on new documents and applies it to the document
/// already loaded in each session, concurrently and bounded, so a launch that
/// attaches to an open browser covers its open tabs. Errors are ignored: a tab
/// that cannot take the script is one the daemon cannot drive either.
pub async fn install_on_sessions(client: &CdpClient, session_ids: &[String]) {
    let installs = session_ids.iter().map(|session_id| async move {
        let _ = queue_on_new_documents(client, session_id).await;
        let _ = tokio::time::timeout(
            CURRENT_DOCUMENT_TIMEOUT,
            client.send_command(
                "Runtime.evaluate",
                Some(json!({ "expression": script(), "returnByValue": true })),
                Some(session_id),
            ),
        )
        .await;
    });
    futures_util::future::join_all(installs).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opts_out_unless_live() {
        assert_eq!(script_for(None), OPT_OUT_SCRIPT);
        assert_eq!(script_for(Some("")), OPT_OUT_SCRIPT);
        assert_eq!(script_for(Some("off")), OPT_OUT_SCRIPT);
        assert_eq!(script_for(Some("live")), LIVE_SCRIPT);
        assert_eq!(script_for(Some(" LIVE ")), LIVE_SCRIPT);
    }

    #[test]
    fn scripts_use_umamis_key() {
        assert!(OPT_OUT_SCRIPT.contains(&format!("\"{UMAMI_DISABLED_KEY}\"")));
        assert!(LIVE_SCRIPT.contains(&format!("\"{UMAMI_DISABLED_KEY}\"")));
    }
}
