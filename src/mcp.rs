use anyhow::Result;
use axum::{routing::get, Json, Router};
use serde_json::json;
use tracing::info;

use crate::cli::McpArgs;

pub async fn run_mcp_server(args: McpArgs) -> Result<()> {
    println!("\n╭─────────────────────────────────────────────────────────────╮");
    println!("│             Amiterra Cluster MCP Server                     │");
    println!("╰─────────────────────────────────────────────────────────────╯");
    println!("  • Model Context Protocol endpoint: http://{}:{}/mcp", args.host, args.port);
    println!("  • Compatible with AI assistants  : Claude Code, Cursor, Codex\n");

    let app = Router::new()
        .route("/mcp", get(mcp_manifest))
        .route("/healthz", get(|| async { "OK" }));

    let addr = format!("{}:{}", args.host, args.port);
    info!("Starting MCP Server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn mcp_manifest() -> Json<serde_json::Value> {
    Json(json!({
        "name": "amiterra-cluster-mcp",
        "version": "0.1.0",
        "description": "Amiterra Autonomous Infrastructure Model Context Protocol Server",
        "tools": [
            {
                "name": "get_cluster_status",
                "description": "Returns current health and state of K3s, eBPF networking, and host tuner daemon (read-only)",
                "inputSchema": { "type": "object", "properties": {} }
            }
        ]
    }))
}
