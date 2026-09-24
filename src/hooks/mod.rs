//! Hook installation and lifecycle management for AI coding agents.

pub mod constants;
pub mod hook_audit_cmd;
pub mod hook_check;
#[deny(clippy::print_stdout, clippy::print_stderr)]
pub mod init;
pub mod integrity;
#[deny(clippy::print_stdout, clippy::print_stderr)]
pub mod post_tool_use_cmd;
pub mod trust;
pub mod verify_cmd;
