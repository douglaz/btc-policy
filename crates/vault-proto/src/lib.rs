//! Wire types shared by coordinator and nodes; drift is a compile error.
//!
//! Two-phase /sign per ADR-0004/0008: {psbt, escape_psbt, pin} ->
//! pending | signed | refusal. See docs/DESIGN.md ("/sign wire contract").
