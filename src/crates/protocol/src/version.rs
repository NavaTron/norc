//! NORC protocol version handling and Adjacent-Major Compatibility (AMC)
//!
//! This module implements the NORC protocol versioning scheme, which uses
//! Adjacent-Major Compatibility (AMC) to balance stability with evolution.
//!
//! # AMC Rules
//!
//! - Versions N and N+1 are compatible (e.g., 1.x.x ↔ 2.x.x)
//! - Versions N and N+2 are **not** compatible (e.g., 1.x.x ✗ 3.x.x)
//! - This prevents unbounded legacy accumulation while maintaining practical compatibility

