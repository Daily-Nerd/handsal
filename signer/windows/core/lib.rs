//! The platform-neutral core of the handsal signer: the canonical subset, the emitter, the draft,
//! the renderer and the command line contract. Nothing here touches a key, a prompt or an
//! operating system API; the key backends live behind the commands that need them.

pub mod acts;
pub mod cli;
pub mod commands;
pub mod devicekey;
pub mod draft;
pub mod emit;
pub mod encoding;
pub mod forms;
pub mod genesis;
pub mod json;
pub mod limits;
pub mod methods;
pub mod policy;
pub mod process;
pub mod profiles;
pub mod registry;
pub mod render;
pub mod render_attach;
pub mod render_genesis;
pub mod render_lines;
pub mod sha256;
pub mod subset;
pub mod text;
pub mod value;
