// An unsupported parameter type must be a HARD compile error (never a permissive
// `Any` schema that widens accepted input — dimension f).
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::{HostTool, ToolError};

struct Custom;

#[crust_tool]
fn bad(_host: &mut HostTool, weird: Custom) -> Result<String, ToolError> {
    let _ = weird;
    Ok(String::new())
}

fn main() {}
