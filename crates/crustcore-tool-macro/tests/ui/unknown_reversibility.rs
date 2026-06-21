// A typo'd / unknown reversibility must be a HARD compile error — never a silent
// fallback to a permissive posture (dimensions b, c).
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::{HostTool, ToolError};

#[crust_tool(reversibility = "Resversible")]
fn typo(_host: &mut HostTool, x: String) -> Result<String, ToolError> {
    Ok(x)
}

fn main() {}
