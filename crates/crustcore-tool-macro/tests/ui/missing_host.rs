// A tool with no leading host-context handle cannot mint a receipt over the host's
// key, so it is rejected at compile time (invariant 10).
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::ToolError;

#[crust_tool]
fn no_host(x: String) -> Result<String, ToolError> {
    Ok(x)
}

fn main() {}
