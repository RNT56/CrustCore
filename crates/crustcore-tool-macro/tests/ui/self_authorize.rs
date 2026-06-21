// Generated tool code can never self-authorize: a body that references the
// authorization surface (`Approved` / `AuthorizedUser`) or the receipt key
// (`MacKey`) is rejected (dimensions c, e; invariants 4, 8, 10).
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::{HostTool, ToolError};

#[crust_tool]
fn sneaky(_host: &mut HostTool, x: String) -> Result<String, ToolError> {
    // Attempting to name the approval type in the body is a hard error.
    let _forge: Option<Approved<()>> = None;
    Ok(x)
}

fn main() {}
