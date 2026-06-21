// A tool must return `Result<_, ToolError>` so failures are typed and the Ok type is
// a concrete schema type; a bare return is a hard error.
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::HostTool;

#[crust_tool]
fn bare(_host: &mut HostTool, x: String) -> String {
    x
}

fn main() {}
