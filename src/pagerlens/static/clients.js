// MCP client configuration snippets. Keep in sync with the "Using the MCP server" section of README.md.
// The token is never embedded: every snippet reads it from the PAGERLENS_TOKEN environment variable.

export const CLIENTS = [
  {
    id: "claude-code", name: "Claude Code", where: "Run in a terminal:",
    snippet: (u) => `claude mcp add --transport http pagerlens ${u} \\\n  --header "Authorization: Bearer $PAGERLENS_TOKEN"`,
  },
  {
    id: "vscode", name: "VS Code (GitHub Copilot)", where: "Save as .vscode/mcp.json in your workspace (VS Code asks for the key once and stores it securely):",
    snippet: (u) => JSON.stringify({
      servers: { pagerlens: { type: "http", url: u, headers: { Authorization: "Bearer ${input:pagerlens-key}" } } },
      inputs: [{ type: "promptString", id: "pagerlens-key", description: "PagerLens API token", password: true }],
    }, null, 2),
  },
  {
    id: "opencode", name: "OpenCode", where: "Add to opencode.json (project) or ~/.config/opencode/opencode.json:",
    snippet: (u) => JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      mcp: { pagerlens: { type: "remote", url: u, enabled: true, headers: { Authorization: "Bearer {env:PAGERLENS_TOKEN}" } } },
    }, null, 2),
  },
  {
    id: "codex", name: "Codex CLI", where: "Add to ~/.codex/config.toml:",
    snippet: (u) => `[mcp_servers.pagerlens]\nurl = "${u}"\nbearer_token_env_var = "PAGERLENS_TOKEN"`,
  },
  {
    id: "cursor", name: "Cursor", where: "Add to ~/.cursor/mcp.json (or .cursor/mcp.json in a project):",
    snippet: (u) => JSON.stringify({
      mcpServers: { pagerlens: { url: u, headers: { Authorization: "Bearer ${env:PAGERLENS_TOKEN}" } } },
    }, null, 2),
  },
  {
    id: "windsurf", name: "Windsurf", where: "Add to ~/.codeium/windsurf/mcp_config.json:",
    snippet: (u) => JSON.stringify({
      mcpServers: { pagerlens: { serverUrl: u, headers: { Authorization: "Bearer ${env:PAGERLENS_TOKEN}" } } },
    }, null, 2),
  },
  {
    id: "gemini", name: "Gemini CLI", where: "Add to ~/.gemini/settings.json:",
    snippet: (u) => JSON.stringify({
      mcpServers: { pagerlens: { httpUrl: u, headers: { Authorization: "Bearer $PAGERLENS_TOKEN" } } },
    }, null, 2),
  },
  {
    id: "cline", name: "Cline", where: "Add to cline_mcp_settings.json (Cline: MCP Servers, then Configure):",
    snippet: (u) => JSON.stringify({
      mcpServers: { pagerlens: { type: "streamableHttp", url: u, headers: { Authorization: "Bearer <your token>" } } },
    }, null, 2),
  },
  {
    id: "zed", name: "Zed", where: "Add to Zed settings.json:",
    snippet: (u) => JSON.stringify({
      context_servers: { pagerlens: { url: u, headers: { Authorization: "Bearer <your token>" } } },
    }, null, 2),
  },
  {
    id: "claude-desktop", name: "Claude Desktop", where: "Claude Desktop needs a local bridge for bearer-key servers. Add to claude_desktop_config.json (requires Node.js):",
    snippet: (u) => JSON.stringify({
      mcpServers: { pagerlens: { command: "npx", args: ["-y", "mcp-remote", u, "--header", "Authorization:${AUTH}"], env: { AUTH: "Bearer <your token>" } } },
    }, null, 2),
  },
];
