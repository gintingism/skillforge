"use strict";

const vscode = require("vscode");
const { LanguageClient, TransportKind } = require("vscode-languageclient/node");

let client;

function getExecutable() {
  const cfg = vscode.workspace.getConfiguration("skillforge");
  return cfg.get("executablePath") || "skillforge";
}

function activate(context) {
  const command = getExecutable();
  const serverOptions = {
    command,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions = {
    documentSelector: [
      { scheme: "file", language: "markdown", pattern: "**/SKILL.md" },
      { scheme: "file", language: "markdown", pattern: "**/.agents/skills/**/*.md" },
    ],
  };

  client = new LanguageClient(
    "skillforgeLsp",
    "SkillForge Language Server",
    serverOptions,
    clientOptions
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("skillforge.audit", (uri) => {
      const target = uri ? vscode.Uri.parse(String(uri)).fsPath : vscode.window.activeTextEditor?.document.uri.fsPath;
      if (!target) return;
      const term = vscode.window.createTerminal("SkillForge Audit");
      term.show();
      term.sendText(`${command} audit "${target}"`);
    }),
    vscode.commands.registerCommand("skillforge.normalize", () => {
      const target = vscode.window.activeTextEditor?.document.uri.fsPath;
      if (!target) return;
      const term = vscode.window.createTerminal("SkillForge Normalize");
      term.show();
      term.sendText(`${command} normalize "${target}" --write`);
    })
  );

  client.start();
}

function deactivate() {
  if (!client) return undefined;
  return client.stop();
}

module.exports = { activate, deactivate };
