# xq-guard 🛡️

**A Lightweight, High-Performance Permission Gateway for AI Agents.**

Built with [Bun](https://bun.sh) & [TypeScript]. Inspired by the security architecture of advanced AI coding assistants.

---

## 🌟 Overview

`xq-guard` is a strategic security layer designed to sit between an AI Agent and the host system. It implements a three-tier defense mechanism to ensure that agentic tool usage is safe, observable, and controllable.

### The Three Layers of Defense:
1.  **Physical Sandbox Check**: Hard-coded path validation to prevent Directory Traversal attacks (Path Escape) before any logic is processed.
2.  **Policy Engine**: A rule-based system (`rules.json`) that matches tool names and input patterns (Regex) against established user preferences.
3.  **Human-in-the-Loop (HITL)**: An interactive CLI prompt that allows users to approve, deny, or create permanent rules on the fly when no existing policy matches.

---

## 🚀 Quick Start

### Prerequisites
- [Bun](https://bun.sh) installed on your system.

### Installation
```bash
git clone https://github.com/sqoder/xq-guard.git
cd xq-guard
bun install
```

### Run the Demo
```bash
bun start
```

---

## 🛠 Architecture

- **`src/engine.ts`**: The core decision-making brain. Handles rule matching (Deny > Ask > Allow) and persistence.
- **`src/tools.ts`**: Pluggable tool definitions with built-in `checkPhysicalSafety` hooks.
- **`src/index.ts`**: The execution orchestrator and interactive CLI handler.

---

## 🔒 Security Features

- **ReadOnly Mode**: Switch the global context to `readOnly` to automatically allow safe operations (like `ls` or `cat`) while still blocking destructive ones.
- **Bypass Mode**: For internal/trusted environments, the permission layer can be fully bypassed.
- **Pattern Matching**: Block specific dangerous command arguments using Regex patterns without disabling the entire tool.

---

## 📝 License

MIT © [sqoder](https://github.com/sqoder)
