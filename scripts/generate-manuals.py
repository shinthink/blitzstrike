#!/usr/bin/env python3
"""Generate manuals for catalog tools missing from manuals-index.json.

Reads tools-catalog.json (authoritative: description, command, flags, install,
tags, alternatives, pipes, homepage) and emits a markdown manual per missing
tool, then updates manuals-index.json. No hallucinated content — every field in
the generated manual comes from the catalog.
"""
import json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
catalog = json.load(open(os.path.join(ROOT, "tools-catalog.json")))["tools"]
index = json.load(open(os.path.join(ROOT, "manuals-index.json")))
idx_tools = index.get("tools", {})

# category -> manual dir
CATEGORY_DIR = {
    "recon": "information-gathering",
    "enumeration": "information-gathering",
    "exploitation": "exploitation",
    "web": "web",
    "active-directory": "active-directory",
    "post-exploitation": "post-exploitation",
    "red-team": "red-team",
    "blue-team": "blue-team",
    "reverse-engineering": "reverse-engineering",
    "forensics": "forensics",
    "mobile": "mobile",
    "wireless": "wireless",
    "cloud": "cloud-native",
    "crypto": "crypto",
    "utility": "utility",
}

RISK = {
    "exploitation": "🔴 High",
    "active-directory": "🔴 High",
    "red-team": "🔴 High",
    "post-exploitation": "🔴 High",
    "web": "🟠 Medium",
    "recon": "🟠 Medium",
    "enumeration": "🟠 Medium",
    "reverse-engineering": "🟠 Medium",
    "forensics": "🟠 Medium",
    "mobile": "🟠 Medium",
    "wireless": "🟠 Medium",
    "cloud": "🟠 Medium",
    "crypto": "🟠 Medium",
    "blue-team": "🟠 Medium",
    "utility": "🟢 Low",
}

CATEGORY_LABEL = {
    "recon": "Information Gathering / Reconnaissance",
    "enumeration": "Enumeration",
    "exploitation": "Exploitation",
    "web": "Web Application Security",
    "active-directory": "Active Directory",
    "post-exploitation": "Post-Exploitation",
    "red-team": "Red Team / Phishing",
    "blue-team": "Blue Team / Detection",
    "reverse-engineering": "Reverse Engineering",
    "forensics": "Forensics",
    "mobile": "Mobile Security",
    "wireless": "Wireless Security",
    "cloud": "Cloud Security",
    "crypto": "Cryptography",
    "utility": "Utility",
}


def slug(name):
    return name.lower().replace(" ", "-").replace("/", "-")


def build_manual(tool):
    name = tool["name"]
    cat = tool.get("category", "utility")
    desc = (tool.get("description") or "").strip()
    command = tool.get("command") or name
    flags = tool.get("flags") or []
    install = tool.get("install") or {}
    homepage = tool.get("homepage") or ""
    tags = tool.get("tags") or []
    alternatives = tool.get("alternatives") or []
    pipes = tool.get("pipes") or []

    # Build a richer description when the catalog one is terse.
    rich_desc = (desc[0].upper() + desc[1:] if desc else name).rstrip(".")
    if tags:
        rich_desc += ". Focus areas: " + ", ".join(tags)
    if alternatives:
        rich_desc += ". Alternatives: " + ", ".join(alternatives)
    rich_desc += "."

    lines = []
    lines.append(f"# {name}")
    lines.append("")
    lines.append(f"- **Category**: {CATEGORY_LABEL.get(cat, cat.title())}")
    lines.append(f"- **Risk Level**: {RISK.get(cat, '🟠 Medium')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Description")
    lines.append("")
    lines.append(rich_desc)
    if homepage:
        lines.append("")
        lines.append(f"Homepage: {homepage}")
    lines.append("")

    lines.append("## Installation")
    lines.append("")
    lines.append("```bash")
    for plat in ("linux", "darwin", "win32"):
        if install.get(plat):
            lines.append(f"# {plat}: {install[plat]}")
    if not any(install.values()):
        lines.append(f"# {command} (see upstream docs)")
    lines.append("```")
    lines.append("")

    # usage
    required = [f for f in flags if f.get("required")]
    lines.append("## Usage")
    lines.append("")
    lines.append("```bash")
    if required:
        req_args = " ".join(
            f"-{f['name'].lstrip('-')} <{f['name'].lstrip('-')}>" for f in required
        )
        lines.append(f"{command} {req_args}")
    else:
        lines.append(f"{command} -h")
    lines.append("```")
    lines.append("")

    if flags and any(f.get("name") for f in flags):
        lines.append("## Parameter Reference")
        lines.append("")
        lines.append("| Parameter | Description |")
        lines.append("|------|------|")
        for f in flags:
            pname = f.get("name", "")
            pdesc = f.get("description", "")
            req = " (required)" if f.get("required") else ""
            if pname:
                lines.append(f"| `{pname}` | {pdesc}{req} |")
        lines.append("")

    if tags:
        lines.append("## Tags")
        lines.append("")
        lines.append(", ".join(tags))
        lines.append("")
    if alternatives:
        lines.append("## Alternatives")
        lines.append("")
        lines.append(", ".join(alternatives))
        lines.append("")
    if pipes:
        lines.append("## Pipeline")
        lines.append("")
        lines.append("Pipes well into: " + ", ".join(pipes))
        lines.append("")

    return "\n".join(lines)


def main():
    # Only generate manuals for catalog tools MISSING from the index. Never
    # overwrite existing hand-written manuals.
    missing = [t for t in catalog if t["name"].lower() not in idx_tools]
    print(f"generating manuals for {len(missing)} missing tools")

    created = 0
    for tool in missing:
        name = tool["name"]
        cat = tool.get("category", "utility")
        d = CATEGORY_DIR.get(cat, "utility")
        manual = build_manual(tool)
        # place in a category dir under manuals/
        dirpath = os.path.join(ROOT, "manuals", d)
        os.makedirs(dirpath, exist_ok=True)
        path = os.path.join(dirpath, f"{slug(name)}.md")
        with open(path, "w") as f:
            f.write(manual)
        # update index (relative path from manuals/)
        idx_tools[name.lower()] = f"{d}/{slug(name)}.md"
        created += 1

    index["tools"] = idx_tools
    with open(os.path.join(ROOT, "manuals-index.json"), "w") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"created {created} manuals, index now has {len(idx_tools)} tools")


if __name__ == "__main__":
    main()
