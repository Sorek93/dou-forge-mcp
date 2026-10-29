"""Operator entrypoint. Approval is intentionally not an MCP capability."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import ForgeError, load_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Dou Forge private alpha")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path.home() / ".local/state/douforge")
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("check")
    sub.add_parser("doctor", help="Read-only local preflight; does not execute or prove ChatGPT login")
    oauth = sub.add_parser("oauth-check", help="Read-only metadata preflight; does not log in")
    oauth.add_argument("--registration", choices=["provided", "cimd", "dcr"], default="provided")
    oauth.add_argument("--ca-file", type=Path, help="Optional administrator-trusted CA bundle")
    serve = sub.add_parser("serve")
    serve.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    serve.add_argument("--port", type=int, default=9384)
    serve.add_argument("--host", default="127.0.0.1", help="Literal bind IP; default loopback")
    serve.add_argument("--container-preview", action="store_true",
                       help="Allow preview on 0.0.0.0; operator must restrict Docker port publishing")
    approve = sub.add_parser("approve")
    approve.add_argument("plan_id")
    approve.add_argument("--yes", action="store_true", help="Operator has reviewed the exact plan")
    try:
        args = parser.parse_args()
        cfg = load_config(args.config)
        if args.operation == "check":
            print(json.dumps({"ok": True, "hosts": len(cfg.hosts), "execution_enabled": cfg.execution_enabled,
                              "shell_enabled": cfg.shell_enabled}, ensure_ascii=False))
        elif args.operation == "doctor":
            from .doctor import diagnose
            report = diagnose(cfg, args.state)
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 2 if report["status"] == "blocked" else 0
        elif args.operation == "oauth-check":
            from .oauth_check import check_oauth, get_json
            result = check_oauth(cfg, registration=args.registration,
                                fetch=lambda url: get_json(url, ca_file=args.ca_file))
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result["status"] == "metadata_ready" else 2
        elif args.operation == "approve":
            from .service import Forge
            forge = Forge(args.config, args.state)
            plan = forge.state.inspect(args.plan_id)
            print(json.dumps({"plan_id": args.plan_id, "principal": plan["principal"],
                              "payload": plan["payload"]}, indent=2, ensure_ascii=False))
            if not args.yes:
                if not sys.stdin.isatty() or input("Approve this exact operation? Type APPROVE: ") != "APPROVE":
                    raise ForgeError("Operator confirmation required")
            print(json.dumps(forge.approve(args.plan_id)))
        else:
            from .server import create_server
            mcp, _ = create_server(args.config, args.state, transport=args.transport)
            if args.transport == "stdio":
                mcp.run()
            else:
                if not 1 <= args.port <= 65535:
                    raise ForgeError("Invalid port")
                from .http_runtime import http_app, validate_bind
                validate_bind(cfg, args.host, args.container_preview)
                import uvicorn
                uvicorn.run(http_app(mcp, args.config, args.host), host=args.host, port=args.port,
                            log_level="warning", proxy_headers=False)
        return 0
    except (ForgeError, OSError) as exc:
        print(f"douforge: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
