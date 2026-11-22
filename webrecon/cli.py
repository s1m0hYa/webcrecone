"""Small CLI: validation, orchestration and presentation only."""

import argparse
import json
import logging
from pathlib import Path

from .analyzer import group_urls
from .config import ConfigError, load_config, with_seed_file
from .crawler import Crawler
from .http_client import AuthorizationError
from .local_analysis import LocalAnalysisError, analyze_js_file
from .report import ReportError, load_report, output_directory, render_summary, save_html_report, save_report
from .safety import redact_url


def build_parser():
    """CLI 인터페이스만 선언한다. 입력 검증·수집·분석 규칙은 담당 모듈에 둔다."""
    parser = argparse.ArgumentParser(prog="python -m webrecon", description="WebRecon: 승인된 웹의 제한적 정적 정찰 (Python 표준 라이브러리)")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="DNS/네트워크 없이 설정과 실행 계획 확인")
    plan.add_argument("--config", required=True, type=Path, help="설정 JSON 경로")
    scan = commands.add_parser("scan", help="명시적으로 승인된 범위에서 순차 GET 정찰")
    scan.add_argument("--config", required=True, type=Path, help="설정 JSON 경로")
    scan.add_argument("--ack-authorized", action="store_true", help="대상 및 전체 origin에 대한 정찰 권한을 확인함")
    scan.add_argument("--dry-run", action="store_true", help="요청 없이 plan과 동일하게 설정 확인")
    for command in (plan, scan):
        command.add_argument("--seeds-file", type=Path, help="추가 시작 URL 목록: UTF-8 파일, 한 줄에 절대 URL 하나")
    local = commands.add_parser("analyze-js", help="로컬 JS 파일 하나를 DNS/HTTP 없이 분석해 JSON·HTML 저장")
    local.add_argument("--input", required=True, type=Path, help="UTF-8 로컬 JS 파일 (최대 1MiB)")
    local.add_argument("--base-url", required=True, help="상대 URL 해석 기준 문서 주소 (접속하지 않음)")
    report = commands.add_parser("report", help="기존 JSON만으로 분류와 요약 재생성 (오프라인)")
    report.add_argument("--input", required=True, type=Path, help="저장된 결과 JSON 경로")
    presentation = report.add_mutually_exclusive_group()
    presentation.add_argument("--list", dest="list_kind", choices=("urls", "apis", "patterns", "variables", "diagnostics"), help="후보·패턴·변수·JS 진단을 JSON으로 출력")
    presentation.add_argument("--format", choices=("text", "html"), default="text", help="text: 터미널 요약(기본), html: output에 오프라인 보고서 저장")
    report.add_argument("--group-by", choices=("domain", "path"), help="--list 결과를 도메인 또는 정확한 경로로 묶기")
    return parser


def main(argv=None):
    """명령을 조합하고 입출력을 담당한다. 오류/--help는 argparse의 SystemExit로 종료할 수 있다."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        if args.command == "analyze-js":
            result = analyze_js_file(args.input, args.base_url)
            destination = save_report(result, None)
            print(render_summary(result))
            print(f"결과 파일: {destination}")
            print(f"HTML 보고서: {save_html_report(result)}")
            return 0
        if args.command == "report":
            # 기존 JSON만 다루므로 Config/Crawler/SafeHttpClient를 만들 필요가 없다.
            if args.group_by and args.list_kind not in ("urls", "apis", "patterns"):
                parser.error("--group-by는 --list urls, apis 또는 patterns와 함께 사용하세요.")
            data = load_report(args.input)
            if args.format == "html":
                print(f"HTML 보고서: {save_html_report(data)}")
            elif args.list_kind:
                entries = data[{"urls": "url_list", "apis": "api_list", "patterns": "endpoint_patterns",
                                "variables": "variables", "diagnostics": "js_diagnostics"}[args.list_kind]]
                print(json.dumps(group_urls(entries, args.group_by) if args.group_by else entries,
                                 ensure_ascii=False, indent=2))
            else:
                print(render_summary(data))
            return 0
        config = load_config(args.config)
        if args.seeds_file:
            config = with_seed_file(config, args.seeds_file)
        output_directory(config)
        if args.command == "plan" or args.dry_run:
            # 승인 검사와 네트워크 클라이언트 생성 전에 종료해야 오프라인 계획이 유지된다.
            plan = config.to_dict()
            plan["target_url"] = redact_url(config.target_url)
            print(json.dumps({"network_enabled": False, "config": plan, "start_urls": config.start_plan(), "sequence": [
                "scan --ack-authorized에서만 DNS와 HTTP 시작",
                "robots.txt의 404/410은 기록 후 계속, 접근 거부·통신 오류는 중단",
                f"robots 200 HTML 처리 설정: {config.robots_html_policy} (continue는 정책 미확인을 기록하고 탐색 계속)",
                "순차 GET, 리다이렉트도 별도 요청 예산과 간격 적용",
                "여러 시작점을 깊이 0으로 등록, 전체 예산 안에서 순차 BFS 탐색",
                "받은 HTML/JS를 MIME에 따라 분석하고 명시적 문서·JS 모듈 참조를 제한 내 반복 탐색",
                "API 호출 선언·폼·일반 URL 문자열은 기록만 하며 실행하지 않음",
                "민감한 값과 HTML 원문을 제외하고 output 아래 JSON 및 오프라인 HTML 보고서 저장",
            ]}, ensure_ascii=False, indent=2))
            return 0
        result = Crawler(config, authorized=args.ack_authorized).run()
        # 내구성 있는 JSON을 먼저 저장한다. HTML 표현 오류가 나도 수집 결과는 남아야 한다.
        destination = save_report(result, config)
        print(render_summary(result))
        print(f"결과 파일: {destination}")
        # Print the durable JSON path first so a presentation error never hides the data.
        print(f"HTML 보고서: {save_html_report(result, config)}")
        observed = result["pages"] or result["scripts"] or any(item.get("purpose") == "script" for item in result["response_documents"])
        return 0 if observed and not any(issue["code"] == "interrupted" for issue in result["issues"]) else 1
    except (ConfigError, AuthorizationError, ReportError, LocalAnalysisError) as exc:
        parser.exit(2, f"오류: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, "중단했습니다.\n")


if __name__ == "__main__":
    raise SystemExit(main())
