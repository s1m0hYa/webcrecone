# 전체 검토 기록

검토일: 2026-11-19. 기능 확장 목록과 실제로 재현해 수정한 문제를 구분한다.
외부 대상 요청·패키지 설치·Git commit/push는 하지 않는다.

## 1차 검토: 수집·분석 경계

Python 모듈 20개와 CLI/HTML 템플릿, 테스트·fixture, 설정·seed·문서·출력 자료를 대조했다.
검토 시작의 전체 테스트는 185개 중 183개 통과/소켓 제한 2개 skip이었다.
아래 문제는 기존 정상 입력 테스트를 통과하던 코드에서 별도 입력으로 재현했다.

| 우선순위 | 재현한 문제 | 수정과 검증 |
| --- | --- | --- |
| 높음 | `/path?`의 빈 쿼리 구분자가 정규화/urljoin 중 사라져 seed·링크·JS 이동·리다이렉트가 자동 방문됨 | scope.resolve_reference와 normalize_url/redact_url에서 구분자 보존. 모든 경로에서 query_not_visited 확인 |
| 높음 | HTML 속성/Location의 탭·개행을 urljoin이 조용히 제거하여 다른 URL로 요청함 | 조합 전 제어 문자 검사. HTML은 잘못된 참조로, redirect는 invalid_redirect로 처리하고 후속 요청 없음 확인 |
| 높음 | Content-Length보다 짧게 끊긴 응답도 HTTPResponse.read1이 정상 EOF로 반환하여 부분 robots를 허용 정책으로 파싱할 수 있음 | 잔여 길이를 검사해 incomplete_response_body로 기록하고 본문 폐기. 부분 robots 중단, 부분 HTML/JS의 추가 URL 추출 없음, 다음 요청 간격 확인 |
| 높음 | `Retry-After: ²`가 isdigit을 통과한 뒤 int에서 예외를 내며 부하 중단 신호를 놓침 | 중단을 값 해석보다 먼저 수행, ASCII 초만 허용. 200/429/503에서 이후 요청 모두 차단 |
| 중간 | HTML base href가 외부 JS의 fetch/location 상대 URL에 전달되지 않음. 인라인 패턴 출처도 base로 바뀜 | 실제 source/document와 해석용 base_url을 분리하고 모듈 체인에 전달. import는 최종 파일 기준 유지 |
| 중간 | endpoint.sources 20개가 링크로 채워진 뒤 JS 호출이 발견되면 API 후보 분류에서 빠짐 | 저장된 HTML/JS의 호출 참조도 분류에 반영. 오프라인 재분석과 GET 관찰/POST 선언 분리 확인 |
| 낮음 | 매우 큰 정수 interval이 설정 오류 대신 math.isfinite의 OverflowError로 종료됨 | 값 범위를 먼저 검증하여 ConfigError로 종료 |

새 회귀는 tests/test_review_regressions.py의 11개다. tests/helpers.py의 메모리 응답은
명시한 Content-Length/Transfer-Encoding을 보존하도록 고쳐 실제 HTTPResponse의 미달/청크 처리를 검증한다.
HTTP 교환·요청 승인·간격 관리는 여전히 SafeHttpClient 한 곳에 있다.

1차 검증 결과:

- `python3 -m unittest discover -s tests -v`: 196개 중 194개 통과, 실제 소켓 2개 skip, 실패 0.
- DNS/소켓을 금지한 help·plan·seed plan·dry-run·기존 report/API 그룹 출력 6개 성공.
- 현존 스캔 JSON 6개를 네트워크 없이 재분석하고 HTML을 메모리에서 생성했다. 기존 파일은 덮어쓰지 않았다.
- 철회된 웹 작업공간 JSON 1개는 현재 스캔 형식이 아니므로 report가 명확히 거부한다. 사용자 자료로 보존했다.
- Python 파일 37개의 3.10 문법 파싱과 운영 코드의 표준 라이브러리 의존성 확인.
- 고정 seed의 비정상 JS/HTML 입력 1,200개에서 예외 없음·추출 개수 상한 유지. 전체 JS 문법의 정확성 증명은 아니다.
- 사용자 설정·seed·기존 output 16개 SHA-256 불변. 실제 Windows/3.10/TLS/브라우저 화면은 미검증.

## 2차 검토: 재검토·실사용성·이식성

추가로 재현한 수집기 문제: max_script_depth=0에서도 JS가 반환한 HTML의 링크 또는
location 이동으로 발견한 `.js`를 다시 읽었다. import/script 종류만 깊이를 증가시키던 탓이다.
JS 큐에 넣는 지점에서 깊이를 증가시키도록 모아 link/navigation도 같은 상한을 적용했다.
기존 HTML↔JS 체인 회귀 21개와 새 경계 회귀 1개를 확인했다. 총 재현·수정 문제는 8개다.

화면 개선:

- 8개 구역을 탭으로 전환한다. 문서가 있으면 페이지·폼, 없으면 자료가 있는 엔드포인트/패턴/진단을 먼저 표시한다.
- 7개 표를 50/100/250행씩 표시한다. 검색은 표 전체에 적용하며 조건 변경 시 첫 페이지로 돌아간다.
- 리소스 유형 필터, 빈 결과·버튼 상태, 방향키/Home/End/Enter/Space 탭 탐색을 지원한다.
- JS를 반환한 페이지를 전체 분석 실패처럼 표시하지 않고 JS 분석 사실을 구분한다.
- JS 비활성 시 전체 표, 인쇄 시 모든 탭의 검색 일치 행을 보여준다. DOM 가상화는 아니다.
- report_template.html(구조), report_ui.js(동작), report_style.css(스타일)를 분리했다.
  render_html이 고정 자산을 읽어 HTML 하나로 삽입하고 UI 코드의 CSP 해시를 계산한다.
  사용자 자료를 script 안에 넣거나 대상 URL을 자동 요청하는 기능은 없다.

이식성·구조·주석:

- test_portability.py가 패키지를 새 한글/공백 경로로 복사해 Python -S로 실행한다.
  help/plan/analyze-js/HTML 재생성이 설치·site-packages 없이 성공했다. 실행한 OS는 Linux다.
- 당시의 공개 템플릿은 배포에서 제외했다. 현재 설정과 seed 입력 형식은 README에서 확인한다.
  기존 사용자 설정/seed를 교체하지 않았다. .gitignore의 개인 설정·결과 제외도 유지한다.
- Python 모듈 20개의 상대 import 그래프에 순환 없음, 운영 코드의 외부 패키지 의존성 없음 확인.
- 네트워크는 SafeHttpClient, HTML/JS 파서는 순수 분석, 저장은 report, UI는 고정 자산으로 분리했다.
  URL 정보 손실, HTTP EOF, 깊이 증가, 출처/base, UI 페이지 분할·인쇄 계약의 이유를 주석에 보완했다.

최종 검증:

- 필수 unittest: **201개 중 199개 통과, 실제 소켓 2개 skip, 실패 0**.
- Python 파일 38개의 Python 3.10 문법 파싱. 실제 Python 3.10 실행 검증은 아니다.
- `node --check webrecon/report_ui.js`, `node tests/check_report_ui.js` 성공.
  Node 22는 이미 설치된 선택적 개발 도구이며 제품/필수 unittest 의존성이 아니다.
  DOM 모의 검사에서 123행 분할·탭/키보드/hash·검색/복합 필터·빈 결과·리소스/변수 필터·인쇄 일치 상태를 확인했다.
- 새 검토용 자료: output/test-verification/webrecon-9b38e0be-c1fc-47dc-a0c3-24f9fd5a8390.json 및 HTML.
  메모리 HTTP 4회, 엔드포인트 후보 131개/API 후보 2개다. validation_context에 실제 네트워크 미사용을 명시했다.
- 실제 TCP/TLS·브라우저 화면/인쇄·Windows/WSL2는 검증하지 않았다. 브라우저가 없으며 설치하지 않았다.
  기존 사용자 파일 16개는 유지했다. 외부 대상 요청·패키지 설치·Git 변경은 없다.
- 최종 문서 대조: 문서 9개/로컬 링크 35개/코드 블록 경계와 개발 가이드 Python 예제 2개 확인.
  새 예제를 포함한 스캔 JSON 7개를 다시 메모리에서 HTML로 생성했고 공개 템플릿+seed plan도
  DNS/소켓 차단 상태에서 성공했다. 기존 JSON/HTML은 재저장하지 않았다.

## 계속 관리할 개선 과제

- 공유 JS의 상대 URL은 첫 발견 문서의 base를 사용한다. 다른 문서 맥락 재분석은 향후 별도 설계가 필요하다.
- JS는 제한된 정적 문법이다. import map·파일 간 상수 전파·실제 함수 호출 관계는 지원하지 않는다.
- 11월 20일 페이지 트리·상세 탐색과 로컬 파일 뷰어를 실제 HTML에 적용했다. 이후 D025에서 파일 선택을 제거하고 콜 그래프를 적용했다. 브라우저별 화면 확인은 남아 있다.
- 설정 방법은 README에서 확인하고 개인 설정·seed 파일은 로컬에 보관한다.
