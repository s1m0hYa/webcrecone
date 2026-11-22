# MVP 기능 명세

## 구현 범위

| 기능 | 동작과 완료 기준 |
| --- | --- |
| 설치 없는 실행 | 루트의 `webrecon/`, Python 3.10+ 문법, 외부 의존성 없음 |
| CLI | help, plan, scan/ack-authorized/dry-run, report, 오프라인 analyze-js |
| 다중 시작점 | JSON seed_urls 또는 plan/scan --seeds-file, 전체 고유 시작점 최대 50개, 모두 깊이 0 |
| 설정 | JSON 객체, 필수 target_url/allowed_origins, 잘못된 타입·알 수 없는 키·상한 초과 거부 |
| 범위 | 정확한 origin 목록, fragment 제거, IDNA·기본 포트·unreserved escape 정규화 |
| 주소 | 사설/특수 주소 차단, 숫자형 루프백의 명시적 테스트 예외, 모든 DNS 응답 검사 |
| 전송 | 순차 GET, 완료 후 1초 이상, 100회 이하, 타임아웃, 리다이렉트 재검증 |
| 제한 신호 | 429/503/Retry-After 후 실행 전체의 추가 요청 차단, 자동 재시도 없음 |
| HTTP 정보 | 상태·최종 URL·헤더의 안전한 부분집합·관찰 바이트·리다이렉트·TLS 상태·오류 |
| HTML | 제목, 링크, 폼/action/method, input/textarea/select/button 구조와 이름, 리소스/iframe/meta |
| 기타 속성 | href/src/action/formaction/data-url/data-href/data-endpoint/poster/cite 참조 |
| 주석 | 개수만 관찰, 내용은 버림 |
| 엔드포인트 | 정규화한 경로 단위 중복 제거, 쿼리/폼 파라미터 이름·메서드·출처 기록 |
| 크롤러 | BFS, 큐/페이지/깊이/요청/추출 수 제한, 재방문 방지 |
| 응답 재귀 분석 | 실제 HTML/JS MIME로 파싱, 새 문서·JS 모듈 참조를 같은 실행 큐에서 반복 처리 |
| robots | 첫 origin 요청 전에 확인, 404/410 부재이면 계속, 기본 실패 시 중단; 명시적 continue의 제한적 200 HTML 예외 |
| 실패 진단 | robots 상태·MIME·전송·잘림·잘못된 본문 원인 구분, 원문 없는 특징 기록, 터미널 표시 |
| 수신 응답 분석 | robots에서 이미 받은 HTML의 링크·폼·인라인 JS 후보를 추가 요청 없이 추출 |
| 수집 상태 | 입력/콘텐츠 발견/HTTP 응답 구분, 큐 후보의 최종 방문 상태, HTML 파싱 수 별도 표시 |
| JavaScript | 인라인 및 승인 범위 .js/.mjs의 리터럴·단순 const/별칭 분석, 실행·발견 API 호출 없음 |
| URL/API 목록 | url_list/api_list 저장, report --list urls 또는 apis, --group-by domain 또는 path |
| 주소 패턴·상수 추적 | fetch/axios/XHR 형태의 단순 const·별칭·결합·템플릿, 근거/미확인 이유, report --list patterns |
| 호출 진단 | 지원 형태의 검출·해석·제외 수, 이유·위치·중복, 토큰화/추적/출력 상한 구분, report --list diagnostics |
| 변수 목록 | 패턴에 연결된 변수의 출처·선언 범위·연결 패턴·이유, report --list variables |
| 로컬 JS 입력 | analyze-js --input 파일 --base-url 문서URL, UTF-8/BOM 일반 파일 1개·최대 1MiB, DNS/HTTP 없음 |
| 작은 구문 확장 | 일반/hex/Unicode 이스케이프 문자열과 단순 문자열 식의 괄호, 코드 실행 없음 |
| sitemap | 옵션 활성화 시 최초 origin의 /sitemap.xml의 urlset URL만 기록 |
| 분석 | 후보 분류, 근거, low/medium 신뢰도, 확인하지 않은 사항 명시 |
| 저장 | UUID 실행 ID·UTC 시각·schema_version=1·제한·관찰·실패를 JSON으로 저장, 같은 ID의 오프라인 HTML 생성 |
| 재분석 | report가 기존 관찰에서 분류/기술 단서를 다시 계산해 요약 출력 |

후보 분류는 authentication, administration, file_handling, data_input, api,
external_integration, configuration, unknown을 사용한다. URL 이름은 낮은 신뢰도,
폼과 비밀번호/파일 필드처럼 선언된 구조는 중간 신뢰도다. high 신뢰도 또는 취약점 판정은 없다.
범위 밖 참조의 external_integration은 통합의 후보라는 뜻이며 실제 연동을 확인한 것이 아니다.
Server/X-Powered-By 및 meta generator는 위장될 수 있는 기술 단서다.

## 자동 방문 규칙

페이지의 a/area href, iframe.src와 JS의 명시적인 페이지 이동은 문서 탐색 후보가 된다.
쿼리, API, 상태 변경 의심 경로, 범위 밖 주소, 알려진 비JS 정적/다운로드 확장자는 제외한다.
폼·CSS·이미지·기타 속성은 기록만 한다. HTML script src, 문서 링크/시작점의 .js/.mjs,
JS의 명시적인 import/export-from/단일 문자열 import()는 JS 큐 후보가 된다.
script/import 참조에 한해 확장자 없는 경로도 지원한다. bare 패키지 이름·계산식 import는 추측하지 않는다.
JS 페이지 이동은 location/window.location/document.location의 대입, href 대입, assign/replace 호출이다.
지원 범위에서 문자열로 완성된 URL만 사용하고 같은 이름의 지역 선언이 관찰되면 이동으로 인정하지 않는다.
JS API 호출(fetch/axios/XHR)과 일반 URL 문자열, robots 선언은 계속 기록만 한다.
같은 URL이 독립적인 페이지 링크로도 발견되면 링크 정책으로 판단한다.
HTML base는 인라인/외부 JS의 상대 주소 해석에도 사용하되 결과 URL에 같은 범위 정책을 적용한다.
기준 주소 base_url과 실제 출처 source/document를 구분한다. 빈 `?`는 보존해 차단하고
참조 조합 전에 제어 문자를 거부한다.

run은 문서 큐를 먼저 처리하고, 비었거나 페이지 예산을 소진하면 JS 하나를 처리한다. JS에서 문서가
발견되면 문서 탐색으로 돌아간다. 두 큐가 비거나 전역 중단 조건이 생길 때 종료한다.
max_depth는 문서 이동 깊이(최초 0, 기본/상한 2), max_script_depth는 JS 참조 체인 깊이
(직접 참조 0, 기본/상한 2)다. JS→HTML 전환이나 페이지 이동으로 JS 깊이를 초기화하지 않는다.
외부 JS는 요청 예산을 공유하며 페이지 시도 예산은 소비하지 않는다. 큐 합계·중복·robots·간격 제한은 동일하다.

받은 탐색 응답의 Content-Type이 HTML/JS이면 요청 당시 예상 종류와 관계없이 해당 파서를 사용한다.
200 이외의 완전한 HTML/JS는 후보만 추출하며 새 요청을 만들지 않는다. 잘림·압축·전송 실패·부하 신호는
분석하지 않는다. 미지원 MIME, 오류 상태의 기록 전용 분석은 각각 unsupported_response_content_type,
unsuccessful_response_recorded_only 진단으로 남긴다. robots/sitemap 정책 처리의 별도 규칙은 유지한다.
Content-Length 미달 응답은 incomplete_response_body로 기록하고 분석하지 않는다.
Retry-After의 값 형식이 잘못되어도 추가 요청을 차단한다.

## 결과 스키마

- 실행: `schema_version`, `scan_id`, `target`, `started_at`, `finished_at`, `limits`, `summary`.
- `start_urls`: target_url과 추가 시작 URL의 마스킹된 목록, 깊이 0, 경로 정책 판정.
  plan의 candidate는 DNS/robots 허용이나 실제 방문 성공을 뜻하지 않는다.
  scan/report에서는 최종 visit_status/visit_reason/http_status를 추가한다.
- `pages`: 요청/최종 URL, 상태, 깊이, 시각, 파싱 여부, 제목·폼·참조·메타·주석 개수.
  HTML 파싱 자료의 base_url은 base href를 반영한 상대 주소 해석 기준이다.
  JS를 반환한 페이지 요청도 응답 관찰로 남지만 parsed=false, analysis_type=javascript다.
  정상 HTML의 분석은 pages.parsed=true, 오류 HTML은 response_documents에서만 분석한다.
- `endpoints`: 경로 URL, 첫 관찰, 파라미터 이름·메서드·발견 종류·필드 타입·출처·분류.
- `requests`: 요청 목적, 시각, 전송 시도 여부, 상태·헤더·바이트·잘림·TLS·오류·redirect.
- `discoveries`: 출처 페이지, 속성·종류·깊이·방문 제외/큐 등록 사유.
  선택 필드 script_depth/document/base_url/source_location/inline_script는 JS 체인 깊이·출처 문서·해석 기준·발견 위치다.
  새 종류 script_import/navigation은 명시적 모듈/이동 근거, script_response는 수신 JS 주소 관찰이다.
  script_depth_limit/scripts_disabled는 추가 요청을 하지 않은 이유다.
  큐 후보의 초기 disposition은 initial_disposition으로 보존하고 최종 disposition을
  response_received/request_failed/blocked/not_visited로 갱신한다. 이 네 값은 visit_status에도
  표시한다. 처음부터 제외한 참조는 기존 disposition을 유지한다. 같은 URL의 별도 실제
  요청이 있으면 visit_status는 그 관찰을 반영한다. response_received는 상태 코드 수신이며
  404나 리다이렉트도 포함한다. 응답 본문의 성공적인 수집·HTML 파싱·기능 존재를 뜻하지 않는다.
- `issues`: 코드·시각·관련 URL. `technologies`: 출처가 있는 제품 단서.
- `unverified`: 기능·취약점, 인증 후 영역, 동적 실행 등을 확인하지 않았다는 설명.
- `robots_paths`: Allow/Disallow, 마스킹된 path_pattern, prefix/pattern 구분, 출처·줄·시각.
  prefix는 실제 파일/페이지 존재를 확인한 뜻이 아니다. 패턴·빈 규칙은 URL 후보로 확장하지 않는다.
- `robots_checks`: 검사 URL·최종 URL·시각·상태·응답 타입·읽은 바이트·잘림·전송 오류,
  decision(allowed/missing/blocked/unknown/continued_unverified), reason, basis(response/saved_metadata), body_signals.
  body_signals의 html_markup/user_agent_directive/empty는 불리언이며 옛 기록·전송 실패는 null이다.
  특징만으로 사이트 유형이나 robots 부재를 확정하지 않는다.
  robots_html_policy=continue로 200 HTML 예외를 적용하면 decision=continued_unverified,
  reason=robots_html_continued, policy_verified=false이며 issues/unverified에도 근거를 남긴다.
- `scripts`: 읽은 JS의 URL·출처·상태·시각·파싱 여부·민감 값 없는 참조와 endpoint_patterns.
  새 자료에는 document/base_url/depth/script_depth/content_type/analysis_type이 포함되며,
  analysis_only=true는 오류 상태 응답을 기록 전용으로 분석했다는 뜻이다.
  parsed=true는 분석 경로 수행을 뜻하며 전체 구문 해석 성공이나 누락 없음을 뜻하지 않는다.
- `response_documents`: 이미 받은 robots HTML의 요청/최종 URL, purpose=robots, HTTP 상태,
  시각, content_type, parse_basis(content_type/html_markup), parsed 및 마스킹된 HTML 파싱 자료.
  원문을 저장하지 않는다. robots 실패 응답·404/410 HTML도 완전하게 수신한 경우만 분석한다.
  발견 출처/discoveries에 context=response_document를 남기고 자동 방문 가능한 형태의 링크도
  response_reference_only로 기록한다. 범위 밖·쿼리·위험 경로는 기존 제외 사유를 유지한다.
  해당 링크·외부 스크립트를 큐에 넣지 않는다. URL/API/패턴 목록에 결과를 포함한다.
  새 자료는 JS 요청에서 받은 HTML(purpose=script)과 오류 페이지 HTML(purpose=page)도 포함한다.
  purpose=script의 200 HTML은 기존 정책 안에서 참조를 큐에 넣고, 오류 상태/robots는 기록만 한다.
  depth/script_depth/analysis_only는 해당 맥락과 기록 전용 여부를 표시한다.
- `url_list`, `api_list`: URL·domain·origin·path·파라미터 이름·근거·분류 및
  observed_methods/declared_methods. 단서가 없는 메서드는 unknown이며 추측하지 않는다.
  path 그룹은 정확한 경로 문자열 기준으로 다른 origin의 같은 경로를 묶는다.
  endpoints와 목록에 provided_as_input/found_in_content/response_observed/input_only 및 방문 상태를
  추가한다. input_only는 입력 출처 외 콘텐츠 발견·HTTP 응답 근거가 없다는 뜻이다.
  found_in_content는 HTML/JS/robots/sitemap의 참조 발견이며 직접 페이지 요청 자체는 제외한다.
- `endpoint_patterns`: pattern, path, domain/origin, unresolved_base, variables,
  parameter_names, expression_kind, declared_methods, 출처, 낮은 신뢰도.
  미확인 base의 domain/origin은 null이며 domain 그룹에서는 unknown으로 묶는다.
  변수가 남는 패턴은 구체적인 URL/API 목록과 분리한다. 문자열로 완성된 주소는 후보에도 기록한다.
  어느 경우도 요청하지 않는다. 이전 JSON에 자료가 없으면 빈 목록이다.
  추가 선택 필드: resolution(resolved/partial/unresolved), resolved_url(완성 주소 또는 null),
  source_location(line/column), bindings(이름·선언/범위 위치·해석 상태),
  unresolved_variables(이름·reason·위치), inline_script(index/html_line/html_column).
  위치는 1부터 시작하며 JS 위치는 해당 스크립트 본문 기준이다. 구버전 자료의 근거를 추측해 채우지 않는다.
  source는 JS 파일 또는 HTML 주소이며 외부 JS의 document는 최초 발견 문서다. base_url은 해석 기준이다.
- `variables`: 주소 패턴의 추적 근거에서 파생한 이름·source·document·inline_script·declaration·scope,
  identity_basis(declaration/scope/reference), resolution, reasons, 연결 endpoints와 references.
  같은 이름도 출처·선언 범위가 다르면 분리하고 같은 변수의 여러 상태는 가장 미확인인 상태로 합친다.
  모든 JS 심볼의 목록이 아니며 변수의 값을 별도 저장하지 않는다.
- `js_diagnostics`: 하위 pages/response_documents/scripts의 같은 이름 목록을 모은 파생 자료.
  source/document/inline_script, detected_calls, resolved_calls, partial_calls, unresolved_calls,
  excluded_calls, duplicate_calls, excluded_reasons, calls, omitted_call_details,
  analysis_issues, limited, limit_reasons, status, coverage를 포함한다.
  calls에는 location/attribute/declared_methods/outcome/reason/duplicate만 있고 원문 인자가 없다.
  검출 수 = 완료 + 부분 + 미확인 + 제외이며 duplicate_calls는 이 합계의 부분집합이다.
  토큰화/구문 오류·모호 구간은 analysis_issues에, 추적/결과 상한은 limit_reasons에도 표시한다.
  status는 bounded_static_analysis 또는 incomplete이며 전자는 전체 문법 분석 완료를 뜻하지 않는다.
- `js_summary`: 기록된 진단 단위의 합계·이유 집계·available·incomplete_units·omitted_units.
  상세는 단위당 최대 min(max_items_per_page, 1000)개이며 HTML은 단위 1개+상세 수의 합이
  같은 페이지 진단 예산 이하여야 한다. 생략한 단위는 HTML의 js_diagnostics_omitted에 남긴다.
  예산 때문에 기록하지 못한 단위의 호출 수는 합계에 포함하지 않는다. 진단이 없는 구버전은
  available=false다. 누락 호출을 0개로 확인했다는 뜻이 아니다.
- 로컬 분석: analysis_mode=local_js, network_enabled=false, start_urls/requests/pages는 비어 있다.
  target/document는 상대 URL 기준이고 승인된 정찰 대상이 아니다. source는 local:input.js이며
  outside_scope=null(미평가), 관찰 HTTP 상태/메서드는 비어 있다. 로컬 경로·파일명·원문은 저장하지 않는다.

summary에는 input_urls 및 상태별 input_urls_* 수, endpoint_candidates, input_only_endpoints,
discovered_endpoints, response_endpoints, pages_parsed를 추가한다. 발견과 응답 수는 겹칠 수 있다.
response_documents_parsed는 별도 응답 문서 파싱 수이며 pages_parsed에 합치지 않는다.
기존 endpoints 수는 호환성을 위해 전체 후보 수로 유지하며 관찰 성공 수로 사용하지 않는다.
stop_reason은 robots의 구체적인 실패 코드, 요청 예산, 페이지 제한, 사용자 중단 등을 표시한다.
페이지 제한은 JS 수집을 중단시키지 않으므로 page_stop_reason도 별도로 남긴다.
기존 schema_version=1 파일은 오프라인으로 재분석하며 원본을 변경하지 않는다.
엔드포인트의 sources는 최대 20개지만 API 분류는 저장된 HTML/JS 호출 참조도 확인한다.
표시용 출처의 상한 도달만으로 나중에 발견한 API 호출 근거를 버리지 않는다.

robots_html_policy는 stop(기본)/continue 문자열만 허용한다. continue 예외는 HTTP 200,
HTML MIME(text/html/application/xhtml+xml), HTML 형태의 본문, 오류·잘림·NUL 없음,
User-agent/Allow/Disallow/Crawl-delay/Request-rate/Sitemap 지시문 형태가 없는 경우뿐이다.
잘못된 MIME의 텍스트 robots, 다른 상태/전송 오류·부하 신호는 예외가 아니다. 예외가 적용되면
seed에서 기존 BFS 및 참조 JS 수집을 계속하며 robots HTML에서 직접 발견한 참조는 기록만 한다.

## 오프라인 HTML 보고서

- scan은 JSON과 같은 ID의 HTML을 output_dir에 생성한다. report --format html은 기존 JSON을
  재분석해 저장소 output에 HTML을 저장하며 입력 파일과 네트워크에 영향을 주지 않는다.
- 전체/API 등 분류·도메인·메서드 근거·방문 상태·승인 범위 필터와 경로/출처 검색을 제공한다.
  응답 메서드와 선언 메서드는 별도 열이다. 출처와 파라미터 이름은 펼쳐 볼 수 있다.
  문서/엔드포인트/리소스/패턴/변수/JS 진단/요청/수집 진단을 8개 탭으로 전환한다.
  표는 50/100/250행 단위로 표시하며 검색은 전체 표에 적용한다. 리소스 유형 필터도 제공한다.
  키보드 탭 이동과 JS 비활성 시 전체 표 표시, 인쇄 시 검색 결과 전체 표시를 유지한다.
  페이지 탐색은 문서별 references에서 정방향·역방향 관계를 구성한다. 목록·가지는 40개씩 표시하고 순환을 표시한다.
  페이지·JS·함수·변수·API 후보/패턴·리소스를 검색한다. 오른쪽 상세에서 호출자·피호출자·변수 사용처를 선택할 수 있다.
  같은 스크립트의 이름 있는 function 선언과 단순 const 화살표 함수의 직접 호출 위치를 함수당 최대 8개 기록한다.
  변수는 단순 선언·매개변수에 연결되는 식별자 사용과 단순 템플릿 보간을 기록한다. 그래프의 선언과 관계를 합쳐
  JS 단위당 최대 1000개, 인라인 단위들의 합은 페이지의 max_items_per_page 이하로 제한하고 생략 여부를 표시한다.
  동일 후보의 반복 위치는 처음 위치 외 후보당 8곳, 분석 단위당 최대 1000곳까지 보존한다.
  파일 간 호출, 객체 메서드, 콜백 등록, 실제 런타임 실행 계보는 미확인이다.
- 파일 참조의 웹 위치·타입·관찰 상태/MIME/크기, 페이지·폼, 동적 패턴, 요청·robots/실패 기록을 표시한다.
  미방문 상태와 후보 분류를 그대로 유지하며 서버 파일 경로나 기능 존재를 추정하지 않는다.
- 주소 패턴 표는 해석 상태, 호출 줄/열, 인라인 script 위치, 펼칠 수 있는 상수 추적과 미확인 이유를 표시한다.
  패턴에는 해석 상태 필터, 변수 표에는 해석 상태·출처 필터와 텍스트 검색을 제공한다.
  JS 진단 표에 호출 상세·제외 이유·토큰화/상한 문제·상세 생략 수를 표시한다.
- 외부 자산 없는 단일 HTML이며 수집 문자열을 이스케이프한다. 브라우저 UI는 로컬 자료를 읽으며
  대상 JS·API 호출은 없다. JavaScript 비활성 시에는 전체 표를 읽을 수 있다.
- 기존 터미널 report와 --list JSON 출력도 유지한다. --format과 --list는 상호 배타적이다.
  --list variables/diagnostics에는 --group-by를 지원하지 않으며 잘못 조합하면 오류로 종료한다.
  analyze-js도 JSON/HTML을 같은 ID로 저장소 output에 생성한다.

## 제외·미구현 기능

공격, 인증 자동화, 파라미터 변조, 폼 제출, GET 외 메서드, 사전 대입, 포트/서브도메인
스캔은 구현하지 않는다. 경로 단위 승인 범위, SPA/JS 실행·고급 구문 분석, CSS URL·srcset 파싱,
외부 form 속성으로 연결한 입력 컨트롤, 정확한 브라우저 DOM 복구, sitemap index/gzip,
robots Sitemap 지시문 추적은 지원하지 않는다.
JS는 같은 스크립트의 선행 단순 const 문자열만 추적한다. let/var, 함수 반환값, 객체 속성,
숫자/산술, 함수 호출·쉼표·조건식이 포함된 괄호, 파일 간 상수/import 해석은 미지원이다.
문자열의 지원 범위는 인용부호/역슬래시/슬래시/백틱/달러, n/r/t/b/f/v, 숫자가 뒤따르지 않는 0,
줄 연속(LF/CRLF), xHH/uHHHH/u{hex}다. 유효 surrogate pair는 조합하며 단독 surrogate,
잘못된 escape·legacy octal 등은 거부한다. URL에 남은 공백·제어 문자·역슬래시는 후보로 쓰지 않는다.
단순 괄호 식의 중첩이 32단계에 도달하면 제외하며 괄호를 지원해도 함수/산술 평가를 허용하지 않는다.
완전한 JS 파서가 아니며 정규식/나눗셈 모호 구간·문법 오류에서 후보가 누락될 수 있다.
호출 인자의 메서드도 단일 리터럴 근거만 인정하며 동적 옵션·spread·중복 선언은 미확인이다.
헤더 전체 원문, HTML 원문, 폼 값은 저장하지 않는다.
SQLite 이력, 변경 탐지, AI, 플러그인은 향후 범위다. 로컬 웹 서비스는 D018에 따라 철회했으며
새 사용자 요청 없이 다시 구현하지 않는다.

## JS 진단의 현재 한계

unresolved_variables는 저장된 패턴의 미확인 이유다. `fetch(makeUrl())` 같은 직접 미지원 인자는
패턴 없이 제외 진단을 남긴다. coverage=recognized_call_shapes_only이며 지원 형태로 검출한 호출만
센다. 미지원 문법·토큰화 실패·모호 구간에서 검출하지 못한 호출은 셀 수 없다. 일반 URL 리터럴
후보 및 모듈/페이지 이동 참조는 fetch/axios/XHR 호출 집계에 들어가지 않는다. 상세/단위 생략도 확인해야 한다. script_item_limit 등은
호환용 통합 신호이고 세부 사유는 js_diagnostics에서 확인한다. 빈 후보나 parsed=true는 완전성 근거가 아니다.

## 2026-11-19 개선 완료 범위

앞서 제안한 네 항목을 구현했다. 테스트는 순수 분석·네트워크 차단 CLI·메모리 전송으로 검증했다.

| 순서 | 기능 | 완료 범위 |
| --- | --- | --- |
| 1 | 추출 누락 진단 | 검출한 호출 중 해석·제외 건수와 이유를 구분하고 위치를 남김. 토큰화 중단도 구별하며 전체 JS 호출을 검출했다는 보장은 하지 않음 |
| 2 | 변수 목록·해석 상태 필터 | 파일·인라인 script·선언 범위가 다른 같은 이름을 구별하고 연결된 패턴/출처/이유를 표시. resolved/partial/unresolved 필터 제공 |
| 3 | 로컬 JS 파일 분석 | analyze-js --input --base-url로 지정 파일 분석, DNS/HTTP 차단 회귀, 크기/형식/마스킹 검사와 JSON/HTML 생성 |
| 4 | 확인된 누락 구문 지원 | 민감값 없는 최소 fixture로 누락을 재현하고 이스케이프 문자열·괄호 표현식 등 작은 문법부터 회귀 테스트와 함께 보완 |

기존 JSON에 없는 원문/제외 정보를 재분석으로 복원하지 않는다. 모든 구현은 표준 라이브러리와
발견 후보 기록 전용 원칙을 유지한다. 실제 HTTP·브라우저·운영체제 검증 과제는 STATUS.md에 별도 기록한다.

## 검증 기준과 상태

설치 없는 CLI, 오프라인 계획/재분석, 승인 차단, 안전 정책, HTML/폼 분석, JSON 생성은
로컬 단위/메모리 HTTP 테스트로 확인한다. **실제 루프백 서버 크롤링 성공은 별도 완료 조건**이며
현재 sandbox의 소켓 제한 때문에 미검증 상태다. 최신 수와 실행 환경은 STATUS.md에 기록한다.
