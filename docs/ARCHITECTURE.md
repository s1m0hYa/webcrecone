# 아키텍처

함수별 읽는 순서, 데이터 계약, 수정·디버깅·테스트 절차는 [개발 가이드](DEVELOPMENT.md)를 참고한다.

## 구성과 책임

| 모듈 | 책임 |
| --- | --- |
| `config.py` | 기본값, 고정 상한, JSON 검증, 저장소 루트 |
| `scope.py` | 순수 URL 정규화, 정확한 origin 검증, 주소 정책, DNS 결과 검증 |
| `safety.py` | 완료 시각 기준 간격·요청 예산, 출력 마스킹 |
| `http_client.py` | 유일한 HTTP 경로, 승인 검사, robots, IP 고정 연결, TLS, 리다이렉트 |
| `models.py` | 일시적 응답과 저장 가능한 실행 결과 모델 |
| `parser.py` | 네트워크 없는 HTML 구조 추출과 필드 값 제거 |
| `javascript.py` | JS 참조 추출 호환 진입점과 저장용 참조 마스킹 |
| `js_resolver.py` | 제한된 토큰화·선언 범위·const 별칭 추적; 네트워크·JS 실행 없음 |
| `js_patterns.py` | 공통 parse_script, URL 후보와 부분 패턴·추적 근거 생성, 공통 추출 예산 |
| `js_references.py` | 기존 토큰/상수 해석을 재사용한 명시적 모듈·페이지 이동 참조 추출 |
| `js_inventory.py` | 저장된 패턴에서 변수 목록 재구성, 기록된 JS 호출 진단 집계 |
| `local_analysis.py` | 로컬 UTF-8 일반 파일의 제한적 읽기, 네트워크 없는 분석 결과 생성 |
| `crawler.py` | BFS 큐·깊이·페이지 제한, 발견 근거 수집, 선택적 sitemap 분석 |
| `analyzer.py` | 후보 분류, 기술 단서, URL/API 목록·도메인/경로 그룹 재생성 |
| `diagnostics.py` | 네트워크 없는 robots 응답 진단, 본문 특징의 불리언 추출, 이전 기록의 메타데이터 재해석 |
| `report.py` | JSON/HTML 원자적 저장, 오프라인 재분석·요약 |
| `html_report.py`, `report_template.html` | 관찰 자료의 HTML 표현과 문서 구조, 외부 연결 없는 단일 보고서 조합 |
| `report_explorer.py`, `report_explorer.js` | 출처별 관찰을 노드·참조로 변환하고 트리·선언 위치·호출자·변수 사용처 표시 |
| `report_ui.js`, `report_style.css` | 탭·검색·페이지 분할 상태와 스타일; 생성 시 HTML에 인라인으로 포함 |
| `cli.py`, `__main__.py` | 인자 처리와 모듈 조합 |

## 데이터 흐름

1. plan/scan CLI가 Config를 생성하고 target_url + seed_urls + 선택적 파일의 URL을 범위 검증·
   정규화·중복 제거한다. 출력 경계도 확인한다. report는 Config 없이 기존 JSON을 읽어 9번으로 간다.
2. plan/dry-run은 설정과 계획만 출력한다. scan은 승인 여부를 Crawler → SafeHttpClient에
   전달한다. 승인 없이는 클라이언트 생성에 실패하며 DNS/HTTP를 시작하지 않는다.
3. Crawler는 모든 시작점을 깊이 0으로 등록한다. 링크 발견 시 같은 범위·경로 정책을 검사한다.
4. client.fetch는 잠금으로 중복 실행을 거부하고 매 목적지의 robots 허용 여부를 검사한다.
   robots 최초 수집은 동일한 내부 요청 함수·간격·예산·주소 검증을 사용한다.
5. 각 시도는 간격 대기 → 예산 소비 → DNS 전체 응답 검증 → 단일 IP 연결 순이다.
   HTTPConnection의 연결 함수만 바꿔 두 번째 DNS 조회·자동 재시도를 제거했다.
   HTTPS는 기본 SSLContext로 원래 호스트의 SNI와 인증서를 검증한다.
6. 요청이 끝나거나 실패하면 finally에서 연결을 닫고 monotonic 완료 시각을 기록한다.
   각 리다이렉트는 이 경로를 다시 통과한다.
7. 상한 안의 완전한 탐색 응답을 실제 MIME에 따라 HTML/JS 순수 파서에 전달한다. 파서는 민감한 값 없는 공개 구조와,
   방문 판단에 필요한 일시적 원본 URL 목록을 반환한다. 원본 URL 목록은 저장하지 않는다.
8. 크롤러가 (scheme, host, port, path) 단위 엔드포인트와 발견 근거를 합친다.
   쿼리 값은 버리고 이름을 합친다. 출처는 경로당 최대 20개만 남긴다.
   API 분류에는 pages/response_documents/scripts의 저장된 호출 참조도 사용해 출처 표시 상한과 분리한다.
9. analyzer가 후보 분류를 붙이고 report가 저장소 output 내부에 임시 파일을 쓴 뒤 교체한다.
   scan은 JSON을 먼저 확정한 뒤 같은 실행 ID의 HTML을 생성한다. HTML 실패로 JSON을 잃지 않는다.

robots는 404/410일 때 부재로 기록하고 탐색을 계속한다. robots_html_policy=continue인 경우
제한적인 200 HTML 예외를 continued_unverified로 기록하고 origin별 임시 허용 정책을 캐시한다.
이는 부재/정상 정책으로의 판정이 아니며 기본 stop과 다른 실패 처리는 유지한다.
HTML 판별 조건은 diagnostics.eligible_for_html_fallback에 모으고 클라이언트만 허용을 결정한다.
새 origin은 같은 검사를 거치며 페이지·JS의 범위·간격·예산·리다이렉트 검증을 계속 적용한다.
성공한 정책의 Allow/Disallow는
`parse_robots_paths`로 별도 추출·마스킹한다. 출력 추출 수 제한은 실제 Disallow 검사에 영향을 주지
않는다. 최종 수집 단계에서 일반 경로만 엔드포인트 후보로 병합하며 크롤링 큐에는 넣지 않는다.

HTML 인라인 JS는 파서의 같은 추출 예산을 사용한다. run은 문서 BFS 큐와 JS 큐를 함께 소진한다.
문서 큐가 비거나 페이지 예산이 끝나면 JS를 하나 처리하고, 새 문서가 추가되면 문서 큐로 돌아간다.
두 큐 크기의 합에 기존 상한을 적용하며 모두 client.fetch를 통과한다. API 호출·일반 문자열은
기록만 하고, 명시적인 script/import·location 이동·iframe.src는 정책 검사 후 큐에 넣는다.

_analyze_response는 예상 파일 종류가 아닌 실제 Content-Type으로 파서를 선택한다. 페이지 URL의
JS 응답은 pages에 응답 관찰/parsed=false, scripts에 분석 자료를 기록한다. JS 요청의 HTML은
purpose=script인 response_documents에 저장한다. 오류 HTML은 purpose=page/script의 별도 문서로
분석하여 정상 pages_parsed에 합치지 않는다. 200 이외 HTML/JS에서 발견한 참조는 record_only다.
잘린 응답·전송/압축 오류·부하 신호는 파싱하지 않는다. 지원하지 않는 MIME은 진단으로 남긴다.

JS 모듈 참조는 최종 파일 URL을 기준으로, fetch/location은 최초 발견 문서의 base_url을 기준으로 해석한다.
base_url은 HTML base href를 반영한 해석 기준이며 source/document의 실제 출처 주소와 구분한다.
ParsedPage.base_url은 일시적 원래 주소, data.base_url 및 저장된 scripts/discoveries의 base_url은 마스킹 주소다.
각 모듈의 const 분석 상태는 독립적이며 import한 변수의 값을 연결하지 않는다. structural_references는
기존 Script 토큰을 재사용하고 import/export-from/단일 리터럴 import() 및 location 계열의 완성 주소를
추출한다. 탐색 근거 종류는 script_import/navigation이며 API 후보인 javascript와 구별한다.
새 참조도 parse_script의 같은 항목 예산을 소비한다. 원문은 버리고 출처·위치·참조 종류만 저장한다.
script_depth는 문서로 전환되어도 전달하며 새로운 script/import 간선마다 증가시켜 순환 시 깊이 초기화를 막는다.

url_list/api_list는 endpoints, pages의 폼·JS 참조, scripts의 참조, requests로 재생성한다.
응답 상태가 있는 전송만 observed_methods로, 폼/JS의 리터럴 메서드는 declared_methods로 구분한다.
기존 schema_version=1 결과의 method 없는 전송 기록은 당시 GET 전용 구현을 근거로 GET으로 읽는다.
새 필드는 선택적 추가이므로 기존 JSON의 report 호환성을 유지한다.

parse_script는 한 스크립트의 토큰·선언 범위를 한 번 구성하고 fetch/axios/XHR 형태의 호출에서
단순 문자열 const·별칭·결합·템플릿을 추적한다. 참조 위치보다 먼저 선언된 상수만 따라가며,
별칭은 선언된 범위에서 해석한다. 함수/블록/화살표 함수/for 범위를 구분하고 매개변수·let/var·
재할당·순환·미지원 표현식은 미확인 이유로 남긴다. 파일 간 및 인라인 script 간 상태를 공유하지 않는다.
호출 인자 전체가 미지원이면 패턴 없이 제외 진단을 남긴다. 별칭 초기화식의 미지원은 Unknown으로
보존할 수 있어 직접 인자와 후보 결과가 다를 수 있다. 선택 인자 diagnostics에 검출/해석/제외 수,
제외 이유·위치와 분석 한계를 채우며 기존 반환값 (references, patterns, limited)은 유지한다.
진단에는 고정 이유 코드와 메서드·위치만 남기고 호출 인자·원문 식을 저장하지 않는다.
일반 문자열/Unicode 이스케이프는 작은 디코더로 처리하고 단순 괄호 식은 기존 문자열 규칙에
재귀적으로 적용한다. 함수 호출·숫자 연산을 평가하거나 Python/JS eval을 사용하지 않는다.

endpoint_patterns는 마스킹한 주소, resolved/partial/unresolved 상태, 호출/선언 위치, 상수 이름,
미확인 이유만 보존한다. 원문 표현식과 별도 상수 값은 저장하지 않는다. 미확인 base의 origin은 null이다.
변수가 남는 패턴은 URL/API 후보 목록과 분리한다. 완성된 주소만 kind=javascript 참조로도 전달하여
기존 _discover의 기록 전용 처리를 적용한다. 두 종류 모두 방문 큐를 만들지 않는다. 추적한 초기화식의
문자열 조각을 일반 URL 리터럴로 중복 수집하지 않는다. 직접 리터럴 호출은 기존 참조 형태를 유지한다.

참조·패턴은 같은 max_items_per_page 예산을 공유한다. 완성 주소의 참조와 추적 기록은 각각 한 항목이다.
토큰 상한 250,000, 입력 1,048,576문자, 구문 괄호 깊이 128, 표현식 괄호 해석 깊이 32,
호출별 추적 깊이 12/이름 해석 128회,
조각 64개/문자열 8,192자 상한을 적용한다. 상한·잘못된 토큰 구조는 limited로 반환하며 크롤러는
기존 추출 제한 진단을 기록한다. HTML은 script 순번/태그 위치를 덧붙이고 analyzer는 저장 자료만 집계한다.
외부 JS의 script_item_limit, HTML의 extraction_limited/html_item_limit 또는
response_document_item_limit은 통합 제한 신호다. 토큰 구조 오류·추적 상한·결과 개수 제한을
이 코드만으로 구별할 수 없다. 새 js_diagnostics의 analysis_issues/limit_reasons로 구체적인 원인을
확인한다. scripts.parsed=true는 파서 호출 사실이며 완전한 구문 해석의 증거가 아니다.

호출 진단 상세는 별도 예산으로 최대 min(max_items_per_page, 1000)개다. HTML에서는 script 단위
기록 1개와 호출 상세 수를 더해 페이지의 같은 진단 예산을 공유한다. 넘친 상세는 omitted_call_details,
진단 단위는 js_diagnostics_omitted로 표시한다. 기록할 수 있는 단위에서는 상세 상한에 도달해도
검출된 호출의 합계·제외 사유 집계를 계속한다. 토큰화/문법 한계 이전에 검출되지 않은 호출은 알 수 없다.
analyzer는 pages/response_documents/scripts의 진단을 모아 js_summary로 합산한다.

variables는 endpoint_patterns의 bindings/unresolved_variables에서 파생한다. 출처, 인라인 script
순번, 이름, 선언 위치(없으면 범위 위치)로 구분한다. 옛 자료에 범위가 없으면 참조 위치를 사용해
섣부른 병합을 피한다. 같은 변수의 패턴·이유를 합치고 가장 미확인인 상태를 표시한다. 전체 심볼
목록이나 별도의 상수 값 목록이 아니다. 해석 상태·출처 필터는 HTML의 data 속성에만 작용한다.

analyze-js는 Config/Crawler/SafeHttpClient 없이 local_analysis → parse_script → analyze_report →
JSON/HTML 저장으로 이어진다. 로컬 일반 파일 여부를 열기 전후 확인하고 최대 1MiB+1을 읽어
초과를 거부한다. UTF-8/BOM만 지원하며 파일명·경로 대신 local:input.js를 출처로 쓴다.
base URL은 순수 정규화와 상대 주소 조합에만 사용한다. DNS/범위/robots/HTTP 검증을 하지 않으며
outside_scope=null, analysis_mode=local_js, network_enabled=false로 관찰 자료와 구별한다.
원본 JS의 웹 URL이 없는 이 모드에서는 모듈 상대 경로도 base URL에 대한 가정이며 unverified에 표시한다.

## 엔드포인트 발견 코드를 읽는 순서

1. parser.parse_html/_PageParser: HTML 속성·폼·인라인 script 추출.
2. js_patterns.parse_script → js_resolver.Script.calls/Resolution: 호출 형태와 단순 const·별칭 해석.
3. crawler._discover: 범위·경로·발견 종류·깊이로 기록 전용 또는 큐 등록을 결정.
   실제 요청은 SafeHttpClient가 다시 범위·robots·주소 검사를 수행한다.
4. analyzer.build_url_list/classify_endpoint/analyze_report: 저장된 근거로 목록·분류·패턴 집계.

위 파싱·분류 함수 자체는 네트워크를 사용하지 않는다. URL 이름/메서드 선언/상수 조합이
판단 근거이며 실제 기능 존재를 확정하지 않는다.

## 관찰 자료 보존

본문은 FetchResult에만 일시적으로 존재한다. ScanResult에는 HTML/본문 필드가 없다.
리다이렉트 기록은 requests의 `redirect_hop`, `redirect_to`에, 최종 관찰 URL은 pages에 남는다.
실패나 차단도 별도 요청 기록과 issues로 남긴다. 큐 등록 당시 disposition은 실행 종료 분석에서
initial_disposition으로 보존하고 최종 방문 상태로 바꾼다. analyzer는 requests를 기준으로
start_urls/discoveries/endpoints 및 URL 목록에 응답 수신·요청 실패·차단·미방문을 표시한다.
같은 주소의 중복 차단 기록이 앞선 실제 응답을 지우지 않도록 응답 기록을 우선한다.
입력·콘텐츠 발견·HTTP 응답은 독립된 근거이며 겹칠 수 있다. 경로별 합산은 기존 엔드포인트
정규화와 마스킹의 정보 손실 한계를 공유한다. pages.parsed를 통해 실제 HTML 파싱과 구별한다.

robots_checks는 origin별 정책 검사 결과다. 클라이언트가 상태·타입·실패·관찰 크기와
본문 특징의 불리언만 보관하고, diagnostics가 진단 코드를 결정한다. 실제 정책 파싱과
접근 허용은 계속 클라이언트가 담당한다. 기존 JSON은 저장된 requests로 진단 자료를
재구성하되 본문 특징은 null, basis는 saved_metadata로 표시한다. 지원 MIME인 200만으로
옛 본문이 유효했다고 추정하지 않고 decision=unknown으로 남긴다.

이미 수신한 robots HTML은 정책 판정과 별도로 분석한다. 클라이언트는 오류·잘림이 없고
HTML MIME 또는 HTML 형태의 본문인 FetchResult만 메모리에 보관하고 take_robots_html_responses로
크롤러에 넘긴 뒤 비운다. origin당 한 번, 최대 20 origin이며 각 본문에 기존 1MiB 상한을 적용한다.
크롤러는 기존 순수 HTML 파서와 마스킹을 사용하고 response_documents에 구조만 저장한다.
참조는 _discover(record_only=True)로 합쳐 범위·경로 판정과 출처를 남기며 큐에는 넣지 않는다.
analyzer는 이 문서의 폼·인라인 JS 선언·동적 패턴을 오프라인 재분석에 포함한다.
pages와 분리하여 robots 응답을 seed 페이지 방문 성공으로 집계하지 않는다.

## 제한의 의미

상대 참조 조합은 scope.resolve_reference로 모은다. urllib.parse.urljoin이 제어 문자를 제거하거나
빈 쿼리 구분자를 생략하기 전에 입력을 검사하고, 정규화/마스킹에도 빈 `?`를 보존한다.
이 함수는 네트워크/범위 승인 기능이 없으며 최종 URL은 기존 client.fetch 검증을 거친다.
HTTPResponse.read1의 EOF만으로 수신 완료를 판단하지 않고 선언된 길이의 잔여량도 확인한다.
미달은 incomplete_response_body로 기록하며 본문을 파서로 넘기지 않는다. Retry-After는 값 해석 전에 중단한다.

- max_requests는 DNS·전송 시도 예산이다. 범위/robots에 의한 요청 전 차단은 소비하지 않는다.
  연결 실패도 한 번으로 센다. 모든 실제 HTTP 요청은 이 예산 안에 포함된다.
- max_pages는 BFS에서 꺼내 fetch하는 시작 URL 수다. 실패도 소비한다.
  리다이렉트 hop과 robots/sitemap은 페이지 수 대신 요청 예산으로 제한한다.
- 외부 JS는 max_pages를 소비하지 않고 공통 요청 예산을 소비한다. max_depth는 문서 링크/iframe/
  JS 페이지 이동에 적용하며 최종 깊이 페이지에 직접 참조된 JS도 읽을 수 있다. JS별 추출 수도 max_items_per_page다.
- max_script_depth(기본/상한 2)는 직접 참조 JS 0부터 추가 모듈/JS 참조 단계를 제한한다.
  HTML로 바뀌거나 페이지로 이동해도 이전 script_depth를 보존한다. 처음부터 문서 링크를 따라간
  경로는 JS를 처음 만날 때 0이다. 두 깊이는 별개이며 어떤 경로도 실행 전체 예산을 늘리지 않는다.
- max_depth는 최초 페이지 0부터 문서 이동 단계다. HTTP 리다이렉트는 두 깊이를 늘리지 않는다.
- 모든 시작점은 깊이 0이며 요청/페이지/큐 예산과 방문 집합을 공유한다. 고유 시작점은 최대 50개다.
  파일은 최대 1MiB, 입력은 합계 1,000항목 이하이며 초기 큐 초과는 설정 단계에서 거부한다.
  plan/result의 start_urls에는 마스킹된 시작 주소와 경로 판정이 남고 실제 방문은 requests/pages로 확인한다.
- 큐는 max_queue_size, 한 페이지의 참조·폼·필드·메타 총합은 max_items_per_page로 제한한다.
- 본문 크기 초과 확인에 1바이트를 더 읽을 수 있다. 메모리 보관은 설정 크기 이하이며
  잘린 HTML과 robots, sitemap은 분석하지 않는다. 압축 해제를 하지 않는다.
- 한 실행에서 정규화된 URL은 다시 요청하지 않는다. 리다이렉트가 이전 URL로 향하면 중단한다.

## 확장 기준

HTML 보고서는 저장된 url_list/requests/pages/response_documents와 패턴·진단만 읽는 표현 계층이다.
파일 후보 유형은 확장자와 HTML script/stylesheet 참조로 판단하며 새로운 수집·분류 요청을 만들지
않는다. 원본 JSON을 바꾸거나 API 존재/미확인 메서드를 추정하지 않는다. HTML 이스케이프, URL 재마스킹,
고정 UI 스크립트의 CSP 해시를 적용하고 대상 URL은 텍스트로 표시한다. 템플릿·UI·CSS는 패키지 옆 파일로
분리해 유지보수하고 표준 라이브러리 string.Template로 한 번 삽입한다. 생성 HTML은 별도 자산 파일이 필요 없다.
정적 표는 JavaScript 없이도 읽을 수 있고
탐색기 데이터는 숨겨진 요소의 이스케이프된 JSON 텍스트로 전달한다. JS는 숫자 ID로 역참조를 구성하고
펼쳐진 가지만 그린다. 링크 관계는 개별 문서·스크립트의 references와 endpoint_patterns에 근거한다.
추가 호출 위치는 같은 분석 단위 안에서만 보충한다. 외부 스크립트의 document는 해당 주소를 해석한 문서다.
js_symbols.py는 스크립트의 토큰·범위·바인딩으로 symbol_graph를 만든다. symbols의 순번은 해당 JS 단위 안에서만 유효하다.
relations는 호출 또는 변수 사용 위치와 양 끝의 심볼 ID를 담는다. source가 null이면 파일/인라인 본문 최상위다.
보고서는 출처와 선언 위치로 새 자료와 종전 함수·주소식 근거를 결합한다. 원본은 새 창 버튼으로 따로 연다.

UI 초기화 후 8개 구역을 탭으로 전환하고 7개 표를 기본 50행씩 표시한다. 문서 탭이 기본이며
검색/필터는 전체 행에 적용한다. 이는 DOM 가상화가 아니므로 대규모 파일의 메모리 비용은 남는다.
인쇄는 모든 탭의 검색 일치 행을 표시하고 페이지 분할만 해제한다. JS 비활성 시 전체 표를 표시한다.

report --format html은 입력 파일 위치와 관계없이 저장소 output에 UUID 기반 HTML만 쓴다.
scan은 기존 output_dir 설정을 따른다. 두 형식은 공통 원자적 저장/경로 경계 검사를 사용하며
HTML 생성 오류가 나면 이미 확정한 JSON은 남고 CLI에 그 경로가 출력되어 있다.

플러그인·이벤트 버스·비동기 큐 없이 명시적인 함수 호출을 사용한다. 향후 분석은 기존
JSON 자료로 추가할 수 있다. 새 수집기를 추가해도 public `fetch`만 사용해야 하며
robots 우회 인자나 원시 연결을 노출하지 않는다. clock/sleep 주입은 테스트 목적이며 CLI에 없다.
Python 코드를 임의로 수정하는 사용자를 막는 보안 샌드박스는 아니다.

변수 목록은 기존 추적 필드에서 재구성할 수 있지만 미기록 호출의 누락 진단은 원본 JS가 없는
옛 JSON에서 복원할 수 없다. js_summary.available=false로 미기록과 호출 0개를 구별한다.
구체적인 지원 범위는 FUNCTIONAL_SPEC.md, 검증 상태와 다음 작업은 STATUS.md에서 관리한다.

## 공유 JS와 모듈 호출의 데이터 흐름

`script_contexts.py`는 실제 HTML의 문서 주소·base와 명시된 스크립트 참조를 수집한다.
전송 종료 후 성공적으로 받은 JS의 최종 주소와 요청 당시 별칭을 대조한다. 이미 관찰한 import를 따라
(최종 파일, 문서, base)마다 한 번 해석한다. 발견 전용 콜백에 저장만 맡긴다.
`report_explorer.py`는 페이지별 JS와 심볼을 생성한 뒤 import 위치, 관찰 파일, export 선언 ID를
대조해 모듈 호출 간선을 만든다. JSON에 근거가 없는 예전 실행은 기존 단위로 표시한다.
