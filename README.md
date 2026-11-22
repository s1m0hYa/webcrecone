# WebRecon

승인된 웹 애플리케이션의 구조, 공개 링크, 폼, 입력 이름과 기술 단서를 관찰하는
Python CLI MVP입니다. 취약점 공격·검증·악용, 인증 자동화, 폼 제출을 수행하지 않습니다.

Python 3.10 이상과 표준 라이브러리만 사용합니다. 저장소 루트의 `webrecon/` 패키지를
직접 실행하므로 pip, editable install, 환경변수, 관리자 권한이 필요하지 않습니다.

## 빠른 시작

저장소 루트에서 Windows PowerShell/CMD:

```text
python -m webrecon --help
python -m webrecon plan --config config.example.json
python -m unittest discover -s tests -v
```

Linux/WSL2에서 `python` 명령이 없다면:

```text
python3 -m webrecon --help
python3 -m webrecon plan --config config.example.json
python3 -m unittest discover -s tests -v
```

Windows의 Python Launcher를 사용하는 환경에서는 `py -3`도 가능합니다.
이 문서의 `example.invalid`는 실행 대상이 아닌 문서용 이름입니다.
`config.example.json`과 `seeds.example.txt`는 문서용 예시입니다. 실제 대상은 Git에서 제외된
`config.local.json`과 `seeds.local.txt`에 설정하세요.
plan은 설정만 검사하며 DNS 조회도 하지 않습니다.

새 환경에서는 실제 대상 정보가 없는 `examples/config.public.json`과 `examples/seeds.public.txt`를
템플릿으로 사용할 수 있습니다. Windows/Linux 모두 다음 복사 명령을 사용할 수 있습니다.

```text
python -c "import shutil; shutil.copyfile('examples/config.public.json', 'config.local.json')"
python -m webrecon plan --config config.local.json
```

`example.invalid`는 접속 대상이 아닙니다. scan 전에 개인 설정의 대상·허용 origin을 수정하세요.

## 승인된 정찰 실행

예시 설정을 `config.local.json`으로 복사하고 승인받은 **전체 origin**을 지정합니다.
origin은 스킴, 정확한 호스트, 포트의 조합입니다. HTTPS의 생략된 포트는 443,
HTTP는 80입니다. 서브도메인, 다른 포트, HTTP→HTTPS 전환은 자동 허용되지 않습니다.
경로 단위 승인 범위는 MVP에서 지원하지 않으므로 일부 경로만 승인된 대상에는 사용하지 마세요.

```text
python -m webrecon plan --config config.local.json
python -m webrecon scan --config config.local.json --dry-run
python -m webrecon scan --config config.local.json --ack-authorized
python -m webrecon report --input output/webrecon-실행ID.json
python -m webrecon report --input output/webrecon-실행ID.json --format html
python -m webrecon report --input output/webrecon-실행ID.json --list urls --group-by domain
python -m webrecon report --input output/webrecon-실행ID.json --list apis --group-by path
python -m webrecon report --input output/webrecon-실행ID.json --list patterns --group-by domain
python -m webrecon report --input output/webrecon-실행ID.json --list variables
python -m webrecon report --input output/webrecon-실행ID.json --list diagnostics
```

Linux/WSL2에서는 필요에 따라 위 명령의 `python`을 `python3`로 바꿉니다.
`--ack-authorized` 없이 scan을 실행하면 네트워크 시작 전에 거부합니다.
report는 저장된 관찰 자료로 분류와 터미널 요약 또는 HTML 보고서를 다시 만들며 원본 JSON을 변경하지 않습니다.
상세 관찰은 HTML과 JSON에서 확인합니다. 종료 코드: 0은 페이지·JS 또는 JS 요청의 HTML 응답
관찰/오프라인 명령 완료, 1은 해당 관찰이 없거나 크롤러가 기록한 사용자 중단,
2는 설정·승인·파일 오류입니다. robots HTML만 받은 실행은 1입니다.
CLI까지 전달된 KeyboardInterrupt는 130으로 종료합니다.
0이어도 전체 탐색 성공을 뜻하지 않으며 `issues`와 `summary`를 확인해야 합니다.

scan 결과에 `url_list`와 `api_list`가 포함됩니다. report의 `--list urls|apis`는 해당 목록을
JSON으로 출력하고, `--group-by domain|path`는 호스트 이름 또는 정확한 경로별로 묶습니다.
같은 도메인의 다른 스킴·포트도 각각의 `origin`과 `url`로 구별합니다. 쿼리 값은 제외합니다.
API 목록은 `/api`, `/graphql` 등의 이름이나 JS 호출에서 얻은 후보이며 실제 API임을 확정하지 않습니다.

각 항목의 `observed_methods`는 응답을 받은 요청의 메서드(현재 GET만), `declared_methods`는
폼 또는 JS에 적힌 메서드입니다. 예를 들어 `fetch('/orders', {method:'POST'})`는 POST 선언으로
기록하며 전송하지 않습니다. 단서가 없으면 두 배열이 비어 있고 `method_status`는 `unknown`입니다.
기존 JSON도 report로 재분석할 수 있지만 과거에 수집하지 않은 robots/JS 자료가 복원되지는 않습니다.

보고서 요약은 입력 시작 URL을 응답 수신·요청 실패·차단·미방문으로 나누고, 엔드포인트 후보 전체와
입력만 있는 후보, 수집 자료에서 발견한 경로, 실제 HTTP 응답을 받은 경로를 별도로 표시합니다.
발견 경로와 응답 경로는 겹칠 수 있으며 합계가 후보 전체와 같아야 하는 것은 아닙니다.
HTTP 응답에는 3xx/4xx/5xx도 포함되므로 HTML 파싱 성공 수를 함께 확인하세요.
JSON의 start_urls/discoveries에는 visit_status, visit_reason, http_status가 포함됩니다.
큐에 넣었던 후보의 disposition은 실행 결과로 바뀌며 초기 값은 initial_disposition에 보존됩니다.

robots 실패 시 요약에 HTTP 상태, Content-Type, 읽은 바이트, 구체적인 실패 코드를 표시합니다.
새 JSON의 robots_checks에는 HTML 형태/User-agent 지시문의 유무만 기록하며 본문 원문은 저장하지 않습니다.
예를 들어 `robots_unexpected_content_type`은 응답 타입이 지원 범위가 아니라는 뜻이고,
`robots_access_denied`는 401/403, `robots_fetch_failed`는 전송·범위 검사 등 실패입니다.
200 HTML 응답을 robots 부재로 단정하지 않으며 기본 설정은 중단입니다. 본문 특징만으로
SPA 기본 페이지인지 접근 안내인지 확정하지 않습니다. 아래 continue 설정을 선택하면
해당 응답을 정책 미확인으로 기록하고 seed 탐색을 계속할 수 있습니다.
기존 JSON을 report로 읽으면 저장된 메타데이터에서 진단을 보완하지만, 당시 미기록한 본문 특징은
미확인으로 표시하고 원본 JSON을 덮어쓰지 않습니다.

## 브라우저에서 결과 보기

scan은 설정된 output 폴더에 같은 실행 ID의 **JSON과 HTML을 함께 저장**하고 두 파일 경로를
출력합니다. HTML 파일을 브라우저에서 열면 됩니다. 웹 서버나 설치가 필요하지 않습니다.
기존 결과는 대상에 다시 접속하지 않고 변환할 수 있습니다.

```text
python3 -m webrecon report --input output/webrecon-실행ID.json --format html
```

Windows에서는 `python` 또는 `py -3`를 사용할 수 있습니다. 오프라인 변환 결과는 저장소
`output/webrecon-실행ID.html`에 저장됩니다. 같은 실행 ID로 다시 생성하면 HTML만 교체하며
입력 JSON은 보존합니다. `--format`과 `--list`는 함께 쓰지 않습니다.

**페이지·호출 관계**에서 왼쪽의 페이지를 고르면 가운데에 해당 문서의 참조 트리가 열립니다.
JS 파일을 펼친 뒤 함수 또는 API를 선택하면 오른쪽에서 선언 메서드와 호출 위치를 확인할 수 있습니다.
왼쪽 목록을 **API 후보·패턴**으로 바꾸면 해당 후보를 참조한 함수·JS·페이지 순서로 살펴볼 수 있습니다.
파일을 공유하는 페이지가 여러 개면 각각의 참조가 표시됩니다. JS 상대 주소의 해석 기준 문서는 상세에 표시됩니다.

- 제목·주소 검색은 선택한 종류의 전체 목록에 적용됩니다. 목록과 트리 가지는 40개씩 표시합니다.
- **함수**에서 이름을 검색하면 선언한 파일·행·열과 직접 호출한 함수, 호출한 쪽의 위치를 확인할 수 있습니다.
  예를 들어 `renderSummary() → summarize() → formatCount()`에서 가운데 함수를 선택하면 양쪽으로 이동할 수 있습니다.
- **변수**를 선택하면 같은 선언을 사용하는 함수와 위치가 표시됩니다. 같은 이름의 매개변수도 선언 위치별로 구분합니다.
  트리의 ‘주소식 의존’은 해당 변수가 주소 해석에 사용되었다는 근거입니다. 변수 값은 저장하지 않습니다.
- 새 분석은 동일 스크립트의 이름 있는 함수와 단순한 const 화살표 함수의 직접 호출을 지원합니다.
  예전 JSON에 호출자가 없으면 저장된 위치만 표시합니다. 인라인 JS의 행·열은 해당 스크립트 본문 기준입니다.
- **원본 새 창 ↗**을 누르면 현재 브라우저로 해당 웹 주소에 접속합니다. 승인 origin 안에서 원래 주소와
  표시 주소가 일치한다고 기록된 페이지·리소스에 제공됩니다. 이전 JSON은 기존 참조를 탐색할 수 있으며,
  원본 주소 확인 필드나 함수 위치가 없으면 해당 기능은 표시되지 않습니다.
- **엔드포인트:** 경로·출처 검색, 도메인·분류·응답/선언 메서드·방문 상태·승인 범위 필터.
  분류 버튼으로 API·인증·관리 등 후보만 볼 수 있고, 출처를 펼쳐 발견 문서와 입력 이름을 확인합니다.
- **파일 위치:** JS·CSS·이미지·글꼴·문서 등의 참조 URL, 출처, 관찰 MIME·크기·HTTP 상태.
  확장자/HTML 참조 기반 후보이며 서버 내부 디스크 경로나 파일 존재를 확인한 결과가 아닙니다.
  리소스 유형 필터에서 JavaScript·CSS·이미지 등을 따로 볼 수 있습니다.
- **페이지·폼 / 주소 패턴:** 파싱한 문서, 폼 구조, 변수 자리표시자, 상수 선언 위치와 미확인 이유.
- **주소식 변수:** 주소 패턴에 연결된 이름, 출처·선언 위치, 연결된 패턴과 미확인 이유.
  주소 패턴에는 해석 상태 필터, 변수에는 해석 상태·출처 필터가 있습니다.
- **JS 추출 진단:** 검출한 호출의 해석/제외 수, 제외 이유, 호출 위치, 토큰화 실패·상한 도달.
- **요청·수집 진단:** 요청 순서, 상태·TLS 검증·오류, robots 정책 미확인, 중단·미처리 큐.

문서 관찰 또는 로컬 JS 분석 결과가 있으면 **페이지·호출 관계 탭**부터 열립니다. 문서가 없으면 엔드포인트·패턴·진단 등 자료가
있는 탭을 선택합니다. 탭으로 목록을 전환하고 각 표는 기본 50개씩, 선택에 따라
100/250개씩 봅니다. 검색은 현재 페이지뿐 아니라 해당 표의 전체 항목에 적용하며 필터를 바꾸면
첫 페이지로 돌아갑니다. 탭에서 방향키/Home/End도 사용할 수 있습니다.
JavaScript가 꺼져 있으면 전체 표가 표시됩니다. 인쇄에는 모든 탭의 현재 검색 결과를 포함합니다.

응답 없는 후보는 HTTP 상태를 비워 두고 미방문·차단·실패로 표시합니다. 메서드 미확인은
GET으로 추정하지 않습니다. 200도 SPA의 공통 HTML일 수 있으므로 기능 존재를 보장하지 않습니다.
분류는 겹칠 수 있고 파일 후보는 전체 엔드포인트 후보의 부분집합입니다.

HTML은 외부 폰트·스크립트·이미지를 불러오지 않습니다. 트리·검색·상세 선택은 로컬에서 처리하며,
사용자가 원본 새 창 버튼을 누를 때만 브라우저가 해당 주소를 엽니다.
브라우저 JavaScript가 꺼져 있어도 전체 목록은 읽을 수 있습니다. 원본 HTML·JS·쿠키·인증 헤더는
포함하지 않지만 대상 URL과 구조가 담기므로 공유할 때는 공개 범위를 확인하세요.
페이지 분할은 화면에 표시하는 행을 줄입니다. 데이터는 여전히 파일/DOM에 모두 있으므로
목록이 매우 크면 단일 HTML의 크기와 브라우저 처리 시간이 증가할 수 있습니다.

이미 받은 robots 응답이 HTML이면 **그 응답 자체에서 URL 후보를 추출**합니다.
a/href, 폼 action, 스크립트·기타 속성 참조, 인라인 JS의 URL/메서드/동적 패턴을 분석하고
`response_documents`에 출처·상태·파싱 자료를 남깁니다. 결과는 URL/API/패턴 목록에도 포함됩니다.
robots 허용 여부와 별개로 메모리의 응답만 분석하므로 추가 요청을 만들지 않습니다.
이 응답의 링크·외부 JS는 직접 자동 방문하지 않습니다. seed 페이지 탐색이 허용되면 그 페이지의
링크와 script src는 기존 BFS·스크립트 수집 경로에서 처리합니다.
401/403 등의 HTML도 이미 완전히 수신한 경우 후보를 기록하지만 경로의 존재·접근 가능성을 뜻하지 않습니다.
잘린 응답·압축·전송 실패는 제외합니다. HTML/JS 원문과 폼 값은 저장하지 않습니다.
터미널의 `별도 응답 HTML 분석`은 seed 페이지 방문 수와 구분됩니다. robots HTML만 받고
페이지·JS·JS 요청의 HTML 응답 관찰이 모두 없으면 scan 종료 코드는 1이며 JSON은 저장합니다.
이전 결과에 응답 본문·파싱 자료가 없으면 report만으로 URL을 복원할 수 없으므로 새 실행이 필요합니다.

## robots가 200 HTML을 반환하는 사이트

설정에 `"robots_html_policy": "continue"`를 넣으면 해당 origin의 robots 정책을 확인하지 못했다는
사실을 기록한 뒤 target/seed → 같은 범위의 페이지 링크 → 참조된 JS 수집을 계속합니다.
배포 예시와 기본 설정은 `"robots_html_policy": "stop"`을 사용합니다.

예외 조건은 **200 응답, HTML MIME(text/html 또는 application/xhtml+xml), HTML 형태 확인,
오류·잘림·NUL·robots 지시문 형태 없음**입니다. 단순히 MIME만 HTML인 텍스트 정책은 예외가 아닙니다.
401/403, 통신 실패, 429/503/Retry-After, 압축·크기 초과 및 정상 robots의 Disallow는 계속 적용합니다.
robots_checks의 decision은 continued_unverified, reason은 robots_html_continued로 표시합니다.
정책을 확인했다는 뜻이 아니며 실행 승인·범위·GET 전용·요청 간격과 모든 예산은 그대로 적용됩니다.
페이지 링크는 최대 깊이 2까지 BFS로 탐색합니다. JS의 명시적 모듈·이동 참조도 아래 제한 내에서
이어 분석합니다. JS는 실행하지 않고 API/폼은 발견만 기록합니다.

## 응답에서 다시 URL 찾기

scan은 새로 받은 탐색 응답을 실제 Content-Type에 따라 분석하고, 발견한 문서·JS 참조를 큐에
넣어 반복합니다. 페이지 URL이 JS를 반환하거나 `.js` URL이 HTML을 반환해도 해당 파서를 사용합니다.
페이지 큐가 비면 JS를 하나 읽고, 그 결과로 새 페이지가 생기면 페이지 탐색으로 돌아갑니다.

```text
페이지 HTML → 참조 JS → import된 JS → location의 페이지 URL
           → 새 HTML의 링크·참조 JS → 같은 방식으로 계속 분석
```

- 자동 탐색 근거: a/area href, iframe.src, HTML script src, 명시적인 JS import/export-from,
  단일 문자열 import(), location/window.location/document.location의 대입·href·assign·replace.
- JS 참조는 `.js/.mjs` 또는 script/import에 명시된 확장자 없는 경로를 읽습니다.
  모듈 상대 경로는 최종 JS URL, fetch/페이지 이동의 상대 경로는 최초 발견 문서의 기준 URL
  (`<base href>`가 있으면 그 주소)을 사용합니다. 실제 출처 문서와 해석 기준은 별도로 기록합니다.
  bare 패키지 이름, 계산한 import, 미확인 이동식·객체 별칭은 추측하지 않습니다.
- API 호출 선언(fetch/axios/XHR), 폼, 일반 URL 문자열, CSS·이미지 등은 계속 발견만 기록합니다.
  쿼리·범위 밖·상태 변경 의심 경로도 자동 요청하지 않습니다.
  값 없이 `?`만 붙은 주소도 방문하지 않으며, 링크·리다이렉트의 제어 문자를 지워서 방문하지 않습니다.
- 문서 이동 깊이는 `max_depth`, JS 참조 체인은 `max_script_depth`로 제한합니다. 직접 참조 JS는
  JS 깊이 0이며 기본값 2에서 추가 2단계까지 읽을 수 있습니다. JS가 HTML을 반환하거나 새 페이지로
  이어져도 기존 JS 깊이는 초기화하지 않습니다. 같은 주소 재요청과 순환도 막습니다.
- 200이 아닌 HTML/JS는 완전히 받은 경우 후보만 추출합니다. 오류 페이지의 안내 링크로 탐색을
  확장하지 않습니다. 잘림·압축·전송 실패·부하 신호는 분석/추가 요청 제한을 유지합니다.
  Content-Length보다 짧게 끊긴 응답은 `incomplete_response_body`로 기록하며 파싱하지 않습니다.
  robots가 이 상태면 탐색을 중단합니다. 비정상 Retry-After 값도 추가 요청 중단 신호로 처리합니다.

재귀 탐색도 실행 전체의 100회 요청·50회 페이지 시도·큐/응답 크기 제한을 공유합니다.
`discoveries`에서 출처·문서/JS 깊이·제외 이유를 확인할 수 있습니다. 미지원 MIME·동적 실행·
문법 한계로 모든 URL을 추출한다고 보장하지 않으며 원본 없는 이전 JSON에 새 후보를 복원할 수는 없습니다.

## 알고 있는 링크에서 시작하기

`seeds.local.txt`에 승인 범위 내 **절대 URL을 한 줄에 하나씩** 넣습니다.
`seeds.example.txt`에서 문서용 입력 예시를 확인할 수 있습니다.
빈 줄과 `#`로 시작하는 주석은 무시하고 UTF-8/BOM,
Windows 줄바꿈을 지원합니다. URL fragment의 `#`는 주석으로 해석하지 않습니다.

```text
https://example.invalid/help
https://example.invalid/products
https://example.invalid/contact
```

실제 대상에 맞게 URL과 config.local.json의 allowed_origins를 설정한 뒤:

```text
python -m webrecon plan --config config.local.json --seeds-file seeds.local.txt
python -m webrecon scan --config config.local.json --seeds-file seeds.local.txt --dry-run
python -m webrecon scan --config config.local.json --seeds-file seeds.local.txt --ack-authorized
```

JSON 설정에 `"seed_urls": ["https://example.invalid/help", "https://example.invalid/products"]`를
추가해도 됩니다. target_url → JSON seed_urls → 파일 순으로 합치고 정규화 후 중복을 제거합니다.
target_url은 그대로 첫 시작점이며 모든 시작점은 깊이 0입니다. 전체 시작점은 최대 50개이고
max_queue_size 이하여야 합니다. 파일은 최대 1MiB, JSON과 파일을 합친 입력은 1,000항목 이하입니다.

목록으로 allowed_origins가 자동 확장되지는 않습니다. 비HTTP·잘못된 URL 또는 범위 밖 URL이
있으면 네트워크 시작 전에 오류를 냅니다. 추가 seed 중 범위 안의 쿼리/API/상태 변경 의심 URL은
발견만 기록하고 방문하지 않습니다. 필수 `target_url`에 이런 URL을 넣으면 설정 오류가 됩니다.
각 origin의 robots 정책도 적용합니다. 요청·페이지 예산은 **실행 전체가 공유**하며
예산이 부족하면 모든 시작점을 방문하지 못할 수 있습니다. plan/dry-run은 마스킹된 시작점과 경로
정책을 보여주지만 DNS/robots를 확인하지는 않습니다. 입력 목록에 비밀정보를 넣지 마세요.
seeds.local*.txt와 seeds.private*.txt는 Git 제외 대상입니다.

## 동적 주소와 상수 추적

같은 스크립트에서 먼저 선언된 단순 `const` 문자열, 변수 별칭, 문자열 결합과 템플릿을
추적합니다. 외부 라이브러리나 JS 실행 없이 `fetch`, `axios.get/post/...`, XHR 형태의
`open` 호출 인자를 분석합니다.

```javascript
const baseUrl = "/api";
const path = baseUrl + "/users";
const url = `${path}/${userId}`;
fetch(url);
```

이 예시는 `/api/users/{userId}`로 기록합니다. `baseUrl`, `path`, `url`의 선언 위치와
`userId`의 미확인 이유도 남깁니다. 정의를 찾지 못한 변수와 함수 인자, 변경 가능한 `let/var`,
재할당이 관찰된 이름을 구분합니다. 함수·블록·화살표 함수·for 범위의 같은 이름을 분리하며,
각 외부 JS 파일과 인라인 script는 독립적으로 분석합니다.

`endpoint_patterns`에는 해석 상태(`resolved`, `partial`, `unresolved`), 호출 위치,
상수 추적 근거와 미확인 변수가 포함됩니다. HTML의 **주소 패턴 · 정적 해석**에서 확인하거나
`report --input <결과.json> --list patterns`로 출력합니다. 위치는 JS 본문 기준 1부터 시작하며,
인라인 코드는 script 순번과 HTML 태그 위치도 표시합니다.

모든 조각이 문자열로 해석되면 URL/API **후보** 목록에도 포함합니다. 변수가 남는 패턴은
해당 목록과 분리합니다. 두 경우 모두 자동 방문하지 않으며 실제 API 존재·실행 가능성을
확정하지 않습니다. 미확인 base의 domain/origin은 null이고 domain 그룹에서는 unknown입니다.

문자열의 일반 이스케이프, `\xHH`, `\uHHHH`, `\u{...}`와 단순 식을 감싼 괄호도 지원합니다.
예를 들어 `const base=("\x2fapi"); fetch((base + "/users"));`는 `/api/users` 후보가 됩니다.
함수 반환값·객체 속성·숫자 연산·파일 간 import는 해석하지 않습니다.
토큰·추적 깊이·조합 크기를 제한하며 전체 JavaScript 문법을 지원하지 않습니다. 민감한 이름의
변수 값은 따라가지 않고, 결과 URL의 쿼리 값·민감 경로를 마스킹합니다. 원문 코드와 별도의
상수 값 목록은 저장하지 않습니다. 기존 JSON에 원본 JS가 없으면 새 추적 결과를 복원할 수 없습니다.

`fetch(makeUrl())`처럼 인자 전체가 미지원 표현식이면 패턴은 제외하고 JS 진단에 위치와 이유를
남깁니다. 검출 수는 해석 완료·부분 해석·미확인·제외 수의 합이며 반복 호출도 포함합니다.
중복 후보는 병합하지만 반복 호출 수는 별도로 표시합니다. 토큰화 중단·모호한 구문 때문에
**검출하지 못한 호출은 집계할 수 없습니다.** `parsed=true`도 전체 구문 해석 성공을 뜻하지 않습니다.
상한 때문에 생략한 호출 상세·스크립트 진단 수를 표시하고 저장된 진단만 합산합니다.
`variables`는 주소 패턴 추적에 등장한 변수 목록이며 파일의 모든 변수를 수집한 결과가 아닙니다.

## 로컬 JavaScript 파일 분석

직접 확보한 JS 파일은 사이트에 다시 접속하지 않고 분석할 수 있습니다.
다음 예제는 DNS·HTTP 요청 없이 실행되며 `output/`에 새 JSON과 HTML을 만듭니다.

```text
python -m webrecon analyze-js --input tests/fixtures/assets/analysis-demo.js --base-url https://example.invalid/
```

실제 파일을 분석할 때는 `--input`을 해당 파일 경로로, `--base-url`을 그 스크립트를 사용한
**문서 URL**로 바꾸세요. 상대 URL 해석 기준일 뿐 해당 주소에 접속하거나 승인 범위로 등록하지
않습니다. 인증·승인 플래그는 이 오프라인 명령에 필요하지 않습니다. 결과의 승인 범위는
`미평가`, 실제 HTTP 응답·관찰 메서드는 비어 있습니다. POST 등은 선언으로만 표시합니다.

UTF-8(BOM 허용) 일반 파일 하나, 최대 1MiB를 지원하며 디렉터리·장치·FIFO는 거부합니다.
원본을 수정하지 않고 코드 원문·로컬 경로·파일명·별도 상수 값 목록을 결과에 저장하지 않습니다.
출처는 `local:input.js`(HTML에서는 ‘로컬 JS 입력’)로 표시합니다. 파일 간 변수 연결은 지원하지 않습니다.
원본 JS의 웹 주소가 없으므로 이 오프라인 명령의 모듈 상대 주소도 `--base-url` 기준의 후보입니다.
완료 후 출력된 JSON으로 `report --list patterns|variables|diagnostics` 또는 HTML 변환을 할 수 있습니다.
`--group-by`는 urls/apis/patterns에만 적용됩니다. report 자체는 JS 파일을 받지 않습니다.
종료 코드 0은 분석 명령 완료이며, 미지원 문법·제외 이유는 JS 진단을 확인해야 합니다.

## 안전 제한

모든 HTTP 요청의 User-Agent는 사용자 지정 문자열로 고정되어 있습니다.
`webrecon/config.py`의 `HTTP_USER_AGENT`에서 관리합니다.

```text
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36
```

robots 정책 평가에는 별도로 `WebRecon/0.1` 식별자를 사용합니다. HTTP 헤더를 변경해도
기존 도구 전용 규칙을 계속 적용하며, 모든 agent 그룹의 Disallow를 합치는 정책도 적용합니다.
이 문자열은 브라우저 실행을 의미하지 않으며 robots HTML 응답 문제의 해결 여부는 미확인입니다.

| 설정 | 기본값 | 허용 범위 |
| --- | --- | --- |
| request_interval | 1초 | 1~60초 |
| max_requests | 100 | 1~100 |
| max_pages | 50 | 1~50 |
| max_depth | 2 | 0~2, 최초 페이지 깊이 0 |
| max_script_depth | 2 | 0~2, 직접 참조 JS 깊이 0 |
| timeout | 10초 | 0.1~10초 |
| max_redirects | 3 | 0~3, 각 fetch의 HTTP 리다이렉트 횟수 |
| max_response_bytes | 1MiB | 1~1,048,576 바이트 |
| max_queue_size | 1,000 | 1~1,000 |
| max_items_per_page | 1,000 | 1~1,000 |
| read_sitemap | false | true 또는 false |
| read_scripts | true | 명시적으로 참조된 JS 수집, false로 비활성화 가능 |
| robots_html_policy | stop | stop 또는 continue: 제한적인 200 HTML 응답 예외 |
| output_dir | output | 저장소 output 내부 상대 경로, `/` 구분 |

- 모든 HTTP는 순차 GET입니다. 이전 요청이 **완료·실패한 뒤** 다음 요청 시작 전
  최소 1초를 기다립니다. robots, sitemap, 리다이렉트, 오류도 같은 예산을 사용합니다.
- 429/503 또는 Retry-After를 받으면 추가 요청을 중단합니다. 재시도하지 않으므로
  Retry-After 이전에 다시 요청하지 않습니다.
- 각 origin의 robots.txt를 먼저 확인합니다. **404/410은 부재로 기록하고 수집을 계속**합니다.
  접근 거부, 통신/서버 오류, 잘림, 지원하지 않는 압축, 잘못된 내용이면 전체 수집을 중단합니다.
  명시적 continue 설정의 200 HTML 예외는 위 조건에 한해 정책 미확인을 기록하고 탐색을 계속합니다.
- robots의 Disallow는 `*`, `$`도 보수적으로 적용합니다. 모든 agent 그룹의
  Disallow를 합치고 Allow 예외로 이를 해제하지 않으므로 일반 크롤러보다 적게 탐색합니다.
- robots의 Allow/Disallow 경로는 `robots_paths`에 출처·줄 번호·시각과 함께 기록합니다.
  일반 경로는 URL 후보 목록에도 포함하고, `*`/`$` 패턴은 선언 목록에만 남깁니다.
  robots 선언을 근거로 새 요청을 만들지 않습니다.
- 쿼리 URL, 상태 변경 의심 경로, API 경로는 발견만 기록합니다. 페이지 링크·iframe.src·
  명시적인 JS 페이지 이동은 문서 큐로 탐색합니다. 폼·스타일·기타 속성 URL은 요청하지 않습니다.
- HTML 인라인 JavaScript와 참조된 승인 범위의 JS 파일을 분석합니다. 모듈·문서 참조를 새로
  발견하면 남은 예산 내에서 이어 탐색합니다. 같은 범위·robots·간격·크기 제한을 적용하며 JS를 실행하지 않습니다.
  fetch, axios 메서드 호출, XMLHttpRequest 형태의 open 및 경로 문자열을 정적으로 추출합니다.
  API 호출 선언과 일반 문자열은 기록만 합니다. 명시적인 import/페이지 이동은 위 자동 탐색 규칙을 따릅니다.
- sitemap 옵션은 최초 origin의 `/sitemap.xml` 한 개에서 URL만 기록합니다.
  목록의 URL이나 sitemap index를 따라가지 않습니다.
- 비공개/루프백/링크로컬/메타데이터/특수 주소는 기본 차단합니다.
  테스트 예외는 `allowed_loopback_hosts`에 열거된 숫자형 루프백 IP에만 적용합니다.

GET에도 부작용이 있을 수 있고 URL 이름만으로 안전을 보장할 수 없습니다.
이 도구는 승인 범위와 보수적인 제한을 적용하지만 무해성을 보장하지 않습니다.
DNS·시간 제한·robots 해석·민감정보 처리의 자세한 한계는 [SECURITY.md](docs/SECURITY.md)를 보세요.

## 로컬 재현

루프백 소켓 사용이 가능한 환경에서만 실행합니다. 첫 터미널에서 테스트 fixture만 제공합니다.

```text
python -m http.server 8000 --bind 127.0.0.1 --directory tests/fixtures
```

다른 터미널의 동일한 저장소 루트에서:

```text
python -m webrecon plan --config tests/fixtures/config.loopback.json
python -m webrecon scan --config tests/fixtures/config.loopback.json --ack-authorized
python -m webrecon plan --config tests/fixtures/config.loopback.json --seeds-file tests/fixtures/seeds.loopback.txt
```

index.html과 about.html, 참조된 assets/app.js를 관찰하고 `output/local-test/`에 JSON과 HTML을 저장합니다.
정찰 종료 후 첫 터미널에서 Ctrl+C로 테스트 서버를 종료합니다. 이는 개발 검증용이며
일반 도구 실행에는 별도의 서버 설치나 실행이 필요하지 않습니다.

테스트는 외부 사이트를 사용하지 않습니다. 시간 정책은 주입한 가상 시계로 검사하고,
메모리 소켓 테스트는 실제 `HTTPConnection`/`HTTPResponse` 코드를 실행합니다.
별도의 실제 루프백 통합 테스트 2개는 소켓 생성이 환경 정책으로 거부되면
이유를 출력하고 skip합니다. **skip은 실제 HTTP 검증 성공이 아닙니다.**
상수 추적 fixture의 회귀 테스트만 확인하려면 다음 명령을 사용할 수 있습니다.

```text
python -m unittest discover -s tests -p test_js_resolution.py -v
```

이 테스트는 `tests/fixtures/assets/const-routes.js`를 메모리 전송으로 분석합니다.
일반 fixture의 index.html에는 이 파일의 참조가 없으므로 위 로컬 scan에서 자동 수집되지는 않습니다.
재귀 응답 분석은 `python -m unittest discover -s tests -p test_recursive_content.py -v`로 검증합니다.
이 테스트도 메모리 HTTP 전송이며 실제 TCP 통합 성공을 뜻하지 않습니다.

## 결과와 개인정보

결과 파일에는 실행 ID·시각·제한, 페이지 구조, 경로별 엔드포인트, 발견 위치,
요청/리다이렉트 기록, 분류 근거·신뢰도, 실패·미확인 항목을 저장합니다.
`requests[].tls_verification`은 `verified`, `failed`, `not_applicable`, `not_attempted` 중 하나입니다.
미연결·초기 실패에서는 인증서 검증 여부를 추측하지 않습니다.

모든 쿼리 값, 폼 입력값, 쿠키, 인증/사용자 정의 헤더 값, 일반 메타 내용은 저장하지 않습니다.
Content-Type/Length와 제한된 Server/X-Powered-By 제품 단서만 헤더 값으로 남깁니다.
HTML 원문·주석 내용은 저장하지 않습니다. 제목과 경로의 알려진 비밀 패턴은 마스킹하지만
임의의 텍스트에 포함된 모든 민감정보를 식별할 수는 없으므로 결과 공유 전 검토가 필요합니다.
`output/`, 개인 설정, 로그, DB, 키 등은 `.gitignore` 대상입니다.
JavaScript 원문도 저장하지 않습니다. 단순 const·결합·템플릿 외 복잡한 문법과 동적 호스트·난독화는
누락될 수 있습니다. 주석과 문자열 안의 호출 예제는 제외하지만 URL 형태의 일반 문자열은 후보가
될 수 있습니다. 정규식/나눗셈이 모호하면 구간을 건너뛰므로 같은 줄의 호출을 놓칠 수 있습니다.
공유 스크립트의 상대 URL은 처음 발견한 문서의 기준 URL(base 포함)을 사용하며 브라우저 실행 결과와 같다고 보장하지 않습니다.

## 개발 인수인계

`AGENTS.md` → 이 README → [현재 상태](docs/STATUS.md) 순서로 읽으세요.
직접 코드를 수정할 때는 [개발 가이드](docs/DEVELOPMENT.md)에서 실행 흐름, 기능별 수정 위치,
데이터 계약, JS 파서 예제와 테스트/디버깅 절차를 확인하세요.
전체 검토에서 재현한 문제·수정·남은 개선점은 [검토 기록](docs/REVIEW.md)에 있습니다.
설계는 [ARCHITECTURE.md](docs/ARCHITECTURE.md), 구현 범위는
[FUNCTIONAL_SPEC.md](docs/FUNCTIONAL_SPEC.md), 선택 이유는 [DECISIONS.md](docs/DECISIONS.md)에 있습니다.
누락 진단, 변수 목록/상태 필터, 로컬 JS 분석, 이스케이프·단순 괄호 식 지원을 구현했습니다.
지원 문법과 진단의 한계, 실제 HTTP·브라우저·운영체제별 남은 검증은 기능 명세와 현재 상태에 기록합니다.
현재 제품은 CLI와 오프라인 보고서이며 로컬 웹 서비스는 사용자 요청으로 철회되었습니다.

현재 검증 환경은 Linux/Python 3.12.3입니다. Windows·WSL2·Python 3.10의 실제 실행 및
실제 TLS 서버 연결은 아직 검증하지 않았습니다. 현재 개발 sandbox는 루프백 소켓도 차단하므로
실제 로컬 HTTP 통합 검증은 별도 실행 가능한 환경에서 완료해야 합니다.
