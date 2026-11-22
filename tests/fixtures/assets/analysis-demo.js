// 오프라인 분석 예제. 실행하거나 실제 주소에 요청하는 테스트가 아니다.
const baseUrl = ("\x2fapi");
const users = (baseUrl + "/users");
fetch((users));
fetch(users); // 같은 선언·주소는 병합하고 반복 호출 수는 진단에 남긴다.

function loadUser(userId) {
    const detail = `${users}/${userId}`;
    fetch(detail);
}

function loadOrder(userId) {
    fetch(baseUrl + "/orders/" + userId); // 다른 함수의 같은 이름은 별도 변수다.
}

fetch(runtimeUrl);                         // 미확인 주소
fetch(makeUrl());                          // 함수 실행이 필요하므로 제외
fetch(`https://${host}/api`);               // 동적 호스트는 제외
fetch("/api/search?q=example-value");       // 쿼리 값은 저장하지 않는다
fetch("/api/orders", {method: "POST"});     // 메서드 선언만 기록
