// 같은 파일에서 함수 세 개와 매개변수·지역 변수의 사용 위치를 따라가는 예제.
const formatCount = count => `총 ${count}개`;

function summarize(items) {
    const count = items.length;
    return formatCount(count);
}

function renderSummary(items) {
    return summarize(items);
}

renderSummary([]);
