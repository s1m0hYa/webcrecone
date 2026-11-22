// Static discovery fixture: functions are declared but never invoked.
function loadCatalog() {
    return fetch('/api/catalog');
}

function sendMessage(payload) {
    return fetch('/api/messages', {method: 'POST', body: payload});
}
