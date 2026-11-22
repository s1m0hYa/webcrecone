// Comments and quoted examples must not create calls.
/* fetch('/comment-only'); */
const sample = "fetch('/quoted-example')";
const baseUrl = "/api";
const path = baseUrl + "/users";
const url = `${path}/${userId}`;
fetch(url);

const listUrl = path + "/list";
axios.post(listUrl);
const helpUrl = "/help-from-js";
fetch(helpUrl);

const token = "/SHORT_PRIVATE";
const protectedUrl = `${baseUrl}/items?token=${token}`;
fetch(protectedUrl);

function selectItem(userId) {
  const details = `${path}/${userId}`;
  fetch(details);
}
