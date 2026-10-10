const statusEl = document.querySelector('#status');
const profile = document.querySelector('#profile');
const username = document.querySelector('#username');
const results = document.querySelector('#results');
async function refreshStatus() {
  try {
    const r = await fetch('/api/me');
    const data = await r.json();
    if (data.connected) {
      statusEl.textContent = 'Connected successfully.';
      profile.hidden = false;
      username.textContent = `Signed in as ${data.user.name}`;
    } else {
      statusEl.textContent = new URLSearchParams(location.search).has('connected') ? 'Login returned, but no session was found. Please try connecting again.' : 'Not connected yet.';
    }
  } catch { statusEl.textContent = 'Connection status is unavailable until the server is configured.'; }
}
document.querySelector('#load-list').addEventListener('click', async () => {
  results.hidden = false; results.textContent = 'Loading your list…';
  try {
    const r = await fetch('/api/animelist'); const data = await r.json();
    if (!r.ok) throw new Error(data.message || 'Could not load list');
    results.textContent = JSON.stringify({fetched_at:data.fetched_at, counts:data.counts, first_10_entries:data.entries.slice(0,10).map(x=>({title:x.node?.title, status:x.list_status?.status, score:x.list_status?.score, episodes_watched:x.list_status?.num_episodes_watched}))}, null, 2);
  } catch(e) { results.textContent = e.message; }
});
document.querySelector('#logout').addEventListener('click', async () => { await fetch('/auth/logout',{method:'POST'}); location.href='/'; });
refreshStatus();
