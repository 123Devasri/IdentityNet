// Admin Dashboard Live Script

document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();
    setInterval(refreshDashboard, 3000);
});

async function refreshDashboard() {
    await fetchStatus();
    await fetchParticipants();
    await fetchPolicy();
}

async function fetchStatus() {
    try {
        const res = await fetch("/api/admin/status");
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById("statGateway").innerText = data.gateway;
        document.getElementById("statProfile").innerText = data.policy_profile;
        document.getElementById("statParticipants").innerText = data.active_participants_count;
    } catch (e) {}
}

async function fetchParticipants() {
    try {
        const res = await fetch("/api/admin/participants");
        if (!res.ok) return;
        const list = await res.json();
        
        document.getElementById("partBadge").innerText = list.length + " Active";
        const tbody = document.querySelector("#participantsTable tbody");
        
        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No active participant sessions</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(p => `
            <tr>
                <td><strong>${p.participant_id}</strong></td>
                <td>${p.name}</td>
                <td><code>${p.ip_address}</code></td>
                <td><code>${p.mac_address || '00-00-00-00-00-00'}</code></td>
                <td><span class="badge-allow">${p.status}</span></td>
                <td>${p.login_time}</td>
            </tr>
        `).join("");
    } catch (e) {}
}

async function fetchPolicy() {
    try {
        const res = await fetch("/api/admin/policy");
        if (!res.ok) return;
        const data = await res.json();
        
        const allowedList = data.allowed || [];
        const ul = document.getElementById("allowedDomainList");
        
        ul.innerHTML = allowedList.map(domain => `
            <li>
                <span>🌐 ${domain}</span>
            </li>
        `).join("");
    } catch (e) {}
}
