// Admin Dashboard Live Control Script

document.addEventListener("DOMContentLoaded", () => {
    refreshDashboard();
    // Poll updates every 3 seconds
    setInterval(refreshDashboard, 3000);
});

async function refreshDashboard() {
    await fetchStatus();
    await fetchParticipants();
    await fetchEvents();
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
                <td><code>${p.mac_address || '00:00:00:00:00:00'}</code></td>
                <td><span class="badge-allow">${p.status}</span></td>
                <td>${p.login_time}</td>
            </tr>
        `).join("");
    } catch (e) {}
}

async function fetchEvents() {
    try {
        const res = await fetch("/api/admin/events?limit=25");
        if (!res.ok) return;
        const list = await res.json();
        const tbody = document.querySelector("#eventsTable tbody");

        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No network events recorded yet</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(e => {
            const badge = e.action === "ALLOWED" 
                ? '<span class="badge-allow">ALLOWED</span>' 
                : '<span class="badge-block">BLOCKED</span>';
            
            return `
                <tr>
                    <td><small>${e.timestamp}</small></td>
                    <td><code>${e.client_ip}</code></td>
                    <td><strong>${e.participant_id || 'Unauthenticated'}</strong></td>
                    <td><code>${e.destination}</code></td>
                    <td>${badge}</td>
                    <td><small class="text-muted">${e.reason || ''}</small></td>
                </tr>
            `;
        }).join("");
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
                <button onclick="removeDomain('${domain}')" class="btn btn-danger btn-sm">REMOVE</button>
            </li>
        `).join("");

        // Highlight active profile button
        if (data.active_profile === "contest-2026") {
            document.getElementById("btnContestProf").className = "btn btn-primary btn-sm";
            document.getElementById("btnExamProf").className = "btn btn-secondary btn-sm";
        } else {
            document.getElementById("btnContestProf").className = "btn btn-secondary btn-sm";
            document.getElementById("btnExamProf").className = "btn btn-primary btn-sm";
        }
    } catch (e) {}
}

async function addDomain(event) {
    event.preventDefault();
    const input = document.getElementById("newDomain");
    const domain = input.value.trim();
    if (!domain) return;

    try {
        const res = await fetch("/api/admin/policy/add", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain })
        });
        if (res.ok) {
            input.value = "";
            await fetchPolicy();
        }
    } catch (e) {}
}

async function removeDomain(domain) {
    if (!confirm(`Are you sure you want to remove '${domain}' from the policy allowlist?`)) return;
    try {
        const res = await fetch("/api/admin/policy/remove", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain })
        });
        if (res.ok) {
            await fetchPolicy();
        }
    } catch (e) {}
}

async function switchProfile(profileName) {
    try {
        const res = await fetch("/api/admin/policy/profile", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ profile: profileName })
        });
        if (res.ok) {
            await refreshDashboard();
        }
    } catch (e) {}
}
