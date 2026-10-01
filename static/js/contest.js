// Contest Workspace Interaction Script

function selectQuestion(id, title, description, sampleInput, sampleOutput, points) {
    document.getElementById("selectedQuestionId").value = id;
    document.getElementById("qTitle").innerText = title;
    document.getElementById("qPoints").innerText = points + " Points";
    document.getElementById("qDesc").innerHTML = "<p>" + description + "</p>";
    document.getElementById("qInput").innerText = sampleInput;
    document.getElementById("qOutput").innerText = sampleOutput;

    // Highlight active list item
    const items = document.querySelectorAll(".problem-item");
    items.forEach(item => item.classList.remove("active"));
    event.currentTarget.classList.add("active");
}

async function submitSolution(event) {
    event.preventDefault();
    const qId = document.getElementById("selectedQuestionId").value;
    const code = document.getElementById("code").value;
    const submitBtn = document.getElementById("submitBtn");
    const resultBox = document.getElementById("submitResult");

    submitBtn.disabled = true;
    submitBtn.innerText = "Submitting...";

    try {
        const formData = new FormData();
        formData.append("question_id", qId);
        formData.append("code", code);

        const response = await fetch("/submit", {
            method: "POST",
            body: formData
        });

        const data = await response.json();
        resultBox.style.display = "block";
        if (response.ok) {
            resultBox.className = "submit-result-box alert alert-success";
            resultBox.innerHTML = `<strong>✅ ${data.message}</strong><br><small>Submission ID: ${data.submission.id} | Status: ACCEPTED</small>`;
        } else {
            resultBox.className = "submit-result-box alert alert-error";
            resultBox.innerHTML = `<strong>❌ Submission Error:</strong> ${data.detail || 'Unknown error'}`;
        }
    } catch (err) {
        resultBox.style.display = "block";
        resultBox.className = "submit-result-box alert alert-error";
        resultBox.innerHTML = "<strong>❌ Connection Error:</strong> Gateway request failed.";
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = "SUBMIT CODE";
    }
}
