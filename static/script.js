console.log("Embed app loaded");

document.addEventListener('DOMContentLoaded', () => {
    verifyIdentity();
});

async function verifyIdentity() {
    const statusElement = document.getElementById('verification-status');
    
    try {
        statusElement.textContent = "Verifying identity with backend...";
        statusElement.className = "status-pending";

        const response = await fetch('/api/auth/exchange');
        
        if (response.ok) {
            const data = await response.json();
            console.log("Identity verified:", data);
            statusElement.textContent = `Verified! User: ${data.userId}`;
            statusElement.className = "status-success";
        } else {
            console.error("Verification failed:", response.status);
            statusElement.textContent = "Verification failed unauthorized";
            statusElement.className = "status-error";
        }
    } catch (error) {
        console.error("Error verifying identity:", error);
        statusElement.textContent = "Error connecting to backend";
        statusElement.className = "status-error";
    }
}