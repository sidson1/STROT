window.onload = () => {
    getNetworkDevices();
};


function init_page(){
    "STROT".forEach((t, a)=> {
        document.getElementById("strot_name").innerText = document.getElementById("strot_name").innerText + t;

    }) 
}

// Function to fetch the list of network devices and process each IP
async function getNetworkDevices() {
    try {
        // Call the Python function and wait for the result
        const devices = await eel.network_devices()(); // Get the list of IPs

        // Process each IP address one by one
        devices.forEach((ip, index) => {
            console.log(`IP ${index + 1}: ${ip}`);
            place_ip(ip)
            // You can perform other actions with each IP here
        });
    } catch (error) {
        console.error("Error fetching network devices:", error);
    }
}

// Example: Trigger the function when a button is clicked

const predefinedPositions = [
    "50,50", "100,150", "200,300", "400,200", "300,100",
    "500,400", "600,250", "700,50", "800,350"
]; // Predefined coordinates as "x,y"
const usedPositions = new Set(); // Store positions already used

function getRandomPredefinedPosition() {
    const availablePositions = predefinedPositions.filter(pos => !usedPositions.has(pos));
    if (availablePositions.length === 0) {
        alert("No more positions available!");
        return null;
    }

    // Randomly select an available position
    const randomIndex = Math.floor(Math.random() * availablePositions.length);
    return availablePositions[randomIndex];
}

function place_ip(ip) {
    const body = document.body;

    // Get a random predefined position that hasn't been used
    const position = getRandomPredefinedPosition();
    if (!position) return; // Stop if no position is available

    usedPositions.add(position);

    // Split position into x and y coordinates
    const [x, y] = position.split(',').map(Number);

    // Create and style the new "Hello World" element
    const helloElement = document.createElement('div');
    helloElement.textContent = ip;
    helloElement.style.position = "absolute";
    helloElement.style.left = `${x}px`;
    helloElement.style.top = `${y}px`;

    // Append to body
    body.appendChild(helloElement);
}