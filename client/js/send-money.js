document.getElementById('transferForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the default form submission

    // Get form data
    const senderEmail = document.getElementById('senderEmail').value;
    const recipientEmail = document.getElementById('recipientEmail').value;
    const amount = document.getElementById('amount').value;
    const message = document.getElementById('message').value;

    // Create JSON object
    const data = {
        sender: senderEmail,
        recipient: recipientEmail,
        amount: amount,
        message: message
    };

    // Send data to server
    fetch('http://httpbin.org/post', { // Replace with your API endpoint
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
        // You can show a success message or redirect the user
    })
    .catch((error) => {
        console.error('Error:', error);
        // You can show an error message to the user
    });
});