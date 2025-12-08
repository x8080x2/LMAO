class TelegramTester {
    constructor() {
        this.bindEvents();
    }

    bindEvents() {
        const testButton = document.getElementById('testTelegram');
        if (testButton) {
            testButton.addEventListener('click', () => this.testTelegramConnection());
        }
    }

    testTelegramConnection() {
        const chatId = document.getElementById('chatid')?.value;
        const botToken = document.getElementById('bottoken')?.value;

        if (!chatId || !botToken) {
            this.showError('Please provide both Chat ID and Bot Token.');
            return;
        }

        $.ajax({
            url: `https://api.telegram.org/bot${botToken}/sendMessage`,
            type: 'POST',
            data: {
                chat_id: chatId,
                text: 'This is a test message from your configuration panel.'
            },
            success: (response) => {
                this.showSuccess('Test message sent successfully!');
            },
            error: (xhr, status, error) => {
                this.showError('An error occurred while sending the test message.');
            }
        });
    }

    showSuccess(message) {
        Swal.fire({
            text: message,
            icon: 'success',
            background: '#f0f8ff',
            color: '#333',
            confirmButtonColor: '#3085d6',
            timer: 1500,
            timerProgressBar: true,
            showConfirmButton: false,
        });
    }

    showError(message) {
        Swal.fire({
            title: 'Error!',
            text: message,
            icon: 'error',
            background: '#f8d7da',
            color: '#721c24',
            confirmButtonColor: '#dc3545',
            timer: 1500,
            timerProgressBar: true,
            showConfirmButton: true,
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    new TelegramTester();
});
