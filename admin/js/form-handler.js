class FormHandler {
    constructor() {
        this.bindEvents();
    }

    bindEvents() {
        $(document).ready(() => {
            $('#combinedForm').on('submit', (event) => this.handleFormSubmit(event));
        });
    }

    handleFormSubmit(event) {
        event.preventDefault();
        
        const formData = $('#combinedForm').serialize();
        console.log(formData);

        $.ajax({
            url: 'config-save',
            type: 'POST',
            data: formData,
            success: (response) => {
                this.showSuccess(response.message);
            },
            error: (xhr, status, error) => {
                this.showError('An error occurred while processing your request.');
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
new FormHandler();
