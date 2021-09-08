const usernameField = document.querySelector('#usernameField');
const feedBackArea = document.querySelector('.invalid-feedback');
const emailField = document.querySelector('#emailField');
const passwordField = document.querySelector('#passwordField');
const passwordField2 = document.querySelector('#passwordField2');
const emailFeedBackArea = document.querySelector('.emailFeedBackArea');
const usernameSuccessOutput = document.querySelector('.usernameSuccessOutput');
const emailSuccessOutput = document.querySelector('.emailSuccessOutput');
const showPasswordToggle = document.querySelector('.showPasswordToggle');
const showPasswordToggle2 = document.querySelector('.showPasswordToggle2');
const submitBtn = document.querySelector('.submit-btn');


const handleToggleInput = (e) => {
    if (showPasswordToggle.textContent === 'SHOW') {
        showPasswordToggle.textContent = 'HIDE';
        passwordField.setAttribute('type', 'text');
    } else {
        showPasswordToggle.textContent = 'SHOW';
        passwordField.setAttribute('type', 'password');
    }
};

showPasswordToggle.addEventListener('click', handleToggleInput);

const handleToggleInput2 = (e) => {
    if (showPasswordToggle2.textContent === 'SHOW') {
        showPasswordToggle2.textContent = 'HIDE';
        passwordField2.setAttribute('type', 'text');
    } else {
        showPasswordToggle2.textContent = 'SHOW';
        passwordField2.setAttribute('type', 'password');
    }
};

showPasswordToggle2.addEventListener('click', handleToggleInput2);


emailField.addEventListener('keyup', (e) => {
    const emailVal = e.target.value;

    emailSuccessOutput.style.display = 'block';
    emailSuccessOutput.textContent = `Checking ${emailVal}`

    emailField.classList.remove('is-invalid');
    emailFeedBackArea.style.display = 'none';

    if (emailVal.length > 0) {
        fetch('/authentication/validate-email', {
                body: JSON.stringify({
                    email: emailVal
                }),
                method: 'POST',
            })
            .then((res) => res.json())
            .then((data) => {
//                emailSuccessOutput.style.display = 'none';
                if (data.email_error) {
                    submitBtn.disabled = true;
                    emailField.classList.add('is-invalid');
                    emailFeedBackArea.style.display = 'block';
                    emailFeedBackArea.innerHTML = `<p>${data.email_error}</p>`;
                }else{
                    submitBtn.removeAttribute('disabled');
                }
            });
    }
});

usernameField.addEventListener('keyup', (e) => {
    const usernameVal = e.target.value;

    usernameSuccessOutput.style.display = 'block';
    usernameSuccessOutput.textContent = `Checking ${usernameVal}`

    usernameField.classList.remove('is-invalid');
    feedBackArea.style.display = 'none';

    if (usernameVal.length > 0) {
        fetch('/authentication/validate-username', {
                body: JSON.stringify({
                    username: usernameVal
                }),
                method: 'POST',
            })
            .then((res) => res.json())
            .then((data) => {
                usernameSuccessOutput.style.display = 'none';
                if (data.username_error){
                    usernameField.classList.add('is-invalid');
                    feedBackArea.style.display = 'block';
                    feedBackArea.innerHTML = `<p>${data.username_error}</p>`;
                    submitBtn.disabled = true;
                }else{
                    submitBtn.removeAttribute('disabled');
                }
            });
    }
});