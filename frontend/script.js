// get form and inputs

const form = document.querySelector(".login-container form");
const username = document.getElementById("username");
const password = document.getElementById("password");

// form submit event
form.addEventListener("submit", function (e) {

    if (username.value.trim() === "" || password.value.trim() === "") {
        e.preventDefault();
        alert("Please fill all fields");
        return;
    }

    if (password.value.length < 6) {
        e.preventDefault();
        alert("Password must be at least 6 characters");
        return;
    }

    // DO NOT preventDefault here
    const btnText = document.getElementById("btn-text");
    const loginBtn = document.getElementById("loginBtn");

    btnText.innerText = "Logging in...";
    loginBtn.disabled = true;


});

// small error animation helper
function shakeInputs() {
    username.classList.add("error");
    password.classList.add("error");

    setTimeout(() => {
        username.classList.remove("error");
        password.classList.remove("error");
    }, 300);
}
// Show password toggle
const togglePassword = document.getElementById("togglePassword");

togglePassword.addEventListener("change", function () {
    if (password.type === "password") {
        password.type = "text";
    } else {
        password.type = "password";
    }
});
