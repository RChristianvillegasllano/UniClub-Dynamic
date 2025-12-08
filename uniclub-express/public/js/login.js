const container = document.querySelector("#auth-container");
const signInForm = document.querySelector("#sign-in-form");
const signUpForm = document.querySelector("#sign-up-form");
const rememberCheckbox = document.querySelector("#remember-me");
const forgotLink = document.querySelector("#forgot-password-link");
const passwordToggles = document.querySelectorAll(".password-toggle");

const sign_up_btn = document.querySelector("#sign-up-btn");
const sign_in_btn = document.querySelector("#sign-in-btn");

const signInRole = document.querySelector("#signin-role");
const signInUmtcId = document.querySelector("#signin-umtcid");
const signInPassword = document.querySelector("#signin-password");

const signupRole = document.querySelector("#signup-role");
const signupUmtcIdInput = document.querySelector("#signup-umtcid");
const signupPasswordInput = document.querySelector("#signup-password");
const signupConfirmInput = document.querySelector("#signup-confirm");

const signupSteps = signUpForm ? signUpForm.querySelectorAll(".step") : [];
const nextBtn = signUpForm ? signUpForm.querySelector("#signup-next") : null;
const backBtn = signUpForm ? signUpForm.querySelector("#signup-back") : null;
const stepIndicator = document.querySelector("#step-indicator");
const progressValue = document.querySelector("#step-progress-value");

let currentStep = 0;

sign_up_btn?.addEventListener("click", () => {
  container?.classList.add("sign-up-mode");
});

sign_in_btn?.addEventListener("click", () => {
  container?.classList.remove("sign-up-mode");
  signInRole.value = "";
  if (signInUmtcId) signInUmtcId.value = "";
  if (signInPassword) signInPassword.value = "";
});

function clampToSixDigits(input) {
  input.addEventListener("input", () => {
    input.value = input.value.replace(/[^0-9]/g, "").slice(0, 6);
  });
  input.addEventListener("paste", (event) => {
    event.preventDefault();
    const paste = (event.clipboardData || window.clipboardData).getData("text");
    input.value = paste.replace(/[^0-9]/g, "").slice(0, 6);
  });
}

if (signInUmtcId) clampToSixDigits(signInUmtcId);
if (signupUmtcIdInput) clampToSixDigits(signupUmtcIdInput);

(function prefillRemembered() {
  if (!signInUmtcId || !rememberCheckbox) return;
  try {
    const remembered = localStorage.getItem("rememberUMTC") === "true";
    const savedId = localStorage.getItem("rememberUMTCId") || "";
    rememberCheckbox.checked = remembered;
    if (remembered && savedId) {
      signInUmtcId.value = savedId;
    }
  } catch (e) {
    console.warn("Unable to read remember-me preference", e);
  }
})();

signInForm?.addEventListener("submit", (event) => {
  event.preventDefault();

  const role = signInRole?.value;
  const umtcId = signInUmtcId?.value.trim();
  const password = signInPassword?.value;

  if (!role) {
    alert("Please select your role.");
    signInRole?.focus();
    return;
  }
  if (!umtcId) {
    alert("Please enter your UMTC ID.");
    signInUmtcId?.focus();
    return;
  }
  if (!/^\d{6}$/.test(umtcId)) {
    alert("UMTC ID must be exactly 6 digits (numbers only).");
    signInUmtcId?.focus();
    return;
  }
  if (!password) {
    alert("Please enter your password.");
    signInPassword?.focus();
    return;
  }

  try {
    if (rememberCheckbox?.checked) {
      localStorage.setItem("rememberUMTC", "true");
      localStorage.setItem("rememberUMTCId", umtcId);
    } else {
      localStorage.removeItem("rememberUMTC");
      localStorage.removeItem("rememberUMTCId");
    }
  } catch (e) {
    console.warn("Unable to store remember-me preference", e);
  }

  const studentAccounts = [
    { id: "345678", password: "member123", name: "Student Member" },
  ];

  const validAccount = studentAccounts.find(
    (account) => account.id === umtcId && account.password === password
  );

  if (!validAccount) {
    alert("Invalid credentials. Please check your UMTC ID and password.");
    return;
  }

  try {
    localStorage.setItem("isLoggedIn", "true");
    localStorage.setItem("userUMTCId", umtcId);
    localStorage.setItem("userName", validAccount.name);
    localStorage.setItem("loginTime", new Date().toISOString());
  } catch (e) {
    console.warn("Failed to store session data:", e);
  }

  alert(`Welcome ${validAccount.name}!`);
  window.location.href = "/student/dashboard";
});

forgotLink?.addEventListener("click", (event) => {
  event.preventDefault();
  const currentId = signInUmtcId?.value.trim();
  const idForReset = currentId || prompt("Enter your UMTC ID to reset password:") || "";
  if (!idForReset) return;
  alert(`Password reset link would be sent for ID: ${idForReset}`);
});

function showStep(stepIndex) {
  if (!signupSteps.length) return;
  signupSteps.forEach((step, index) => {
    step.classList.toggle("active", index === stepIndex);
  });
  const total = signupSteps.length;
  if (stepIndicator) stepIndicator.textContent = `${stepIndex + 1} / ${total}`;
  if (progressValue) {
    const percentage = ((stepIndex + 1) / total) * 100;
    progressValue.style.width = `${percentage}%`;
  }
}

function validateStep1() {
  const role = signupRole?.value;
  const name = document.querySelector("#signup-fullname")?.value.trim();
  const umtcId = signupUmtcIdInput?.value.trim();
  const email = document.querySelector("#signup-email")?.value.trim();
  const pass = signupPasswordInput?.value;
  const confirm = signupConfirmInput?.value;

  if (!role || !name || !umtcId || !email || !pass || !confirm) {
    alert("Please complete all required fields.");
    return false;
  }
  if (!/^\d{6}$/.test(umtcId)) {
    alert("UMTC ID must be exactly 6 digits.");
    return false;
  }
  const hasUpper = /[A-Z]/.test(pass);
  const hasNumber = /\d/.test(pass);
  const hasSymbol = /[^A-Za-z0-9]/.test(pass);
  if (!hasUpper || !hasNumber || !hasSymbol) {
    alert("Password must include an uppercase letter, number, and symbol.");
    return false;
  }
  if (pass !== confirm) {
    alert("Passwords do not match.");
    return false;
  }
  if (!/@umindanao\.edu\.ph$/i.test(email)) {
    alert("Please use your @umindanao.edu.ph email.");
    return false;
  }
  return true;
}

showStep(currentStep);

nextBtn?.addEventListener("click", () => {
  if (!validateStep1()) return;
  currentStep = Math.min(currentStep + 1, signupSteps.length - 1);
  showStep(currentStep);
});

backBtn?.addEventListener("click", () => {
  currentStep = Math.max(currentStep - 1, 0);
  showStep(currentStep);
});

signUpForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  const contact = document.querySelector("#signup-contact")?.value.trim();
  const course = document.querySelector("#signup-course")?.value.trim();
  const year = document.querySelector("#signup-year")?.value;
  if (!contact || !course || !year) {
    alert("Please complete contact, course, and year level.");
    return;
  }
  alert("Signup successful! We'll reach out with next steps.");
});

passwordToggles.forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const targetId = toggle.getAttribute("data-target");
    const input = document.getElementById(targetId);
    if (!input) return;
    const isPassword = input.getAttribute("type") === "password";
    input.setAttribute("type", isPassword ? "text" : "password");
    toggle.innerHTML = `<i class="fas fa-${isPassword ? "eye-slash" : "eye"}"></i>`;
  });
});

