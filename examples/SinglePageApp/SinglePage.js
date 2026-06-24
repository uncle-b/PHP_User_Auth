let bodyToken = null;
let csrfToken = null;
let userId = null;
let signedIn = false;
let sessionData = sessionStorage.getItem("sessionData")

if(sessionData){
    let sess = JSON.parse(sessionData);
    if(sess.bodyToken){bodyToken = sess.bodyToken};
    if(sess.userId){userId = sess.userId};
}


let getEl = (id) => {
    return document.getElementById(id);
}

let loaderMsg = (msg) => {
    let ldrMsg = getEl("loader-message");
    ldrMsg.innerHTML = msg;
}

let showPage = (pageId) => {
    let pages = document.getElementsByClassName("page");
    for(let i=0; i<pages.length; i++){
        if(pages[i].id != pageId){
            pages[i].style.display = "None";
        } else {
            pages[i].style.display = "Block";
        }
    }
}


// Global variables for password reset
let resetAccount = null;
let resetToken = null;

// Check URL parameters on page load for password reset
function checkUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const account = urlParams.get('account');
    const token = urlParams.get('token');
    
    if (account && token) {
        resetAccount = account;
        resetToken = token;
        // Clear the URL parameters to avoid showing them in the address bar
        window.history.replaceState({}, document.title, window.location.pathname);
        // Show the password reset page
        showPage('page-password-reset');
    }
}

let signUp = async () => {

    let usr = getEl("signup-usr");
    let pwd = getEl("pwd1");
    let eml = getEl("eml");

    let req = {
        userName: usr.value,
        password: pwd.value,
        email: eml.value,
        validationUrl: window.location.hostname+"/examples/SinglePageApp/emailValidate.php"
    }

    if (csrfToken){
        req.csrfToken = csrfToken;
    }

    loaderMsg("Signing you up...")
    showPage("page-loader");

    let url = "/Auth/api/SignUp.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken);

    if(res.error===false){
        showPage("page-sign-up-success");
    } else {
        getEl("sign-up-message").innerHTML = res.message;
        showPage("page-sign-up");
    }


}

let signIn = async () => {

    let usr = getEl("usr");
    let psw = getEl("psw");
    let trustDevice = getEl("trust-device");

    if(usr.value && psw.value){

        let req = {
            userName: usr.value,
            password: psw.value,
            
        }

        if (csrfToken){
            req.csrfToken = csrfToken;
        }


        loaderMsg("Signing you in...")
        showPage("page-loader");


        let url = "/Auth/api/SignIn.php";
        let method = "POST";
        let res = await authFetchJSON(url, req, bodyToken);

        if(res.error===false){
            //Sign in successful

            // {"error":false,"mfaPending":true,"userId":1,"username":"Bart","message":"MFA code sent to your email"}
            if(res.mfaPending === true){
                userId = res.userId
                showPage("page-mfa-complete");
            } else {
                if(res.bodyToken){bodyToken = res.bodyToken};
                if(res.csrfToken){csrfToken = res.csrfToken};
                if(res.userId){userId = res.userId};
                signedIn = true;

                let sess = {
                            bodyToken: res.bodyToken,
                            userId: res.userId
                            };

                sessionStorage.setItem("sessionData", JSON.stringify(sess));


                showPage("page-content");
            }


            
        } else {
            //Sign in failed
            let msg = "An unknown error occured";
            if(res.message){msg = res.message;}

            let msgBox = getEl("sign-in-message");
                msgBox.innerHTML = msg;

            showPage("page-sign-in");

        }
    }
}

let mfaComplete = async () => {
    let usr = getEl("usr");
    let psw = getEl("psw");
    let trustDevice = getEl("trust-device");
    let mfa = getEl("mfa_code");

    if(usr.value && psw.value && mfa.value){

        let req = {
            userName: usr.value,
            password: psw.value,
            csrfToken: csrfToken,
            mfa_code: mfa.value,
            userId: userId,
            trustDevice: trustDevice.checked
        }

        loaderMsg("Checking MFA code...")
        showPage("page-loader");

        let url = "/Auth/api/SignIn.php";
        let method = "POST";
        let res = await authFetchJSON(url, req, bodyToken);

        if(res.error === false){
            // Sign in completed
            if(res.bodyToken){bodyToken = res.bodyToken};
            if(res.csrfToken){csrfToken = res.csrfToken};
            if(res.userId){userId = res.userId};
            signedIn = true;
            showPage("page-content");
        } else {
            //Sign in failed
            let msg = "An unknown error occured";
            if(res.message){msg = res.message;}
            let msgBox = getEl("sign-in-message");
                msgBox.innerHTML = msg;

            showPage("page-sign-in");
        }
    }
}

let signOut = async () => {
    loaderMsg("Signing you out..")
    showPage("page-loader");

    let req = {};
    let url = "/Auth/api/SignOut.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken, method);

    bodyToken = null;
    csrfToken = null;
    userId = null;
    signedIn = false;

    sessionStorage.removeItem("sessionData");
    
    showPage("page-sign-in");
}


let showSecretData = async () => {
    loaderMsg("Obtaining some super secret data..")
    showPage("page-loader");

    let req = {};
    let url = "SecretContent.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken, method);

    //Show response
    let dest = getEl("secret-content");
        dest.innerHTML = res.message;

    showPage("page-content");
}


// Password Forgot function
let passwordForgot = async () => {
    let username = getEl("forgot-username");
    
    if(!username.value || username.value.length < 3) {
        getEl("password-forgot-message").innerHTML = "Please enter a valid username (minimum 3 characters).";
        return;
    }

    let req = {
        username: username.value,
        resetURL: window.location.origin + window.location.pathname
    };
    
    if (csrfToken) {
        req.csrfToken = csrfToken;
    }

    loaderMsg("Sending reset link...");
    showPage("page-loader");

    let url = "/Auth/api/passwordForgot.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken);

    if(res.error === false) {
        // Success - show success message
        getEl("password-forgot-message").innerHTML = res.message;
        showPage("page-password-forgot");
    } else {
        // Error
        getEl("password-forgot-message").innerHTML = res.message;
        showPage("page-password-forgot");
    }
}

// Password Reset function
let passwordReset = async () => {
    let pwd1 = getEl("reset-pwd1");
    let pwd2 = getEl("reset-pwd2");
    
    if(!pwd1.value || !pwd2.value) {
        getEl("password-reset-message").innerHTML = "Please enter and confirm your new password.";
        return;
    }
    
    if(pwd1.value !== pwd2.value) {
        getEl("password-reset-message").innerHTML = "Passwords do not match.";
        return;
    }
    
    if(!validatePassWord(pwd1)) {
        getEl("password-reset-message").innerHTML = "Password does not meet requirements.";
        return;
    }
    
    if(!resetAccount || !resetToken) {
        getEl("password-reset-message").innerHTML = "Invalid or expired reset link.";
        return;
    }

    let req = {
        account: resetAccount,
        token: resetToken,
        newPassword: pwd1.value
    };
    
    if (csrfToken) {
        req.csrfToken = csrfToken;
    }

    loaderMsg("Resetting password...");
    showPage("page-loader");

    let url = "/Auth/api/passwordReset.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken);

    if(res.error === false) {
        // Success - reset the global variables and show success page
        resetAccount = null;
        resetToken = null;
        pwd1.value = "";
        pwd2.value = "";
        showPage("page-password-reset-success");
    } else {
        // Error
        getEl("password-reset-message").innerHTML = res.message;
        showPage("page-password-reset");
    }
}

// Toggle password visibility for reset form
function togglePasswordVisibility() {
    let pwd1 = getEl("reset-pwd1");
    let pwd2 = getEl("reset-pwd2");
    
    if(pwd1.type === "password") {
        pwd1.type = "text";
        pwd2.type = "text";
    } else {
        pwd1.type = "password";
        pwd2.type = "password";
    }
}

// Validate password reset form
function validatePasswordReset() {
    let pwd1 = getEl("reset-pwd1");
    let pwd2 = getEl("reset-pwd2");
    let subm = getEl("button-password-reset");
    
    // Reset styles
    pwd1.style.backgroundColor = "#ffffff";
    pwd2.style.backgroundColor = "#ffffff";
    
    // Validate password strength
    if(validatePassWord(pwd1) === false) {
        subm.disabled = true;
        pwd1.style.backgroundColor = "#ffcccc";
        return;
    }
    
    // Validate passwords match
    if(pwd2.value !== pwd1.value) {
        subm.disabled = true;
        pwd2.style.backgroundColor = "#ffcccc";
        return;
    }
    
    // If both validations pass
    if(validatePassWord(pwd1) === true && pwd2.value === pwd1.value) {
        subm.disabled = false;
    }
}


/*None
function input(id, clss, type, parent=null){

    let newInput = document.createElement("INPUT");
        newInput.id = id;
        newInput.className = clss;
        newInput.type = type;

    if(parent !== null){
        parent.appendChild(newInput);
    }

    return newInput;

}


function signInPage(){
    let contentArea = document.getElementById("content-area");
    let topBar = document.getElementById("top-bar");

    topBar.innerHTML = "";
    contentArea.innerHTML = "";
    
    let usr = input("usr", "", "text", contentArea);
    let psw = input("psw", "", "password", contentArea);



}
*/

function pageLoader(){

    if(bodyToken === null){
        showPage("page-sign-in");;
    } else {
        showPage("page-content");
    }
}


