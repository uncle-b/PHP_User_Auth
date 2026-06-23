let bodyToken = null;
let csrfToken = null;
let userId = null;
let signedIn = false;

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


let signUp = async () => {

    let usr = getEl("usr");
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

    console.log(req);

    loaderMsg("Signing you up...")
    showPage("page-loader");

    let url = "/Auth/api/SignUp.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken);

    console.log(JSON.stringify(res));

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


        console.log(req);

        loaderMsg("Signing you in...")
        showPage("page-loader");


        let url = "/Auth/api/SignIn.php";
        let method = "POST";
        let res = await authFetchJSON(url, req, bodyToken);

        console.log(JSON.stringify(res));

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


    console.log("Complete MFA procedure")
    console.log(usr.value);
    console.log(psw.value);
    console.log(mfa.value);

    if(usr.value && psw.value && mfa.value){

        let req = {
            userName: usr.value,
            password: psw.value,
            csrfToken: csrfToken,
            mfa_code: mfa.value,
            userId: userId,
            trustDevice: trustDevice.checked
        }

        console.log(JSON.stringify(req));

        loaderMsg("Checking MFA code...")
        showPage("page-loader");

        let url = "/Auth/api/SignIn.php";
        let method = "POST";
        let res = await authFetchJSON(url, req, bodyToken);

        console.log(JSON.stringify(res));

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

    console.log(JSON.stringify(res));

    if(res.error === false){
        let bodyToken = null;
        let csrfToken = null;
        let userId = null;
        let signedIn = false;
    } else {
        alert(res.message);
    }
    
    showPage("page-sign-in");
}


let showSecretData = async () => {
    loaderMsg("Obtaining some super secret data..")
    showPage("page-loader");

    let req = {};
    let url = "SecretContent.php";
    let method = "POST";
    let res = await authFetchJSON(url, req, bodyToken, method);

    console.log(JSON.stringify(res));

    //Show response
    let dest = getEl("secret-content");
        dest.innerHTML = res.message;

    showPage("page-content");
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


function pageLoader(){

    if(bodyToken === null){
        signInPage();
    }



}
*/
