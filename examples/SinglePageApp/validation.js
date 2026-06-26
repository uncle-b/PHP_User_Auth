function validatePassWord(element){
    let pwd = element.value;
    // Match server-side validation: requires lowercase, uppercase, digit, special char, min 8 chars
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*-]).{8,}$/
    return regex.test(pwd);
}

function validateEmail(element){
    if(element.type == "email"){
        return element.checkValidity();
    }

    //Non html5 fallback - more comprehensive regex
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(element.value);
}

function validateUserName(element){
    let usr = element.value;
    // Match reasonable username requirements: alphanumeric and common special chars, 3-50 chars
    const regex = /^[a-zA-Z0-9!#$%&'*+=?^_`{|}~-]{3,50}$/;
    return regex.test(usr);
}

function validateInput(){
    let subm = document.getElementById("button-sign-up");
        subm.disabled = false;

    document.getElementById("pwd1").style.backgroundColor = "#ffffff";
    document.getElementById("pwd2").style.backgroundColor = "#ffffff";
    document.getElementById("signup-usr").style.backgroundColor = "#ffffff";
    document.getElementById("eml").style.backgroundColor = "#ffffff";

    if(validatePassWord(document.getElementById("pwd1"))==false){
        subm.disabled = true;
        document.getElementById("pwd1").style.backgroundColor = "#ffcccc"
    }

    if(document.getElementById("pwd2").value !== document.getElementById("pwd1").value){
        subm.disabled = true;
        document.getElementById("pwd2").style.backgroundColor = "#ffcccc"
    }

    if(validateEmail(document.getElementById("eml"))==false){
        subm.disabled = true;
        document.getElementById("eml").style.backgroundColor = "#ffcccc";
    }
    if(validateUserName(document.getElementById("signup-usr"))==false){
        subm.disabled = true;
        document.getElementById("signup-usr").style.backgroundColor = "#ffcccc";
    }
}