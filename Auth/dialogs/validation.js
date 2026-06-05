function validatePassWord(element){
    let pwd = element.value;
    const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*-]).{8,}$/
    return regex.test(pwd);
}

function validateEmail(element){
    if(element.type == "email"){
        return element.checkValidity();
    }

    //Non html5 fallback
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email);
}

function validateUserName(element){
    let usr = element.value;
    const regex = /^[a-z0-9]*$/gi
    return regex.test(usr);
}