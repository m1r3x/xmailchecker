const secret = "6b647294775f31ff6feaf95a77661e3974fc6563b5cb65d6db35cba74a6e4f6d";
const authServer = 'https://urchin-app-5xqlg.ondigitalocean.app';

document.addEventListener('DOMContentLoaded', () => {
    if(!checkAuthorized()){
        loadLoginPage()
    }
    else{
        loadDashboard()
    }
    
});

async function sleep(delay) {
    var start = new Date().getTime();
    while (new Date().getTime() < start + delay);
}

function checkAuthorized(){
    var session = localStorage.getItem('token');
    if(!session) return 0
    return 1
}

const loginPageContent =
`
<div class="container" id="container">
        <div class="form-container sign-up-container">
           <form id="registerForm">
            <!-- Register form -->
            <h1>Register</h1>
            <div id="RegisterError"></div><br>
            <input type="text" id="registerFirstname" placeholder="First name">
            <input type="test" id="registerLastname" placeholder="Last name">
            <input type="email" id="registerEmail" placeholder="Email">
            <input type="password" id="registerPassword" placeholder="Password">
            <button>Register</button>
           </form>
        </div>
        <div class="form-container sign-in-container">
            <!-- Log in form -->
            <form id="loginForm">
            <h1>Log in</h1> <br>
            <div id="LoginError"></div> <br>
            <input type="text" id="email" placeholder="Email">
            <input type="password" id="password" placeholder="Password">
            <br>
            <a href="#" style="font-size: medium;" id="forgotPasswordLink">Forgot your password?</a>
            <button>Log in</button>
            </form>
        </div>
        <!-- sidebar content -->
        <div class="overlay-container">
            <div class="overlay">
                <div class="overlay-panel overlay-left">
                    <h1>Have an account?</h1>
                    <p>Click here log in!</p>
                    <button class="ghost" id="signIn">Log in</button>
                </div>
                <div class="overlay-panel overlay-right">
                    <h1>Don't have an account?</h1>
                    <p>Click to register an account now!</p>
                    <button class="ghost" id="signUp">Register</button>
                </div>
            </div>
        </div>
    </div>
`

function loadLoginPage(){
    const app = document.getElementById('app');
    app.innerHTML = loginPageContent
    console.log('login page loaded')

    const container = document.querySelector('#container');
    const signInButton = document.querySelector('#signIn');
    const signUpButton = document.querySelector('#signUp');

    signUpButton.addEventListener('click', () => container.classList.add
    ('right-panel-active'));
    signInButton.addEventListener('click', () => container.classList.remove
    ('right-panel-active'));

    //Handle LOGIN
    document.getElementById('loginForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
      
        try {
            const response = await fetch(`${authServer}/api/auth/signin`, {
                method: 'POST',
                headers: {
                'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });
            if(response.ok){
                handleSuccessfulLogin(response)
            }
            else{
                handleLoginError(response)
            }
        } catch (error) {
            console.error('Error during login:', error);
        }
      });

    //Handle REGISTRATION
    document.getElementById('registerForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        const firstname = document.getElementById('registerFirstname').value;
        const lastname = document.getElementById('registerLastname').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;
      
        try {
            const response = await fetch(`${authServer}/api/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ firstname, lastname, email, password }),
            });
            if(response.ok){
                handleSuccessfulRegister(response)
            }else{
                handleRegistrationError(response)
            }

        } catch (error) {
          console.error('Error during registration:', error);
        }
      });

    //for forgot password
    document.getElementById("forgotPasswordLink").addEventListener("click", async function(event){
        event.preventDefault();
        loadPassForgotPage();
    })
}

passForgotPageContent = `
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    body, html {
        font-family: Arial, Helvetica, sans-serif;
        background: #f8f8f8;
        background-attachment: fixed;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        height: 100%;
        margin: 0 auto;
    }
    .email-container {
        background: #fff;
        border-radius: 10px;
        box-shadow: 0 14px 28px rgba(0, 0, 0, .25), 0 10px 10px rgba(0, 0, 0, .22);
        padding: 1.8rem;
        width: 20rem;
        text-align: center;
    }
    h1 {
        margin: 0.2rem;
        font-size: 1.2rem;
    }
    input[type="email"] {
        width: 100%;
        height: 2.2rem;
        text-indent: 1rem;
        border: 1px solid #ccc;
        border-left: none;
        border-right: none;
        border-top: none;
        outline: none;
        margin: 0.6rem 0;
    }
    input[type="email"]:focus {
        border-bottom: 1px solid #4caf50;
    }
    button {
        padding: 0.4rem 1rem;
        background: #417dff;
        color: white;
        border: 1px solid #fff;
        outline: none;
        cursor: pointer;
        width: 100%;
        border-radius: 8px;
        transition: all 100ms ease-in;
        margin: 0.6rem 0;
        font-size: 0.8rem;
    }
    button:hover {
        background-color: #3868d8;
    }
    button:active {
        background-color: #2e57c0;
        transform: translateY(1px);
    }
</style>
<div class="email-container">
    <h3>Enter your email address. We will send you one time password.</h3>
    <p id="notifyUser"></p>
    <input type="email" name="email" id="email" placeholder="example@example.com">
    <button type="submit" id="submitButton">Submit</button>
    <a href="#" id="goToResetPage">Reset Page</a><br><br>
    <a href="#" id="goBackButton">Go back</a><br>
</div>
`

function loadPassForgotPage(){
    const app = document.getElementById('app');
    app.innerHTML = passForgotPageContent

    const goBackButton = document.getElementById("goBackButton")
    goBackButton.addEventListener("click", function(event){
        event.preventDefault()
        loadLoginPage()
    })

    const goToResetPage = document.getElementById("goToResetPage")
    goToResetPage.addEventListener("click", function(event){
        event.preventDefault()
        loadResetPage()
    })

    const submitButton = document.getElementById("submitButton")
    submitButton.addEventListener("click", function(){
        const email = document.getElementById('email').value;
        console.log(email)
        const nofifyElem = document.getElementById('notifyUser')
        if(email == ""){
            nofifyElem.innerHTML = '<p class="error">Please enter your email address.</p>'
        }
        else{
            const encodedEmail = btoa(email)
            console.log(encodedEmail)
            fetch(`${authServer}/api/auth/reset/${encodedEmail}`)
                .then(async response => {
                    if (!response.ok) {
                        //throw new Error('Network response was not ok');
                    }
                    const data = await response.json();
                    console.log(response)
                    nofifyElem.innerHTML = '<p class="clean">If your email is registered then you will receive an OTP code.</p>'
                })
                .catch(error => {
                console.error('There was a problem with the fetch operation:', error);
            });
        }
    })
}

const resetPageContent =
`
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    body, html {
        font-family: Arial, Helvetica, sans-serif;
        background: #f8f8f8;
        background-attachment: fixed;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        height: 100%;
        margin: 0 auto;
    }
    .reset-container {
        background: #fff;
        border-radius: 10px;
        box-shadow: 0 14px 28px rgba(0, 0, 0, .25), 0 10px 10px rgba(0, 0, 0, .22);
        padding: 1.8rem;
        width: 20rem;
        text-align: center;
    }
    h1 {
        margin: 0.2rem;
        font-size: 1.2rem;
    }
    input[type="email"], input[type="text"], input[type="password"] {
        width: 100%;
        height: 2.2rem;
        text-indent: 1rem;
        border: 1px solid #ccc;
        border-left: none;
        border-right: none;
        border-top: none;
        outline: none;
        margin: 0.6rem 0;
    }
    input[type="email"]:focus, input[type="text"]:focus, input[type="password"]:focus {
        border-bottom: 1px solid #4caf50;
    }
    button {
        padding: 0.4rem 1rem;
        background: #417dff;
        color: white;
        border: 1px solid #fff;
        outline: none;
        cursor: pointer;
        width: 100%;
        border-radius: 8px;
        transition: all 100ms ease-in;
        margin: 0.6rem 0;
        font-size: 0.8rem;
    }
    button:hover {
        background-color: #3868d8;
    }
    button:active {
        background-color: #2e57c0;
        transform: translateY(1px);
    }
</style>

<div class="reset-container">
    <h1>Password Reset</h1>
    <p id="notifyUser"></p>
    <input type="email" name="email" id="email" placeholder="Email">
    <input type="text" name="otp" id="otp" placeholder="OTP">
    <input type="password" name="new_password" id="new_password" placeholder="New Password">
    <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm Password">
    <button type="submit" id="submit">Reset Password</button><br>
    <!-- <a href="#" id="goBackButton2">Go back</a><br> -->
</div>

`

function loadResetPage(){
    const app = document.getElementById('app');
    app.innerHTML = resetPageContent

    const submitButton = document.getElementById("submit")
    submitButton.addEventListener("click", function(){
        const email = document.getElementById('email').value;
        const otp = document.getElementById('otp').value;
        const newPassword = document.getElementById('new_password').value;
        const confirmPassword = document.getElementById('confirm_password').value;

        // const goBackButton = document.getElementById("goBackButton2")
        // goBackButton.addEventListener("click", function(event){
        //     event.preventDefault()
        //     console.log('clicked')
        //     loadLoginPage()
        // })

        const nofifyElem = document.getElementById('notifyUser')
        if(email == ""){
            nofifyElem.innerHTML = '<p class="error">Please enter your email address.</p>'
        }
        else{
            const encodedEmail = btoa(email)
            console.log(encodedEmail)
            console.log(newPassword, confirmPassword)
            fetch(`${authServer}/api/auth/resetpassword`,{
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }, 
                body: JSON.stringify({
                    email: email,
                    otp: otp,
                    newPassword: newPassword,
                    confirmPassword: confirmPassword
                })
                
            }).then(async response => {
                    // if (!response.ok) {
                    //     throw new Error('Network response was not ok');
                    // }
                    var responseData = await response.json() 
                    if(responseData.status === "error"){
                        nofifyElem.innerHTML = '<p class="error">'+ responseData.message +'</p>';
                    }else{
                        nofifyElem.innerHTML = '<p class="clean">Your password has been reset successfully.</p>';
                        setTimeout(() => {
                            loadLoginPage();
                        }, 2000);
                    }
                })
                .catch(error => { 
                    nofifyElem.innerHTML = '<p class="error">'+ error +'</p>';
                    console.error('There was a problem with the fetch operation:', error);
                });
        }
    })
}


const dashboardContent = 
`
<div id="main-container">
    <div id="welcomeMessage"><h1>Welcome, null</h1></div>
    <p>Please open an email so that we can check it.</p>

    <button id="logoutButton" class="nice-button">Log out</button>

    <button id="checkEmailButton" class="nice-button">Check</button> <br><br>

    <div id="machine_learning" class="result-notification" >Checking text...</div>

    <div id="filesWrapper">
        <div id="files" class="result-notification">Checking files...</div>
    </div>
    <div id="linksWrapper">
        <div id="links" class="result-notification">Checking links...</div>
    </div>
</div>
`

async function loadDashboard() {
    const app = document.getElementById('app');
    app.innerHTML = dashboardContent

    var userName = await localStorage.getItem('name')
    var lastName = await localStorage.getItem('surname')
    const welcomeMessage = document.getElementById('welcomeMessage')
    welcomeText = '<h1>Welcome, ' + userName + ' ' + lastName + '</h1>'
    welcomeMessage.innerHTML = welcomeText

    const logoutButton = document.getElementById('logoutButton');
    logoutButton.addEventListener('click', ()=>{
        console.log('log out successful')
        localStorage.removeItem('token')
        localStorage.removeItem('name')
        localStorage.removeItem('surname')
        loadLoginPage()
    });
    const checkEmailButton = document.getElementById('checkEmailButton')
    checkEmailButton.addEventListener('click', () => {
        checkEmailContent()
    })
}

async function handleSuccessfulLogin(response) {
    const data = await response.json();
    localStorage.setItem('token', data.data.token);
    localStorage.setItem('name', data.data.firstname);
    localStorage.setItem('surname', data.data.lastname);
    loadDashboard()
}

async function handleSuccessfulRegister(response) {
    const data = await response.json();
    const notificationElem = document.getElementById("RegisterError")
    notificationElem.innerHTML = '<p class="clean">' + data.message + '</p>'
}


async function handleLoginError(response){
    const responseData = await response.json();
    //{"status":"error","message":"Incorrect password"}
    console.log('an error happened with the response')

    const loginErrorElem = document.getElementById('LoginError')
    if(responseData.message.includes('"password" with value')){
        loginErrorElem.innerHTML = `<p class="error">Incorrect password</p>`
    }else {
    loginErrorElem.innerHTML = '<p class="error">' + responseData.message + '</p>'}
}

async function handleRegistrationError (response){
    const responseData = await response.json();
    console.log('an error happened with the response')

    const registerErrorElem = document.getElementById('RegisterError')
    if(responseData.message.includes('"password" with value')){
        registerErrorElem.innerHTML = `<p class="error">
                                                     This password does not meet our requirements. Please make sure your password includes at least<br>
                                                     8 characters at minimum</p>
                                                     1 number <br>
                                                     1 upper case letter<br>
                                                     1 lower case letter<br>
                                                     1 special character<br>
                                                     
                                                     `
    }else {
        registerErrorElem.innerHTML = '<p class="error">' + responseData.message + '</p>'}
}

function checkEmailContent(){
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.scripting.executeScript({
          target: {tabId: tabs[0].id},
          function: getPageText,
        }, async function(results) {
            console.log(results)
          const payload = results[0].result;
          sendMailContentToModel(payload)
        });
      });
}


function getPageText() {

        const payload = []

        const element = document.querySelector('.ii.gt');
        const subject = document.querySelector('.hP');

        const urls = []

        const hrefElements = element.querySelectorAll("a[href]");
        hrefElements.forEach(x => {
            urls.push(x.href)
        })

        if (element == null){
            payload.push('')
        }else{
            newtextt = subject.textContent + '.\n' + element.textContent
            payload.push(newtextt.replace(/\s+/g, " ").trim())
        }
    
        const elements = document.querySelectorAll('.aQy.aZr.e');
        //console.log(elements)
        const file_urls = [];

        elements.forEach(x => {
            file_urls.push(x.href)
        });

        if (file_urls.length > 0){
            payload.push(file_urls)
        }else{
            payload.push('')
        }

        payload.push(urls)

        return payload

}


async function fetchFileAndUploadToVirusTotal(url) {
    const apiKey = secret;
    const uploadUrl = 'https://www.virustotal.com/api/v3/files';
  

    const response = await fetch(url);
  
    if (!response.ok) {
      throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
    }
  

    const file = await response.blob();
    const formData = new FormData();
    formData.append('file', file, file.name);
  

    const uploadResponse = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
      },
      body: formData,
    });
  
    if (!uploadResponse.ok) {
      throw new Error(`Failed to upload file: ${uploadResponse.status} ${uploadResponse.statusText}`);
    }
  
    const data = await uploadResponse.json();
    return data;
  }

async function getFileHash(url) {
    const response = await fetch(url);
    const buffer = await response.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
}


function VTHash(hash){    
    const url = 'https://www.virustotal.com/api/v3/files/'+hash
    
    const options = {
      headers: {
        accept: 'application/json',

        'x-apikey': secret
      }
    };
    
    return fetch(url, options)
        .then(response => {
            if (!response.ok) {
              throw new Error('File not uploaded');
            }
            return response.json();
        })
        .then(data => data)

    }

function base64RemovePadding(str) {
    return str.replace(/={1,2}$/, '');
}

function VT_URL_Get(url) {
    const options = {
        method: 'GET',
        //act as if you don't see this api key here
        headers: {accept: 'application/json', 'x-apikey': secret}
    };
    
    const encodedUrl = encodeURIComponent(url);
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${base64RemovePadding(btoa(url))}`;
    
    return fetch(apiUrl, options)
        .then(response => {
        if (!response.ok) {
            throw new Error('Url not scanned');
        }
        return response.json();
        })
        .then(data => {
        return data;
        });
}


async function VT_URL_Scan(url) {
    const encodedParams = new URLSearchParams();
    encodedParams.set('url', url);
    
    const options = {
      method: 'POST',
      headers: {
        accept: 'application/json',

        'x-apikey': secret,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: encodedParams
    };
    
    return fetch('https://www.virustotal.com/api/v3/urls', options)
      .then(function (response) {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(function (data) {
        console.log(data);
      })
      .catch(function (error) {
        console.error('There was a problem with the fetch operation:', error);
      });
    
  }
  


function sendMailContentToModel(payload){

    textContent = payload[0]

    file_urls = payload[1]

    if (file_urls.length > 0){
        file_urls.forEach(url => {
            getFileHash(url).then(hash => VTHash(hash).then(data => {
            const fileElement = document.getElementById('files');

            if (data.data.attributes.last_analysis_stats.malicious == 0){
                if (data.data.attributes.last_analysis_stats.suspicious == 0){

                    newElement = document.createElement('p')
                    newElement.textContent =  'The '+data.data.attributes.type_description +' file is safe \n';
                    newElement.style.color = "green";
                } else {
                    newElement = document.createElement('p')
                    newElement.textContent =  'The '+data.data.attributes.type_description +' file is suspicious \n';
                    newElement.style.color = "orange";
                }
            } else {
                newElement = document.createElement('p')
                newElement.textContent =  'The '+data.data.attributes.type_description +' file is malicious \n';
                newElement.style.color = "red";
            }
            
            fileElement.innerHTML = fileElement.innerHTML.replace("Checking files...", "");

            fileElement.appendChild(newElement);

              })
              .catch(error => {
                const fileElement = document.getElementById('files');
                const newContent = document.createTextNode('The file '+hash+'is just uploaded to virustotal, recheck the email in a few minutes' + '\n');
                fileElement.appendChild(newContent);

                fetchFileAndUploadToVirusTotal(url)
                .then(data => console.log(data))
                .catch(error => console.error(error));
              }
        ))});
    }

    text_urls = payload[2];


    if (text_urls.length > 0){
        text_urls.forEach(url => {
            VT_URL_Get(url).then(data => {
                const urlElement = document.getElementById('links');

                if (url.length > 50){
                    x = url.slice(0, url.indexOf('/', 8)) + '/*';;
                } else {
                    x = url
                }

                if (data.data.attributes.last_analysis_stats.malicious == '0'){
                    if (data.data.attributes.last_analysis_stats.suspicious == '0'){
                        newElement = document.createElement('p')
                        newElement.textContent =  'The url '+x+' is safe \n';
                        newElement.style.color = "green";
                    } else {
                        newElement = document.createElement('p')
                        newElement.textContent =  'The url '+x+' is suspicious \n';
                        newElement.style.color = "orange";
                    } 
                } else {
                    newElement = document.createElement('p')
                    newElement.textContent =  'The url '+x+' is malicious \n';
                    newElement.style.color = "red";
                }

                urlElement.innerHTML = urlElement.innerHTML.replace("Checking links...", "");
                urlElement.appendChild(newElement);
                
            }).catch(error => {
                const urlElement = document.getElementById('links');

                if (url.length > 50){
                    x = url.slice(0, url.indexOf('/', 8)) + '/*';
                } else {
                    x = url
                }

                const newContent = document.createTextNode('The url '+x+' is just uploaded to virustotal, recheck in a few seconds' + '\n');
                urlElement.appendChild(newContent);
                VT_URL_Scan(url)
                .then(data => console.log(data))
                .catch(error => console.error(error));
            })
        });
    }


    var jwt_token = localStorage.getItem('token');

    console.log('sending content to ml')
    fetch('https://starfish-app-bkywk.ondigitalocean.app/', {
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Session':  jwt_token
        },
        method: 'POST',
        body: JSON.stringify({ "email_content": textContent })

      }).then((response) => response.json())
        .then(data => {
            console.log(JSON.stringify(data));
            if (data['is_spam'] == 'N/A') {
                const outputElem = document.getElementById('machine_learning')
                outputElem.innerHTML = '<p class="error">' + 'Not logged in'+ '</p>'
            }
            else if (data['is_spam'] == true) {
                let outputElem = document.getElementById('machine_learning')

                outputElem.innerHTML = outputElem.innerHTML.replace("Checking text...", "")

                newElement = document.createElement('p')
                newElement.textContent = 'Text is predicted to be spam.';
                newElement.style.color = "orange";

                outputElem.appendChild(newElement);
            }
            else {
                let outputElem = document.getElementById('machine_learning')

                outputElem.innerHTML = outputElem.innerHTML.replace("Checking text...", "")

                newElement = document.createElement('p')
                newElement.textContent = 'Text is predicted to be clean.';
                newElement.style.color = "green";

                outputElem.appendChild(newElement);
            }
    });
}


