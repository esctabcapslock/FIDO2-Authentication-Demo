function base64UrlToBase64(base64url) {
    return base64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(base64url.length + (4 - (base64url.length % 4)) % 4, '=');
}


async function register() {
    const username = document.getElementById('username').value;
    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });

    const options = await response.json();

    options.user.id = Uint8Array.from(atob(base64UrlToBase64(options.user.id)), c => c.charCodeAt(0));
    options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

    console.log('[credentials.create]', { publicKey: options })
    const credential = await navigator.credentials.create({ publicKey: options });
    console.log('[credentials.create credential]', credential)
    const attestationResponse = {
        id: credential.id,
        rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId))),
        response: {
            attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.attestationObject))),
            clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.clientDataJSON)))
        },
        type: credential.type
    };

    const verifyResponse = await fetch('/register/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, attestationResponse })
    });

    const result = await verifyResponse.text();
    alert(result);
}

async function login() {
    const username = document.getElementById('username').value;
    const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });

    const options = await response.json();
    options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));

    const assertion = await navigator.credentials.get({ publicKey: options });
    const assertionResponse = {
        id: assertion.id,
        rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.rawId))),
        response: {
            authenticatorData: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.authenticatorData))),
            clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.clientDataJSON))),
            signature: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.signature))),
            userHandle: assertion.response.userHandle ? btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.userHandle))) : null
        },
        type: assertion.type
    };

    const verifyResponse = await fetch('/login/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, assertionResponse })
    });

    const result = await verifyResponse.text();
    alert(result);
}

document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('loginBtn').addEventListener('click', login);