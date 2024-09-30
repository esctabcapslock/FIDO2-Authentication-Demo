const express = require('express');
const bodyParser = require('body-parser');
const { Fido2Lib } = require('fido2-lib');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3000;

// In-memory user and session data (you can replace this with database storage)
const users = {};
const sessions = {};

// Fido2Lib initialization
const fido2 = new Fido2Lib({
    timeout: 60000,
    rpId: 'localhost', // replace with your domain
    rpName: 'FIDO2 Demo',
    challengeSize: 64,
    attestation: 'direct',
    attestation: "none",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "required"
});

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));

// Routes

// Registration - Step 1 (Begin registration)
app.post('/register', async (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).send('Username is required');
    }

    // Create user if not exists
    if (!users[username]) {
        users[username] = { id: uuidv4(), credentials: [] };
    }

    const user = users[username];

    // Generate a challenge
    const registrationOptions = await fido2.attestationOptions()

    registrationOptions.user.id = Buffer.from(user.id, 'utf-8').toString('base64')
    registrationOptions.user.name = username
    registrationOptions.user.displayName = username


    // Store the challenge in session (for simplicity using in-memory session)
    sessions[username] = {
        challenge: registrationOptions.challenge,
        origin: req.headers.origin
    };

    registrationOptions.challenge = Buffer.from(registrationOptions.challenge).toString('base64')

    console.log('registrationOptions',registrationOptions)

    res.json(registrationOptions);
});

// Registration - Step 2 (Verify registration)
app.post('/register/verify', async (req, res) => {
    const { username, attestationResponse } = req.body;
    const session = sessions[username];

    if (!session) {
        return res.status(400).send('Session expired or invalid');
    }

    const user = users[username];
    const expectedChallenge = session.challenge;

    // Verify attestation
    const attestationExpectations = {
        challenge: expectedChallenge,
        origin: session.origin,
        factor: 'either'
    };

    const attestationResponseObj =  { 
        // id : Uint8Array.from(atob(attestationResponse.id,), c => c.charCodeAt(0))
        // rawId : Uint8Array.from(atob(attestationResponse.rawId), c => c.charCodeAt(0)),

        // expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId object and id object
        // id : Buffer.from(attestationResponse.id),
        // rawId : Buffer.from(attestationResponse.rawId),

        // expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId object and id string
        // id : attestationResponse.id,
        // rawId : Buffer.from(attestationResponse.rawId),

        // expected 'id' or 'rawId' field of request to be ArrayBuffer, got rawId string and id string
        // id : attestationResponse.id,
        // rawId : attestationResponse.rawId,

        rawId : Uint8Array.from(atob(attestationResponse.rawId), c => c.charCodeAt(0)).buffer,
        response:{
            clientDataJSON: attestationResponse.response.clientDataJSON, 
            attestationObject: attestationResponse.response.attestationObject,  
        }
    }

    console.log('[fido2.attestationResult attestationExpectations] ', attestationExpectations)
    console.log('[fido2.attestationResult attestationResponse] ', attestationResponse)
    console.log('[fido2.attestationResult res]', attestationResponseObj)
    

    let result;
    try {
        result = await fido2.attestationResult(
            attestationResponseObj,
            attestationExpectations
        );
    } catch (err) {
        console.error(err)
        return res.status(400).send(`Registration verification failed: ${err.message}`);
    }


    console.log('[/register/verify result]',result)
    

    // Store credential in user
    user.credentials.push({
        credentialId: result.authnrData.get('credId'),
        publicKey: result.authnrData.get('credentialPublicKeyPem'),
        counter: result.authnrData.get('counter')
    });

    delete sessions[username]; // Clear the session after registration

    res.send('Registration successful');
});

// Login - Step 1 (Begin login)
app.post('/login', async (req, res) => {
    const { username } = req.body;

    if (!users[username]) {
        return res.status(404).send('User not found');
    }

    const user = users[username];
    const allowCredentials = user.credentials.map(cred => ({
        type: 'public-key',
        id: cred.credentialId
    }));

    const assertionOptions = await fido2.assertionOptions({
        challenge: Buffer.from(uuidv4(), 'utf-8'),
        allowCredentials,
        userVerification: 'preferred'
    });

    // Store the challenge in session
    sessions[username] = {
        challenge: assertionOptions.challenge,
        origin: req.headers.origin
    };

    assertionOptions.challenge = Buffer.from(assertionOptions.challenge).toString('base64')

    res.json(assertionOptions);
});

// Login - Step 2 (Verify login)
app.post('/login/verify', async (req, res) => {
    const { username, assertionResponse } = req.body;
    const session = sessions[username];

    if (!session) {
        return res.status(400).send('Session expired or invalid');
    }

    const user = users[username];
    const expectedChallenge = session.challenge;

    const userHandle = Buffer.from(assertionResponse.response.userHandle || '', 'base64');


    console.log('[/login/verify] user',user)
    console.log('[/login/verify] assertionResponse',assertionResponse)
    // Find credential
    const credential = user.credentials.find(cred => 
         Buffer.compare(
            Buffer.from(cred.credentialId, 'base64'), Buffer.from(assertionResponse.id, 'base64')
        ) === 0
    );
    

    if (!credential) {
        return res.status(400).send('Credential not found');
    }

    // Verify assertion
    const assertionExpectations = {
        challenge: expectedChallenge,
        origin: session.origin,
        factor: 'either',
        publicKey: credential.publicKey,
        prevCounter: credential.counter,
        userHandle
    };

    let result;
    try {
        result = await fido2.assertionResult(
            {
                rawId : Uint8Array.from(atob(assertionResponse.rawId), c => c.charCodeAt(0)).buffer,
                credentialPublicKeyPem: credential.publicKey,
                response:{
                    clientDataJSON: assertionResponse.response.clientDataJSON,
                    authenticatorData: assertionResponse.response.authenticatorData,
                    signature: assertionResponse.response.signature,
                    userHandle: assertionResponse.response.userHandle,
                },
            },
            assertionExpectations
        );
    } catch (err) {
        console.error(err)
        return res.status(400).send(`Login verification failed: ${err.message}`);
    }

    // Update counter
    credential.counter = result.authnrData.get('counter');

    delete sessions[username]; // Clear session after login

    res.send('Login successful');
});

// Start the server
app.listen(port, () => {
    console.log(`FIDO2 demo server running on http://localhost:${port}`);
});

