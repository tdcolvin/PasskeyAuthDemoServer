/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import dotenv from 'dotenv';
import express, { Request } from 'express';
import session from 'express-session';
import memoryStore from 'memorystore';

dotenv.config();

import {
  AuthenticationResponseJSON,
  // Authentication
  generateAuthenticationOptions,
  GenerateAuthenticationOptionsOpts,
  // Registration
  generateRegistrationOptions,
  GenerateRegistrationOptionsOpts,
  RegistrationResponseJSON,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
  WebAuthnCredential,
} from '@simplewebauthn/server';

import { addUser, addUserCredential, getUserByUsername } from './database';
import { getSession, updateSession } from './session';

export const app = express();
const MemoryStore = memoryStore(session);

const {
  ENABLE_CONFORMANCE,
  RP_ID = 'auth.tomcolvin.co.uk',
} = process.env;

app.use(express.static('./public/'));
app.use(express.json());
app.use(
  session({
    secret: 'secret123',
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  }),
);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  import('./fido-conformance').then(
    ({ fidoRouteSuffix, fidoConformanceRouter }) => {
      app.use(fidoRouteSuffix, fidoConformanceRouter);
    },
  );
}

/**
 * RP ID represents the "scope" of websites on which a credential should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export const expectedOrigin = [
  `https://${rpID}`,
  "android:apk-key-hash:H8aaJx3lOZCaxVnsZU5__ALkVjXJALA11rtegEE0Ldc",   // signed using the keystore in the app folder
  "android:apk-key-hash:gdkPOK8n_ukOng6OGtrjq7HU9V4EbXSDTalcuOMYErY",   // signed using laptop debug keystore
];

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the credential.
 *
 * Here, the example server assumes the following user has completed login:
 */



/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req: Request<unknown, unknown, unknown, { username: string }>, res) => {
  const { username } = req.query;
  if (!username) {
    console.error("No username specified");
    return res.status(400).send({ error: "Please specify a user name as ?username=XXX" });
  }

  const user = await getUserByUsername(username);
  if (user) {
    console.error("User with username " + username + " already exists");
    return res.status(400).send({ error: "User with that username already exists" });
  }

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: 'SimpleWebAuthn Example',
    rpID,
    userName: username,
    userDisplayName: username,
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
      /**
       * Wondering why user verification isn't required? See here:
       *
       * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
       */
      userVerification: 'preferred',
    },
    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  await updateSession(req.session.id, {
    expectedChallenge: options.challenge,
    requestedUsername: username,
    precreatedUserId: options.user.id
  });

  console.log("updated sessionID="+req.session.id + " session=", await getSession(req.session.id));

  return res.send(options);
});

app.post('/verify-registration', async (req, res) => {
  const body: RegistrationResponseJSON = req.body;

  console.log("sessionID="+req.session.id);
  const session = await getSession(req.session.id);
  if (!session || !session.precreatedUserId || !session.requestedUsername) {
    console.error("Failed to read session, session=", session ?? "[undefined]");
    return res.status(400).send({ error: "Failed to read session, did you call /generate-registration-options?" });
  }

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${session.expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credential } = registrationInfo;
      /**
       * Add the returned credential to the user's list of credentials
       */
      const newCredential: WebAuthnCredential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: body.response.transports,
      };

      await addUser(session.precreatedUserId, session.requestedUsername);
      await addUserCredential(session.precreatedUserId, newCredential);
  }

  await updateSession(req.session.id, { expectedChallenge: null, requestedUsername: null })

  return res.send({ verified });
});

/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req: Request<unknown, unknown, unknown, { username: string }>, res) => {
  // You need to know the user by this point
  const { username } = req.query;
  if (!username) {
    return res.status(400).send({ error: "Please specify user name" });
  }

  const user = await getUserByUsername(username);
  if (!user) {
    return res.status(400).send({ error: "No such user" });
  }

  console.log("User", user);

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    /**
     * Wondering why user verification isn't required? See here:
     *
     * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
     */
    userVerification: 'preferred',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);
  await updateSession(req.session.id, { expectedChallenge: options.challenge, signInUsername: username });

  return res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
  const body: AuthenticationResponseJSON = req.body;

  const { expectedChallenge, signInUsername} = await getSession(req.session.id);

  if (!expectedChallenge || !signInUsername) {
    return res.status(400).send({ error: "Call /generate-authentication-options" });
  }

  const user = await getUserByUsername(signInUsername);
  if (!user) {
    return res.status(400).send({ error: "No such user" });
  }

  let dbCredential: WebAuthnCredential | undefined;
  // "Query the DB" here for a credential matching `cred.id`
  for (const cred of user.credentials) {
    if (cred.id === body.id) {
      dbCredential = cred;
      break;
    }
  }

  if (!dbCredential) {
    return res.status(400).send({
      error: 'Authenticator is not registered with this site',
    });
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: dbCredential,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the credential's counter in the DB to the newest count in the authentication
    dbCredential.counter = authenticationInfo.newCounter;
  }

  await updateSession(req.session.id, { expectedChallenge: null, signInUsername: null });

  return res.send({ verified });
});