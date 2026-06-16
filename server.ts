import express from "express";
import path from "path";
import crypto from "crypto";
import * as admin from "firebase-admin";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { createServer as createViteServer } from "vite";
import firebaseConfig from "./firebase-applet-config.json";

// Initialize Firebase Admin with Firestore Database ID
admin.initializeApp({
  projectId: firebaseConfig.projectId,
});

const db = getFirestore(firebaseConfig.firestoreDatabaseId);

const auth = getAuth();

const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory challenge store for WebAuthn challenges
const challengesMap = new Map<string, { challenge: string; username?: string }>();

// 1. Check Username Availability
app.get("/api/auth/username-check/:username", async (req, res) => {
  try {
    const { username } = req.params;
    if (!username || typeof username !== "string") {
      return res.status(400).json({ error: "Invalid username" });
    }
    const cleanUsername = username.trim().toLowerCase();
    const query = await db.collection("profiles").where("username", "==", cleanUsername).limit(1).get();
    return res.json({ available: query.empty });
  } catch (err: any) {
    console.error("Error in username availability check:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 2. Registration Options Flow
app.post("/api/auth/register-options", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username || typeof username !== "string") {
      return res.status(400).json({ error: "Username is required" });
    }
    const cleanUsername = username.trim().toLowerCase();
    
    // Fast verification
    const query = await db.collection("profiles").where("username", "==", cleanUsername).limit(1).get();
    if (!query.empty) {
      return res.status(400).json({ error: "Username is already registered" });
    }

    const uid = crypto.randomUUID();
    const rpID = req.hostname === "localhost" || req.hostname === "127.0.0.1" ? req.hostname : req.hostname;
    
    const options = await generateRegistrationOptions({
      rpName: "huggchat",
      rpID,
      userID: Buffer.from(uid),
      userName: cleanUsername,
      userDisplayName: username.trim(),
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "preferred",
      },
      supportedAlgorithmIDs: [-7], // ES256
    });

    // Request the PRF extension specifically
    (options.extensions as any) = {
      ...options.extensions,
      prf: {
        eval: {
          first: Buffer.from("huggchat-mek-salt-v1"),
        },
      },
    };

    challengesMap.set(uid, { challenge: options.challenge, username: cleanUsername });

    // Clean up after 5 minutes
    setTimeout(() => {
      challengesMap.delete(uid);
    }, 5 * 60 * 1000);

    return res.json({ uid, options });
  } catch (err: any) {
    console.error("Error generating registration options:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 3. Verify Registration Flow
app.post("/api/auth/verify-registration", async (req, res) => {
  try {
    const { uid, response: credentialResponse, wrappedMek, identityPubkey } = req.body;
    if (!uid || !credentialResponse || !wrappedMek || !identityPubkey) {
      return res.status(400).json({ error: "Missing registration payload" });
    }

    const stored = challengesMap.get(uid);
    if (!stored) {
      return res.status(400).json({ error: "Registration session expired. Please restart." });
    }

    const rpID = req.hostname;
    const origin = req.headers.origin || `https://${req.headers.host}`;

    const verification = await verifyRegistrationResponse({
      response: credentialResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo || !verification.registrationInfo.credential) {
      return res.status(400).json({ error: "Fails authentication criteria" });
    }

    const { id: credentialID, publicKey: credentialPublicKey } = verification.registrationInfo.credential;
    const credIdBase64 = Buffer.from(credentialID).toString("base64url");
    const pubKeyBase64 = Buffer.from(credentialPublicKey).toString("base64");

    // Provision User Record securely
    let userRecord;
    try {
      userRecord = await auth.createUser({
        uid: uid,
        displayName: stored.username,
      });
    } catch (err: any) {
      if (err.code === "auth/uid-already-exists") {
        userRecord = await auth.getUser(uid);
      } else {
        throw err;
      }
    }

    // Write Secure Profiles and Credentials bypass client rules using Firebase Admin SDK with server privilege limits.
    const batch = db.batch();

    const credRef = db.collection("credentials").doc(credIdBase64);
    batch.set(credRef, {
      id: credIdBase64,
      user_id: uid,
      public_key: pubKeyBase64,
      wrapped_mek: wrappedMek,
      created_at: FieldValue.serverTimestamp(),
    });

    const profileRef = db.collection("profiles").doc(uid);
    batch.set(profileRef, {
      id: uid,
      username: stored.username,
      identity_pubkey: identityPubkey,
    });

    await batch.commit();
    challengesMap.delete(uid);

    // Mint short-lived Firebase Auth Custom Token
    const customToken = await auth.createCustomToken(uid);

    return res.json({ success: true, customToken });
  } catch (err: any) {
    console.error("Error verifying registration:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 4. Login Options Flow
app.post("/api/auth/login-options", async (req, res) => {
  try {
    const { username } = req.body;
    let allowCredentials = undefined;

    if (username && typeof username === "string") {
      const cleanUsername = username.trim().toLowerCase();
      const profileQuery = await db.collection("profiles").where("username", "==", cleanUsername).limit(1).get();
      
      if (!profileQuery.empty) {
        const uid = profileQuery.docs[0].id;
        const credsQuery = await db.collection("credentials").where("user_id", "==", uid).get();
        if (!credsQuery.empty) {
          allowCredentials = credsQuery.docs.map((doc) => ({
            id: Buffer.from(doc.id, "base64url"),
            type: "public-key" as const,
          }));
        }
      } else {
        return res.status(404).json({ error: `Username '${username}' not found.` });
      }
    }

    const rpID = req.hostname;
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: "preferred",
    });

    // Inject PRF requests to evaluate salt
    (options.extensions as any) = {
      ...options.extensions,
      prf: {
        eval: {
          first: Buffer.from("huggchat-mek-salt-v1"),
        },
      },
    };

    challengesMap.set(options.challenge, { challenge: options.challenge });

    // Clean up after 5 minutes
    setTimeout(() => {
      challengesMap.delete(options.challenge);
    }, 5 * 60 * 1000);

    return res.json({ options });
  } catch (err: any) {
    console.error("Error generating login options:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 5. Verify Authentication Assertions
app.post("/api/auth/verify-authentication", async (req, res) => {
  try {
    const { response: assertionResponse } = req.body;
    if (!assertionResponse || !assertionResponse.id) {
      return res.status(400).json({ error: "Missing authentication payload parameters" });
    }

    const credIdBase64 = assertionResponse.id;
    const credDoc = await db.collection("credentials").doc(credIdBase64).get();
    if (!credDoc.exists) {
      return res.status(404).json({ error: "Hardware passkey not registered on this service" });
    }

    const credData = credDoc.data()!;
    const { user_id, public_key, wrapped_mek } = credData;

    // Decode ClientData challenge
    const clientDataJSON = JSON.parse(Buffer.from(assertionResponse.response.clientDataJSON, "base64").toString());
    const clientChallenge = clientDataJSON.challenge;

    const stored = challengesMap.get(clientChallenge);
    if (!stored) {
      return res.status(400).json({ error: "Session challenge timed out. Please retry." });
    }

    const rpID = req.hostname;
    const origin = req.headers.origin || `https://${req.headers.host}`;

    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: credIdBase64,
        publicKey: Buffer.from(public_key, "base64"),
        counter: 0,
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "Sovereign WebAuthn verification fails" });
    }

    challengesMap.delete(clientChallenge);

    // Clean Session custom token
    const customToken = await auth.createCustomToken(user_id);

    return res.json({
      success: true,
      customToken,
      wrappedMek: wrapped_mek,
    });
  } catch (err: any) {
    console.error("Error verifying authentication:", err);
    return res.status(500).json({ error: err.message });
  }
});

// Static files server & Vite Development integration middleware
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`huggchat Server booted on port ${PORT}`);
  });
}

startServer();
