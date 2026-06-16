import express from "express";
import path from "path";
import crypto from "crypto";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { createServer as createViteServer } from "vite";

const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory challenge store for WebAuthn challenges
const challengesMap = new Map<string, { challenge: string; username?: string }>();

// 1. Check Username Availability
// Handled directly client-side via Firestore query, but endpoint kept for API compatibility.
app.get("/api/auth/username-check/:username", async (req, res) => {
  return res.json({ available: true });
});

// 2. Registration Options Flow
app.post("/api/auth/register-options", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username || typeof username !== "string") {
      return res.status(400).json({ error: "Username is required" });
    }
    const cleanUsername = username.trim().toLowerCase();

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
      prf: {},
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
    const { uid, response: credentialResponse } = req.body;
    if (!uid || !credentialResponse) {
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

    challengesMap.delete(uid);

    return res.json({ 
      success: true, 
      credId: credIdBase64, 
      pubKey: pubKeyBase64 
    });
  } catch (err: any) {
    console.error("Error verifying registration:", err);
    return res.status(500).json({ error: err.message });
  }
});

// 4. Login Options Flow
app.post("/api/auth/login-options", async (req, res) => {
  try {
    const rpID = req.hostname;
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: "preferred",
    });

    // Inject PRF requests to evaluate salt
    (options.extensions as any) = {
      ...options.extensions,
      prf: {
        eval: {
          first: Buffer.from("huggchat-mek-salt-v1").toString("base64url"),
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

// 5. Verify Authentication Assertions (Optional, kept for API matching)
app.post("/api/auth/verify-authentication", async (req, res) => {
  try {
    const { response: assertionResponse, publicKey } = req.body;
    if (!assertionResponse || !assertionResponse.id || !publicKey) {
      return res.status(400).json({ error: "Missing authentication payload parameters" });
    }

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
        id: assertionResponse.id,
        publicKey: Buffer.from(publicKey, "base64"),
        counter: 0,
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "Sovereign WebAuthn verification fails" });
    }

    challengesMap.delete(clientChallenge);

    return res.json({
      success: true,
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
