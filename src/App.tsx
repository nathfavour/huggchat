import React, { useState, useEffect } from "react";
import { signInWithCustomToken, signOut, onAuthStateChanged, signInWithEmailAndPassword } from "firebase/auth";
import { doc, getDoc, collection, query, where, getDocs, setDoc } from "firebase/firestore";
import { auth, db } from "./firebase";
import { PasskeyAuth } from "./components/PasskeyAuth";
import { ChatWindow } from "./components/ChatWindow";
import { SettingsPanel } from "./components/SettingsPanel";
import { UserProfile } from "./types";
import { deriveRecoveryKeyFromPass, decryptPayload, hexToBuf, bufToHex, generateIdentityKeypair, wrapMek } from "./cryptoUtils";
import { 
  ShieldAlert, 
  Key, 
  Unlock, 
  RefreshCw, 
  Sparkles, 
  CornerDownLeft, 
  Eye, 
  EyeOff, 
  Terminal,
  ShieldAlert as AlertIcon
} from "lucide-react";

export default function App() {
  const [currentUserProfile, setCurrentUserProfile] = useState<UserProfile | null>(null);
  const [unwrappedMek, setUnwrappedMek] = useState<Uint8Array | null>(null);
  const [globalError, setGlobalError] = useState<string>("");
  const [isInitializing, setIsInitializing] = useState<boolean>(true);

  // Recovery process states (Section 6.2 & 6.3)
  const [isRecovering, setIsRecovering] = useState<boolean>(false);
  const [recoverUsername, setRecoverUsername] = useState<string>("");
  const [recoverPassword, setRecoverPassword] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [isDerivingRecovery, setIsDerivingRecovery] = useState<boolean>(false);
  const [recoveryStep, setRecoveryStep] = useState<"username" | "masterpass">("username");
  const [matchingProfile, setMatchingProfile] = useState<any | null>(null);
  const [matchingBackup, setMatchingBackup] = useState<any | null>(null);

  // Settings screen toggle
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);

  // Clear global erro on timeout
  useEffect(() => {
    if (globalError) {
      const t = setTimeout(() => setGlobalError(""), 8000);
      return () => clearTimeout(t);
    }
  }, [globalError]);

  // Synchronise state with Firebase Authentication changes
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setIsInitializing(true);
      if (user) {
        try {
          // Fetch existing user profile
          const profileDoc = await getDoc(doc(db, "profiles", user.uid));
          if (profileDoc.exists()) {
            const data = profileDoc.data();
            setCurrentUserProfile({
              id: user.uid,
              username: data.username || "anonymous",
              identity_pubkey: data.identity_pubkey || "",
            });
          }
        } catch (err: any) {
          setGlobalError("Sovereign sync error. Please reload.");
        }
      } else {
        setCurrentUserProfile(null);
        setUnwrappedMek(null);
      }
      setIsInitializing(false);
    });

    return () => unsubscribe();
  }, []);

  const handleAuthSuccess = (
    uid: string,
    username: string,
    mekBytes: Uint8Array,
    customToken: string
  ) => {
    setUnwrappedMek(mekBytes);
    setCurrentUserProfile({
      id: uid,
      username: username,
      identity_pubkey: "",
    });
  };

  const handleWipeSession = async () => {
    try {
      await signOut(auth);
      setUnwrappedMek(null);
      setCurrentUserProfile(null);
      localStorage.clear(); // Wipe sensitive JWKs and local buffers
      setIsSettingsOpen(false);
    } catch (err) {
      console.error(err);
    }
  };

  // Sovereign Recovery Engine (Section 6.2 & 6.3)
  const handleNextRecoveryStep = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoverUsername.trim()) return;

    setIsDerivingRecovery(true);
    setGlobalError("");

    try {
      const cleanUsername = recoverUsername.trim().toLowerCase();
      // 1. Query matching user profiles
      const qProfile = query(collection(db, "profiles"), where("username", "==", cleanUsername));
      const snapProfile = await getDocs(qProfile);

      if (snapProfile.empty) {
        throw new Error(`Username profile '${recoverUsername}' not found on server.`);
      }

      const profDoc = snapProfile.docs[0];
      const profData = profDoc.data();

      // 2. Fetch the sovereign masterpass backup block from sub-collection
      const backupRef = doc(db, "profiles", profDoc.id, "backups", "masterpass");
      const backupSnap = await getDoc(backupRef);

      if (!backupSnap.exists()) {
        throw new Error("No secure Master Pass recovery block was configured for this profile.");
      }

      setMatchingProfile({
        id: profDoc.id,
        username: profData.username,
        identity_pubkey: profData.identity_pubkey,
      });

      setMatchingBackup(backupSnap.data());
      setRecoveryStep("masterpass");
    } catch (err: any) {
      setGlobalError(err.message || "Recovery failure. Check username.");
    } finally {
      setIsDerivingRecovery(false);
    }
  };

  const handleVerifyMasterPassRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoverPassword || !matchingBackup || !matchingProfile) return;

    setIsDerivingRecovery(true);
    setGlobalError("");

    try {
      // 1. Derive recovery 256-bit symmetric wrap key using Argon2id WASM (hash-wasm)
      const derivedRecoveryKey = await deriveRecoveryKeyFromPass(recoverPassword, matchingBackup.salt);

      // 2. Encrypt/decrypt payload to unwrap the core MEK key
      const encryptedMekBytes = hexToBuf(matchingBackup.wrapped_mek);
      const decryptedMek = await decryptPayload(encryptedMekBytes, derivedRecoveryKey);

      // 3. Re-enroll local identity: recreate a fresh X25519 identity coordinate
      const cipherKeyPair = await generateIdentityKeypair();

      // Store fresh private coordinates local storage
      localStorage.setItem(`huggchat_priv_${matchingProfile.id}`, cipherKeyPair.privateKeyJwk);

      // 4. Derive high-entropy deterministic security password from matching / sovereign Master Encryption Key (MEK)
      const passwordSource = new TextEncoder().encode(bufToHex(decryptedMek) + "huggchat-passkey-v1");
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", passwordSource);
      const firebasePassword = bufToHex(new Uint8Array(hashBuffer));

      // 5. Authenticate directly on Firebase securely via standard Email/Password
      const userEmail = `${matchingProfile.username}@huggchat.internal`;
      await signInWithEmailAndPassword(auth, userEmail, firebasePassword);

      // Save new coordinates to server using now authenticated session
      await setDoc(doc(db, "profiles", matchingProfile.id), {
        id: matchingProfile.id,
        username: matchingProfile.username,
        identity_pubkey: cipherKeyPair.publicKeyHex, // Note: Updates their search registry
      });

      setUnwrappedMek(decryptedMek);

      // Reset recovery pane
      setIsRecovering(false);
      setRecoveryStep("username");
      setRecoverUsername("");
      setRecoverPassword("");
    } catch (err: any) {
      console.error(err);
      setGlobalError("Argon2id Decryption Blocked: Sovereign Master Pass is incorrect.");
    } finally {
      setIsDerivingRecovery(false);
    }
  };

  const cancelRecovery = () => {
    setIsRecovering(false);
    setRecoveryStep("username");
    setRecoverUsername("");
    setRecoverPassword("");
    setGlobalError("");
  };

  return (
    <div className="min-h-screen bg-[#000000] flex flex-col justify-between font-sans selection:bg-[#C1B2A3]/30">
      {/* 1. Header Navigation */}
      <header className="border-b border-[#23211F] bg-[#0A0908] px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded bg-[#141211] border border-[#23211F] flex items-center justify-center text-[#C1B2A3]">
            <Key className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-wide text-[#EAE2D8]">huggchat</h1>
            <p className="text-[10px] font-mono text-[#8A7E73] uppercase tracking-widest leading-none">
              v2.0 • Sovereign Vault
            </p>
          </div>
        </div>

        {currentUserProfile && (
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-[#8A7E73] bg-[#0A0908] border border-[#23211F] px-2.5 py-1 rounded">
              Active Session: <span className="text-[#C1B2A3] font-semibold">{currentUserProfile.username}</span>
            </span>
          </div>
        )}
      </header>

      {/* 2. Main content viewport */}
      <main className="flex-grow flex items-center justify-center p-6 bg-[#000000]">
        {isInitializing ? (
          <div className="flex flex-col items-center justify-center space-y-3">
            <RefreshCw className="w-8 h-8 text-[#8A7E73] animate-spin" />
            <p className="font-mono text-xs text-[#8A7E73] tracking-widest uppercase">
              Syncing hardware vault...
            </p>
          </div>
        ) : currentUserProfile && unwrappedMek ? (
          /* Active chat workspace or Settings overlay */
          isSettingsOpen ? (
            <SettingsPanel
              currentUserProfile={currentUserProfile}
              unwrappedMek={unwrappedMek}
              setError={setGlobalError}
              onClose={() => setIsSettingsOpen(false)}
            />
          ) : (
            <ChatWindow
              currentUserProfile={currentUserProfile}
              unwrappedMek={unwrappedMek}
              onLogout={handleWipeSession}
              openSettings={() => setIsSettingsOpen(true)}
            />
          )
        ) : isRecovering ? (
          /* Master Pass Recovery flow (Section 6.2 & 6.3) */
          <div className="w-full max-w-md mx-auto bg-[#141211] border border-[#23211F] rounded-lg p-8 shadow-[2px_2px_0px_#23211F,4px_4px_0px_#1E1B19,6px_6px_0px_#0A0908]">
            <div className="flex flex-col items-center mb-8">
              <div className="w-12 h-12 rounded-full bg-[#1A1817] border border-[#23211F] flex items-center justify-center mb-3 text-[#C1B2A3]">
                <Unlock className="w-5 h-5" />
              </div>
              <h1 className="font-sans text-xl font-semibold tracking-tight text-[#EAE2D8] mb-1">
                Sovereign Recovery Hub
              </h1>
              <p className="font-mono text-[10px] text-[#8A7E73] tracking-wider uppercase">
                Argon2id WASM key derivation
              </p>
            </div>

            {recoveryStep === "username" ? (
              <form onSubmit={handleNextRecoveryStep} className="space-y-5">
                <div>
                  <label className="block text-xs font-mono uppercase tracking-wider text-[#C1B2A3] mb-2">
                    Enter Registered Username
                  </label>
                  <input
                    type="text"
                    required
                    value={recoverUsername}
                    onChange={(e) => setRecoverUsername(e.target.value)}
                    placeholder="e.g. alice-99"
                    className="w-full bg-[#0A0908] border border-[#23211F] rounded px-4 py-3 text-xs text-[#EAE2D8] placeholder-[#5A5046] focus:outline-none focus:border-[#C1B2A3]"
                  />
                </div>

                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={cancelRecovery}
                    className="flex-1 py-3 text-xs font-mono uppercase bg-[#0A0908] border border-[#23211F] text-[#8A7E73] hover:text-[#C1B2A3] rounded transition-all cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isDerivingRecovery || !recoverUsername}
                    className="flex-1 py-3 text-xs font-mono uppercase bg-[#1E1B19] border border-[#23211F] text-[#EAE2D8] hover:bg-[#23211F] rounded transition-all disabled:opacity-40 cursor-pointer flex items-center justify-center gap-2"
                  >
                    {isDerivingRecovery ? (
                      <div className="w-4 h-4 border-2 border-t-transparent border-[#EAE2D8] rounded-full animate-spin" />
                    ) : (
                      "Query Profile"
                    )}
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleVerifyMasterPassRecovery} className="space-y-5">
                <div className="p-3.5 rounded bg-[#0A0908] border border-[#23211F] text-[11px] text-[#8A7E73] leading-relaxed">
                  Profile <span className="text-[#C1B2A3] font-mono font-semibold">{matchingProfile.username}</span> coordinates loaded. Enter your Sovereign Master Pass to unwrap the core Master Encryption Key (MEK) inside secure application memory.
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase tracking-wider text-[#C1B2A3] mb-2">
                    Secured Master Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      required
                      value={recoverPassword}
                      onChange={(e) => setRecoverPassword(e.target.value)}
                      placeholder="Input master password..."
                      className="w-full bg-[#0A0908] border border-[#23211F] rounded pl-4 pr-10 py-3 text-xs text-[#EAE2D8] placeholder-[#5A5046] focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-3 text-[#5A5046] hover:text-[#C1B2A3]"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={cancelRecovery}
                    className="flex-1 py-3 text-xs font-mono uppercase bg-[#0A0908] border border-[#23211F] text-[#8A7E73] hover:text-[#C1B2A3] rounded transition-all cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isDerivingRecovery || !recoverPassword}
                    className="flex-1 py-3 text-xs font-mono uppercase bg-[#1E1B19] border border-[#23211F] text-[#EAE2D8] hover:bg-[#23211F] rounded transition-all disabled:opacity-40 cursor-pointer flex items-center justify-center gap-2"
                  >
                    {isDerivingRecovery ? (
                      <div className="w-4 h-4 border-2 border-t-transparent border-[#EAE2D8] rounded-full animate-spin" />
                    ) : (
                      <>
                        <CornerDownLeft className="w-4 h-4" />
                        Unwrap MEK
                      </>
                    )}
                  </button>
                </div>
              </form>
            )}
          </div>
        ) : (
          /* Primary unauthenticated home (Passkey first + Recovery Fallback option) */
          <div className="flex flex-col items-center">
            <PasskeyAuth onAuthSuccess={handleAuthSuccess} setError={setGlobalError} />
            
            <button
              id="goto-recovery-btn"
              onClick={() => {
                setIsRecovering(true);
                setGlobalError("");
              }}
              className="mt-6 text-xs font-mono uppercase tracking-wider text-[#8A7E73] hover:text-[#C1B2A3] transition-colors border-b border-dashed border-[#23211F] pb-0.5"
            >
              Recover Account via Master Pass
            </button>
          </div>
        )}
      </main>

      {/* 3. Global notification rail and Footer */}
      <footer className="border-t border-[#23211F] bg-[#0A0908] px-8 py-4 flex flex-col items-center relative overflow-hidden select-none">
        {/* Global error alert panel */}
        {globalError && (
          <div className="absolute inset-x-0 bottom-full bg-red-950/90 border-t border-red-800 px-8 py-3.5 flex items-center gap-3 text-xs text-red-300 font-mono tracking-wide shadow-inner">
            <ShieldAlert className="w-4.5 h-4.5 text-red-400 shrink-0" />
            <span className="flex-1 capitalize">{globalError}</span>
          </div>
        )}

        <div className="w-full max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-center text-[#5A5046]">
          <span className="text-[10px] font-mono uppercase tracking-widest flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5" /> 256-bit AES-GCM-256 Multi-layer Handshakes
          </span>
          <span className="text-[10px] font-sans">
            Sovereign zero-knowledge stack. Completely client-authoritative E2EE payload caching.
          </span>
        </div>
      </footer>
    </div>
  );
}
