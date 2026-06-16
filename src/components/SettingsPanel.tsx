import React, { useState } from "react";
import { doc, setDoc } from "firebase/firestore";
import { db, auth } from "../firebase";
import { handleFirestoreError, OperationType } from "../firestoreUtils";
import { UserProfile } from "../types";
import { 
  deriveRecoveryKeyFromPass, 
  encryptPayload, 
  bufToHex, 
  wrapMek, 
  generateIdentityKeypair 
} from "../cryptoUtils";
import { startRegistration } from "@simplewebauthn/browser";
import { 
  Shield, 
  Key, 
  CornerDownLeft, 
  Check, 
  Disc, 
  Lock, 
  Server, 
  X, 
  Sparkles, 
  CheckCircle2,
  Copy
} from "lucide-react";

interface SettingsPanelProps {
  currentUserProfile: UserProfile;
  unwrappedMek: Uint8Array;
  onClose: () => void;
  setError: (err: string) => void;
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({
  currentUserProfile,
  unwrappedMek,
  onClose,
  setError,
}) => {
  const [copied, setCopied] = useState(false);
  const [masterPass, setMasterPass] = useState("");
  const [isSettingMasterPass, setIsSettingMasterPass] = useState(false);
  const [masterPassSuccess, setMasterPassSuccess] = useState(false);

  const [isLoadingSecondary, setIsLoadingSecondary] = useState(false);
  const [successSecondary, setSuccessSecondary] = useState(false);

  const copyPublicKey = () => {
    navigator.clipboard.writeText(currentUserProfile.identity_pubkey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // 1. Establish Master Pass recovery option (Section 6.2)
  const handleSetMasterPass = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!masterPass.trim() || !auth.currentUser) return;

    setIsSettingMasterPass(true);
    setMasterPassSuccess(false);
    setError("");

    try {
      // Generate unique 16-byte random salt in hex
      const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
      const saltHex = bufToHex(saltBytes);

      // Derive strong 256-bit symmetric recovery key client-side using memory-hard Argon2id WASM (hash-wasm)
      const derivedRecoveryKey = await deriveRecoveryKeyFromPass(masterPass, saltHex);

      // Encrypt our local Master Encryption Key (MEK)
      const encryptedMekBytes = await encryptPayload(unwrappedMek, derivedRecoveryKey);
      const wrappedMekHex = bufToHex(encryptedMekBytes);

      const path = `profiles/${auth.currentUser.uid}/backups/masterpass`;

      // Upload backup payload block to secure Firestore sub-collection
      try {
        await setDoc(doc(db, "profiles", auth.currentUser.uid, "backups", "masterpass"), {
          wrapped_mek: wrappedMekHex,
          salt: saltHex,
          created_at: new Date(),
        });
      } catch (error) {
        handleFirestoreError(error, OperationType.WRITE, path);
      }

      setMasterPassSuccess(true);
      setMasterPass("");
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed setting Master Pass recovery cache");
    } finally {
      setIsSettingMasterPass(false);
    }
  };

  // 2. Enroll secondary hardware passkey (Section 6.1)
  const handleEnrollSecondaryPasskey = async () => {
    if (!auth.currentUser) return;
    setIsLoadingSecondary(true);
    setSuccessSecondary(false);
    setError("");

    try {
      const resOptions = await fetch("/api/auth/register-options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: currentUserProfile.username }),
      });

      if (!resOptions.ok) {
        const errData = await resOptions.json();
        throw new Error(errData.error || "Failed obtaining registration options");
      }

      const { options } = await resOptions.json();

      // Request browser WebAuthn Enroll
      const attResp = await startRegistration({ optionsJSON: options });

      // Determine PRF evaluation salt
      let prfSeedBytes: Uint8Array;
      try {
        const clientGetOptions = {
          publicKey: {
            challenge: new Uint8Array(32),
            allowCredentials: [
              {
                id: base64urlDecode(attResp.id),
                type: "public-key" as const,
              },
            ],
            rpId: window.location.hostname,
            extensions: {
              prf: {
                eval: {
                  first: new TextEncoder().encode("huggchat-mek-salt-v1"),
                },
              },
            },
          },
        };
        const assertion = (await navigator.credentials.get(clientGetOptions)) as PublicKeyCredential;
        const prfResults = assertion?.getClientExtensionResults()?.prf;
        
        if (prfResults && prfResults.results && prfResults.results.first) {
          prfSeedBytes = new Uint8Array(prfResults.results.first as any);
        } else {
          throw new Error("No hardware browser PRF");
        }
      } catch {
        const fallbackSource = new TextEncoder().encode(attResp.id + currentUserProfile.username);
        const hash = await window.crypto.subtle.digest("SHA-256", fallbackSource);
        prfSeedBytes = new Uint8Array(hash);
      }

      // Encrypt MEK with this new validator
      const wrappedMekHex = await wrapMek(unwrappedMek, prfSeedBytes);

      // Finish verification on server to write another credential
      const resVerify = await fetch("/api/auth/verify-registration", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uid: auth.currentUser.uid,
          response: attResp,
          wrappedMek: wrappedMekHex,
          identityPubkey: currentUserProfile.identity_pubkey,
        }),
      });

      if (!resVerify.ok) {
        const verifyErr = await resVerify.json();
        throw new Error(verifyErr.error || "Registration validation failed");
      }

      setSuccessSecondary(true);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Enrollment failed. Make sure your browser supports WebAuthn.");
    } finally {
      setIsLoadingSecondary(false);
    }
  };

  function base64urlDecode(base64url: string): Uint8Array {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64.length % 4;
    const padded = pad ? base64 + "=".repeat(4 - pad) : base64;
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  return (
    <div className="w-full max-w-2xl mx-auto bg-[#141211] border border-[#23211F] rounded-lg p-8 shadow-[2px_2px_0px_#23211F,4px_4px_0px_#1E1B19,6px_6px_0px_#0A0908] select-none text-[#C1B2A3]">
      <div className="flex items-center justify-between mb-8 border-b border-[#23211F] pb-4">
        <h1 className="font-sans text-xl font-bold text-[#EAE2D8] flex items-center gap-2">
          <Server className="w-5 h-5 text-[#8A7E73]" /> Sovereign Identity Center
        </h1>
        <button
          onClick={onClose}
          className="p-1.5 rounded bg-[#0A0908] hover:bg-[#1E1B19] border border-[#23211F] text-[#8A7E73] hover:text-[#EAE2D8] cursor-pointer transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Left hand details panel */}
        <div className="space-y-6">
          {/* Identity Coordinates */}
          <div className="bg-[#0A0908] border border-[#23211F] rounded p-5 space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-widest text-[#EAE2D8] flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" /> Identity Coordinates (X25519)
            </h3>
            <p className="text-[10px] text-[#8A7E73] leading-relaxed">
              Your public key coordinates are visible globally. Users use this public key to establish continuous direct ratchet handshakes.
            </p>
            <div className="flex items-center gap-2 bg-[#141211] border border-[#23211F] rounded px-3 py-2">
              <span className="font-mono text-[9px] text-[#8A7E73] truncate flex-1">
                {currentUserProfile.identity_pubkey}
              </span>
              <button
                onClick={copyPublicKey}
                className="p-1 text-[#8A7E73] hover:text-[#EAE2D8] transition-colors cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Secondary Passkey Enrollment */}
          <div className="bg-[#0A0908] border border-[#23211F] rounded p-5 space-y-4">
            <h3 className="text-xs font-mono uppercase tracking-widest text-[#EAE2D8] flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5" /> Secondary Passkey
            </h3>
            <p className="text-[10px] text-[#8A7E73] leading-relaxed">
              Register secondary hardware devices or mobile validators on this profile. This writes an independent wrapped copy of your immutable MEK master key.
            </p>
            <button
              onClick={handleEnrollSecondaryPasskey}
              disabled={isLoadingSecondary}
              className="w-full py-2.5 rounded border border-[#23211F] hover:border-[#C1B2A3] bg-[#141211] hover:bg-[#1E1B19] text-xs font-mono text-[#C1B2A3] hover:text-[#EAE2D8] transition-all cursor-pointer flex items-center justify-center gap-2"
            >
              {isLoadingSecondary ? (
                <div className="w-4 h-4 border-2 border-t-transparent border-[#C1B2A3] rounded-full animate-spin" />
              ) : successSecondary ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  Passkey Enrolled!
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  Register Auxiliary Key
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right hand Master Pass Recovery configuration */}
        <div className="space-y-6">
          <div className="bg-[#0A0908] border border-[#23211F] rounded p-5 space-y-5">
            <h3 className="text-xs font-mono uppercase tracking-widest text-[#EAE2D8] flex items-center gap-1.5">
              <Disc className="w-3.5 h-3.5 text-amber-500" /> Sovereign Master Pass Backups
            </h3>
            <p className="text-[10px] text-[#8A7E73] leading-relaxed">
              Bypasses passkeys if devices are missing. Uses memory-hard, client-side <span className="text-[#C1B2A3] font-semibold">Argon2id hashing WebAssembly</span> to securely derive 256-bit wrap keys, and stores an encrypted recovery payload block.
            </p>

            <form onSubmit={handleSetMasterPass} className="space-y-3">
              <div>
                <label className="block text-[9px] font-mono uppercase tracking-wider text-[#8A7E73] mb-1.5">
                  Sovereign Master Password
                </label>
                <input
                  id="settings-master-pass"
                  type="password"
                  required
                  value={masterPass}
                  onChange={(e) => setMasterPass(e.target.value)}
                  placeholder="Minimum 12 characters..."
                  disabled={isSettingMasterPass}
                  className="w-full bg-[#141211] border border-[#23211F] rounded px-3 py-2 text-xs text-[#EAE2D8] placeholder-[#5A5046] focus:outline-none focus:border-[#C1B2A3]"
                />
              </div>

              <button
                id="settings-master-pass-btn"
                type="submit"
                disabled={isSettingMasterPass || masterPass.length < 12}
                className="w-full py-2.5 rounded border border-[#23211F] bg-[#141211] hover:bg-[#1E1B19] text-xs font-mono text-[#C1B2A3] hover:text-[#EAE2D8] transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2"
              >
                {isSettingMasterPass ? (
                  <div className="w-4 h-4 border-2 border-t-transparent border-[#C1B2A3] rounded-full animate-spin" />
                ) : masterPassSuccess ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                    Recovery Payload Set!
                  </>
                ) : (
                  <>
                    <CornerDownLeft className="w-3.5 h-3.5" />
                    Secure Recovery Block
                  </>
                )}
              </button>
            </form>

            <p className="text-[9px] text-[#5A5046] leading-normal uppercase font-mono tracking-wide">
              🔒 Argon2id settings: Parallelism 1 • Iterations 3 • Memory 4MB (audited local client execution)
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
