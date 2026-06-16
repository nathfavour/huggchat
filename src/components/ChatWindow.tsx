import React, { useState, useEffect, useRef } from "react";
import { 
  collection, 
  query, 
  where, 
  getDocs, 
  addDoc, 
  setDoc, 
  doc, 
  onSnapshot, 
  getDoc, 
  serverTimestamp, 
  orderBy 
} from "firebase/firestore";
import { db, auth } from "../firebase";
import { handleFirestoreError, OperationType } from "../firestoreUtils";
import { UserProfile, ChatSession, EncryptedMessage } from "../types";
import { 
  computeSharedSecret, 
  ratchetChainKey, 
  encryptPayload, 
  decryptPayload, 
  packMessage, 
  unpackMessage, 
  bufToHex, 
  hexToBuf 
} from "../cryptoUtils";
import { secureCacheDB } from "../indexedDB";
import { 
  Send, 
  MessageSquare, 
  Plus, 
  Users, 
  Mic, 
  MicOff, 
  Volume2, 
  Search, 
  Settings, 
  ChevronRight, 
  UserPlus, 
  LogOut, 
  Smile, 
  AlertTriangle,
  Shield
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface ChatWindowProps {
  currentUserProfile: UserProfile;
  unwrappedMek: Uint8Array;
  onLogout: () => void;
  openSettings: () => void;
}

export const ChatWindow: React.FC<ChatWindowProps> = ({ 
  currentUserProfile, 
  unwrappedMek, 
  onLogout, 
  openSettings 
}) => {
  // Sidebar states
  const [chats, setChats] = useState<ChatSession[]>([]);
  const [activeChat, setActiveChat] = useState<ChatSession | null>(null);
  const [profiles, setProfiles] = useState<{ [userId: string]: UserProfile }>({});
  
  // Search state
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UserProfile[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState("");

  // Group creation state
  const [isCreatingGroup, setIsCreatingGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [selectedGroupParticipants, setSelectedGroupParticipants] = useState<string[]>([]); // User IDs

  // Message area state
  const [messages, setMessages] = useState<any[]>([]);
  const [inputText, setInputText] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);

  // Voice Note Recording
  const [isRecording, setIsRecording] = useState(false);
  const [mediaRecorder, setMediaRecorder] = useState<MediaRecorder | null>(null);
  const [recordedChunks, setRecordedChunks] = useState<Blob[]>([]);
  const [voiceNoteError, setVoiceNoteError] = useState("");

  const chatEndRef = useRef<HTMLDivElement | null>(null);

  // Native Emojis List
  const emojis = ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚", "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️", "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡", "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓", "🤫", "🫠", "👍", "🔥", "❤️", "🎯", "✨"];

  // 1. Initialise Direct & Groups listener
  useEffect(() => {
    if (!auth.currentUser) return;
    const path = "chats";
    
    // Set up standard snapshot listener for chats
    const q = query(
      collection(db, path),
      where("participants", "array-contains", auth.currentUser.uid)
    );

    const unsubscribe = onSnapshot(
      q,
      async (snapshot) => {
        const chatsList: ChatSession[] = [];
        const missingUserIds: string[] = [];

        for (const docSnap of snapshot.docs) {
          const data = docSnap.data();
          const chat: ChatSession = {
            id: docSnap.id,
            is_group: data.is_group || false,
            participants: data.participants || [],
            created_at: data.created_at,
            name: data.name || "",
          };
          chatsList.push(chat);

          // Find if we have missing profiles in local cache
          chat.participants.forEach((pid) => {
            if (pid !== auth.currentUser?.uid && !profiles[pid] && !missingUserIds.includes(pid)) {
              missingUserIds.push(pid);
            }
          });
        }

        // Fetch missing profiles
        if (missingUserIds.length > 0) {
          await fetchProfiles(missingUserIds);
        }

        setChats(chatsList);
      },
      (error) => {
        handleFirestoreError(error, OperationType.GET, path);
      }
    );

    return () => unsubscribe();
  }, [profiles]);

  // Fetch profiles helper
  const fetchProfiles = async (uids: string[]) => {
    try {
      const uidsToFetch = uids.filter((id) => !profiles[id]);
      if (uidsToFetch.length === 0) return;

      const profileCollection = "profiles";
      const q = query(collection(db, profileCollection), where("id", "in", uidsToFetch));
      const querySnap = await getDocs(q);

      const updatedProfiles = { ...profiles };
      querySnap.forEach((docSnap) => {
        const data = docSnap.data();
        updatedProfiles[docSnap.id] = {
          id: docSnap.id,
          username: data.username || "anonymous",
          identity_pubkey: data.identity_pubkey || "",
        };
      });
      setProfiles(updatedProfiles);
    } catch (err) {
      console.error("Error fetching profiles:", err);
    }
  };

  // 2. Discover contacts by exact username
  const handleSearchContact = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    setSearchError("");
    setSearchResults([]);

    try {
      const cleanSearch = searchQuery.trim().toLowerCase();
      if (cleanSearch === currentUserProfile.username) {
        setSearchError("You cannot query your own username.");
        setIsSearching(false);
        return;
      }

      const q = query(collection(db, "profiles"), where("username", "==", cleanSearch));
      const snap = await getDocs(q);

      if (snap.empty) {
        setSearchError(`Username '${searchQuery}' not found.`);
      } else {
        const results: UserProfile[] = [];
        snap.forEach((docSnap) => {
          const data = docSnap.data();
          results.push({
            id: docSnap.id,
            username: data.username || "anonymous",
            identity_pubkey: data.identity_pubkey || "",
          });
        });
        setSearchResults(results);
      }
    } catch (err: any) {
      setSearchError(err.message || "Failed to search profiles");
    } finally {
      setIsSearching(false);
    }
  };

  // Start 1-on-1 Chat
  const startDirectChat = async (contact: UserProfile) => {
    if (!auth.currentUser) return;
    try {
      // Check if chat already exists
      const existing = chats.find(
        (c) => !c.is_group && c.participants.includes(contact.id)
      );

      if (existing) {
        setActiveChat(existing);
        setSearchQuery("");
        setSearchResults([]);
        return;
      }

      // Generate secure composite chatId
      const sortedIds = [auth.currentUser.uid, contact.id].sort();
      const chatId = `dm_${sortedIds[0]}_${sortedIds[1]}`;

      const chatRef = doc(db, "chats", chatId);
      const chatDoc = await getDoc(chatRef);

      if (!chatDoc.exists()) {
        const path = `chats/${chatId}`;
        try {
          await setDoc(chatRef, {
            id: chatId,
            is_group: false,
            participants: [auth.currentUser.uid, contact.id],
            created_at: serverTimestamp(),
          });
        } catch (error) {
          handleFirestoreError(error, OperationType.CREATE, path);
        }
      }

      // Pre-add profile to local cache
      setProfiles((prev) => ({ ...prev, [contact.id]: contact }));

      setActiveChat({
        id: chatId,
        is_group: false,
        participants: [auth.currentUser.uid, contact.id],
        created_at: new Date(),
      });

      setSearchQuery("");
      setSearchResults([]);
    } catch (err) {
      console.error("Error starting direct chat:", err);
    }
  };

  // Start Group Chat
  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!auth.currentUser || !newGroupName.trim() || selectedGroupParticipants.length === 0) return;

    try {
      const chatId = `group_${crypto.randomUUID()}`;
      const participants = [auth.currentUser.uid, ...selectedGroupParticipants];

      // 1. Generate local Sender Chain Key (SCK) and signing keypair for continuous ratchet
      const mySck = window.crypto.getRandomValues(new Uint8Array(32));
      const sckHex = bufToHex(mySck);
      const signingKeys = await window.crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const exportedSigningPub = await window.crypto.subtle.exportKey("raw", signingKeys.publicKey);
      const signingPubHex = bufToHex(new Uint8Array(exportedSigningPub));

      // Cache our own group chain key and signing keys locally inside IndexedDB
      await secureCacheDB.saveSenderKey(chatId, auth.currentUser.uid, {
        senderChainKey: sckHex,
        signingPublicKey: signingPubHex,
      });

      // 2. Encrypt & Distribute Alice's starting SCK to Bobby/Charlie individually via 1-on-1 direct channels
      // Under Section 7.1 "These setup packets are transmitted as invisible, automated system messages"
      const pathChats = `chats/${chatId}`;
      await setDoc(doc(db, "chats", chatId), {
        id: chatId,
        is_group: true,
        name: newGroupName.trim(),
        participants,
        created_at: serverTimestamp(),
      });

      // Send automated "system-key-setup" markers encrypted for each participant
      for (const pid of selectedGroupParticipants) {
        const contactProfile = profiles[pid];
        if (!contactProfile) continue;

        // Compute secure 1-on-1 key agreement
        const myPrivJwk = localStorage.getItem(`huggchat_priv_${auth.currentUser.uid}`);
        if (!myPrivJwk) continue;

        const sharedSecretRaw = await computeSharedSecret(myPrivJwk, contactProfile.identity_pubkey);
        
        // Encrypt our starting SCK
        const payloadData = new TextEncoder().encode(JSON.stringify({ sck: sckHex, sig_pub: signingPubHex }));
        const encryptedSck = await encryptPayload(payloadData, sharedSecretRaw);
        
        // Pack as prefix 0x03 (System Setup)
        const packed = new Uint8Array(1 + encryptedSck.length);
        packed[0] = 0x03;
        packed.set(encryptedSck, 1);

        // Upload setup packet to group messages
        const msgId = `sys_${crypto.randomUUID()}`;
        await setDoc(doc(db, "chats", chatId, "messages", msgId), {
          id: msgId,
          sender_id: auth.currentUser?.uid,
          payload: bufToHex(packed),
          recipient_id: pid, // Directed specifically to this user
          created_at: serverTimestamp(),
        });
      }

      setActiveChat({
        id: chatId,
        is_group: true,
        participants,
        created_at: new Date(),
        name: newGroupName.trim(),
      });

      setIsCreatingGroup(false);
      setNewGroupName("");
      setSelectedGroupParticipants([]);
    } catch (err: any) {
      console.error("Error creating group:", err);
    }
  };

  // Toggle group participant
  const toggleGroupParticipant = (pid: string) => {
    setSelectedGroupParticipants((prev) =>
      prev.includes(pid) ? prev.filter((id) => id !== pid) : [...prev, pid]
    );
  };

  // 3. Listen to Active Messages
  useEffect(() => {
    if (!activeChat || !auth.currentUser) return;

    const path = `chats/${activeChat.id}/messages`;
    const q = query(
      collection(db, "chats", activeChat.id, "messages"),
      orderBy("created_at", "asc")
    );

    const unsubscribe = onSnapshot(
      q,
      async (snapshot) => {
        const messagesList: any[] = [];

        for (const docSnap of snapshot.docs) {
          const docData = docSnap.data();
          const rawPayloadHex = docData.payload || "";
          
          if (!rawPayloadHex) continue;
          
          const rawPayloadBytes = hexToBuf(rawPayloadHex);
          const prefixHeader = rawPayloadBytes[0];

          // Check if this is a group "system setup metadata" envelope
          if (prefixHeader === 0x03) {
            // Only process if Bob is the matching recipient_id
            if (docData.recipient_id === auth.currentUser?.uid) {
              const senderId = docData.sender_id;
              const senderProfile = profiles[senderId];
              
              if (senderProfile) {
                try {
                  const myPrivJwk = localStorage.getItem(`huggchat_priv_${auth.currentUser?.uid}`);
                  if (myPrivJwk) {
                    const sharedSecretRaw = await computeSharedSecret(myPrivJwk, senderProfile.identity_pubkey);
                    const decrypted = await decryptPayload(rawPayloadBytes.slice(1), sharedSecretRaw);
                    const credSetup = JSON.parse(new TextDecoder().decode(decrypted));
                    
                    // Save decrypted peer group chain key inside IndexedDB
                    await secureCacheDB.saveSenderKey(activeChat.id, senderId, {
                      senderChainKey: credSetup.sck,
                      signingPublicKey: credSetup.sig_pub,
                    });
                  }
                } catch (err) {
                  console.error("Failed Decrypting Peer SCK:", err);
                }
              }
            }
            continue; // Skip rendering system keys inside regular chat list
          }

          // Fetch message decryption keys
          let decryptedText = "";
          let decryptedAudioUrl = "";
          let decryptFailed = false;

          try {
            const senderId = docData.sender_id;

            if (senderId === auth.currentUser?.uid) {
              // Self-messages decrypting:
              // For direct 1-on-1: we can use the local direct ratchet send key, 
              // but even simpler: let's decrypt using the derived E2EE session key or standard direct ratchet cache
              if (!activeChat.is_group) {
                const contactId = activeChat.participants.find((p) => p !== auth.currentUser?.uid) || "";
                const contactProfile = profiles[contactId];
                if (contactProfile) {
                  const myPrivJwk = localStorage.getItem(`huggchat_priv_${auth.currentUser?.uid}`);
                  if (myPrivJwk) {
                    const sharedSecretRaw = await computeSharedSecret(myPrivJwk, contactProfile.identity_pubkey);
                    // Standard symmetric AES decapsulate
                    const unpacked = unpackMessage(await decryptPayload(rawPayloadBytes, sharedSecretRaw));
                    if (unpacked.type === "text") {
                      decryptedText = new TextDecoder().decode(unpacked.data);
                    } else {
                      const blob = new Blob([unpacked.data], { type: "audio/ogg" });
                      decryptedAudioUrl = URL.createObjectURL(blob);
                    }
                  }
                }
              } else {
                // Group post sent by me: decrypt using our own generated sender keys
                const cachedSetup = await secureCacheDB.getSenderKey(activeChat.id, auth.currentUser?.uid);
                if (cachedSetup) {
                  const keyBytes = hexToBuf(cachedSetup.senderChainKey);
                  const unpacked = unpackMessage(await decryptPayload(rawPayloadBytes, keyBytes));
                  if (unpacked.type === "text") {
                    decryptedText = new TextDecoder().decode(unpacked.data);
                  } else {
                    const blob = new Blob([unpacked.data], { type: "audio/ogg" });
                    decryptedAudioUrl = URL.createObjectURL(blob);
                  }
                }
              }
            } else {
              // Messages sent by Alice (peer):
              if (!activeChat.is_group) {
                const senderProfile = profiles[senderId];
                if (senderProfile) {
                  const myPrivJwk = localStorage.getItem(`huggchat_priv_${auth.currentUser?.uid}`);
                  if (myPrivJwk) {
                    const sharedSecretRaw = await computeSharedSecret(myPrivJwk, senderProfile.identity_pubkey);
                    const unpacked = unpackMessage(await decryptPayload(rawPayloadBytes, sharedSecretRaw));
                    if (unpacked.type === "text") {
                      decryptedText = new TextDecoder().decode(unpacked.data);
                    } else {
                      const blob = new Blob([unpacked.data], { type: "audio/ogg" });
                      decryptedAudioUrl = URL.createObjectURL(blob);
                    }
                  }
                }
              } else {
                // Group post: decrypt Bob's payload using Alice's distributed cached keys
                const aliceSckRecord = await secureCacheDB.getSenderKey(activeChat.id, senderId);
                if (aliceSckRecord) {
                  const keyBytes = hexToBuf(aliceSckRecord.senderChainKey);
                  const unpacked = unpackMessage(await decryptPayload(rawPayloadBytes, keyBytes));
                  
                  // Step her group key forward internally to protect forward secrecy (Section 7.3)
                  const { nextChainKey } = await ratchetChainKey(keyBytes);
                  await secureCacheDB.saveSenderKey(activeChat.id, senderId, {
                    senderChainKey: bufToHex(nextChainKey),
                    signingPublicKey: aliceSckRecord.signingPublicKey,
                  });

                  if (unpacked.type === "text") {
                    decryptedText = new TextDecoder().decode(unpacked.data);
                  } else {
                    const blob = new Blob([unpacked.data], { type: "audio/ogg" });
                    decryptedAudioUrl = URL.createObjectURL(blob);
                  }
                } else {
                  decryptFailed = true;
                }
              }
            }
          } catch (err) {
            console.error("Decryption error:", err);
            decryptFailed = true;
          }

          messagesList.push({
            id: docSnap.id,
            sender_id: docData.sender_id,
            decryptedText: decryptFailed ? "🔐 Decryption Key Mismatch / Sync Blocked" : decryptedText,
            decryptedAudioUrl,
            error: decryptFailed,
            created_at: docData.created_at?.toDate() || new Date(),
          });
        }

        setMessages(messagesList);
        setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
      },
      (error) => {
        handleFirestoreError(error, OperationType.GET, path);
      }
    );

    return () => unsubscribe();
  }, [activeChat, profiles]);

  // 4. Send Message Frame
  const handleSendMessage = async (rawBinaryData: Uint8Array, type: "text" | "audio") => {
    if (!activeChat || !auth.currentUser) return;

    setIsSending(true);
    try {
      let finalPayloadHex = "";

      if (!activeChat.is_group) {
        // Direct E2EE messaging: Encrypt using shared secret directly (highly safe for zero network config)
        const contactId = activeChat.participants.find((p) => p !== auth.currentUser?.uid) || "";
        const contactProfile = profiles[contactId];
        
        if (contactProfile) {
          const myPrivJwk = localStorage.getItem(`huggchat_priv_${auth.currentUser?.uid}`);
          if (myPrivJwk) {
            const sharedSecretRaw = await computeSharedSecret(myPrivJwk, contactProfile.identity_pubkey);
            
            // Pack raw message
            const packed = packMessage(type, rawBinaryData);
            const cipherBytes = await encryptPayload(packed, sharedSecretRaw);
            
            finalPayloadHex = bufToHex(cipherBytes);
          }
        }
      } else {
        // Group E2EE Messaging: Encrypt using our active SCK from IndexedDB (Section 7.2)
        const cachedSetup = await secureCacheDB.getSenderKey(activeChat.id, auth.currentUser?.uid);
        if (cachedSetup) {
          const keyBytes = hexToBuf(cachedSetup.senderChainKey);
          
          // Pack and encrypt
          const packed = packMessage(type, rawBinaryData);
          const cipherBytes = await encryptPayload(packed, keyBytes);
          finalPayloadHex = bufToHex(cipherBytes);

          // Step key ratchet forward and update local cache database immediately
          const { nextChainKey } = await ratchetChainKey(keyBytes);
          await secureCacheDB.saveSenderKey(activeChat.id, auth.currentUser?.uid, {
            senderChainKey: bufToHex(nextChainKey),
            signingPublicKey: cachedSetup.signingPublicKey,
          });
        }
      }

      if (finalPayloadHex) {
        const msgId = crypto.randomUUID();
        const msgPath = `chats/${activeChat.id}/messages/${msgId}`;
        try {
          await setDoc(doc(db, "chats", activeChat.id, "messages", msgId), {
            id: msgId,
            sender_id: auth.currentUser?.uid,
            payload: finalPayloadHex,
            created_at: serverTimestamp(),
          });
        } catch (error) {
          handleFirestoreError(error, OperationType.WRITE, msgPath);
        }
      }

      setInputText("");
      setShowEmojiPicker(false);
    } catch (err) {
      console.error("Error sending message:", err);
    } finally {
      setIsSending(false);
    }
  };

  const triggerSendText = () => {
    if (!inputText.trim()) return;
    const binary = new TextEncoder().encode(inputText.trim());
    handleSendMessage(binary, "text");
  };

  // 5. Audios / voice notes recording engine
  const startRecordingVoice = async () => {
    setVoiceNoteError("");
    setRecordedChunks([]);

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) {
          setRecordedChunks((prev) => [...prev, e.data]);
        }
      };

      recorder.onstop = async () => {
        const audioBlob = new Blob(recordedChunks, { type: "audio/ogg" });
        const arrayBuffer = await audioBlob.arrayBuffer();
        await handleSendMessage(new Uint8Array(arrayBuffer), "audio");
        
        // Disable tracks
        stream.getTracks().forEach((track) => track.stop());
      };

      recorder.start();
      setMediaRecorder(recorder);
      setIsRecording(true);
    } catch (err: any) {
      setVoiceNoteError("Microphone access denied or blocked. Verify frame permissions.");
      console.error(err);
    }
  };

  const stopRecordingVoice = () => {
    if (mediaRecorder && isRecording) {
      mediaRecorder.stop();
      setIsRecording(false);
    }
  };

  // Derived user names mapping
  const getChatName = (chat: ChatSession) => {
    if (chat.is_group) return chat.name || "Unnamed Group";
    const contactId = chat.participants.find((p) => p !== auth.currentUser?.uid) || "";
    return profiles[contactId]?.username || "anonymous";
  };

  return (
    <div className="flex h-[82vh] w-full rounded-xl overflow-hidden border border-[#23211F] bg-[#0A0908] shadow-[1px_1px_0px_#23211F,2px_2px_0px_#1E1B19,3px_3px_0px_#161412,4px_4px_0px_#0A0908,5px_5px_0px_#000000]">
      {/* 1. Left side controls rail */}
      <div className="w-80 border-r border-[#23211F] bg-[#141211] flex flex-col">
        {/* Head header */}
        <div className="p-4 border-b border-[#23211F] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-[#1A1817] border border-[#23211F] flex items-center justify-center font-mono text-xs text-[#EAE2D8] uppercase">
              {currentUserProfile.username.slice(0, 2)}
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-semibold text-[#EAE2D8]">
                {currentUserProfile.username}
              </span>
              <span className="text-[10px] font-mono text-[#8A7E73] tracking-wide uppercase">
                Offline Sovereign
              </span>
            </div>
          </div>
          <div className="flex gap-1.5">
            <button
              onClick={openSettings}
              className="p-1.5 rounded bg-[#1E1B19] hover:bg-[#23211F] border border-[#23211F] text-[#C1B2A3] cursor-pointer hover:text-[#EAE2D8] transition-colors"
              title="Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              onClick={onLogout}
              className="p-1.5 rounded bg-[#1E1B19] hover:bg-red-950/40 border border-[#23211F] text-red-400 cursor-pointer hover:text-red-300 transition-colors"
              title="Identity Wipe"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Discovery contact search box */}
        <div className="p-4 border-b border-[#23211F] bg-[#0A0908]">
          <form onSubmit={handleSearchContact} className="flex gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Find contact..."
                className="w-full bg-[#141211] text-xs border border-[#23211F] rounded pl-8 pr-2 py-2 text-[#EAE2D8] placeholder-[#5A5046] focus:outline-none focus:border-[#C1B2A3]"
              />
              <Search className="w-3.5 h-3.5 text-[#5A5046] absolute left-2.5 top-2.5" />
            </div>
            <button
              type="submit"
              disabled={isSearching}
              className="px-3 rounded border border-[#23211F] bg-[#141211] text-[#C1B2A3] hover:text-[#EAE2D8] cursor-pointer hover:bg-[#1E1B19]"
            >
              <UserPlus className="w-3.5 h-3.5" />
            </button>
          </form>

          {searchError && (
            <div className="mt-2 text-[10px] font-mono text-amber-500 bg-amber-950/20 px-2 py-1.5 rounded border border-amber-900/30 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 shrink-0" />
              {searchError}
            </div>
          )}

          {searchResults.length > 0 && (
            <div className="mt-2 space-y-1">
              {searchResults.map((contact) => (
                <div
                  key={contact.id}
                  onClick={() => startDirectChat(contact)}
                  className="flex items-center justify-between p-2 rounded bg-[#1E1B19] border border-[#23211F] hover:bg-[#23211F] cursor-pointer transition-colors"
                >
                  <span className="text-xs font-mono text-[#EAE2D8]">
                    {contact.username}
                  </span>
                  <Plus className="w-3.5 h-3.5 text-[#C1B2A3]" />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Group creation helper */}
        <div className="p-4 border-b border-[#23211F]">
          {!isCreatingGroup ? (
            <button
              onClick={() => setIsCreatingGroup(true)}
              className="w-full flex items-center justify-center gap-2 border border-dashed border-[#23211F] hover:border-[#C1B2A3] bg-[#0A0908] hover:bg-[#141211] py-2 text-xs font-mono text-[#C1B2A3] hover:text-[#EAE2D8] rounded transition-all cursor-pointer"
            >
              <Users className="w-4 h-4" /> Assemble Group
            </button>
          ) : (
            <form onSubmit={handleCreateGroup} className="space-y-3">
              <input
                type="text"
                required
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                placeholder="Group Name"
                className="w-full bg-[#0A0908] text-xs border border-[#23211F] rounded px-3 py-2 text-[#EAE2D8] placeholder-[#5A5046]"
              />
              <div className="text-[10px] uppercase font-mono text-[#8A7E73] tracking-wider mb-1">
                Select Participants:
              </div>
              <div className="max-h-24 overflow-y-auto space-y-1 pr-1">
                {(Object.values(profiles) as UserProfile[]).map((p) => (
                  <label
                    key={p.id}
                    className="flex items-center gap-2 p-1.5 rounded bg-[#0A0908] border border-[#23211F] hover:bg-[#1E1B19] cursor-pointer text-xs"
                  >
                    <input
                      type="checkbox"
                      checked={selectedGroupParticipants.includes(p.id)}
                      onChange={() => toggleGroupParticipant(p.id)}
                      className="accent-[#C1B2A3]"
                    />
                    <span className="font-mono text-[#EAE2D8]">{p.username}</span>
                  </label>
                ))}
              </div>
              <div className="flex gap-2 justify-end pt-1">
                <button
                  type="button"
                  onClick={() => setIsCreatingGroup(false)}
                  className="px-2 py-1.5 text-[10px] font-mono uppercase bg-[#141211] text-[#8A7E73] hover:text-[#C1B2A3] rounded cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!newGroupName || selectedGroupParticipants.length === 0}
                  className="px-3 py-1.5 text-[10px] font-mono uppercase bg-[#1E1B19] border border-[#23211F] text-[#EAE2D8] hover:bg-[#23211F] rounded disabled:opacity-40 cursor-pointer"
                >
                  Create
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Chats feeds stream */}
        <div className="flex-grow overflow-y-auto p-4 space-y-2">
          <div className="text-[10px] uppercase font-mono text-[#5A5046] tracking-widest mb-3">
            Sovereign Threads
          </div>
          {chats.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center opacity-40">
              <MessageSquare className="w-8 h-8 text-[#5A5046] mb-2" />
              <p className="text-xs font-mono text-[#8A7E73]">No chats. Find contact above.</p>
            </div>
          ) : (
            chats.map((chat) => {
              const active = activeChat?.id === chat.id;
              return (
                <div
                  key={chat.id}
                  onClick={() => setActiveChat(chat)}
                  className={`flex items-center justify-between p-3 rounded border transition-colors cursor-pointer ${
                    active
                      ? "bg-[#1E1B19] border-[#C1B2A3] text-[#EAE2D8]"
                      : "bg-[#0B0A09] border-[#23211F] text-[#8A7E73] hover:bg-[#141211] hover:text-[#C1B2A3]"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <div className="w-7 h-7 rounded-full bg-[#1A1817] border border-[#23211F] flex items-center justify-center font-mono text-[10px] text-[#C1B2A3]">
                      {chat.is_group ? <Users className="w-3.5 h-3.5" /> : "1:1"}
                    </div>
                    <span className="text-xs font-sans font-medium tracking-wide">
                      {getChatName(chat)}
                    </span>
                  </div>
                  <ChevronRight className="w-3 h-3 opacity-50" />
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* 2. Right side active communication area */}
      <div className="flex-1 bg-[#0A0908] flex flex-col justify-between">
        {activeChat ? (
          <>
            {/* Thread header banner */}
            <div className="p-4 border-b border-[#23211F] bg-[#141211] flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold tracking-wide text-[#EAE2D8]">
                  {getChatName(activeChat)}
                </h2>
                <p className="text-[10px] font-mono text-[#8A7E73] uppercase tracking-wider">
                  {activeChat.is_group 
                    ? `Group Thread • ${activeChat.participants.length} verified devices`
                    : "End-to-End Encrypted Tunnel"
                  }
                </p>
              </div>
              <div className="w-2 h-2 rounded-full bg-[#2aeb9e] animate-pulse" />
            </div>

            {/* Conversation list */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              <AnimatePresence initial={false}>
                {messages.map((msg) => {
                  const mine = msg.sender_id === auth.currentUser?.uid;
                  return (
                    <motion.div
                      key={msg.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`flex ${mine ? "justify-end" : "justify-start"}`}
                    >
                      <div
                        className={`max-w-[70%] p-3.5 rounded border ${
                          mine
                            ? "bg-[#1E1B19] border-[#23211F] text-[#EAE2D8] rounded-tr-none shadow-[2px_2px_0px_#0A0908]"
                            : "bg-[#141211] border-[#23211F] text-[#C1B2A3] rounded-tl-none shadow-[2px_2px_0px_#000000]"
                        }`}
                      >
                        {/* Sender handle */}
                        {!mine && (
                          <div className="text-[9px] font-mono text-[#8A7E73] uppercase tracking-wider mb-1.5 font-semibold">
                            {profiles[msg.sender_id]?.username || "anonymous"}
                          </div>
                        )}

                        {/* Message payload content */}
                        {msg.decryptedAudioUrl ? (
                          <div className="flex items-center gap-2.5 py-1.5">
                            <button
                              onClick={() => {
                                const audio = new Audio(msg.decryptedAudioUrl);
                                audio.play();
                              }}
                              className="p-2 rounded-full bg-[#1A1817] hover:bg-[#23211F] border border-[#23211F] text-[#C1B2A3] hover:text-[#EAE2D8] cursor-pointer flex items-center justify-center transition-colors"
                            >
                              <Volume2 className="w-4 h-4" />
                            </button>
                            <span className="text-[10px] font-mono text-[#8A7E73] tracking-widest uppercase">
                              Voice Note
                            </span>
                          </div>
                        ) : (
                          <p className="text-xs font-sans leading-relaxed break-words whitespace-pre-wrap selection:bg-[#C1B2A3]/30">
                            {msg.decryptedText}
                          </p>
                        )}

                        {/* Timestamp indicator */}
                        <div className="text-[8px] font-mono text-[#5A5046] text-right mt-1.5">
                          {msg.created_at ? msg.created_at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""}
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
              <div ref={chatEndRef} />
            </div>

            {/* Input assembly controllers */}
            <div className="p-4 border-t border-[#23211F] bg-[#141211] space-y-3 relative">
              {/* Emojis selection pad */}
              {showEmojiPicker && (
                <div className="absolute bottom-full left-4 bg-[#141211] border border-[#23211F] rounded-lg p-3 max-w-[280px] grid grid-cols-8 gap-1.5 shadow-[2px_2px_0px_#000000] z-50">
                  {emojis.map((emoji) => (
                    <button
                      key={emoji}
                      onClick={() => setInputText((prev) => prev + emoji)}
                      className="text-lg p-1.5 hover:bg-[#1E1B19] rounded transition-colors cursor-pointer"
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              )}

              {/* Input section */}
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setShowEmojiPicker(!showEmojiPicker)}
                  className="p-2.5 rounded bg-[#0A0908] border border-[#23211F] text-[#C1B2A3] hover:bg-[#1E1B19] hover:text-[#EAE2D8] transition-all cursor-pointer"
                >
                  <Smile className="w-4 h-4" />
                </button>

                {/* Mic buttons stack */}
                {isRecording ? (
                  <button
                    onClick={stopRecordingVoice}
                    className="p-2.5 rounded bg-red-950/50 border border-red-800 text-red-400 hover:bg-red-900/60 transition-all cursor-pointer"
                    title="Stop and Send voice note"
                  >
                    <MicOff className="w-4 h-4 animate-pulse" />
                  </button>
                ) : (
                  <button
                    onClick={startRecordingVoice}
                    className="p-2.5 rounded bg-[#0A0908] border border-[#23211F] text-[#C1B2A3] hover:bg-[#1E1B19] hover:text-[#EAE2D8] transition-all cursor-pointer"
                    title="Record voice note"
                  >
                    <Mic className="w-4 h-4" />
                  </button>
                )}

                <input
                  id="chat-text-input"
                  type="text"
                  value={inputText}
                  placeholder={isRecording ? "🎤 Recording encrypted audio..." : "Message E2EE tunnel..."}
                  disabled={isRecording || isSending}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") triggerSendText();
                  }}
                  onChange={(e) => setInputText(e.target.value)}
                  className="flex-grow bg-[#0A0908] border border-[#23211F] rounded-md px-4 py-3 text-xs text-[#EAE2D8] placeholder-[#5A5046] focus:outline-none focus:border-[#C1B2A3] font-sans tracking-wide"
                />

                <button
                  id="chat-send-frame-btn"
                  onClick={triggerSendText}
                  disabled={!inputText.trim() || isSending}
                  className="p-3 bg-[#0A0908] border border-[#23211F] rounded-md text-[#C1B2A3] hover:text-[#EAE2D8] hover:bg-[#1E1B19] transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>

              {voiceNoteError && (
                <div className="text-[10px] font-mono text-red-500 pt-1">
                  {voiceNoteError}
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="flex-grow flex flex-col items-center justify-center py-24 select-none opacity-40">
            <Shield className="w-16 h-16 text-[#5A5046] stroke-1 mb-4" />
            <h1 className="font-sans text-xl text-[#EAE2D8] tracking-tight font-semibold mb-1">
              Zero-Knowledge Sanctuary
            </h1>
            <p className="text-xs font-mono text-[#8A7E73] tracking-widest uppercase">
              Select or open encrypted tunnel conversations
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
