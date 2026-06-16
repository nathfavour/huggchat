export interface UserProfile {
  id: string;
  username: string;
  identity_pubkey: string;
}

export interface ChatSession {
  id: string;
  is_group: boolean;
  participants: string[];
  created_at: any; // Firestore Timestamp
  name?: string; // Derived group name or contact name
}

export interface EncryptedMessage {
  id: string;
  sender_id: string;
  payload: string; // Hex payload containing prefix header + encrypted bytes
  ephemeral_pubkey?: string; // X25519 Ephemeral key for DH ratchet
  created_at: any; // Firestore Timestamp
}

export interface UIState {
  currentUser: UserProfile | null;
  wrappedMek: string | null;
  unwrappedMek: Uint8Array | null; // Keep in-memory
  activeChat: ChatSession | null;
  profiles: { [userId: string]: UserProfile };
}

export interface CredentialRecord {
  id: string;
  user_id: string;
  public_key: string;
  wrapped_mek: string;
  created_at: any;
}

export interface DirectRatchetState {
  chatId: string;
  sendingChainKey: string; // hex
  receivingChainKey: string; // hex
  lastDhPublicKey: string; // hex (counterparty's latest known DH public key used)
  myDhPrivateKey: string; // jwk / raw representing my private key
  myDhPublicKey: string; // hex representing my public key
}

export interface SenderKeyRecord {
  chatId: string;
  senderId: string;
  senderChainKey: string; // hex
  signingPublicKey: string; // hex
}
