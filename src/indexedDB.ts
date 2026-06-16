import { DirectRatchetState, SenderKeyRecord } from "./types";

const DB_NAME = "huggchat_secure_cache_v1";
const DB_VERSION = 1;

class SecureCacheDB {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = request.result;
        if (!db.objectStoreNames.contains("direct_ratchets")) {
          // Keyed by chatId
          db.createObjectStore("direct_ratchets", { keyPath: "chatId" });
        }
        if (!db.objectStoreNames.contains("sender_keys")) {
          // Keyed compound: chat_sender (chatId + "_" + senderId)
          db.createObjectStore("sender_keys", { keyPath: "id" });
        }
      };
    });
  }

  private async getStore(storeName: string, mode: IDBTransactionMode): Promise<IDBObjectStore> {
    await this.init();
    if (!this.db) throw new Error("Database not initialized");
    const tx = this.db.transaction(storeName, mode);
    return tx.objectStore(storeName);
  }

  // Direct 1-on-1 Ratchets management
  async getDirectRatchet(chatId: string): Promise<DirectRatchetState | null> {
    try {
      const store = await this.getStore("direct_ratchets", "readonly");
      return new Promise((resolve, reject) => {
        const req = store.get(chatId);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve(req.result || null);
      });
    } catch {
      return null;
    }
  }

  async saveDirectRatchet(state: DirectRatchetState): Promise<void> {
    const store = await this.getStore("direct_ratchets", "readwrite");
    return new Promise((resolve, reject) => {
      const req = store.put(state);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    });
  }

  // Group chats Sender Keys management (SCK + S_pub)
  async getSenderKey(chatId: string, senderId: string): Promise<SenderKeyRecord | null> {
    try {
      const store = await this.getStore("sender_keys", "readonly");
      const id = `${chatId}_${senderId}`;
      return new Promise((resolve, reject) => {
        const req = store.get(id);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          if (!req.result) return resolve(null);
          resolve({
            chatId: req.result.chatId,
            senderId: req.result.senderId,
            senderChainKey: req.result.senderChainKey,
            signingPublicKey: req.result.signingPublicKey,
          });
        };
      });
    } catch {
      return null;
    }
  }

  async saveSenderKey(chatId: string, senderId: string, data: { senderChainKey: string; signingPublicKey: string }): Promise<void> {
    const store = await this.getStore("sender_keys", "readwrite");
    const id = `${chatId}_${senderId}`;
    return new Promise((resolve, reject) => {
      const req = store.put({
        id,
        chatId,
        senderId,
        ...data,
      });
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    });
  }

  async clearGroupKeys(chatId: string): Promise<void> {
    const store = await this.getStore("sender_keys", "readwrite");
    return new Promise<void>((resolve, reject) => {
      const req = store.openCursor();
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          const record = cursor.value;
          if (record.chatId === chatId) {
            cursor.delete();
          }
          cursor.continue();
        } else {
          resolve();
        }
      };
    });
  }

  async clearAll(): Promise<void> {
    await this.init();
    if (!this.db) return;
    const directStore = await this.getStore("direct_ratchets", "readwrite");
    directStore.clear();
    const senderStore = await this.getStore("sender_keys", "readwrite");
    senderStore.clear();
  }
}

export const secureCacheDB = new SecureCacheDB();
