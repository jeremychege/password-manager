import React, { useState, useEffect } from 'react';
import { Lock, Key, Eye, EyeOff, Plus, Trash2, Save, Download, Upload, Shield, AlertCircle, CheckCircle, Copy, Search } from 'lucide-react';

// Simulated SubtleCrypto implementation for the browser
const subtle = window.crypto.subtle;

// Helper functions
const stringToBuffer = (str) => new TextEncoder().encode(str);
const bufferToString = (buffer) => new TextDecoder().decode(buffer);
const encodeBuffer = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
const decodeBuffer = (base64) => Uint8Array.from(atob(base64), c => c.charCodeAt(0));
const getRandomBytes = (length) => window.crypto.getRandomValues(new Uint8Array(length));

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;

// Password Manager Implementation
class Keychain {
  constructor(salt, hmacKey, aesKey) {
    this.data = { 
      kvs: {},
      salt: salt
    };
    this.secrets = {
      hmacKey: hmacKey,
      aesKey: aesKey
    };
  }

  static async init(password) {
    const salt = encodeBuffer(getRandomBytes(16));
    const keys = await Keychain.deriveKeys(password, salt);
    const keychain = new Keychain(salt, keys.hmacKey, keys.aesKey);
    const authEncrypted = await keychain.encryptPassword("auth", "auth");
    keychain.data.auth = JSON.stringify(authEncrypted);
    return keychain;
  }

  static async deriveKeys(password, salt) {
    const passwordKey = await subtle.importKey(
      "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]
    );
    
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: decodeBuffer(salt),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      passwordKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign"]
    );
    
    const hmacKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer("hmac-key"));
    const hmacKey = await subtle.importKey(
      "raw", hmacKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
    );
    
    const aesKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer("aes-key"));
    const aesKeyBytes = new Uint8Array(aesKeyMaterial.slice(0, 32));
    const aesKey = await subtle.importKey(
      "raw", aesKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]
    );
    
    return { hmacKey, aesKey };
  }

  static async load(password, repr, trustedDataCheck) {
    const parsed = JSON.parse(repr);
    const keys = await Keychain.deriveKeys(password, parsed.salt);
    const keychain = new Keychain(parsed.salt, keys.hmacKey, keys.aesKey);
    keychain.data.kvs = parsed.kvs || {};
    keychain.data.auth = parsed.auth;
    
    if (parsed.auth) {
      try {
        const authData = JSON.parse(parsed.auth);
        const decrypted = await keychain.decryptPassword(authData, "auth");
        if (decrypted !== "auth") throw "Invalid password";
      } catch (e) {
        throw "Invalid password";
      }
    }
    
    if (trustedDataCheck !== undefined) {
      const currentHash = await keychain.computeHash();
      if (currentHash !== trustedDataCheck) {
        throw "Integrity check failed";
      }
    }
    
    return keychain;
  }

  async hashDomain(domain) {
    const hmac = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(domain));
    return encodeBuffer(hmac);
  }

  async encryptPassword(domain, password) {
    const paddedPassword = password.padEnd(MAX_PASSWORD_LENGTH, '\0');
    const iv = getRandomBytes(12);
    const aad = stringToBuffer(domain);
    
    const ciphertext = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad },
      this.secrets.aesKey,
      stringToBuffer(paddedPassword)
    );
    
    return { iv: encodeBuffer(iv), ciphertext: encodeBuffer(ciphertext) };
  }

  async decryptPassword(encryptedData, domain) {
    const iv = decodeBuffer(encryptedData.iv);
    const ciphertext = decodeBuffer(encryptedData.ciphertext);
    const aad = stringToBuffer(domain);
    
    const decrypted = await subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad },
      this.secrets.aesKey,
      ciphertext
    );
    
    const paddedPassword = bufferToString(decrypted);
    return paddedPassword.replace(/\0+$/, '');
  }

  async computeHash() {
    const sortedKeys = Object.keys(this.data.kvs).sort();
    const dataToHash = JSON.stringify({
      salt: this.data.salt,
      kvs: this.data.kvs,
      keys: sortedKeys
    });
    const hash = await subtle.digest("SHA-256", stringToBuffer(dataToHash));
    return encodeBuffer(hash);
  }

  async dump() {
    const representation = {
      salt: this.data.salt,
      kvs: this.data.kvs,
      auth: this.data.auth
    };
    const repr = JSON.stringify(representation);
    const hash = await this.computeHash();
    return [repr, hash];
  }

  async get(name) {
    const hashedDomain = await this.hashDomain(name);
    if (!(hashedDomain in this.data.kvs)) return null;
    const encryptedData = JSON.parse(this.data.kvs[hashedDomain]);
    return await this.decryptPassword(encryptedData, name);
  }

  async set(name, value) {
    const hashedDomain = await this.hashDomain(name);
    const encryptedData = await this.encryptPassword(name, value);
    this.data.kvs[hashedDomain] = JSON.stringify(encryptedData);
  }

  async remove(name) {
    const hashedDomain = await this.hashDomain(name);
    if (hashedDomain in this.data.kvs) {
      delete this.data.kvs[hashedDomain];
      return true;
    }
    return false;
  }

  async getAllEntries() {
    const entries = [];
    for (const [hashedDomain, encryptedValue] of Object.entries(this.data.kvs)) {
      entries.push({ hashedDomain, encryptedValue });
    }
    return entries;
  }
}

// Main App Component
export default function PasswordManager() {
  const [keychain, setKeychain] = useState(null);
  const [masterPassword, setMasterPassword] = useState('');
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  
  const [entries, setEntries] = useState([]);
  const [newDomain, setNewDomain] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [visiblePasswords, setVisiblePasswords] = useState({});

  const showMessage = (type, text) => {
    setMessage({ type, text });
    setTimeout(() => setMessage({ type: '', text: '' }), 4000);
  };

  const createNewKeychain = async () => {
    if (!masterPassword || masterPassword.length < 8) {
      showMessage('error', 'Master password must be at least 8 characters');
      return;
    }
    
    setLoading(true);
    try {
      const kc = await Keychain.init(masterPassword);
      setKeychain(kc);
      setIsUnlocked(true);
      setEntries([]);
      showMessage('success', 'New password manager created successfully!');
    } catch (error) {
      showMessage('error', 'Failed to create keychain: ' + error);
    }
    setLoading(false);
  };

  const unlockKeychain = async () => {
    if (!keychain) {
      showMessage('error', 'Please create or load a keychain first');
      return;
    }
    
    setLoading(true);
    try {
      const [repr] = await keychain.dump();
      const unlockedKc = await Keychain.load(masterPassword, repr);
      setKeychain(unlockedKc);
      setIsUnlocked(true);
      await loadEntries(unlockedKc);
      showMessage('success', 'Keychain unlocked successfully!');
    } catch (error) {
      showMessage('error', 'Invalid master password');
    }
    setLoading(false);
  };

  const loadEntries = async (kc) => {
    const loadedEntries = [];
    // Since domains are hashed, we need to store them separately in real use
    // For demo purposes, we'll keep track of domains as we add them
    setEntries(loadedEntries);
  };

  const addEntry = async () => {
    if (!newDomain || !newPassword) {
      showMessage('error', 'Please enter both domain and password');
      return;
    }
    
    setLoading(true);
    try {
      await keychain.set(newDomain, newPassword);
      const newEntry = { domain: newDomain, password: newPassword };
      setEntries([...entries, newEntry]);
      setNewDomain('');
      setNewPassword('');
      showMessage('success', `Password saved for ${newDomain}`);
    } catch (error) {
      showMessage('error', 'Failed to add entry: ' + error);
    }
    setLoading(false);
  };

  const removeEntry = async (domain) => {
    setLoading(true);
    try {
      await keychain.remove(domain);
      setEntries(entries.filter(e => e.domain !== domain));
      showMessage('success', `Removed password for ${domain}`);
    } catch (error) {
      showMessage('error', 'Failed to remove entry: ' + error);
    }
    setLoading(false);
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      showMessage('success', 'Password copied to clipboard!');
    } catch (error) {
      showMessage('error', 'Failed to copy password');
    }
  };

  const exportKeychain = async () => {
    try {
      const [repr, hash] = await keychain.dump();
      const data = { repr, hash };
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'keychain-backup.json';
      a.click();
      showMessage('success', 'Keychain exported successfully!');
    } catch (error) {
      showMessage('error', 'Failed to export keychain');
    }
  };

  const importKeychain = (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const data = JSON.parse(e.target.result);
        const kc = await Keychain.load(masterPassword, data.repr, data.hash);
        setKeychain(kc);
        setIsUnlocked(true);
        await loadEntries(kc);
        showMessage('success', 'Keychain imported successfully!');
      } catch (error) {
        showMessage('error', 'Failed to import keychain: ' + error);
      }
    };
    reader.readAsText(file);
  };

  const lockKeychain = () => {
    setIsUnlocked(false);
    setMasterPassword('');
    setEntries([]);
    setVisiblePasswords({});
    showMessage('success', 'Keychain locked');
  };

  const filteredEntries = entries.filter(e => 
    e.domain.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < 16; i++) {
      password += chars[array[i] % chars.length];
    }
    setNewPassword(password);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-100 via-purple-50 to-pink-100">
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Shield className="w-12 h-12 text-indigo-600" />
            <h1 className="text-4xl font-bold text-gray-800">Secure Password Manager</h1>
          </div>
          <p className="text-gray-600">Encrypted with AES-GCM & PBKDF2</p>
        </div>

        {/* Message Alert */}
        {message.text && (
          <div className={`mb-6 p-4 rounded-lg flex items-center gap-2 ${
            message.type === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
          }`}>
            {message.type === 'success' ? <CheckCircle className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
            {message.text}
          </div>
        )}

        {!isUnlocked ? (
          // Login/Create Screen
          <div className="bg-white rounded-2xl shadow-xl p-8 max-w-md mx-auto">
            <div className="flex items-center justify-center mb-6">
              <Lock className="w-16 h-16 text-indigo-600" />
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Master Password
                </label>
                <input
                  type="password"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  placeholder="Enter your master password"
                  onKeyPress={(e) => e.key === 'Enter' && (keychain ? unlockKeychain() : createNewKeychain())}
                />
              </div>

              <button
                onClick={createNewKeychain}
                disabled={loading}
                className="w-full bg-indigo-600 text-white py-3 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 font-medium"
              >
                {loading ? 'Creating...' : 'Create New Keychain'}
              </button>

              <button
                onClick={unlockKeychain}
                disabled={loading || !keychain}
                className="w-full bg-purple-600 text-white py-3 rounded-lg hover:bg-purple-700 transition disabled:opacity-50 font-medium"
              >
                {loading ? 'Unlocking...' : 'Unlock Existing Keychain'}
              </button>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-300"></div>
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-white text-gray-500">Or import from file</span>
                </div>
              </div>

              <label className="w-full bg-gray-100 text-gray-700 py-3 rounded-lg hover:bg-gray-200 transition cursor-pointer flex items-center justify-center gap-2 font-medium">
                <Upload className="w-5 h-5" />
                Import Keychain
                <input
                  type="file"
                  accept=".json"
                  onChange={importKeychain}
                  className="hidden"
                />
              </label>
            </div>
          </div>
        ) : (
          // Main Password Manager Interface
          <div className="space-y-6">
            {/* Top Actions Bar */}
            <div className="bg-white rounded-xl shadow-lg p-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-6 h-6 text-green-600" />
                <span className="font-medium text-gray-700">Unlocked & Secure</span>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={exportKeychain}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Export
                </button>
                <button
                  onClick={lockKeychain}
                  className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition flex items-center gap-2"
                >
                  <Lock className="w-4 h-4" />
                  Lock
                </button>
              </div>
            </div>

            {/* Add New Entry */}
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                <Plus className="w-6 h-6" />
                Add New Password
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="Domain (e.g., google.com)"
                  className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
                <div className="relative">
                  <input
                    type={showNewPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Password"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent pr-20"
                  />
                  <button
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-12 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  >
                    {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                  <button
                    onClick={generatePassword}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-indigo-600 hover:text-indigo-700"
                    title="Generate Password"
                  >
                    <Key className="w-5 h-5" />
                  </button>
                </div>
              </div>
              <button
                onClick={addEntry}
                disabled={loading}
                className="mt-4 w-full bg-indigo-600 text-white py-3 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 font-medium"
              >
                {loading ? 'Adding...' : 'Add Password'}
              </button>
            </div>

            {/* Search Bar */}
            <div className="bg-white rounded-xl shadow-lg p-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search domains..."
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
            </div>

            {/* Password List */}
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4">
                Saved Passwords ({filteredEntries.length})
              </h2>
              
              {filteredEntries.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <Key className="w-16 h-16 mx-auto mb-4 opacity-30" />
                  <p>No passwords saved yet</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {filteredEntries.map((entry, idx) => (
                    <div key={idx} className="border border-gray-200 rounded-lg p-4 hover:border-indigo-300 transition">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="font-medium text-gray-800 mb-1">{entry.domain}</div>
                          <div className="flex items-center gap-2">
                            <input
                              type={visiblePasswords[idx] ? "text" : "password"}
                              value={entry.password}
                              readOnly
                              className="bg-gray-50 px-3 py-1 rounded text-sm flex-1"
                            />
                            <button
                              onClick={() => setVisiblePasswords({...visiblePasswords, [idx]: !visiblePasswords[idx]})}
                              className="text-gray-500 hover:text-gray-700"
                            >
                              {visiblePasswords[idx] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                            <button
                              onClick={() => copyToClipboard(entry.password)}
                              className="text-indigo-600 hover:text-indigo-700"
                            >
                              <Copy className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => removeEntry(entry.domain)}
                              className="text-red-600 hover:text-red-700"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}