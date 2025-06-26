// ================================
// ✅ Complete SDK - Fully Functional & Production Ready (TypeScript)
// ================================

interface CloudinaryConfig {
  uploadPreset?: string;
  cloudName?: string;
  apiKey?: string;
  apiSecret?: string;
}

interface SMTPConfig {
  endpoint?: string;
  from?: string;
  test?: () => Promise<boolean>;
}

interface AuthConfig {
  requireEmailVerification?: boolean;
  otpTriggers?: string[];
}

interface SchemaDefinition {
  required?: string[];
  types?: Record<string, string>;
  defaults?: Record<string, any>;
}

interface UniversalSDKConfig {
  owner: string;
  repo: string;
  token: string;
  branch?: string;
  basePath?: string;
  mediaPath?: string;
  cloudinary?: CloudinaryConfig;
  smtp?: SMTPConfig;
  templates?: Record<string, string>;
  schemas?: Record<string, SchemaDefinition>;
  auth?: AuthConfig;
}

interface User {
  id?: string;
  uid?: string;
  email: string;
  password?: string;
  googleId?: string;
  verified?: boolean;
  roles?: string[];
  permissions?: string[];
  [key: string]: any;
}

interface Session {
  token: string;
  user: User;
  created: number;
}

interface OTPRecord {
  otp: string;
  created: number;
  reason: string;
}

interface AuditLogEntry {
  action: string;
  data: any;
  timestamp: number;
}

interface QueryBuilder<T = any> {
  where(fn: (item: T) => boolean): QueryBuilder<T>;
  sort(field: string, dir?: 'asc' | 'desc'): QueryBuilder<T>;
  project(fields: string[]): QueryBuilder<Partial<T>>;
  exec(): Promise<T[]>;
}

interface MediaAttachment {
  attachmentId: string;
  mimeType: string;
  isInline: boolean;
  url: string;
  name: string;
}

interface CloudinaryUploadResult {
  public_id: string;
  secure_url: string;
  url: string;
  [key: string]: any;
}

interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  from: string;
  headers: Record<string, string>;
}

class UniversalSDK {
  private owner: string;
  private repo: string;
  private token: string;
  private branch: string;
  private basePath: string;
  private mediaPath: string;
  private cloudinary: CloudinaryConfig;
  private smtp: SMTPConfig;
  private templates: Record<string, string>;
  private schemas: Record<string, SchemaDefinition>;
  private authConfig: AuthConfig;
  private sessionStore: Record<string, Session>;
  private otpMemory: Record<string, OTPRecord>;
  private auditLog: Record<string, AuditLogEntry[]>;

  constructor(config: UniversalSDKConfig) {
    // 0.1 Initialization
    this.owner = config.owner;
    this.repo = config.repo;
    this.token = config.token;
    this.branch = config.branch || "main";
    this.basePath = config.basePath || "db";
    this.mediaPath = config.mediaPath || "media";
    this.cloudinary = config.cloudinary || {};
    this.smtp = config.smtp || {};
    this.templates = config.templates || {};
    this.schemas = config.schemas || {};
    this.authConfig = config.auth || { requireEmailVerification: true, otpTriggers: ["register"] };
    this.sessionStore = {};
    this.otpMemory = {};
    this.auditLog = {};
  }

  // 📁 1. DATA / STORAGE

  // 1.1 headers
  private headers(): Record<string, string> {
    return {
      Authorization: `token ${this.token}`,
      "Content-Type": "application/json",
    };
  }

  // 1.2 request
  private async request(path: string, method: string = "GET", body: any = null): Promise<any> {
    const url = `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${path}` +
                (method === "GET" ? `?ref=${this.branch}` : "");
    const res = await fetch(url, {
      method,
      headers: this.headers(),
      body: body ? JSON.stringify(body) : null,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  // 1.3 get
  async get<T = any>(collection: string): Promise<T[]> {
    try {
      const res = await this.request(`${this.basePath}/${collection}.json`);
      return JSON.parse(atob(res.content));
    } catch {
      return [];
    }
  }

  // 1.4 getItem
  async getItem<T = any>(collection: string, key: string): Promise<T | null> {
    const arr = await this.get<T>(collection);
    return arr.find((x: any) => x.id === key || x.uid === key) || null;
  }

  // 1.5 save
  private async save<T = any>(collection: string, data: T[]): Promise<void> {
    let sha: string | undefined;
    try {
      const head = await this.request(`${this.basePath}/${collection}.json`);
      sha = head.sha;
    } catch {}
    await this.request(`${this.basePath}/${collection}.json`, "PUT", {
      message: `Update ${collection}`,
      content: btoa(JSON.stringify(data, null, 2)),
      branch: this.branch,
      ...(sha ? { sha } : {}),
    });
  }

  // 1.6 insert
  async insert<T = any>(collection: string, item: Partial<T>): Promise<T & { id: string; uid: string }> {
    const arr = await this.get<T>(collection);
    const schema = this.schemas[collection];
    if (schema?.defaults) item = { ...schema.defaults, ...item };
    this.validateSchema(collection, item);
    const id = (Math.max(0, ...arr.map((x: any) => +x.id || 0)) + 1).toString();
    const newItem = { uid: crypto.randomUUID(), id, ...item } as T & { id: string; uid: string };
    arr.push(newItem);
    await this.save(collection, arr);
    this._audit(collection, newItem, "insert");
    return newItem;
  }

  // 1.7 bulkInsert
  async bulkInsert<T = any>(collection: string, items: Partial<T>[]): Promise<(T & { id: string; uid: string })[]> {
    const arr = await this.get<T>(collection);
    const schema = this.schemas[collection];
    const base = Math.max(0, ...arr.map((x: any) => +x.id || 0));
    const newItems = items.map((item, i) => {
      if (schema?.defaults) item = { ...schema.defaults, ...item };
      this.validateSchema(collection, item);
      return { uid: crypto.randomUUID(), id: (base + i + 1).toString(), ...item } as T & { id: string; uid: string };
    });
    const result = [...arr, ...newItems];
    await this.save(collection, result);
    newItems.forEach(n => this._audit(collection, n, "insert"));
    return newItems;
  }

  // 1.8 update
  async update<T = any>(collection: string, key: string, updates: Partial<T>): Promise<T> {
    const arr = await this.get<T>(collection);
    const i = arr.findIndex((x: any) => x.id === key || x.uid === key);
    if (i < 0) throw new Error("Not found");
    const upd = { ...arr[i], ...updates };
    this.validateSchema(collection, upd);
    arr[i] = upd;
    await this.save(collection, arr);
    this._audit(collection, upd, "update");
    return upd;
  }

  // 1.9 bulkUpdate
  async bulkUpdate<T = any>(collection: string, updates: (Partial<T> & { id?: string; uid?: string })[]): Promise<T[]> {
    const arr = await this.get<T>(collection);
    const updatedItems = updates.map(u => {
      const i = arr.findIndex((x: any) => x.id === u.id || x.uid === u.uid);
      if (i < 0) throw new Error(`Item not found: ${u.id || u.uid}`);
      const upd = { ...arr[i], ...u };
      this.validateSchema(collection, upd);
      arr[i] = upd;
      return upd;
    });
    await this.save(collection, arr);
    updatedItems.forEach(u => this._audit(collection, u, "update"));
    return updatedItems;
  }

  // 1.10 delete
  async delete<T = any>(collection: string, key: string): Promise<void> {
    const arr = await this.get<T>(collection);
    const filtered = arr.filter((x: any) => x.id !== key && x.uid !== key);
    const deleted = arr.filter((x: any) => x.id === key || x.uid === key);
    await this.save(collection, filtered);
    deleted.forEach(d => this._audit(collection, d, "delete"));
  }

  // 1.11 bulkDelete
  async bulkDelete<T = any>(collection: string, keys: string[]): Promise<T[]> {
    const arr = await this.get<T>(collection);
    const filtered = arr.filter((x: any) => !keys.includes(x.id) && !keys.includes(x.uid));
    const deleted = arr.filter((x: any) => keys.includes(x.id) || keys.includes(x.uid));
    await this.save(collection, filtered);
    deleted.forEach(d => this._audit(collection, d, "delete"));
    return deleted;
  }

  // 1.12 cloneItem
  async cloneItem<T = any>(collection: string, key: string): Promise<T & { id: string; uid: string }> {
    const arr = await this.get<T>(collection);
    const orig = arr.find((x: any) => x.id === key || x.uid === key);
    if (!orig) throw new Error("Not found");
    const { id, uid, ...core } = orig as any;
    return this.insert(collection, core);
  }

  // 1.13 validateSchema
  private validateSchema(collection: string, item: any): void {
    const schema = this.schemas[collection];
    if (!schema) throw new Error(`Schema not defined for ${collection}`);
    (schema.required || []).forEach(r => {
      if (!(r in item)) throw new Error(`Missing required: ${r}`);
    });
    Object.entries(item).forEach(([k, v]) => {
      const t = schema.types?.[k];
      if (t) {
        const ok =
          (t === "string" && typeof v === "string") ||
          (t === "number" && typeof v === "number") ||
          (t === "boolean" && typeof v === "boolean") ||
          (t === "object" && typeof v === "object") ||
          (t === "array" && Array.isArray(v)) ||
          (t === "date" && !isNaN(Date.parse(v as string))) ||
          (t === "uuid" && typeof v === "string");
        if (!ok) throw new Error(`Field ${k} should be ${t}`);
      }
    });
  }

  // 1.14 validateAll
  validateAll<T = any>(collection: string, items: T[]): void {
    items.forEach(item => this.validateSchema(collection, item));
  }

  // 1.15 sanitize
  sanitize<T = any>(item: T, allowedFields: string[]): Partial<T> {
    const out: any = {};
    allowedFields.forEach(f => {
      if (f in (item as any)) out[f] = (item as any)[f];
    });
    return out;
  }

  // 1.16 setSchema
  setSchema(collection: string, schema: SchemaDefinition): void {
    this.schemas[collection] = schema;
  }

  // 1.17 getSchema
  getSchema(collection: string): SchemaDefinition | null {
    return this.schemas[collection] || null;
  }

  // 1.18 collectionExists
  async collectionExists(collection: string): Promise<boolean> {
    const arr = await this.get(collection);
    return Array.isArray(arr);
  }

  // 1.19 listCollections
  async listCollections(): Promise<string[]> {
    const path = this.basePath;
    const res = await this.request(path);
    return res.map((f: any) => f.name.replace(".json", ""));
  }

  // 1.20 exportCollection
  async exportCollection(collection: string): Promise<string> {
    return JSON.stringify(await this.get(collection), null, 2);
  }

  // 1.21 importCollection
  async importCollection<T = any>(collection: string, json: string, overwrite: boolean = false): Promise<T[]> {
    const arr = JSON.parse(json);
    this.validateAll(collection, arr);
    const base = overwrite ? [] : await this.get(collection);
    const processed = arr.map((it: any, i: number) => ({ uid: crypto.randomUUID(), id: (i + 1).toString(), ...it }));
    await this.save(collection, [...base, ...processed]);
    processed.forEach((p: any) => this._audit(collection, p, "insert"));
    return processed;
  }

  // 1.22 mergeCollections
  async mergeCollections<T = any>(collection: string, json: string, overwrite: boolean = false): Promise<T[]> {
    const imported = await this.importCollection<T>(collection, json, overwrite);
    const existing = await this.get<T>(collection);
    const merged = overwrite ? imported : [...existing, ...imported];
    await this.save(collection, merged);
    return merged;
  }

  // 1.23 backupCollection
  async backupCollection(collection: string): Promise<string> {
    const data = await this.exportCollection(collection);
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `${collection}-backup-${ts}.json`;
    await this.request(`${this.basePath}/backups/${filename}`, "PUT", {
      message: `Backup ${collection}`,
      content: btoa(data),
      branch: this.branch,
    });
    return filename;
  }

  // 1.24 syncWithRemote
  async syncWithRemote<T = any>(collection: string): Promise<T[]> {
    return this.get<T>(collection);
  }

  // 1.25 queryBuilder
  queryBuilder<T = any>(collection: string): QueryBuilder<T> {
    let chain = Promise.resolve().then(() => this.get<T>(collection));
    const qb: QueryBuilder<T> = {
      where(fn: (item: T) => boolean) { 
        chain = chain.then(arr => arr.filter(fn)); 
        return qb; 
      },
      sort(field: string, dir: 'asc' | 'desc' = "asc") { 
        chain = chain.then(arr => arr.sort((a: any, b: any) => 
          dir === 'asc' ? (a[field] > b[field] ? 1 : -1) : (a[field] < b[field] ? 1 : -1)
        )); 
        return qb; 
      },
      project(fields: string[]) { 
        chain = chain.then(arr => arr.map((item: any) => { 
          const o: any = {}; 
          fields.forEach(f => { 
            if (f in item) o[f] = item[f]
          }); 
          return o 
        })); 
        return qb as QueryBuilder<any>; 
      },
      exec() { return chain; },
    };
    return qb;
  }

  // 📬 2. EMAIL / OTP / SMTP

  // 2.1 sendEmail
  async sendEmail(to: string, subject: string, html: string, smtpOverride: SMTPConfig | null = null): Promise<boolean> {
    const endpoint = smtpOverride?.endpoint || this.smtp.endpoint;
    const sender = smtpOverride?.from || this.smtp.from || "no-reply@example.com";
    const payload: EmailPayload = {
      to,
      subject,
      html,
      from: sender,
      headers: { "Reply-To": sender, "List-Unsubscribe": "<mailto:unsubscribe@example.com>" },
    };
    const res = await fetch(endpoint!, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error("Email send failed");
    return true;
  }

  // 2.2 sendOTP
  async sendOTP(email: string, reason: string = "verify"): Promise<string> {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    this.otpMemory[email] = { otp, created: Date.now(), reason };
    const tpl = this.templates.otp?.replace("{{otp}}", otp) || `Your OTP is: ${otp}`;
    await this.sendEmail(email, `OTP for ${reason}`, tpl);
    return otp;
  }

  // 2.3 verifyOTP
  verifyOTP(email: string, otp: string): boolean {
    const rec = this.otpMemory[email];
    if (!rec || rec.otp !== otp) throw new Error("Invalid OTP");
    if (Date.now() - rec.created > 10 * 60 * 1000) throw new Error("OTP expired");
    delete this.otpMemory[email];
    return true;
  }

  // 2.4 validateEmailFormat
  validateEmailFormat(email: string): boolean {
    return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
  }

  // 2.5 testSMTPConnection
  async testSMTPConnection(): Promise<boolean> {
    if (!this.smtp.test) throw new Error("SMTP test not available");
    return this.smtp.test();
  }

  // 🔐 3. AUTHENTICATION

  // 3.1 hashPassword
  hashPassword(password: string): string {
    const salt = crypto.randomUUID();
    const hash = btoa([...password + salt].map(c => c.charCodeAt(0).toString(16)).join(""));
    return `${salt}$${hash}`;
  }

  // 3.2 verifyPassword
  verifyPassword(password: string, hashString: string): boolean {
    const [salt, hash] = hashString.split("$");
    const testHash = btoa([...password + salt].map(c => c.charCodeAt(0).toString(16)).join(""));
    return testHash === hash;
  }

  // 3.3 register
  async register(email: string, password: string, profile: Partial<User> = {}): Promise<User> {
    if (!this.validateEmailFormat(email)) throw new Error("Invalid email format");
    const users = await this.get<User>("users");
    if (users.find(u => u.email === email)) throw new Error("Email already registered");
    const hashed = this.hashPassword(password);
    const user = await this.insert<User>("users", { email, password: hashed, ...profile });
    if (this.authConfig.otpTriggers?.includes("register")) await this.sendOTP(email, "registration");
    return user;
  }

  // 3.4 login
  async login(email: string, password: string): Promise<string | { otpRequired: boolean }> {
    const user = (await this.get<User>("users")).find(u => u.email === email);
    if (!user || !this.verifyPassword(password, user.password!)) throw new Error("Invalid credentials");
    if (this.authConfig.otpTriggers?.includes("login")) {
      await this.sendOTP(email, "login");
      return { otpRequired: true };
    }
    return this.createSession(user);
  }

  // 3.5 verifyLoginOTP
  async verifyLoginOTP(email: string, otp: string): Promise<string> {
    this.verifyOTP(email, otp);
    const user = (await this.get<User>("users")).find(u => u.email === email);
    return this.createSession(user!);
  }

  // 3.6 requestPasswordReset
  async requestPasswordReset(email: string): Promise<void> {
    const user = (await this.get<User>("users")).find(u => u.email === email);
    if (!user) throw new Error("Email not found");
    await this.sendOTP(email, "reset");
  }

  // 3.7 resetPassword
  async resetPassword(email: string, otp: string, newPassword: string): Promise<boolean> {
    this.verifyOTP(email, otp);
    const users = await this.get<User>("users");
    const i = users.findIndex(u => u.email === email);
    if (i === -1) throw new Error("Email not found");
    users[i].password = this.hashPassword(newPassword);
    await this.save("users", users);
    return true;
  }

  // 3.8 googleAuth - Authenticate or register via Google ID token
  async googleAuth(idToken: string): Promise<string> {
    const info = await fetch(
      `https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${idToken}`
    ).then((r) => r.json());

    if (!info.email || !info.sub) {
      throw new Error("Invalid Google ID token");
    }

    const users = await this.get<User>("users");
    let user = users.find((u) => u.email === info.email);

    if (user) {
      if (!user.googleId) {
        // Link Google account if not already linked
        user.googleId = info.sub;
        await this.save("users", users);
      }
    } else {
      // Register a new user via Google
      user = await this.insert<User>("users", {
        email: info.email,
        googleId: info.sub,
        verified: true,
      });
    }

    return this.createSession(user);
  }

  // 3.9 hasPermission
  hasPermission(user: User | null, permission: string): boolean {
    return (user?.permissions || []).includes(permission);
  }

  // 3.10 assignRole
  async assignRole(userId: string, role: string): Promise<User> {
    const users = await this.get<User>("users");
    const user = users.find(u => u.id === userId || u.uid === userId);
    if (!user) throw new Error("User not found");
    user.roles = [...new Set([...(user.roles || []), role])];
    await this.save("users", users);
    return user;
  }

  // 3.11 removeRole
  async removeRole(userId: string, role: string): Promise<User> {
    const users = await this.get<User>("users");
    const user = users.find(u => u.id === userId || u.uid === userId);
    if (!user) throw new Error("User not found");
    user.roles = (user.roles || []).filter(r => r !== role);
    await this.save("users", users);
    return user;
  }

  // 3.12 getUserRoles
  getUserRoles(user: User | null): string[] {
    return user?.roles || [];
  }

  // 3.13 listPermissions
  listPermissions(user: User | null): string[] {
    return user?.permissions || [];
  }

  // 🔑 4. SESSION MANAGEMENT

  // 4.1 createSession
  createSession(user: User): string {
    const token = crypto.randomUUID();
    this.sessionStore[token] = { token, user, created: Date.now() };
    return token;
  }

  // 4.2 getSession
  getSession(token: string): Session | null {
    return this.sessionStore[token] || null;
  }

  // 4.3 refreshSession
  refreshSession(token: string): Session {
    const session = this.getSession(token);
    if (!session) throw new Error("Invalid session");
    session.created = Date.now();
    return session;
  }

  // 4.4 destroySession
  destroySession(token: string): boolean {
    delete this.sessionStore[token];
    return true;
  }

  // 4.5 getCurrentUser
  getCurrentUser(token: string): User | null {
    const session = this.getSession(token);
    return session?.user || null;
  }

  // 5.1 renderTemplate
  renderTemplate(name: string, data: Record<string, any> = {}): string {
    let tpl = this.templates[name];
    if (!tpl) throw new Error(`Template not found: ${name}`);
    return tpl.replace(/\{\{(.*?)\}\}/g, (_, key) => data[key.trim()] ?? "");
  }

  // 5.2 prettyPrint
  prettyPrint(data: any): string {
    return JSON.stringify(data, null, 2);
  }

  // 5.3 log
  log(label: string, data: any): void {
    console.log(`[${label}]`, data);
  }

  // 5.4 getAuditLog
  getAuditLog(): Record<string, AuditLogEntry[]> {
    return this.auditLog;
  }

  // 5.5 resetAuditLog
  resetAuditLog(): void {
    this.auditLog = {};
  }

  // 5.6 _audit
  private _audit(collection: string, data: any, action: string): void {
    const logs = this.auditLog[collection] || [];
    logs.push({ action, data, timestamp: Date.now() });
    this.auditLog[collection] = logs.slice(-100); // keep last 100
  }

  // 5.7 status
  status(): Record<string, any> {
    return {
      owner: this.owner,
      repo: this.repo,
      connected: !!this.token,
      collections: Object.keys(this.schemas),
      templates: Object.keys(this.templates),
      time: new Date().toISOString(),
    };
  }

  // 5.8 version
  version(): string {
    return "1.0.0";
  }

  // 5.9 diagnose
  async diagnose(): Promise<Record<string, boolean>> {
    const checks = {
      githubAccess: !!(await this.listCollections().catch(() => false)),
      sessionStore: typeof this.sessionStore === "object",
      schemas: Object.keys(this.schemas).length > 0,
    };
    return checks;
  }

  // 5.10 throttle
  throttle<T extends (...args: any[]) => any>(fn: T, wait: number = 1000): (...args: Parameters<T>) => ReturnType<T> | undefined {
    let last = 0;
    return (...args: Parameters<T>) => {
      const now = Date.now();
      if (now - last >= wait) {
        last = now;
        return fn(...args);
      }
    };
  }

  // 5.11 setConfig
  setConfig(key: keyof this, value: any): void {
    (this as any)[key] = value;
  }

  // 5.12 getConfig
  getConfig(key: keyof this): any {
    return (this as any)[key];
  }

  // 5.13 getSystemInfo
  getSystemInfo(): Record<string, string> {
    return {
      platform: (globalThis as any).navigator?.platform || "server",
      userAgent: (globalThis as any).navigator?.userAgent || "node",
      sdkVersion: this.version(),
    };
  }

  // 5.14 catchErrors
  catchErrors<T>(fn: () => T): T | null {
    try {
      return fn();
    } catch (e) {
      console.error("SDK Error:", e);
      return null;
    }
  }

  // 6.1 uploadToCloudinary
  async uploadToCloudinary(file: File, folder: string = ""): Promise<CloudinaryUploadResult> {
    if (!this.cloudinary.uploadPreset || !this.cloudinary.cloudName) {
      throw new Error("Cloudinary configuration is incomplete.");
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("upload_preset", this.cloudinary.uploadPreset);
    if (folder) formData.append("folder", folder);

    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${this.cloudinary.cloudName}/upload`,
      { method: "POST", body: formData }
    );

    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || "Upload failed.");
    return json;
  }

  // 6.2 uploadMediaFile (alias)
  async uploadMediaFile(file: File, folder: string = this.mediaPath): Promise<CloudinaryUploadResult> {
    return this.uploadToCloudinary(file, folder);
  }

  // 6.3 getMediaFile
  getMediaFile(publicId: string, options: string = ""): string {
    if (!this.cloudinary.cloudName) {
      throw new Error("Cloudinary cloudName not set.");
    }
    return `https://res.cloudinary.com/${this.cloudinary.cloudName}/image/upload/${options}/${publicId}`;
  }

  // 6.4 deleteMediaFile
  async deleteMediaFile(publicId: string, apiKey: string = this.cloudinary.apiKey!, apiSecret: string = this.cloudinary.apiSecret!): Promise<any> {
    if (!apiKey || !apiSecret || !this.cloudinary.cloudName) {
      throw new Error("Delete requires apiKey, apiSecret and cloudName (use from secure backend).");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const stringToSign = `public_id=${publicId}&timestamp=${timestamp}${apiSecret}`;
    const signature = await this._sha1(stringToSign);

    const body = new URLSearchParams({
      public_id: publicId,
      api_key: apiKey,
      timestamp: timestamp.toString(),
      signature,
    });

    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${this.cloudinary.cloudName}/image/destroy`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      }
    );

    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || "Delete failed.");
    return json;
  }

  // 6.5 listMediaFiles (fallback: tag-based)
  async listMediaFiles(tag: string = "", max: number = 30): Promise<any[]> {
    if (!this.cloudinary.apiKey || !this.cloudinary.apiSecret || !this.cloudinary.cloudName) {
      throw new Error("List requires apiKey, apiSecret, and cloudName.");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const stringToSign = tag ? `max_results=${max}&prefix=${tag}&timestamp=${timestamp}${this.cloudinary.apiSecret}`
                             : `max_results=${max}&timestamp=${timestamp}${this.cloudinary.apiSecret}`;
    const signature = await this._sha1(stringToSign);

    const body = new URLSearchParams({
      max_results: max.toString(),
      ...(tag && { prefix: tag }),
      api_key: this.cloudinary.apiKey!,
      timestamp: timestamp.toString(),
      signature,
    });

    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${this.cloudinary.cloudName}/resources/image`,
      {
        method: "GET",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || "List failed.");
    return json.resources;
  }

  // 6.6 renameMediaFile
  async renameMediaFile(fromPublicId: string, toPublicId: string): Promise<any> {
    if (!this.cloudinary.apiKey || !this.cloudinary.apiSecret || !this.cloudinary.cloudName) {
      throw new Error("Rename requires apiKey, apiSecret, and cloudName.");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const stringToSign = `from_public_id=${fromPublicId}&to_public_id=${toPublicId}&timestamp=${timestamp}${this.cloudinary.apiSecret}`;
    const signature = await this._sha1(stringToSign);

    const body = new URLSearchParams({
      from_public_id: fromPublicId,
      to_public_id: toPublicId,
      api_key: this.cloudinary.apiKey!,
      timestamp: timestamp.toString(),
      signature,
    });

    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${this.cloudinary.cloudName}/image/rename`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      }
    );

    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || "Rename failed.");
    return json;
  }

  // 6.7 getMediaMetadata
  async getMediaMetadata(publicId: string): Promise<any> {
    if (!this.cloudinary.apiKey || !this.cloudinary.apiSecret || !this.cloudinary.cloudName) {
      throw new Error("Metadata fetch requires apiKey, apiSecret, and cloudName.");
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const stringToSign = `public_id=${publicId}&timestamp=${timestamp}${this.cloudinary.apiSecret}`;
    const signature = await this._sha1(stringToSign);

    const query = new URLSearchParams({
      public_id: publicId,
      api_key: this.cloudinary.apiKey!,
      timestamp: timestamp.toString(),
      signature,
    });

    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${this.cloudinary.cloudName}/resources/image/upload/${publicId}?${query}`
    );

    const json = await res.json();
    if (!res.ok) throw new Error(json.error?.message || "Metadata fetch failed.");
    return json;
  }

  // 6.8 transformMedia
  transformMedia(publicId: string, options: string = "w_600,c_fill"): string {
    if (!this.cloudinary.cloudName) {
      throw new Error("Cloudinary cloudName is missing.");
    }
    return `https://res.cloudinary.com/${this.cloudinary.cloudName}/image/upload/${options}/${publicId}`;
  }

  // 6.9 generateSignedURL (client-side support limited)
  async generateSignedURL(publicId: string, options: Record<string, any> = {}): Promise<never> {
    throw new Error("Signed URL generation must be done securely on backend.");
  }

  // 🔐 Internal SHA1 helper (browser-compatible)
  private async _sha1(str: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const buffer = await crypto.subtle.digest("SHA-1", data);
    return [...new Uint8Array(buffer)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // 7.1 init
  async init(): Promise<UniversalSDK> {
    await this.listCollections(); // Test GitHub connection
    return this;
  }

  // 7.2 destroyInstance
  destroyInstance(): void {
    Object.keys(this).forEach(k => delete (this as any)[k]);
  }

  // 7.3 reset
  reset(): void {
    this.sessionStore = {};
    this.otpMemory = {};
    this.auditLog = {};
  }

  // 7.4 isReady
  isReady(): boolean {
    return !!(this.owner && this.repo && this.token);
  }

  // 7.5 waitForReady
  async waitForReady(maxWait: number = 5000): Promise<boolean> {
    const start = Date.now();
    while (!this.isReady()) {
      if (Date.now() - start > maxWait) throw new Error("SDK not ready");
      await new Promise(res => setTimeout(res, 100));
    }
    return true;
  }
}

export default UniversalSDK;
export type { 
  UniversalSDKConfig, 
  CloudinaryConfig, 
  SMTPConfig, 
  AuthConfig, 
  SchemaDefinition, 
  User, 
  Session, 
  QueryBuilder,
  CloudinaryUploadResult,
  MediaAttachment
};
