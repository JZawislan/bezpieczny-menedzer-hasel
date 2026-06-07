import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

const API_URL = 'http://localhost:8080/api'
const KDF_ITERATIONS = 210_000
const AUTH_PURPOSE = 'bezpieczny-menedzer:auth'
const VAULT_PURPOSE = 'bezpieczny-menedzer:vault'
const SESSION_STORAGE_KEY = 'bezpieczny-menedzer-session'

type UserRole = 'USER' | 'ADMIN'

type AuthResponse = {
  token: string
  username: string
  role: UserRole
}

type StoredSession = AuthResponse & {
  kdfSalt?: string
  kdfIterations?: number
}

type KdfResponse = {
  username: string
  kdfSalt: string
  kdfIterations: number
}

type VaultEntryResponse = {
  id: number
  label: string
  encryptedPayload: string
  iv: string
  algorithm: string
  kdf: string
  kdfIterations: number
  createdAt: string
  updatedAt: string
}

type DecryptedVaultEntry = VaultEntryResponse & {
  site: string
  login: string
  password: string
  notes: string
  failedToDecrypt?: boolean
}

type AdminUser = {
  id: number
  username: string
  role: UserRole
  vaultEntriesCount: number
}

type VaultForm = {
  label: string
  site: string
  login: string
  password: string
  notes: string
}

const emptyVaultForm: VaultForm = {
  label: '',
  site: '',
  login: '',
  password: '',
  notes: '',
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function readStoredSession() {
  const rawSession = localStorage.getItem(SESSION_STORAGE_KEY)
  if (!rawSession) {
    return null
  }

  try {
    return JSON.parse(rawSession) as StoredSession
  } catch {
    localStorage.removeItem(SESSION_STORAGE_KEY)
    return null
  }
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

function base64ToBytes(value: string) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0))
}

function joinBytes(left: Uint8Array, right: Uint8Array) {
  const result = new Uint8Array(left.length + right.length)
  result.set(left)
  result.set(right, left.length)
  return result
}

async function importMasterPassword(masterPassword: string) {
  return crypto.subtle.importKey('raw', encoder.encode(masterPassword), 'PBKDF2', false, ['deriveBits', 'deriveKey'])
}

async function deriveAuthHash(masterPassword: string, saltBase64: string, iterations: number) {
  const masterKey = await importMasterPassword(masterPassword)
  const salt = joinBytes(base64ToBytes(saltBase64), encoder.encode(AUTH_PURPOSE))
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    masterKey,
    256,
  )
  return bytesToBase64(new Uint8Array(bits))
}

async function deriveVaultKey(masterPassword: string, saltBase64: string, iterations: number) {
  const masterKey = await importMasterPassword(masterPassword)
  const salt = joinBytes(base64ToBytes(saltBase64), encoder.encode(VAULT_PURPOSE))
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptVaultPayload(vaultKey: CryptoKey, payload: Omit<VaultForm, 'label'>) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    vaultKey,
    encoder.encode(JSON.stringify(payload)),
  )

  return {
    encryptedPayload: bytesToBase64(new Uint8Array(encrypted)),
    iv: bytesToBase64(iv),
  }
}

async function decryptVaultPayload(vaultKey: CryptoKey, entry: VaultEntryResponse) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(entry.iv) },
    vaultKey,
    base64ToBytes(entry.encryptedPayload),
  )
  return JSON.parse(decoder.decode(decrypted)) as Omit<VaultForm, 'label'>
}

function App() {
  const [storedSession] = useState<StoredSession | null>(() => readStoredSession())
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [masterPassword, setMasterPassword] = useState('')
  const [showForgotPassword, setShowForgotPassword] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetOtp, setResetOtp] = useState('')
  const [resetOtpVerified, setResetOtpVerified] = useState(false)
  const [resetMasterPassword, setResetMasterPassword] = useState('')
  const [resetMasterPasswordRepeat, setResetMasterPasswordRepeat] = useState('')
  const [token, setToken] = useState(storedSession?.token ?? '')
  const [currentUser, setCurrentUser] = useState(storedSession?.username ?? '')
  const [currentRole, setCurrentRole] = useState<UserRole>(storedSession?.role ?? 'USER')
  const [currentKdfSalt, setCurrentKdfSalt] = useState(storedSession?.kdfSalt ?? '')
  const [currentKdfIterations, setCurrentKdfIterations] = useState(storedSession?.kdfIterations ?? KDF_ITERATIONS)
  const [vaultKey, setVaultKey] = useState<CryptoKey | null>(null)
  const [entries, setEntries] = useState<DecryptedVaultEntry[]>([])
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([])
  const [resetPasswords, setResetPasswords] = useState<Record<number, string>>({})
  const [currentPasswordForChange, setCurrentPasswordForChange] = useState('')
  const [newMasterPassword, setNewMasterPassword] = useState('')
  const [form, setForm] = useState<VaultForm>(emptyVaultForm)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [visiblePasswords, setVisiblePasswords] = useState<Set<number>>(() => new Set())
  const [message, setMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const hasSession = Boolean(token && currentUser)
  const isVaultUnlocked = Boolean(vaultKey)
  const isAdmin = currentRole === 'ADMIN'

  const sortedEntries = useMemo(
    () => [...entries].sort((left, right) => Date.parse(right.updatedAt) - Date.parse(left.updatedAt)),
    [entries],
  )

  useEffect(() => {
    if (!hasSession) {
      return
    }

    if (isAdmin) {
      loadAdminUsers()
    }
  }, [hasSession, isAdmin])

  useEffect(() => {
    if (!hasSession || !isVaultUnlocked) {
      return
    }

    loadVault()
  }, [hasSession, isVaultUnlocked])

  async function requestJson<T>(path: string, init: RequestInit = {}) {
    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    })

    if (!response.ok) {
      throw new Error('Operacja nie powiodla sie.')
    }

    if (response.status === 204) {
      return undefined as T
    }

    return (await response.json()) as T
  }

  async function requestText(path: string, init: RequestInit = {}) {
    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    })

    const text = await response.text()
    if (!response.ok) {
      throw new Error(text || 'Operacja nie powiodla sie.')
    }
    return text
  }

  async function submitAuth(mode: 'login' | 'register') {
    setIsLoading(true)
    setMessage('')

    try {
      const normalizedUsername = username.trim().toLowerCase()
      const normalizedEmail = email.trim().toLowerCase()
      if (normalizedUsername.length < 3) {
        throw new Error('Login musi miec co najmniej 3 znaki.')
      }
      if (mode === 'register' && !normalizedEmail.includes('@')) {
        throw new Error('Podaj poprawny adres e-mail do odzyskiwania hasla.')
      }
      if (masterPassword.length < 8) {
        throw new Error('Haslo glowne musi miec co najmniej 8 znakow.')
      }
      const kdf =
        mode === 'register'
          ? {
              username: normalizedUsername,
              kdfSalt: bytesToBase64(crypto.getRandomValues(new Uint8Array(16))),
              kdfIterations: KDF_ITERATIONS,
            }
          : await requestJson<KdfResponse>(`/auth/kdf/${encodeURIComponent(normalizedUsername)}`, {
              headers: {},
            })

      const authHash = await deriveAuthHash(masterPassword, kdf.kdfSalt, kdf.kdfIterations)
      const response = await fetch(`${API_URL}/auth/${mode}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(
          mode === 'register'
            ? {
                username: normalizedUsername,
                email: normalizedEmail,
                password: authHash,
                kdfSalt: kdf.kdfSalt,
                kdfIterations: kdf.kdfIterations,
              }
            : { username: normalizedUsername, password: authHash },
        ),
      })

      if (!response.ok) {
        throw new Error(mode === 'login' ? 'Nieprawidlowy login lub haslo glowne.' : 'Nie udalo sie utworzyc konta.')
      }

      const data = (await response.json()) as AuthResponse
      const session = {
        ...data,
        kdfSalt: kdf.kdfSalt,
        kdfIterations: kdf.kdfIterations,
      }
      saveSession(session)
      setVaultKey(await deriveVaultKey(masterPassword, kdf.kdfSalt, kdf.kdfIterations))
      setMasterPassword('')
      setEmail('')
      setMessage(
        mode === 'login'
          ? 'Zalogowano i odblokowano sejf.'
          : `Konto utworzone i sejf odblokowany. Rola: ${data.role}.`,
      )
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Wystapil blad.')
    } finally {
      setIsLoading(false)
    }
  }

  async function sendResetOtp(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsLoading(true)
    setMessage('')

    try {
      const normalizedEmail = resetEmail.trim().toLowerCase()
      if (!normalizedEmail.includes('@')) {
        throw new Error('Podaj poprawny adres e-mail.')
      }
      const text = await requestText(`/auth/forgot-password/verifyMail/${encodeURIComponent(normalizedEmail)}`, {
        method: 'POST',
      })
      setResetOtp('')
      setResetOtpVerified(false)
      setMessage(text)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie wyslac maila z kodem.')
    } finally {
      setIsLoading(false)
    }
  }

  async function verifyResetOtp() {
    setIsLoading(true)
    setMessage('')

    try {
      const normalizedEmail = resetEmail.trim().toLowerCase()
      if (!/^\d{6}$/.test(resetOtp.trim())) {
        throw new Error('Kod OTP musi miec 6 cyfr.')
      }
      const text = await requestText(
        `/auth/forgot-password/verifyOtp/${encodeURIComponent(resetOtp.trim())}/${encodeURIComponent(normalizedEmail)}`,
        { method: 'POST' },
      )
      setResetOtpVerified(true)
      setMessage(text)
    } catch (error) {
      setResetOtpVerified(false)
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie zweryfikowac kodu OTP.')
    } finally {
      setIsLoading(false)
    }
  }

  async function finishForgotPassword() {
    setIsLoading(true)
    setMessage('')

    try {
      const normalizedEmail = resetEmail.trim().toLowerCase()
      if (!resetOtpVerified) {
        throw new Error('Najpierw zweryfikuj kod OTP.')
      }
      if (resetMasterPassword.length < 8) {
        throw new Error('Nowe haslo glowne musi miec co najmniej 8 znakow.')
      }
      if (resetMasterPassword !== resetMasterPasswordRepeat) {
        throw new Error('Nowe hasla nie sa takie same.')
      }

      const kdfSalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
      const password = await deriveAuthHash(resetMasterPassword, kdfSalt, KDF_ITERATIONS)
      const text = await requestText(`/auth/forgot-password/changePassword`, {
        method: 'POST',
        body: JSON.stringify({
          email: normalizedEmail,
          otp: parseInt(resetOtp.trim(), 10),
          password,
          repeatPassword: password,
          kdfSalt,
          kdfIterations: KDF_ITERATIONS,
        }),
      })

      setUsername('')
      setResetEmail('')
      setResetOtp('')
      setResetOtpVerified(false)
      setResetMasterPassword('')
      setResetMasterPasswordRepeat('')
      setShowForgotPassword(false)
      setMessage(text)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie zresetowac hasla.')
    } finally {
      setIsLoading(false)
    }
  }

  async function unlockVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsLoading(true)
    setMessage('')

    try {
      if (masterPassword.length < 8) {
        throw new Error('Haslo glowne musi miec co najmniej 8 znakow.')
      }
      const kdf =
        currentKdfSalt && currentKdfIterations
          ? { username: currentUser, kdfSalt: currentKdfSalt, kdfIterations: currentKdfIterations }
          : await requestJson<KdfResponse>(`/auth/kdf/${encodeURIComponent(currentUser)}`, { headers: {} })
      const authHash = await deriveAuthHash(masterPassword, kdf.kdfSalt, kdf.kdfIterations)
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username: currentUser, password: authHash }),
      })

      if (!response.ok) {
        throw new Error('Nieprawidlowe haslo glowne.')
      }

      const data = (await response.json()) as AuthResponse
      saveSession({ ...data, kdfSalt: kdf.kdfSalt, kdfIterations: kdf.kdfIterations })
      setVaultKey(await deriveVaultKey(masterPassword, kdf.kdfSalt, kdf.kdfIterations))
      setMasterPassword('')
      setMessage('Sejf odblokowany.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie odblokowac sejfu.')
    } finally {
      setIsLoading(false)
    }
  }

  function saveSession(session: StoredSession) {
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session))
    setToken(session.token)
    setCurrentUser(session.username)
    setCurrentRole(session.role)
    setCurrentKdfSalt(session.kdfSalt ?? '')
    setCurrentKdfIterations(session.kdfIterations ?? KDF_ITERATIONS)
  }

  async function loadVault() {
    if (!vaultKey) {
      return
    }

    try {
      const encryptedEntries = await requestJson<VaultEntryResponse[]>('/vault')
      const decryptedEntries = await Promise.all(
        encryptedEntries.map(async (entry) => {
          try {
            const payload = await decryptVaultPayload(vaultKey, entry)
            return { ...entry, ...payload }
          } catch {
            return { ...entry, site: '', login: '', password: '', notes: '', failedToDecrypt: true }
          }
        }),
      )
      setEntries(decryptedEntries)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie pobrac sejfu.')
    }
  }

  async function loadAdminUsers() {
    try {
      setAdminUsers(await requestJson<AdminUser[]>('/admin/users'))
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie pobrac listy uzytkownikow.')
    }
  }

  async function deleteUser(user: AdminUser) {
    if (!confirm(`Usunac konto ${user.username}? Tej operacji nie mozna cofnac.`)) {
      return
    }

    setIsLoading(true)
    setMessage('')

    try {
      await requestJson<void>(`/admin/users/${user.id}`, { method: 'DELETE' })
      setAdminUsers((current) => current.filter((item) => item.id !== user.id))
      setMessage(`Konto ${user.username} zostalo usuniete.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie usunac konta.')
    } finally {
      setIsLoading(false)
    }
  }

  async function resetUserPassword(user: AdminUser) {
    const temporaryPassword = resetPasswords[user.id]?.trim() ?? ''
    if (temporaryPassword.length < 8) {
      setMessage('Haslo tymczasowe musi miec co najmniej 8 znakow.')
      return
    }

    if (!confirm(`Zresetowac haslo konta ${user.username}? Sejf tego uzytkownika zostanie wyczyszczony.`)) {
      return
    }

    setIsLoading(true)
    setMessage('')

    try {
      const kdfSalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
      const password = await deriveAuthHash(temporaryPassword, kdfSalt, KDF_ITERATIONS)
      const updatedUser = await requestJson<AdminUser>(`/admin/users/${user.id}/reset-password`, {
        method: 'POST',
        body: JSON.stringify({ password, kdfSalt, kdfIterations: KDF_ITERATIONS }),
      })
      setAdminUsers((current) => current.map((item) => (item.id === user.id ? updatedUser : item)))
      setResetPasswords((current) => ({ ...current, [user.id]: '' }))
      setMessage(`Haslo konta ${user.username} zostalo zresetowane, a sejf wyczyszczony.`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie zresetowac hasla.')
    } finally {
      setIsLoading(false)
    }
  }

  async function changeOwnPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!vaultKey) {
      return
    }
    if (currentPasswordForChange.length < 8 || newMasterPassword.length < 8) {
      setMessage('Obecne i nowe haslo glowne musza miec co najmniej 8 znakow.')
      return
    }
    if (entries.some((entry) => entry.failedToDecrypt)) {
      setMessage('Najpierw odblokuj wszystkie wpisy poprawnym haslem, zeby zmienic haslo glowne.')
      return
    }

    setIsLoading(true)
    setMessage('')

    try {
      const oldKdf =
        currentKdfSalt && currentKdfIterations
          ? { username: currentUser, kdfSalt: currentKdfSalt, kdfIterations: currentKdfIterations }
          : await requestJson<KdfResponse>(`/auth/kdf/${encodeURIComponent(currentUser)}`, { headers: {} })
      const newKdfSalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
      const currentPassword = await deriveAuthHash(currentPasswordForChange, oldKdf.kdfSalt, oldKdf.kdfIterations)
      const newPassword = await deriveAuthHash(newMasterPassword, newKdfSalt, KDF_ITERATIONS)
      const newVaultKey = await deriveVaultKey(newMasterPassword, newKdfSalt, KDF_ITERATIONS)

      const data = await requestJson<AuthResponse>('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          currentPassword,
          newPassword,
          kdfSalt: newKdfSalt,
          kdfIterations: KDF_ITERATIONS,
        }),
      })

      await Promise.all(
        entries.map(async (entry) => {
          const encrypted = await encryptVaultPayload(newVaultKey, {
            site: entry.site,
            login: entry.login,
            password: entry.password,
            notes: entry.notes,
          })
          return requestJson<VaultEntryResponse>(`/vault/${entry.id}`, {
            method: 'PUT',
            body: JSON.stringify({
              label: entry.label,
              ...encrypted,
              algorithm: 'AES-GCM-256',
              kdf: 'PBKDF2-SHA256',
              kdfIterations: KDF_ITERATIONS,
            }),
          })
        }),
      )

      saveSession({ ...data, kdfSalt: newKdfSalt, kdfIterations: KDF_ITERATIONS })
      setVaultKey(newVaultKey)
      setCurrentPasswordForChange('')
      setNewMasterPassword('')
      setMessage('Haslo glowne zostalo zmienione, a wpisy przepisane na nowy klucz.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie zmienic hasla glownego.')
    } finally {
      setIsLoading(false)
    }
  }

  async function saveEntry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!vaultKey) {
      return
    }

    setIsLoading(true)
    setMessage('')

    try {
      const encrypted = await encryptVaultPayload(vaultKey, {
        site: form.site,
        login: form.login,
        password: form.password,
        notes: form.notes,
      })
      const body = {
        label: form.label || form.site || form.login,
        ...encrypted,
        algorithm: 'AES-GCM-256',
        kdf: 'PBKDF2-SHA256',
        kdfIterations: KDF_ITERATIONS,
      }
      const path = editingId ? `/vault/${editingId}` : '/vault'
      await requestJson<VaultEntryResponse>(path, {
        method: editingId ? 'PUT' : 'POST',
        body: JSON.stringify(body),
      })

      setForm(emptyVaultForm)
      setEditingId(null)
      setMessage(editingId ? 'Wpis zaktualizowany.' : 'Wpis zapisany jako szyfrogram.')
      await loadVault()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie zapisac wpisu.')
    } finally {
      setIsLoading(false)
    }
  }

  async function deleteEntry(id: number) {
    setIsLoading(true)
    setMessage('')

    try {
      await requestJson<void>(`/vault/${id}`, { method: 'DELETE' })
      setEntries((current) => current.filter((entry) => entry.id !== id))
      setMessage('Wpis usuniety.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Nie udalo sie usunac wpisu.')
    } finally {
      setIsLoading(false)
    }
  }

  function editEntry(entry: DecryptedVaultEntry) {
    setEditingId(entry.id)
    setForm({
      label: entry.label,
      site: entry.site,
      login: entry.login,
      password: entry.password,
      notes: entry.notes,
    })
  }

  function logout() {
    localStorage.removeItem(SESSION_STORAGE_KEY)
    setToken('')
    setCurrentUser('')
    setCurrentRole('USER')
    setCurrentKdfSalt('')
    setCurrentKdfIterations(KDF_ITERATIONS)
    setVaultKey(null)
    setEntries([])
    setAdminUsers([])
    setResetPasswords({})
    setCurrentPasswordForChange('')
    setNewMasterPassword('')
    setForm(emptyVaultForm)
    setEditingId(null)
    setVisiblePasswords(new Set())
    setMessage('Wylogowano i wyczyszczono klucz z pamieci.')
  }

  function togglePassword(id: number) {
    setVisiblePasswords((current) => {
      const next = new Set(current)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  if (hasSession) {
    return (
      <main className="app-shell vault-shell">
        <section className="manager-panel">
          <header className="manager-header">
            <div>
              <p className="eyebrow">Bezpieczny menedzer hasel</p>
              <h1>Sejf: {currentUser}</h1>
              <p className="muted">
                Backend przechowuje tylko zaszyfrowane wpisy. Odszyfrowanie dzieje sie w React.
                {isAdmin ? ' Masz aktywne uprawnienia administratora.' : ''}
              </p>
            </div>
            <button type="button" className="secondary-button" onClick={logout}>
              Wyloguj
            </button>
          </header>

          {isAdmin && (
            <section className="admin-panel" aria-label="Panel administratora">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Administracja</p>
                  <h2>Konta uzytkownikow</h2>
                </div>
                <button className="secondary-button" disabled={isLoading} onClick={loadAdminUsers} type="button">
                  Odswiez
                </button>
              </div>

              <div className="users-list">
                {adminUsers.map((user) => (
                  <article className="user-row" key={user.id}>
                    <div>
                      <h3>{user.username}</h3>
                      <p className="muted">
                        Rola: {user.role} | wpisy w sejfie: {user.vaultEntriesCount}
                      </p>
                    </div>
                    <label>
                      Haslo tymczasowe
                      <input
                        autoComplete="new-password"
                        disabled={user.username === currentUser}
                        minLength={8}
                        onChange={(event) =>
                          setResetPasswords((current) => ({ ...current, [user.id]: event.target.value }))
                        }
                        placeholder="min. 8 znakow"
                        type="password"
                        value={resetPasswords[user.id] ?? ''}
                      />
                    </label>
                    <div className="user-actions">
                      <button
                        className="secondary-button"
                        disabled={isLoading || user.username === currentUser}
                        onClick={() => resetUserPassword(user)}
                        type="button"
                      >
                        Resetuj haslo
                      </button>
                      <button
                        className="danger-button"
                        disabled={isLoading || user.username === currentUser}
                        onClick={() => deleteUser(user)}
                        type="button"
                      >
                        Usun konto
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          )}

          {!isVaultUnlocked ? (
            <form className="unlock-panel" onSubmit={unlockVault}>
              <div>
                <h2>Odblokuj sejf</h2>
                <p className="muted">Sesja zostala przywrocona. Wpisz haslo glowne, zeby odszyfrowac wpisy.</p>
              </div>
              <label>
                Haslo glowne
                <input
                  autoComplete="current-password"
                  minLength={8}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  required
                  type="password"
                  value={masterPassword}
                />
              </label>
              <button disabled={isLoading} type="submit">
                Odblokuj
              </button>
            </form>
          ) : (
            <>
          <form className="vault-form" onSubmit={saveEntry}>
            <label>
              Nazwa wpisu
              <input
                onChange={(event) => setForm((current) => ({ ...current, label: event.target.value }))}
                placeholder="np. GitHub"
                required
                type="text"
                value={form.label}
              />
            </label>
            <label>
              Strona lub aplikacja
              <input
                onChange={(event) => setForm((current) => ({ ...current, site: event.target.value }))}
                placeholder="https://github.com"
                type="text"
                value={form.site}
              />
            </label>
            <label>
              Login
              <input
                autoComplete="off"
                onChange={(event) => setForm((current) => ({ ...current, login: event.target.value }))}
                required
                type="text"
                value={form.login}
              />
            </label>
            <label>
              Haslo do zapisania
              <input
                autoComplete="new-password"
                onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                required
                type="password"
                value={form.password}
              />
            </label>
            <label className="full-row">
              Notatki
              <textarea
                onChange={(event) => setForm((current) => ({ ...current, notes: event.target.value }))}
                rows={3}
                value={form.notes}
              />
            </label>
            <div className="actions full-row">
              <button disabled={isLoading} type="submit">
                {editingId ? 'Zapisz zmiany' : 'Dodaj wpis'}
              </button>
              {editingId && (
                <button
                  className="secondary-button"
                  disabled={isLoading}
                  onClick={() => {
                    setEditingId(null)
                    setForm(emptyVaultForm)
                  }}
                  type="button"
                >
                  Anuluj edycje
                </button>
              )}
            </div>
          </form>

          <form className="password-reset-panel" onSubmit={changeOwnPassword}>
            <div className="section-heading">
              <div>
                <p className="eyebrow">Konto</p>
                <h2>Reset hasla glownego</h2>
              </div>
            </div>
            <label>
              Obecne haslo glowne
              <input
                autoComplete="current-password"
                minLength={8}
                onChange={(event) => setCurrentPasswordForChange(event.target.value)}
                required
                type="password"
                value={currentPasswordForChange}
              />
            </label>
            <label>
              Nowe haslo glowne
              <input
                autoComplete="new-password"
                minLength={8}
                onChange={(event) => setNewMasterPassword(event.target.value)}
                required
                type="password"
                value={newMasterPassword}
              />
            </label>
            <button disabled={isLoading} type="submit">
              Zmien haslo
            </button>
          </form>

          <section className="entries-list" aria-label="Zapisane hasla">
            {sortedEntries.length === 0 ? (
              <p className="empty-state">Brak wpisow. Dodaj pierwsze haslo, zeby sprawdzic szyfrowany zapis.</p>
            ) : (
              sortedEntries.map((entry) => (
                <article className="entry-card" key={entry.id}>
                  <div>
                    <h2>{entry.label}</h2>
                    <p className="muted">{entry.site || 'Bez adresu strony'}</p>
                  </div>
                  {entry.failedToDecrypt ? (
                    <p className="status">Nie mozna odszyfrowac wpisu tym kluczem.</p>
                  ) : (
                    <dl>
                      <div>
                        <dt>Login</dt>
                        <dd>{entry.login}</dd>
                      </div>
                      <div>
                        <dt>Haslo</dt>
                        <dd>{visiblePasswords.has(entry.id) ? entry.password : '************'}</dd>
                      </div>
                      {entry.notes && (
                        <div>
                          <dt>Notatki</dt>
                          <dd>{entry.notes}</dd>
                        </div>
                      )}
                    </dl>
                  )}
                  <div className="entry-actions">
                    <button className="secondary-button" onClick={() => togglePassword(entry.id)} type="button">
                      {visiblePasswords.has(entry.id) ? 'Ukryj' : 'Pokaz'}
                    </button>
                    <button className="secondary-button" onClick={() => editEntry(entry)} type="button">
                      Edytuj
                    </button>
                    <button className="danger-button" onClick={() => deleteEntry(entry.id)} type="button">
                      Usun
                    </button>
                  </div>
                </article>
              ))
            )}
          </section>
            </>
          )}

          {message && <p className="status">{message}</p>}
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
      <div className="auth-layout">
        <form className="login-panel" onSubmit={(event) => {
          event.preventDefault()
          submitAuth('login')
        }}>
          <div>
            <p className="eyebrow">Bezpieczny menedzer hasel</p>
            <h1>Odblokuj sejf</h1>
            <p className="muted">Haslo glowne zostaje w przegladarce. Backend dostaje tylko hash autoryzacyjny.</p>
          </div>

          <label>
            Login
            <input
              autoComplete="username"
              minLength={3}
              onChange={(event) => setUsername(event.target.value)}
              required
              type="text"
              value={username}
            />
          </label>

          <label>
            E-mail do odzyskiwania
            <input
              autoComplete="email"
              onChange={(event) => setEmail(event.target.value)}
              placeholder="wymagany przy tworzeniu konta"
              type="email"
              value={email}
            />
          </label>

          <label>
            Haslo glowne
            <input
              autoComplete="current-password"
              minLength={8}
              onChange={(event) => setMasterPassword(event.target.value)}
              required
              type="password"
              value={masterPassword}
            />
          </label>

          <div className="actions">
            <button disabled={isLoading} type="submit">
              Zaloguj
            </button>
            <button
              className="secondary-button"
              disabled={isLoading}
              onClick={() => submitAuth('register')}
              type="button"
            >
              Utworz konto
            </button>
          </div>

          <button
            className="link-button"
            disabled={isLoading}
            onClick={() => {
              setShowForgotPassword((current) => !current)
              setMessage('')
            }}
            type="button"
          >
            Nie pamietasz hasla?
          </button>

          {message && <p className="status">{message}</p>}
        </form>

        {showForgotPassword && (
          <form className="login-panel forgot-panel" onSubmit={sendResetOtp}>
            <div>
              <p className="eyebrow">Odzyskiwanie dostepu</p>
              <h2>Reset hasla</h2>
              <p className="muted">
                Po resecie sejf zostanie wyczyszczony, bo starego klucza szyfrujacego nie da sie odzyskac.
              </p>
            </div>

            <label>
              E-mail
              <input
                autoComplete="email"
                onChange={(event) => {
                  setResetEmail(event.target.value)
                  setResetOtpVerified(false)
                }}
                required
                type="email"
                value={resetEmail}
              />
            </label>

            <button disabled={isLoading} type="submit">
              Wyslij kod
            </button>

            <label>
              Kod OTP
              <input
                inputMode="numeric"
                maxLength={6}
                onChange={(event) => {
                  setResetOtp(event.target.value)
                  setResetOtpVerified(false)
                }}
                pattern="[0-9]{6}"
                type="text"
                value={resetOtp}
              />
            </label>

            <button className="secondary-button" disabled={isLoading || resetOtp.length !== 6} onClick={verifyResetOtp} type="button">
              Zweryfikuj kod
            </button>

            <label>
              Nowe haslo glowne
              <input
                autoComplete="new-password"
                minLength={8}
                onChange={(event) => setResetMasterPassword(event.target.value)}
                type="password"
                value={resetMasterPassword}
              />
            </label>

            <label>
              Powtorz nowe haslo
              <input
                autoComplete="new-password"
                minLength={8}
                onChange={(event) => setResetMasterPasswordRepeat(event.target.value)}
                type="password"
                value={resetMasterPasswordRepeat}
              />
            </label>

            <button disabled={isLoading || !resetOtpVerified} onClick={finishForgotPassword} type="button">
              Ustaw nowe haslo
            </button>
          </form>
        )}
      </div>
    </main>
  )
}

export default App
