import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

const API_URL = 'http://localhost:8080/api'
const KDF_ITERATIONS = 210_000
const AUTH_PURPOSE = 'bezpieczny-menedzer:auth'
const VAULT_PURPOSE = 'bezpieczny-menedzer:vault'

type AuthResponse = {
  token: string
  username: string
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
  const [username, setUsername] = useState('')
  const [masterPassword, setMasterPassword] = useState('')
  const [token, setToken] = useState('')
  const [currentUser, setCurrentUser] = useState('')
  const [vaultKey, setVaultKey] = useState<CryptoKey | null>(null)
  const [entries, setEntries] = useState<DecryptedVaultEntry[]>([])
  const [form, setForm] = useState<VaultForm>(emptyVaultForm)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [visiblePasswords, setVisiblePasswords] = useState<Set<number>>(() => new Set())
  const [message, setMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const isAuthenticated = Boolean(token && currentUser && vaultKey)

  const sortedEntries = useMemo(
    () => [...entries].sort((left, right) => Date.parse(right.updatedAt) - Date.parse(left.updatedAt)),
    [entries],
  )

  useEffect(() => {
    if (!isAuthenticated) {
      return
    }

    loadVault()
  }, [isAuthenticated])

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

  async function submitAuth(mode: 'login' | 'register') {
    setIsLoading(true)
    setMessage('')

    try {
      const normalizedUsername = username.trim().toLowerCase()
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
      setToken(data.token)
      setCurrentUser(data.username)
      setVaultKey(await deriveVaultKey(masterPassword, kdf.kdfSalt, kdf.kdfIterations))
      setMasterPassword('')
      setMessage(mode === 'login' ? 'Zalogowano i odblokowano sejf.' : 'Konto utworzone i sejf odblokowany.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Wystapil blad.')
    } finally {
      setIsLoading(false)
    }
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
    setToken('')
    setCurrentUser('')
    setVaultKey(null)
    setEntries([])
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

  if (isAuthenticated) {
    return (
      <main className="app-shell vault-shell">
        <section className="manager-panel">
          <header className="manager-header">
            <div>
              <p className="eyebrow">Bezpieczny menedzer hasel</p>
              <h1>Sejf: {currentUser}</h1>
              <p className="muted">Backend przechowuje tylko zaszyfrowane wpisy. Odszyfrowanie dzieje sie w React.</p>
            </div>
            <button type="button" className="secondary-button" onClick={logout}>
              Wyloguj
            </button>
          </header>

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

          {message && <p className="status">{message}</p>}
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
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

        {message && <p className="status">{message}</p>}
      </form>
    </main>
  )
}

export default App
