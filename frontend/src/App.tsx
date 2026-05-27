import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

const API_URL = 'http://localhost:8080/api'

type AuthResponse = {
  token: string
  username: string
}

function App() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(() => localStorage.getItem('jwtToken') ?? '')
  const [currentUser, setCurrentUser] = useState(() => localStorage.getItem('username') ?? '')
  const [message, setMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    if (!token) {
      return
    }

    fetch(`${API_URL}/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error('Sesja wygasla. Zaloguj sie ponownie.')
        }
        return response.json() as Promise<{ username: string }>
      })
      .then((data) => {
        setCurrentUser(data.username)
        localStorage.setItem('username', data.username)
      })
      .catch((error: Error) => {
        setToken('')
        setCurrentUser('')
        localStorage.removeItem('jwtToken')
        localStorage.removeItem('username')
        setMessage(error.message)
      })
  }, [token])

  async function submitAuth(mode: 'login' | 'register') {
    setIsLoading(true)
    setMessage('')

    try {
      const response = await fetch(`${API_URL}/auth/${mode}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      })

      if (!response.ok) {
        throw new Error(mode === 'login' ? 'Nieprawidlowy login lub haslo.' : 'Nie udalo sie utworzyc konta.')
      }

      const data = (await response.json()) as AuthResponse
      setToken(data.token)
      setCurrentUser(data.username)
      localStorage.setItem('jwtToken', data.token)
      localStorage.setItem('username', data.username)
      setPassword('')
      setMessage(mode === 'login' ? 'Zalogowano.' : 'Konto utworzone i zalogowane.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Wystapil blad.')
    } finally {
      setIsLoading(false)
    }
  }

  function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    submitAuth('login')
  }

  function logout() {
    setToken('')
    setCurrentUser('')
    localStorage.removeItem('jwtToken')
    localStorage.removeItem('username')
    setMessage('Wylogowano.')
  }

  if (token && currentUser) {
    return (
      <main className="app-shell">
        <section className="manager-panel">
          <div>
            <p className="eyebrow">Bezpieczny menedzer hasel</p>
            <h1>Witaj, {currentUser}</h1>
            <p className="muted">
              Logowanie JWT dziala. To jest miejsce, w ktorym dodamy liste zapisanych hasel.
            </p>
          </div>
          <button type="button" className="secondary-button" onClick={logout}>
            Wyloguj
          </button>
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
      <form className="login-panel" onSubmit={handleLogin}>
        <div>
          <p className="eyebrow">Bezpieczny menedzer hasel</p>
          <h1>Logowanie</h1>
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
          Haslo
          <input
            autoComplete="current-password"
            minLength={8}
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
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
