# Bezpieczny menedzer hasel

Projekt sklada sie z backendu Spring Boot, frontendu React oraz bazy PostgreSQL.

## Uruchomienie przez Docker Compose

1. Skopiuj przykladowy plik zmiennych:

```powershell
Copy-Item .env.example .env
```

2. Otworz `.env` i ustaw wlasne wartosci:

```env
DB_PASSWORD=twoje-haslo-do-bazy

JWT_SECRET=dlugi-losowy-sekret-do-podpisywania-tokenow-jwt-minimum-32-znaki

MAIL_USERNAME=twoj-adres@gmail.com
MAIL_PASSWORD=16-znakowe-haslo-aplikacji-google
```

> Gmail wymaga wlaczonego 2FA oraz wygenerowanego App Password do SMTP.
> Zwykle haslo do konta Google moze zostac zablokowane przez Google.

3. Zbuduj i uruchom caly projekt:

```powershell
docker compose up --build
```

4. Otworz aplikacje:

```text
http://localhost:5173
```

Backend bedzie dostepny pod:

```text
http://localhost:8080
```

## Uruchomienie lokalne bez Dockera

Wymagania:

* JDK 21
* Node.js
* PostgreSQL

Backend:

```powershell
cd backend

$env:DB_PASSWORD="twoje-haslo-do-bazy"
$env:JWT_SECRET="dlugi-losowy-sekret"

$env:MAIL_USERNAME="twoj-adres@gmail.com"
$env:MAIL_PASSWORD="16-znakowe-haslo-aplikacji-google"

.\mvnw.cmd spring-boot:run
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

## Aktualny zakres bezpieczenstwa

* Haslo uzytkownika jest zapisywane jako hash BCrypt, nie jako tekst jawny.
* Po zalogowaniu backend zwraca token JWT podpisany HMAC-SHA256 przez biblioteke Nimbus JOSE + JWT.
* Endpoint `/api/me` wymaga naglowka `Authorization: Bearer <token>`.
* Sekret JWT, haslo bazy oraz dane SMTP nie sa wpisane na stale w kodzie, tylko przekazywane przez zmienne srodowiskowe.
* Backend nie uruchomi sie z sekretem JWT krotszym niz 32 bajty, bo HS256 wymaga odpowiednio dlugiego klucza.
* Dostepne jest odzyskiwanie hasla przez jednorazowy kod OTP wysylany e-mailem.

Sam JWT jest bezpiecznym i standardowym mechanizmem tylko wtedy, gdy jest poprawnie uzyty: musi byc podpisany silnym sekretem, miec krotki czas zycia, byc przesylany przez HTTPS i nie powinien byc przechowywany w miejscu latwym do kradziezy przez XSS.

W tym MVP token jest zapisywany w `localStorage`, co jest proste do pokazania w projekcie, ale w wersji bardziej produkcyjnej lepszym kierunkiem beda ciasteczka `HttpOnly`/`Secure` albo bardzo rygorystyczna ochrona frontendu przed XSS.

Na dalszym etapie trzeba dodac:

* bezpieczne szyfrowanie wpisow menedzera hasel,
* osobny klucz szyfrujacy uzytkownika,
* ograniczanie prob logowania,
* rate limiting dla OTP,
* wygasanie i uniewaznianie kodow resetu,
* lepsza obsluge wygasania tokenow JWT,
* audyt operacji bezpieczenstwa.

## Uwagi

Plik `.env` nie powinien byc commitowany do repozytorium.

Nalezy dodac go do `.gitignore`:

```gitignore
.env
```
