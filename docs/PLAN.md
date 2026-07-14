---
message: "feat: interop vectors, unverified decode for the frontend, clock skew and key rotation"
tag: "v0.1.0"
---

> Este plan se despacha vía el flujo CodeJob. Ver skill: agents-workflow.
> Lee `AGENTS.md` antes de tocar nada: las invariantes de seguridad de esta librería
> **no son negociables** y varias de las tareas de abajo existen precisamente para
> blindarlas.

# PLAN — `tinywasm/jwt`: cerrar los agujeros e igualar front y back

## Contexto (resumen sin contexto previo)

`github.com/tinywasm/jwt` firma y verifica JWT (HS256) de forma **isomórfica**: el mismo
código corre en el backend nativo y dentro de un binario WASM/edge (navegador,
Cloudflare Workers, `goflare`).

Nació extrayendo `server/jwt.go` de `github.com/tinywasm/user`, para que un consumidor
que solo necesita **verificar** un token no tenga que importar el stack de auth entero
(ORM, bcrypt, OAuth, driver de BD) para hacerlo.

La v0.0.x ya cierra las invariantes de seguridad básicas (secreto vacío, sujeto vacío,
`alg` ignorado, `exp` obligatorio, comparación en tiempo constante) y las cubre con
tests en `tests/`. **Este plan cubre lo que falta**, y falta lo suficiente como para que
la librería aún no sea utilizable desde el frontend.

## El problema, en tres partes

### 1. Nadie ha demostrado que emitamos un JWT de verdad

Los tests actuales solo hacen **round-trip contra nosotros mismos**: firmamos y
verificamos con el mismo código. Eso pasa en verde aunque nuestro base64 o nuestro JSON
estén mal **en ambas direcciones a la vez**. No hay ni un solo vector de respuesta
conocida.

Si nuestro token no es un JWT válido para el resto del mundo, el fallo aparecerá el día
que alguien ponga un proxy, un API gateway o una librería ajena delante — no antes.

### 2. El frontend no puede usar esta librería

Un frontend **no tiene el secreto** (y si lo tuviera, sería el fallo de seguridad, no la
solución). Pero sí necesita leer sus propios claims: saber a qué hora expira la sesión
para renovarla antes, o mostrar el usuario actual sin una llamada al servidor.

Hoy la única puerta de entrada es `Verify`, que exige el secreto. **La librería se
declara isomórfica y la mitad frontend no puede llamarla.**

### 3. El reloj y la rotación de claves

- **Desfase de reloj:** el reloj de un Worker en el edge y el del backend no son el
  mismo. Un token recién emitido puede llegar con `iat` en el futuro, o expirar unos
  segundos antes de tiempo. Sin tolerancia, esto son 401 intermitentes imposibles de
  reproducir.
- **Rotación:** cambiar `JWTSecret` hoy **invalida de golpe todas las sesiones vivas**.
  No hay forma de aceptar el secreto viejo mientras se emite con el nuevo.

## Tareas

### 1. Vectores de interoperabilidad (RFC 7515) — lo más importante

Añade a `tests/` una prueba de **respuesta conocida**, no un round-trip:

- Un token **fijo, escrito a mano en el test** (generado con una implementación ajena:
  `jwt.io`, `golang-jwt`), con su secreto, que **debe verificar**.
- Y a la inversa: un `Sign` nuestro sobre unos claims fijos con un `iat`/`exp` fijos
  debe producir **exactamente** la cadena esperada, byte a byte.

El segundo caso obliga a fijar el orden de los campos en el JSON. Si `tinywasm/json` no
garantiza un orden estable de serialización, **para y repórtalo**: es un defecto aguas
arriba y el arreglo va en el `docs/PLAN.md` de esa librería, nunca parcheado aquí.

Registra ambos en `RunJWTTests` (ver `AGENTS.md`: un `TestXxx` suelto solo corre en
**uno** de los dos entornos).

### 2. `DecodeUnverified` — la mitad frontend

```go
// DecodeUnverified reads the claims WITHOUT checking the signature. The token is
// UNTRUSTED input: treat the result as a display hint, never as an authorization
// decision.
func DecodeUnverified(token string) (Claims, error)
```

El nombre es la mitad del diseño: tiene que ser **imposible de confundir** con `Verify`.
Nada de `Parse`, ni `Read`, ni `Claims()`. Quien escriba `DecodeUnverified` y luego
autorice con el resultado no puede alegar que no lo sabía.

Documenta en el README, con ejemplo, cuál es el reparto:

- **Frontend/edge sin secreto** → `DecodeUnverified`, solo para UI (¿cuándo expiro?).
- **Backend/edge con secreto** → `Verify`, siempre, para cualquier decisión.

Debe seguir rechazando la forma malformada (3 partes, base64 válido, `sub` y `exp`
presentes): que no verifique la firma no significa que se trague cualquier cosa.

### 3. Tolerancia de reloj

```go
// Leeway is the clock skew tolerated when checking exp. Default: 60s.
```

Aplícala **solo a `exp`**, no la conviertas en una ventana de gracia arbitraria. Un test
debe fijar el borde: un token expirado hace `Leeway - 1s` pasa; uno expirado hace
`Leeway + 1s` **no**. Y otro test el caso exacto `now == exp`.

Decide y **justifica en el código** si `Leeway` es una constante o un parámetro. Si es
parámetro, no puede colarse por un `Config` opcional que por defecto valga cero: el
valor cero tiene que ser el seguro y el útil a la vez.

### 4. Rotación de claves sin cerrar sesiones

```go
// VerifyAny tries each secret in order and returns the claims of the first that
// authenticates the token. For rotation: pass the new secret first, the old one second.
func VerifyAny(secrets [][]byte, token string) (Claims, error)
```

Invariantes que el test debe fijar:

- Un `secrets` vacío, o con un secreto vacío dentro, **se rechaza** (`ErrEmptySecret`) —
  la regla del secreto vacío no se relaja por venir en una lista.
- Recorre **todos** los secretos antes de fallar: nada de cortocircuitos que filtren por
  tiempo cuál de ellos era el bueno.
- `ErrTokenExpired` sigue siendo distinguible: si la firma es válida con alguno pero el
  token expiró, el error es *expirado*, no *inválido*.

### 5. `FromBearer` — quitar el parseo duplicado del consumidor

`tinywasm/user` lleva a mano el `fmt.HasPrefix(auth, "Bearer ")`. Ese parseo es del
formato, no de la app:

```go
// FromBearer extracts the token from an Authorization header value.
// Returns ErrInvalidToken if the header is absent or not a Bearer credential.
func FromBearer(authorizationHeader string) (string, error)
```

Insensible a mayúsculas en el esquema (`bearer` es legal según RFC 6750). Cuando esté,
`user` debe **borrar** su copia y llamar a esta.

### 6. Fuzz de `Verify`

Un `FuzzVerify` (nativo, `//go:build !wasm`) que le mete entradas arbitrarias: **nunca**
debe hacer panic, y nunca debe devolver `err == nil`. Es la red que atrapa lo que a los
casos escritos a mano se les escapa (índices, runes, base64 raro).

### 7. TinyGo

`gotest -tinygo` tiene que estar en verde y quedar documentado en el README. Un
`gotest` normal **no lo demuestra**: compila el WASM con el toolchain de Go, que sí
soporta la stdlib entera (ver `AGENTS.md`).

## Fuera de alcance — no lo hagas

- **Más algoritmos** (RS256, ES256, `alg` negociable). HS256-only **es** el modelo de
  seguridad. Añadir negociación de algoritmo reintroduce la clase de vulnerabilidad que
  esta librería cierra por diseño.
- **Refresh tokens, revocación, blacklists.** Necesitan estado; esta librería es pura y
  no tiene BD. Eso es de `tinywasm/user`.
- **`Claims` como bolsa `map[string]any`.** Si hace falta un claim registrado nuevo
  (`nbf`, `aud`, `iss`), se añade como **campo**. Ver `AGENTS.md`.

## Criterios de aceptación

1. `gotest` verde (nativo + wasm) y `gotest -tinygo` verde.
2. Un JWT emitido por una implementación **ajena** verifica con `Verify`, y un `Sign`
   nuestro sobre claims fijos produce la cadena esperada byte a byte.
3. `DecodeUnverified` existe, está documentada como no-autorizante y tiene test.
4. Los tests de borde de `Leeway` y de `VerifyAny` (incluida la lista vacía) pasan.
5. `FuzzVerify` corre 60s sin panic y sin un solo `nil` de error.
6. Todos los tests nuevos están registrados en `RunJWTTests`.
7. Las invariantes de `AGENTS.md` siguen intactas: `RejectsAlgNone`, `RejectsEmptySecret`,
   `RejectsEmptySubject`, `RejectsMissingExp` y `ExpiredIsDistinguishable` **siguen en
   verde sin haber sido modificados**.

## Aguas arriba

Si una tarea destapa un defecto en `tinywasm/json`, `tinywasm/base64`, `tinywasm/crypto`
o `tinywasm/time`: **para y repórtalo en el resumen final.** El arreglo va en el
`docs/PLAN.md` de esa librería. Nunca lo rodees aquí.

## Ciclo de vida de este archivo

No borres ni renombres este archivo: el flujo CodeJob lo gestiona.
