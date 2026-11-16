# Tuta Bridge — design del primo blocco (M0–M2)

Data: 15 novembre 2026
Stato: proposta, in attesa di approvazione
Riferimento: `tuta-bridge-spec.md` (specifica principale, commit Tuta `5dba964`)

## 1. Intento

Costruire le fondamenta del bridge e arrivare a un comando che, dato un account
Tuta, produca file `.eml` apribili da un client di posta. Nessun server IMAP o
SMTP in questo blocco: quelli sono M5–M7. Il risultato di M0–M2 deve dimostrare
che login, lettura delle mail, corpo e allegati funzionano davvero, prima di
investire su store, eventi e protocolli.

## 2. Perché un blocco separato

La specifica principale è una roadmap lunga. Questo documento restringe
l'ambito a tre milestone con criteri di accettazione verificabili:

- **M0 — setup e verifiche.** Progetto compilabile, dipendenza dall'SDK
  risolta, risposte ai punti aperti documentate in `NOTES.md`.
- **M1 — login da CLI.** `login`, `logout`, `status` con credenziali nel
  Secret Service e TOTP.
- **M2 — lettura da CLI.** `dump` di messaggi completi di corpo e allegati.

## 3. Obiettivi e non-obiettivi

### Obiettivi

- Un binario `tuta-bridge` eseguibile su Linux.
- Login interattivo con password Tuta e codice TOTP, senza che le credenziali
  passino mai da argv, variabili d'ambiente, file di configurazione o log.
- Credenziali SDK salvate solo nel Secret Service di sistema.
- Elenco cartelle e mail con paginazione.
- Caricamento di `MailDetails`, corpo (testo o HTML) e allegati.
- Generazione di MIME stabile e apribile da Thunderbird.
- Test unitari eseguibili offline; test reali solo manuali e su richiesta
  dell'utente.

### Non-obiettivi

- IMAP, SMTP, IDLE, SQLite, event bus, cache offline, invio.
- Più account, calendario, contatti, Tuta Drive.
- Distribuzione del binario o scelta della licenza (rinviata).
- Account con KDF bcrypt: vengono rifiutati con un messaggio esplicito.

## 4. Decisioni già prese dall'utente

- Segreti solo nel **Secret Service**; nessun fallback a file cifrato.
- Il secondo fattore dell'account è **TOTP**.
- L'utente non condivide le credenziali: il login reale lo esegue l'utente
  stesso. Il programma deve quindi funzionare in modo interattivo e stampare
  istruzioni chiare; nessun test automatico contatta il server Tuta.
- Licenza da decidere più avanti; non blocca M0–M2, ma va decisa prima di
  qualunque distribuzione.
- Codice, commenti, nomi e messaggi di commit in inglese. Documentazione in
  italiano, come da specifica principale.

## 5. Decisioni tecniche

| Tema | Scelta | Motivo |
|---|---|---|
| Linguaggio | Rust, edition 2021, toolchain stabile | L'SDK e le primitive crittografiche sono Rust |
| Struttura | Un crate binario con libreria interna, moduli per porte e adapter | Sufficiente per M0–M2; niente workspace prematuro |
| Dipendenza SDK | `tuta-sdk` da Git, `rev = 5dba964...` completo, feature `net` | Verificato con `cargo metadata` fuori dal workspace Tuta |
| CLI | `clap` con subcomandi | Standard, testabile |
| Runtime | `tokio` | L'SDK è asincrono |
| Prompt | `rpassword` per password e codice TOTP | Nessuna eco e nessun argv |
| Segreti | `keyring` 3.x, store Secret Service predefinito su Linux | Unica opzione scelta dall'utente; disponibile nell'ambiente |
| MIME | `mail-builder` 2.x | Costruzione RFC 5322/MIME; confini da rendere deterministici |
| Errori | `thiserror` nella libreria, `anyhow` solo nel `main` | Messaggi utente puliti e tipi di errore espliciti |
| Log | `tracing`, senza contenuti per default | Requisito di sicurezza della specifica |
| Test | `tempfile`, `mockall` solo se necessario; fake scritti a mano | Le porte rendono i fake semplici |

La licenza del progetto resta non decisa. Il file `LICENSE` non viene creato in
questo blocco.

## 6. Fatti verificati durante la ricognizione

La ricognizione è stata fatta sul clone sparse di `tutao/tutanota` al commit
`5dba96493532804ebd5a541024aa217ca3b7874d` (v369.261113.0).

1. **Modello dei tipi del server.** I modelli client sono inclusi nella build
   (`include_str!`). Il modello del server viene letto dal file
   `server_type_models_sdk.json` e, quando l'hash restituito dal server cambia,
   viene scaricato a runtime da `ApplicationTypesService` e riscritto su file.
   Non è necessario ricompilare a ogni aggiornamento del modello.
2. **Listato e paginazione.** `EntityClient::load_range` e
   `CryptoEntityClient::load_range` accettano `list_id`, `start_id`, `count` e
   `ListLoadDirection`. Per la pagina più recente si parte da
   `CustomId::max_id()` con direzione `DESC`.
3. **Dipendenze esterne.** Un progetto Cargo fuori dal workspace Tuta risolve
   e compila `tuta-sdk` via Git con `rev` completo, inclusa la dipendenza
   `uniffi` da Git. Verificato con `cargo check`, circa 30 secondi, nessun
   pacchetto di sistema aggiuntivo.
4. **Login nell'SDK.** `Sdk::create_session` esiste ma è dichiarato non pronto
   per la produzione: usa sempre Argon2id, ignora `kdfVersion` e non gestisce
   le challenge del secondo fattore. Per un account con TOTP va quindi
   implementato in `tuta-client` il flusso di pre-sessione.
5. **Formato JSON del protocollo.** I numeri viaggiano come stringhe e i byte
   come base64 standard. `serde_json` sui tipi generati non basta: serve un
   piccolo codec dedicato per le quattro strutture di pre-sessione.
6. **Corpo e allegati.** `MailDetailsBlob` è un **BLOB_ELEMENT_TYPE**, non
   un'entità normale: si scarica dal blob server con un read token d'archivio
   (`BlobAccessTokenService`, storage `v=13`, `read` come array e `write` come
   `[]`) e si richiede con `v=118`. I campi del server-model vengono decifrati
   con la chiave di sessione della mail. Gli allegati sono entità
   `tutanota::TutanotaFile` con `blobs: Vec<Blob>`; il download richiede un
   read token d'istanza, una GET su `BlobService` nel formato multiplo (`193`)
   con risposta incapsulata (conteggio, id, size, ciphertext) e la decifratura
   dei chunk con la chiave della `TutanotaFile`. `TutanotaFile.size` è la
   dimensione cifrata, non quella in chiaro. L'SDK non espone il download: va
   portato in `tuta-client`.

## 7. Architettura

Regola di dipendenza: il dominio e i casi d'uso non importano mai `tutasdk`.
L'SDK vive solo negli adapter.

```
src/
  main.rs                 composizione: clap -> casi d'uso -> adapter
  lib.rs
  domain/
    account.rs            AccountId, StoredCredentials
    mail.rs               Folder, MessageSummary, MessageContent, Attachment
    error.rs              errori di dominio
  ports/
    credentials.rs        trait CredentialStore
    prompt.rs             trait LoginPrompt
    mail_source.rs        trait MailSource
    renderer.rs           trait MessageRenderer
  app/
    login.rs              caso d'uso login
    logout.rs             caso d'uso logout
    status.rs             caso d'uso status
    dump.rs               caso d'uso dump
  adapters/
    cli.rs                clap, comandi, stampa
    keyring_store.rs      Secret Service
    terminal_prompt.rs    rpassword
    tuta/
      pre_session.rs      pre-sessione TOTP via REST
      json.rs             codec JSON del protocollo
      session.rs          Sdk::login, resume, close
      mail_source.rs      cartelle, mail, dettagli
      content.rs          corpo, header, indirizzi
      blob.rs             read token + download + decifratura
    mime.rs               rendering RFC 5322 con mail-builder
  config.rs               percorsi XDG, account attivo, base URL
```

### Porte principali

```rust
pub trait CredentialStore {
    fn save(&self, account: &AccountId, credentials: &StoredCredentials) -> Result<()>;
    fn load(&self, account: &AccountId) -> Result<Option<StoredCredentials>>;
    fn delete(&self, account: &AccountId) -> Result<()>;
}

pub trait LoginPrompt {
    fn mail_address(&self) -> Result<String>;
    fn password(&self) -> Result<SecretString>;
    fn totp_code(&self) -> Result<String>;
}

pub trait MailSource {
    async fn folders(&self) -> Result<Vec<Folder>>;
    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>>;
    async fn content(&self, message: &MessageSummary) -> Result<MessageContent>;
}

pub trait MessageRenderer {
    fn render(&self, content: &MessageContent) -> Result<Vec<u8>>;
}
```

Le porte sono piccole e orientate al caso d'uso (interface segregation). Gli
adapter dipendono dalle porte, non viceversa (dependency inversion). Il codice
di dominio non contiene `async` inutile: l'asincronia resta nei casi d'uso che
parlano con la rete.

### Decisioni sui punti aperti

1. **Account attivo.** Un file non segreto
   `$XDG_CONFIG_HOME/tuta-bridge/config.toml` contiene `active_account` e
   `base_url` (default `https://app.tuta.com`). `login` lo scrive; `status`,
   `logout` e `dump` lo leggono. Nessuna enumerazione del Secret Service.
2. **Nomi delle cartelle.** `--folder` accetta gli alias stabili `inbox`,
   `sent`, `drafts`, `trash`, `junk`, `archive` (case-insensitive) oppure il
   nome esatto di una cartella personalizzata, confrontato senza distinzione
   di maiuscole. Le etichette non sono cartelle in M2.
3. **Contenuto MIME.** `MessageContent` porta `from`, `to`, `cc`, `bcc`,
   `reply_to`, `sent_at`, `subject`, `message_id`, `in_reply_to`,
   `references`, corpo e allegati. `Date` viene da `sent_at`, mai dall'orologio.
   Gli header originali in `MailDetails.headers` vengono riusati quando
   presenti; altrimenti il `Message-ID` è
   `<tuta-{list_id}-{element_id}@tuta-bridge.invalid>`.
4. **Secondo fattore.** In questo blocco è supportato solo TOTP. Se la
   challenge non è TOTP, il bridge restituisce un errore esplicito di funzione
   non supportata. L'approvazione da un altro dispositivo e U2F/WebAuthn sono
   rimandate: il tipo 0 delle challenge Tuta è U2F, non un flusso di
   approvazione.
5. **Nomi dei file.** `dump` scrive
   `{received_at:%Y%m%d-%H%M%S}-{element_id}.eml`, con `element_id`
   sanificato. Lo stesso messaggio produce sempre lo stesso nome; una seconda
   esecuzione sovrascrive gli stessi file.
6. **Alternativa plain.** Se il corpo sembra HTML, diventa `text/html` e la
   parte `text/plain` è derivata con `html_to_text` di `mail-parser`. Se il
   corpo è già testo, si produce solo `text/plain`.
7. **Test di rete offline.** La porta `SessionFactory` permette di testare il
   caso d'uso con un fake. L'adapter HTTP concreto ha un test con server locale
   (`wiremock`) e `base_url` sovrascrivibile con `--base-url` e
   `TUTA_BRIDGE_BASE_URL`. Nessun test usa il server Tuta reale.
8. **Immagini inline.** `Attachment` porta `cid` e `mime_type`. Se `cid` è
   presente, l'allegato viene reso come parte inline con `Content-ID`;
   altrimenti come attachment con `Content-Disposition: attachment`.
9. **Logout parziale.** La cancellazione locale è autorevole: se
   `CloseSessionService` fallisce, la voce viene comunque rimossa, viene
   stampato un avviso e il comando esce con 0.
10. **Errori nel dump.** `dump` continua sui messaggi successivi, scrive gli
    `.eml` riusciti, riporta quelli falliti su stderr ed esce con codice
    non-zero se almeno uno è fallito.

### Porta di sessione

```rust
pub struct SessionRequest {
    pub mail_address: String,
    pub password: SecretString,
    pub totp: Arc<dyn Fn() -> Result<String> + Send + Sync>,
}

pub struct NewSession {
    pub user_id: String,
    pub access_token: String,
    pub encrypted_passphrase_key: Vec<u8>,
}

#[async_trait]
pub trait SessionFactory {
    async fn create(&self, request: SessionRequest) -> Result<NewSession>;
    async fn resume(&self, credentials: &StoredCredentials) -> Result<Box<dyn Session>>;
}

#[async_trait]
pub trait Session {
    fn account(&self) -> AccountInfo;
    fn mail(&self) -> &dyn MailSource;
    async fn close(&self) -> Result<()>;
}
```

L'adapter `TutaSessionFactory` compone `TutaPreSession` (che parla con
`SaltService`, `SessionService` e `SecondFactorAuthService` tramite
`RestClient` e il codec JSON) e `Sdk::login` per riprendere la sessione.


### Flusso di login

1. Prompt di indirizzo e password.
2. `SaltService` per sale e `kdfVersion`.
3. Se `kdfVersion` è bcrypt, errore esplicito; nessuna migrazione.
4. Derivazione Argon2id con `derive_user_passphrase_key` dell'SDK.
5. `authVerifier = base64url(sha256(chiave))` con la funzione dell'SDK.
6. Generazione di una `accessKey` AES-256 casuale.
7. `SessionService` con `clientIdentifier = "tuta-bridge"`.
8. Se ci sono challenge TOTP: prompt del codice e `SecondFactorAuthService`
   POST con `type = 1`, poi polling GET finché `secondFactorPending` è falso.
   Qualsiasi altro tipo di challenge produce un errore esplicito.
9. `Credentials` con `encryptedPassphraseKey` cifrata con la `accessKey`.
10. `Sdk::login(credentials)` e salvataggio nel Secret Service.
11. Le credenziali in memoria vengono azzerate con `zeroize` appena possibile.

Nessun dato sensibile viene loggato; gli errori riportano solo la fase fallita.

### Flusso di `dump`

1. Carica le credenziali dal Secret Service e fa `Sdk::login`.
2. Elenca le cartelle e risolve il nome richiesto.
3. Carica le mail con `load_range` in ordine decrescente.
4. Per ogni mail carica `MailDetailsBlob` con la chiave della mail.
5. Decodifica il corpo: `compressedText` è già decompresso dal mapper
   dell'SDK; viene preferito a `text` quando presente. Il tipo (HTML o testo)
   si deduce dal contenuto.
6. Carica le `TutanotaFile`, scarica e decifra i blob.
7. Sintetizza il MIME e scrive
   `{received_at:%Y%m%d-%H%M%S}-{element_id}.eml` nella directory indicata,
   con permessi `0600`; la directory è `0700`.
8. Il rendering è deterministico: stessi input, stessi byte. `--limit` deve
   essere positivo.

## 8. Interfaccia CLI

```text
tuta-bridge [--base-url <url>] login [--email <address>]
tuta-bridge [--base-url <url>] logout
tuta-bridge [--base-url <url>] status
tuta-bridge [--base-url <url>] dump --folder <name> --limit <n> --out <dir>
```

- `--base-url` è globale e ha precedenza sulla variabile
  `TUTA_BRIDGE_BASE_URL` e sul file di configurazione.
- `--email` è facoltativo: se assente viene chiesto.
- La password e il codice TOTP non hanno flag.
- `status` mostra indirizzo, ID utente e presenza delle credenziali, mai il
  token.
- `logout` chiama `CloseSessionService` in modo best-effort e cancella
  comunque la voce dal Secret Service.
- Codici di uscita distinti per: credenziali assenti, login fallito, 2FA
  fallito, cartella inesistente, errore di rete, dump parzialmente fallito.

## 9. Sicurezza

- Solo Secret Service; servizio `tuta-bridge`, utente = indirizzo mail.
- Nessun segreto in `Debug`, log, messaggi d'errore o nomi di file.
- `SecretString`/`Zeroizing` per password, chiavi e token in memoria.
- Log di default a livello `warn`, senza soggetti, mittenti, indirizzi o corpi.
- Il dump scrive file `.eml` in chiaro: la directory di output è una scelta
  esplicita dell'utente e viene documentata come tale.
- Timeout di rete e un solo retry con backoff per le chiamate non idempotenti
  non vengono introdotti in M0–M2; il client HTTP dell'SDK mantiene la
  gestione della sospensione.

## 10. Strategia di test

- **Codec JSON:** fixture sintetiche per salt, sessione, 2FA; numeri come
  stringhe, byte come base64, ID tuple come array.
- **Pre-sessione HTTP:** test dell'adapter con `wiremock` su una base URL
  locale; copre salt, sessione, TOTP e polling.
- **Casi d'uso:** fake di `CredentialStore`, `LoginPrompt`, `MailSource`,
  `SessionFactory` e `MessageRenderer`; verifica di errori e ordine delle
  chiamate.
- **MIME:** test golden su una mail sintetica con corpo HTML, alternativa plain,
  due allegati e un'immagine inline; due rendering consecutivi devono essere
  identici.
- **Keyring:** test manuale documentato, perché il Secret Service non è
  disponibile in CI.
- **Reale:** solo comandi eseguiti dall'utente con il proprio account; nessuna
  fixture con dati veri e nessun test automatico di rete.

## 11. Rischi e domande aperte

| Rischio | Impatto | Mitigazione |
|---|---|---|
| Build di `tuta-sdk` richiede sottomoduli/CMake | M0 bloccato | Provare subito una build minima; documentare i pacchetti di sistema |
| Il formato JSON di pre-sessione cambia | Login rotto | Codec isolato, fixture, messaggio d'errore chiaro, `NOTES.md` |
| `MailDetailsBlob` senza chiave propria | M2 bloccato | Decifratura esplicita con la chiave della mail, già prevista |
| Porting blob più grande del previsto | M2 in ritardo | Sotto-passi M2a–M2d con acceptance separati |
| Confini MIME casuali in `mail-builder` | Byte instabili | Verifica in M2d; se serve, boundary deterministico o rendering proprio |
| Licenza non decisa | Blocca la distribuzione | Decisione prima di M8; non blocca M0–M2 |

## 12. Criteri di accettazione

- **M0:** `cargo build` e `cargo test` passano; `NOTES.md` risponde ai punti
  1–6 della sezione 6; la build dell'SDK è documentata.
- **M1:** l'utente esegue `login`, inserisce password e TOTP, e `status` mostra
  l'account. `logout` rimuove la voce dal Secret Service. Un secondo `status`
  dopo il logout dice chiaramente che non ci sono credenziali.
- **M2:** `dump --folder inbox --limit 10 --out ./out` produce dieci `.eml`
  apribili in Thunderbird, con oggetto, mittente, destinatari, data, corpo,
  allegati e immagini inline corretti; eseguire due volte produce byte e nomi
  identici.

## 13. Cosa resta al costruttore

- Nomi definitivi di moduli e tipi, finché rispettano la regola di dipendenza.
- Scelta dei dettagli di formattazione dei messaggi CLI.
- Strategia di retry interna alle singole chiamate, se emerge dalla pratica.
- Suddivisione fine dei sotto-passi M2a–M2d.
