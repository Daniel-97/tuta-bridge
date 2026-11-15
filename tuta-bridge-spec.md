# Tuta Bridge: bridge locale IMAP/SMTP per usare Tuta Mail con qualunque client di posta locale

Documento di specifica e ricognizione tecnica, destinato a un agente di sviluppo locale.

- **Data della ricognizione:** 15 novembre 2026
- **Repository analizzato:** `tutao/tutanota`, commit `5dba964` (v369.261113.0, 13 novembre 2026)
- **Lingua del progetto:** documentazione in italiano, codice e commenti a scelta (preferibile inglese per gli identificatori)

---

## 0. Come usare questo documento (leggere prima di tutto)

1. La ricognizione è stata **di sola lettura**: nessun codice è stato scritto, compilato o eseguito. Tutto ciò che è scritto sul codice di Tuta viene dalla lettura dei sorgenti.
2. Ogni affermazione tecnica ha un tag:
   - **[VERIFICATO]**: letto direttamente nel codice al commit indicato.
   - **[DA VERIFICARE]**: ipotesi, dedotta dai nomi di simboli o da conoscenza generale. Non va trattata come un fatto.
3. In caso di discrepanza tra questo documento e il codice, **vale il codice**. Aggiorna il documento (sezione 9, "Registro delle verifiche") quando scopri qualcosa.
4. Il repository di Tuta è stato riorganizzato di recente: i percorsi dei file TypeScript qui indicati potrebbero non esistere in versioni diverse. Se un percorso manca, cerca il simbolo con `grep -rn`.
5. Dall'ambiente della ricognizione **non era raggiungibile `tuta.com`**: nulla è stato provato contro il server reale. Il primo contatto con il server reale è una decisione del proprietario del progetto (vedi regole operative, sezione 12).

---

## 1. Scopo del progetto

Costruire un demone locale ("bridge") che permetta di usare un account **Tuta Mail** come un normale account IMAP/SMTP in **qualunque client di posta locale**: Thunderbird, ma anche Evolution, KMail, Geary, Apple Mail, Outlook, client da terminale (mutt/neomutt, aerc) e strumenti di sincronizzazione (mbsync/isync, offlineimap). **Thunderbird è il primo client di riferimento per i test, non l'unico bersaglio**: il bridge non deve contenere logica specifica per un singolo client (vedi 6.7).

Il bridge è l'equivalente per Tuta di quello che Proton Bridge è per Proton: gira sulla macchina dell'utente, parla con le API di Tuta (dove tutto è cifrato end-to-end), decifra in locale ed espone i messaggi a un client standard su `127.0.0.1` tramite IMAP e SMTP.

### 1.1 Obiettivi (v1)

- Esporre un account Tuta a **qualunque client IMAP/SMTP standard** su `127.0.0.1`, senza dipendere da comportamenti specifici di un client. Thunderbird è il primo client di test.
- **Lettura:** cartelle, messaggi, flag letto/non letto, allegati, ricerca di base.
- **Tempo reale:** nuovi messaggi e cambiamenti visibili in Thunderbird tramite IMAP IDLE.
- **Scrittura:** cambio flag, spostamenti, cestino, archivio, **invio** via SMTP.
- **Cache locale** per uso offline e per rendere veloce IMAP.
- Uso personale, un account, Linux come piattaforma principale.

### 1.2 Non-obiettivi (v1)

- Calendario e contatti (CalDAV/CardDAV), Tuta Drive.
- Gestione account (registrazione, abbonamento, alias, cambio password, ecc.).
- Più account contemporanei (da progettare in modo da non impedirlo, ma non implementare).
- Windows e macOS (non vietati, ma non prioritari).
- Distribuzione pubblica del binario (vedi rischi legali e ToS, sezione 3.5).

### 1.3 Perché serve

Tuta non offre IMAP, POP3 o SMTP. Dal 13 febbraio 2026 esiste un'estensione ufficiale per Thunderbird, ma **non è una vera integrazione**: mostra la versione web di Tuta in una webview nella barra laterale. Mancano quindi cartelle e ricerca integrate nel client, inbox unificata con altri account, filtri di Thunderbird, uso offline vero. Il bridge colma questo vuoto, e lo fa per qualunque altro client locale, non solo per Thunderbird.

---

## 2. Contesto e fonti

| Fatto | Fonte | Affidabilità |
|---|---|---|
| Tuta non supporta IMAP/POP3/SMTP su nessun piano, per via del modello di cifratura | più articoli di settore (2026) | media (secondarie) |
| Tuta ha dichiarato pubblicamente che non offrirà un bridge, per poter far evolvere il protocollo (es. crittografia post-quantum) | smtpedia.com (agosto 2026) | **bassa**: fonte secondaria, non verificata su fonti Tuta |
| Dal 13 febbraio 2026 esiste un'estensione ufficiale Thunderbird basata su webview, open source | Clubic, JustGeek (2026) | media |
| Il client Tuta è open source, licenza **GPLv3** | `LICENSE.txt` nel repo | **[VERIFICATO]** |

L'idea iniziale era il reverse engineering dell'app desktop di Tuta. **Non serve**: i sorgenti dei client e dell'SDK sono pubblici, quindi il protocollo si ricava dal codice.

Riferimento esterno (da conoscenza generale, non verificato in questa ricognizione): **Hydroxide**, un bridge Proton di terze parti scritto in Go con le librerie `go-imap` e `go-smtp` di emersion, utile come esempio di struttura di un bridge non ufficiale.

---

## 3. Scoperte della ricognizione

### 3.1 Il repository

**[VERIFICATO]**

- Workspace Cargo alla radice (`Cargo.toml`) con membri: `tuta-sdk/rust/sdk`, `tuta-sdk/rust/uniffi-bindgen`, `tuta-sdk/rust/crypto-primitives`, `tuta-sdk/rust/util`, `src/app-kit/mimimi`.
- `rust-version = 1.84.0`, `edition = 2021`, `publish = false`, `license-file = LICENSE.txt` (GPLv3).
- La dipendenza `uniffi` è presa **da Git** (`mozilla/uniffi-rs`, revisione fissata), quindi la build richiede accesso a GitHub.
- Client TypeScript in `src/` (riorganizzato di recente), SDK Rust in `tuta-sdk/rust/`.

Per riprodurre la ricognizione:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/tutao/tutanota.git
cd tutanota
git sparse-checkout set tuta-sdk \
  src/app-kit/local-store/event \
  src/applications/common/api/worker/facades \
  src/platform-kit/base/facades
# commit analizzato: 5dba964 (se disponibile: git fetch --depth 1 origin <sha completo> && git checkout)
```

### 3.2 L'SDK Rust (`tuta-sdk`): cosa c'è

**[VERIFICATO]** salvo dove indicato.

**Struttura e build**

- Crate `tuta-sdk`, libreria `tutasdk`, `crate-type = ["cdylib", "staticlib", "lib"]`. Circa 47.000 righe di Rust, di cui una parte grande è codice generato (`entities/generated`, `services/generated`).
- Pensato per **mobile** (binding `uniffi` verso Kotlin e Swift). L'I/O è **iniettato**: HTTP tramite il trait `RestClient` (`src/bindings/rest_client.rs`, metodo `request_binary(url, method, options)`), file tramite `FileClient` (`src/bindings/file_client.rs`).
- Feature Cargo: `net` (client HTTP nativo con `hyper` + `rustls`, in `src/net/native_rest_client.rs`), `logging`, `testing`, `test-with-local-http-server`. Le dipendenze del workspace usano `default-features = false`, quindi per un uso da binario nativo serve abilitare `net`.
- Esistono anche `bindings/native_file_client.rs` e `bindings/test_file_client.rs`, e un `SuspendableRestClient` che gestisce la sospensione delle richieste ordinata dal server (da mantenere).

**Punto d'ingresso (`src/lib.rs`)**

- `Sdk::new(base_url: String, raw_rest_client: Arc<dyn RestClient>, file_client: Arc<dyn FileClient>)`; esiste anche `Sdk::new_without_suspension`.
- `Sdk::login(credentials: Credentials) -> Result<Arc<LoggedInSdk>, LoginError>`: **riprende una sessione esistente** (chiama `login_facade.resume_session(&credentials)`). All'inizio carica il modello dei tipi del server con `type_model_provider.initialize_server_model_from_file()`.
- `Sdk::create_session(mail_address, passphrase)`: il commento nel codice dice che **non è pronto per la produzione** ("only does temporary login for free users without offline").
- Header HTTP inviati dall'SDK (`HeadersProvider`): `cv` (versione client, `CARGO_PKG_VERSION`), `v` (versione del modello), `accessToken` se presente.

**`Credentials` (`src/login/credentials.rs`)**

```rust
pub struct Credentials {
    pub login: String,                    // indirizzo mail
    pub user_id: GeneratedId,
    pub access_token: String,
    pub encrypted_passphrase_key: Vec<u8>,
    pub credential_type: CredentialType,  // Internal | External
}
```

**`LoggedInSdk`** espone: `mail_facade()`, `calendar_facade()`, `blob_facade()`, `contact_facade`, `customer_facade`, `get_entity_client()`, `get_service_executor()`, `get_user()`, `get_user_id()`, `get_user_group_id()`, `get_current_sym_group_key()`, `instance_mapper`, `type_model_provider`.

**`MailFacade` (`src/mail_facade.rs`)**

- `load_user_mailbox()`, `load_folders_for_mailbox(...)`
- `load_untyped_mail(&IdTupleGenerated)` (restituisce l'entità decifrata; il test lo converte in `Mail` con `instance_mapper.parse_entity`)
- `get_group_id_for_mail_address(...)`
- `set_unread_status_for_mails(...)`, `trash_mails(...)`, `archive_mails(...)`, `simple_move_mail(...)`
- `get_crypto_entity_client()`

**Cartelle (`src/folder_system.rs`)**: `FolderSystem` con `MailSetKind` e `system_folder_by_type(kind)`.

**Entità generate (`src/entities/generated/tutanota.rs`)**

- `Mail` (type id 97): tra gli altri `subject`, `receivedDate`, `state`, `unread`, `confidential`, `replyType`, `sender: MailAddress`, `firstRecipient`, `recipientCount`, `attachments: Vec<IdTupleGenerated>`, `conversationEntry`, `mailDetails: Option<IdTupleGenerated>`, `mailDetailsDraft`, `bucketKey`, `sets: Vec<IdTupleGenerated>`, `movedTime`, `differentEnvelopeSender`, `authStatus`, `encryptionAuthStatus`, `phishingStatus`, `method`, `sendAt`, `processingState`.
- `MailDetails` (type id 1282): `sentDate`, `authStatus`, `replyTos`, `recipients`, `headers: Option<Header>`, `body: Body`.
- `MailBox`, più le entità di contatti e calendario.

**Crittografia (`src/crypto/`, più la crate `crypto-primitives`)**: `argon2_id.rs`, `hkdf.rs`, `key_encryption.rs`, `kyber.rs` (ML-KEM, post-quantum), `rsa.rs`, `x25519.rs`, `tuta_crypt.rs`, `asymmetric_crypto_facade.rs`, `crypto_facade.rs`, `public_key_provider.rs`. Dipendenze chiave: `argon2`, `pqcrypto-mlkem`, `rsa`, `x25519-dalek`, `sha2`, `sha3`, `hkdf`, `zeroize`, `lz4_flex`.

**Login (`src/login/login_facade.rs`)**: `resume_session`, `derive_user_passphrase_key` (funzione pubblica), enum `LoginError`.

**Servizi generati (`src/services/generated/`)**, tra cui (nomi letti, non tutti esaminati): `SaltService`, `SessionService`, `CloseSessionService`, `SecondFactorAuthService`, `SecondFactorAuthAllowedService`, `DraftService`, `SendDraftService`, `MoveMailService`, `SimpleMoveMailService`, `UnreadMailStateService`, `ApplyLabelService`, `ManageLabelService`, `MailFolderService`, `PublicKeyService`, `BlobAccessTokenService`, `BlobService`, `ApplicationTypesService`, `ImapService`, `ImapFolderService`, `ImportMailService`, `MailExportTokenService`, `ReportMailService`.

- `ImapService`, `ImapFolderService` e `ImportMailService` **[DA VERIFICARE]** riguardano con ogni probabilità la funzione di *importazione* da altri server IMAP, **non** un server IMAP.

**Test come fonte di esempi (`tuta-sdk/rust/sdk/tests/`)**: `download_mail_test.rs` (login + caricamento di una mail con un `TestRestClient` e fixture JSON), `get_default_folders.rs`, `login_behaviours.rs`, `create_session.rs`, `contact_facade.rs`, `calendar_facade.rs`, `upload_blob_*.rs`, `can_manipulate_remote_instances.rs`. I test che parlano con un server vero richiedono un server Tuta locale su `localhost:9000` e sono ignorati di default.

### 3.3 Cosa manca all'SDK Rust per fare un bridge

| Necessità del bridge | Stato nell'SDK Rust | Riferimento TS da cui portare |
|---|---|---|
| Login con password (salt, KDF, verifier, creazione sessione) | **Manca.** `login()` presuppone credenziali già esistenti; `create_session` è sperimentale | `LoginFacade.createSession` |
| Secondo fattore (TOTP / approvazione da altro dispositivo) | **Manca** (`secondFactorAuthentications` lasciato vuoto nel login) | `LoginFacade.authenticateWithSecondFactor`, `waitUntilSecondFactorApproved` |
| Aggiornamenti in tempo reale (websocket) | **Non trovato**: nessuna traccia di websocket o entity event batch fuori dal codice generato | `EventBusClient.ts` |
| Elenco mail di una cartella con paginazione | **[DA VERIFICARE]**: probabilmente fattibile con l'entity client generico, nessun metodo dedicato visto | |
| Caricamento di `MailDetails` (corpo, destinatari, header) | Tipo presente, **nessun metodo visto** che lo carichi | `MailFacade.loadMailDetailsBlob` |
| Download e decifratura allegati | `BlobFacade` ha solo funzioni di **upload** (`encrypt_and_upload_multiple`, `encrypt_multiple_file_data`, `encrypt_and_upload_single_legacy`); esiste `blob_access_token_facade` | `BlobFacade.downloadAndDecrypt*`, `MailFacade.loadAttachments` |
| Invio | `DraftService` e `SendDraftService` esistono solo come **definizioni generate**, nessuna facade | `MailFacade.createDraft`, `updateDraft`, `sendDraft` |
| Gestione etichette | servizi `ApplyLabelService`/`ManageLabelService` generati, nessuna facade vista | |
| Come l'SDK ottiene il modello dei tipi del server | **[DA VERIFICARE]**, vedi rischio 3.5.1 | `ApplicationTypesFacade` |

### 3.4 Il client TypeScript: flussi di riferimento

Percorsi al commit analizzato **[VERIFICATO]**:

- `src/platform-kit/base/facades/LoginFacade.ts`
- `src/app-kit/local-store/event/EventBusClient.ts`
- `src/applications/common/api/worker/facades/lazy/MailFacade.ts`
- `src/applications/common/api/worker/facades/lazy/BlobFacade.ts`
- Test utili come documentazione eseguibile: `test/tests/network/LoginFacadeTest.ts`, `test/tests/api/worker/EventBusClientTest.ts`, `test/tests/api/worker/facades/MailFacadeTest.ts`, `test/tests/api/worker/facades/BlobFacadeTest.ts`.

#### 3.4.1 Login (`LoginFacade.createSession`, circa riga 283)

Sequenza **[VERIFICATO]**:

1. `loadUserPassphraseKey(mail, passphrase)`: `GET SaltService` con la mail (normalizzata in minuscolo e senza spazi) → restituisce `salt` e `kdfVersion`.
2. Derivazione della chiave (`deriveUserPassphraseKey`): `Bcrypt` (account vecchi, chiave a 128 bit) oppure `Argon2id` (moderno).
3. `authVerifier = createAuthVerifierAsBase64Url(userPassphraseKey)`. **[DA VERIFICARE]** come viene calcolato: cercare la definizione con `grep -rn createAuthVerifierAsBase64Url`.
4. `POST SessionService` con `CreateSessionData { accessKey, authToken: null, authVerifier, clientIdentifier, mailAddress, recoverCodeVerifier: null, user: null }`. Per una sessione **persistente** il client genera una `accessKey` AES-256 casuale e la invia nel campo `accessKey`.
5. Risposta `CreateSessionReturn { accessToken, user, challenges[] }`. Se `challenges` non è vuoto, serve il secondo fattore.
6. Caricamento dell'utente, sblocco della chiave del gruppo utente con la passphrase key (`initSession`).
7. Costruzione delle credenziali: `accessToken`, `encryptedPassphraseKey = encryptKey(accessKey, userPassphraseKey)` (e `encryptedPassword`, che nel bridge **non va usato né salvato**), `userId`, tipo `Internal`.
8. Per account non "moderni" il client fa `migrateKdfType` verso Argon2id subito dopo il login.

Il parametro `clientIdentifier` identifica il client verso il server: **usare un valore onesto** (es. `tuta-bridge`), non spacciarsi per il client ufficiale.

#### 3.4.2 Secondo fattore

- Se arrivano challenge, il client fa **polling** con `GET SecondFactorAuthService` (`SecondFactorAuthGetData { accessToken }`) finché `secondFactorPending` non diventa falso (l'utente approva da un altro dispositivo).
- Per inviare un codice dal client stesso: `POST SecondFactorAuthService` con `SecondFactorAuthData` (`authenticateWithSecondFactor`).
- La generazione/verifica del TOTP lato client è in `generateTotpCode` (vedi `TotpVerifier`). **[DA VERIFICARE]** i campi esatti di `SecondFactorAuthData` per TOTP; leggerli nelle entità generate e in `LoginFacadeTest.ts`.
- WebAuthn/U2F come secondo fattore: **non analizzato**. Probabile non supporto nel bridge v1 (documentare l'errore all'utente).

#### 3.4.3 Aggiornamenti in tempo reale (`EventBusClient.ts`)

**[VERIFICATO]**:

- Websocket su `"/event?" + authQuery + "&groupsToLastEventBatchIds=" + "<gruppo>=<batchId>;..."`. Il parametro `groupsToLastEventBatchIds` dice al server qual è l'ultimo batch già elaborato per ogni gruppo: il server **rimanda gli eventi persi** alla (ri)connessione. (La composizione completa di `authQuery` è poco sopra, righe ~215-228: leggerla.)
- Messaggi di testo nel formato `tipo;json` (`message.data.split(";")`, il resto è il valore). `MessageType.EntityUpdate = "entityUpdate"`; altri tipi gestiti: aggiornamento contatori non letti, marcatori phishing, stato "leader", stato operazioni, `InitialSyncDone`, stima del lavoro di sync iniziale (i valori stringa esatti vanno letti nell'enum, riga ~90).
- Payload `entityUpdate`: oggetto `WebsocketEntityData` con `eventBatchId`, `eventBatchOwner` (gruppo), `entityUpdates[]` (application, typeId, istanza, operazione) e `applicationTypesHash`.
- I batch di eventi **scadono dopo 45 giorni**; se il bridge resta spento oltre quel limite il client TS lancia `OutOfSyncError` e serve una **risincronizzazione completa** (il codice lascia un margine di sicurezza di un giorno).
- Il client tiene l'ultimo `batchId` per gruppo in uno storage persistente: il bridge deve fare lo stesso nel proprio SQLite.
- **[DA VERIFICARE]** il ruolo del messaggio "leader status" (il web client elegge un leader tra più schede; un bridge unico è l'unico client, ma potrebbe dover rispondere o ignorare).

#### 3.4.4 Corpo e allegati

- `MailFacade.loadMailDetailsBlob(mail)` (riga ~1303) carica i `MailDetails` (corpo, destinatari, header); per le bozze `loadMailDetailsDraft` (riga ~1341).
- `MailFacade.loadAttachments(mail)` (riga ~1289) restituisce le entità `File`; il contenuto passa dai blob (`BlobFacade.downloadAndDecrypt`, riga ~556, e le varianti per più istanze, riga ~679) con token di accesso ottenuto via `BlobAccessTokenService`.
- **[DA VERIFICARE]** formato del corpo (le dipendenze dell'SDK includono `lz4_flex`, quindi il corpo potrebbe essere compresso), presenza di immagini inline (cid) e come si ricavano nome e MIME type degli allegati.

#### 3.4.5 Invio

- `MailFacade.createDraft` (riga ~343) → `POST DraftService`; `updateDraft` (riga ~509); `sendDraft(draft, recipients, language, sendAt, allowUndo)` (riga ~753) → `POST SendDraftService` (riga ~823).
- Destinatari interni (utenti Tuta): cifratura end-to-end con chiavi pubbliche (`PublicKeyService`). Destinatari esterni: **[DA VERIFICARE]** come sono gestiti (mail normale in chiaro lato server vs. mail "confidenziale" con password). Leggere `sendDraft` e la costruzione di `Recipient`.

### 3.5 Rischi e vincoli

1. **Modello dei tipi del server.** `Sdk::login` chiama `initialize_server_model_from_file()`, quindi il modello pare caricato **da un file incluso nella build**. Il client TS invece lo gestisce dinamicamente (`ApplicationTypesFacade`, hash del modello nel websocket `applicationTypesHash`). In `type_model_provider.rs` (riga ~221) viene costruita una mappa di header con `cv`, il che **suggerisce** che esista una strada per scaricare il modello dal server (e il servizio `ApplicationTypesService` esiste nei servizi generati). **[DA VERIFICARE]** come funziona. Se il modello è fisso nella build, ogni aggiornamento del server che cambia il modello (le versioni del modello avanzano di continuo, es. `TutanotaModelV98` in un commit recente) può rompere il bridge finché non si ricompila.
2. **Protocollo non documentato e in evoluzione.** Nessuna garanzia di stabilità. Mitigazione: SDK ancorato a un commit preciso, test di non regressione, rilevazione degli errori di modello con messaggio chiaro.
3. **Termini di servizio.** Non verificato cosa dicano su client non ufficiali. Controllare prima di qualunque uso diverso da quello personale. Usare un **account di prova dedicato** durante lo sviluppo.
4. **Licenza.** Il repo è **GPLv3**. Un bridge che linka `tutasdk` e viene distribuito è un'opera derivata: va rilasciato sotto GPLv3 compatibile. Per uso personale non c'è obbligo, ma conviene scegliere la licenza fin da subito.
5. **Sicurezza.** Un bridge sposta testo decifrato fuori dal perimetro E2EE. Vedi sezione 7.
6. **Rate limiting e blocchi.** Evitare polling aggressivo; mantenere `SuspendableRestClient`; backoff esponenziale; un solo websocket.
7. **KDF bcrypt.** Account con KDF bcrypt: il client ufficiale li migra ad Argon2id al login. Il bridge **non deve migrare di nascosto**: rifiutare con messaggio esplicito o chiedere conferma.
8. **Semantica IMAP vs Tuta** (UID stabili, etichette multiple, ecc.): sezione 6.

---

## 4. Architettura proposta

```
 Client di posta ──IMAP/SMTP (127.0.0.1, TLS)──►  tuta-bridge  ──HTTPS + WSS──►  server Tuta
 (Thunderbird, mutt, mbsync, ...)
                                                   │
        ┌──────────────────────────────────────────┤
        │  imap server    smtp submission server   │
        │       │                 │                │
        │   store (SQLite)   outbox/queue          │
        │       │                 │                │
        │   sync engine  ◄── event bus (websocket) │
        │       │                 │                │
        │   tuta-client (wrapper sull'SDK)         │
        │       │                                  │
        │   tutasdk (path/git, commit fissato)     │
        └──────────────────────────────────────────┘
        secret store (keyring) · config (XDG) · log
```

Componenti:

- **`tuta-client`**: strato sottile che **isola** `tutasdk` e implementa le parti mancanti (login, 2FA, event bus, `MailDetails`, allegati, invio). Il resto del bridge non deve dipendere direttamente dai tipi dell'SDK.
- **`store`**: SQLite con messaggi, cartelle, mapping UID, stato di sync (`last_batch_id` per gruppo).
- **`sync`**: sync iniziale e incrementale; consuma gli eventi websocket e aggiorna lo store.
- **`imap`**: server IMAP che legge dallo store e scrive tramite `tuta-client`.
- **`smtp`**: server di submission che trasforma il MIME ricevuto in bozza + invio.
- **`cli`**: `login`, `logout`, `status`, `serve`, `dump` (debug), `resync`.

---

## 5. Decisioni di progetto

### 5.1 Linguaggio: Rust (raccomandato)

Motivi: l'SDK (e le primitive crittografiche, post-quantum inclusi) è già in Rust; la parte più rischiosa e più facile da sbagliare (cifratura, derivazione chiavi, decifratura di entità) è già fatta e testata. Resta da portare solo la logica di sessione/eventi/blob/invio, che è "protocollo", non crittografia pura.

Alternative scartate (ma documentate):

- **Go** (con `go-imap`/`go-smtp`): server IMAP/SMTP più comodi, ma tutta la crittografia e il modello andrebbero riscritti, PQ incluso.
- **Sidecar Node/TypeScript** che riusa il codice dei worker del client web: pesante per le dipendenze da browser.

### 5.2 Dipendenza dall'SDK

- Aggiungere `tutasdk` come dipendenza **ancorata a un commit** (path su un clone locale/submodule, oppure `git` con `rev`), con `features = ["net"]`. **[DA VERIFICARE]**: poiché i `Cargo.toml` dell'SDK usano ereditarietà dal workspace (`version.workspace = true`, ecc.) e `uniffi` è una dipendenza Git, controllare che la risoluzione funzioni da un workspace esterno; in caso contrario, il progetto del bridge può essere un **nuovo membro del workspace clonato**.
- Non fare fork a meno di necessità; se servono patch all'SDK, tenerle come patch esplicite e minimali.
- Aggiornare il commit dell'SDK solo di proposito, con test.

### 5.3 Storage

- **SQLite** (es. `rusqlite` o `sqlx`). Schema indicativo:

```
accounts(id, mail_address, user_id, ...)
mailboxes(id, tuta_set_id_list, tuta_set_id_elem, name, kind, imap_name, uidvalidity, next_uid)
messages(id, mailbox_id, uid, tuta_mail_list, tuta_mail_elem,
         received_at, unread, subject, size, rfc822_cache BLOB NULL, ...)
labels(...)           -- se mappate come keyword IMAP
sync_state(group_id, last_batch_id, initial_sync_done)
```

- La cache del corpo (`rfc822_cache`) può essere generata alla prima lettura (lazy) per non scaricare tutto l'archivio subito.
- Cifratura a riposo del database: vedi sezione 7.

### 5.4 Crate da valutare (da verificare lo stato di manutenzione)

`tokio`, `tokio-tungstenite` (websocket), `rusqlite`/`sqlx`, `mail-parser` e `mail-builder` (MIME), una crate di codec IMAP (es. `imap-codec`) oppure un parser scritto a mano per il sottoinsieme necessario, `tokio-rustls` + `rcgen` (TLS locale), `keyring` o `secret-service` (credenziali), `clap`, `tracing`, `zeroize`. Per l'invio `mail-parser` è utile a smontare il MIME in ingresso.

### 5.5 Configurazione e credenziali

- File di configurazione e dati in directory XDG (`$XDG_CONFIG_HOME`, `$XDG_DATA_HOME`), permessi `0600`/`0700`.
- Si salvano le `Credentials` dell'SDK (token di accesso + chiave passphrase cifrata) nel keyring di sistema, **non** la password dell'account.

---

## 6. Mapping IMAP ⇄ Tuta

Tutto ciò che segue è **progettazione**, con le basi da verificare nel codice dove indicato.

### 6.1 Cartelle ed etichette

- Le cartelle di sistema (`MailSetKind`) si mappano su cartelle IMAP standard con attributi special-use (`\Inbox`, `\Sent`, `\Drafts`, `\Trash`, `\Junk`, `\Archive`).
- `Mail.sets` è una lista di identificativi: **[DA VERIFICARE]** se cartelle ed etichette sono entrambe "MailSet" distinti dal `kind`, e come si distingue la cartella principale dalle etichette. Proposta: cartella = mailbox IMAP; etichette = **keyword IMAP** (`$label_nome`), perché in Tuta una mail può avere più etichette ma una sola cartella (da verificare).
- Sottocartelle: **[DA VERIFICARE]** come Tuta rappresenta la gerarchia; mapparla con separatore `/`.

### 6.2 UID e UIDVALIDITY

- Gli ID di Tuta (`IdTupleGenerated`) **non sono interi crescenti**: serve una **tabella di mapping** `(mailbox, tuta_mail_id) → uid`, con UID assegnati in ordine crescente al primo ingresso della mail in quella mailbox.
- `UIDVALIDITY` per mailbox, stabile; cambiarlo solo in caso di risincronizzazione completa.
- Spostare una mail tra cartelle = nuova UID nella cartella di destinazione, scomparsa dall'origine (per IMAP è `EXPUNGE` + nuovo `EXISTS`). **[DA VERIFICARE]** se in Tuta una mail spostata mantiene lo stesso ID.

### 6.3 Flag

- `\Seen` ⇄ `!Mail.unread` (scrittura via `set_unread_status_for_mails`).
- `\Answered`, `$Forwarded` ⇄ `Mail.replyType` (**[DA VERIFICARE]**).
- `\Draft` ⇄ `Mail.state` (**[DA VERIFICARE]** valori).
- `\Deleted` + `EXPUNGE`: mappare su `trash_mails`, **non** su cancellazione definitiva, salvo cartella Cestino.
- `\Flagged`: **nessun equivalente noto** in Tuta. Non fingere supporto (rifiutare o tenerlo solo in locale, documentando la scelta).

### 6.4 Sintesi del messaggio RFC 5322

Tuta salva i campi separati; il bridge costruisce il MIME:

- `From` da `Mail.sender` (nome + indirizzo; considerare `differentEnvelopeSender`).
- `To`/`Cc`/`Bcc` da `MailDetails.recipients`; `Reply-To` da `replyTos`.
- `Date` da `MailDetails.sentDate`; `INTERNALDATE` IMAP da `Mail.receivedDate`.
- `Subject` da `Mail.subject`.
- `Message-ID`, `In-Reply-To`, `References`: se `MailDetails.headers` contiene gli header originali, **riusarli**; altrimenti sintetizzare un `Message-ID` stabile (es. `<tuta-{lista}-{elemento}@tuta-bridge.invalid>`). **[DA VERIFICARE]** cosa contiene davvero `Header` e se è presente per la posta in uscita.
- Corpo: HTML (verificare formato/compressione); aggiungere una parte `text/plain` derivata come alternativa.
- Allegati: parti MIME con nome, tipo e Content-ID per le immagini inline.
- Garantire che lo stesso messaggio produca **gli stessi byte** a ogni lettura (stabilità di `RFC822.SIZE`, boundary deterministici), altrimenti Thunderbird si confonde.

### 6.5 Comandi IMAP da supportare (v1)

`CAPABILITY`, `LOGIN` (con password locale del bridge), `LOGOUT`, `NOOP`, `LIST`/`LSUB`, `SELECT`/`EXAMINE`, `STATUS`, `FETCH`/`UID FETCH` (`FLAGS`, `UID`, `INTERNALDATE`, `RFC822.SIZE`, `ENVELOPE`, `BODYSTRUCTURE`, `BODY[]`, `BODY.PEEK[...]`), `SEARCH`/`UID SEARCH` (criteri base; la ricerca sul **corpo** richiede cache locale decifrata), `STORE`, `COPY`/`MOVE`, `EXPUNGE`, `IDLE`, `CREATE`/`DELETE`/`RENAME` (solo se mappabili sulle cartelle Tuta, altrimenti `NO`).
Estensioni utili: `UIDPLUS`, `MOVE`, `SPECIAL-USE`, `IDLE`, `LITERAL+`.

### 6.6 SMTP (submission)

Ascolto locale su `127.0.0.1` (es. porta 1025), `AUTH` con le credenziali locali. Il bridge: analizza il MIME in ingresso, crea la bozza (`DraftService`), la invia (`SendDraftService`) e inserisce la mail in "Inviata" in modo coerente con ciò che Tuta fa lato server. Verificare il comportamento per Bcc, destinatari esterni e allegati grandi.

### 6.7 Compatibilità con client diversi da Thunderbird

**Principio:** il bridge deve essere un server IMAP/SMTP **conforme agli standard**, senza logica specifica per un client. Thunderbird è solo il primo client di test.

**Standard di riferimento** (verificare i testi, non fidarsi della memoria): IMAP4rev1 (RFC 3501; IMAP4rev2, RFC 9051, solo in un secondo momento), UIDPLUS (RFC 4315), IDLE (RFC 2177), SPECIAL-USE (RFC 6154), MOVE (RFC 6851); SMTP submission (RFC 6409) con `AUTH PLAIN` e `AUTH LOGIN` solo sopra TLS.

**Differenze tipiche tra famiglie di client** (conoscenza generale, **[DA VERIFICARE]** con test reali):

| Famiglia | Esempi | Cosa mette sotto stress |
|---|---|---|
| Client desktop | Thunderbird, Evolution, KMail, Geary, Claws | cartelle e special-use, IDLE, più connessioni parallele, ricerca, gestione del certificato tramite interfaccia grafica |
| Strumenti di sincronizzazione | mbsync/isync, offlineimap | scaricano tutto: **coerenza di UID, UIDVALIDITY e RFC822.SIZE**, grandi intervalli di `UID FETCH`, estensione UIDPLUS; sono i test migliori per trovare bug di consistenza |
| Client da terminale | mutt/neomutt, aerc, alpine | uso intensivo di `FETCH`/`SEARCH`, configurazione manuale di TLS e certificato, poca tolleranza a risposte non standard |
| Client chiusi o più rigidi | Apple Mail, Outlook | TLS con certificato attendibile (un certificato autofirmato va installato come attendibile), nessuna autoconfigurazione, supporto variabile per i keyword IMAP |

**Conseguenze di progetto:**

1. **TLS configurabile:** TLS implicito e STARTTLS, certificato generato dal bridge **e** possibilità di fornire il proprio; comando per esportare il certificato/CA. Il testo in chiaro su loopback, se previsto per client che non gestiscono certificati locali, è un'opzione **esplicita e disattivata di default**.
2. **Porte e indirizzo di ascolto configurabili** (porte non privilegiate di default, solo loopback di default).
3. **Autenticazione:** supportare sia `LOGIN` che `AUTHENTICATE PLAIN` per IMAP, e `AUTH PLAIN`/`AUTH LOGIN` per SMTP; nome utente = indirizzo Tuta o un nome fisso, password = quella locale generata dal bridge.
4. **Capability oneste:** annunciare solo ciò che è davvero implementato (niente CONDSTORE/QRESYNC finché non esistono); i client si adattano alle capability dichiarate.
5. **Stabilità dei dati:** UID, UIDVALIDITY, `RFC822.SIZE` e byte del messaggio devono essere identici a ogni lettura; è critico per gli strumenti di sincronizzazione.
6. **Connessioni concorrenti:** molti client aprono più connessioni IMAP insieme. Il server deve gestirle con stato coerente, usando **un solo** backend e **un solo** websocket verso Tuta condivisi.
7. **Messaggi grandi:** gestire i literal e gli allegati grandi in streaming, senza caricare tutto in memoria.
8. **Etichette come keyword IMAP:** i client che non le supportano devono ignorarle senza rompere la sincronizzazione. Decisione da prendere: esporre le etichette *anche* come cartelle virtuali (opzionale, disattivato di default).
9. **Nessun workaround specifico per un client nel nucleo del server.** Se ne serve uno, va isolato in un modulo `compat/`, con test e un commento che nomina il client e la versione.
10. **Matrice di compatibilità:** tenere nel README l'elenco dei client e delle versioni provate, con l'esito.

---

## 7. Sicurezza

- Ascolto **solo su `127.0.0.1`** (o su socket Unix per SMTP/IMAP se il client lo permette). Mai su `0.0.0.0`.
- **Password locale casuale** generata dal bridge per Thunderbird (come Proton Bridge), distinta dalla password Tuta.
- TLS con **certificato autofirmato** generato localmente (con possibilità di fornire il proprio) e documentazione per farlo accettare ai vari client (vedi 6.7); niente IMAP/SMTP in chiaro anche su localhost, se evitabile. Il testo in chiaro su loopback, se previsto, è un'opzione esplicita e disattivata di default.
- Segreti: **keyring di sistema**; mai password, token o chiavi nei log, né in file di configurazione in chiaro. Usare `zeroize` sulle chiavi in memoria.
- **Cache locale decifrata**: è il compromesso principale (le mail in chiaro su disco). Opzioni: database cifrato (SQLCipher o cifratura a livello di file con chiave nel keyring) e cache del corpo opzionale/disattivabile. Decisione da prendere e documentare presto.
- Il log deve essere per default **senza contenuti** (niente soggetti, mittenti o corpi), con un livello di debug esplicito e avvertito.
- Trattare `Credentials` (token + chiave passphrase cifrata) come **equivalenti a una password**.
- Gestire la scadenza/revoca della sessione (token non più valido): richiedere nuovo login, non riprovare in loop.

---

## 8. Roadmap a milestone

Ogni milestone ha un criterio di accettazione verificabile. Procedere in ordine e non saltare M0.

### M0: Ricognizione operativa e setup

- Clonare il repo Tuta (sparse) al commit `5dba964`, creare il progetto del bridge, compilare `tutasdk` con `features = ["net"]`.
- Eseguire `cargo test -p tuta-sdk` (i test che richiedono il server locale restano ignorati).
- Risolvere i punti **[DA VERIFICARE]** più bloccanti: (a) come l'SDK ottiene il modello dei tipi (leggere `type_model_provider.rs`), (b) come caricare una lista di mail (leggere `entity_client.rs`/`crypto_entity_client.rs`), (c) risoluzione della dipendenza `uniffi` da Git fuori dal workspace.
- **Accettazione:** il progetto compila; un documento `NOTES.md` riassume le risposte a (a), (b), (c).

### M1: Login da riga di comando

- Implementare in `tuta-client`: `GET SaltService` → KDF (Argon2id, usando `derive_user_passphrase_key` dell'SDK) → `authVerifier` → `POST SessionService` → gestione challenge (TOTP e approvazione da altro dispositivo con polling) → costruzione `Credentials` → `Sdk::login`.
- Rifiutare gli account bcrypt con messaggio chiaro (non migrare).
- Salvare le credenziali nel keyring; comandi `login`, `logout` (con `CloseSessionService`), `status`.
- **Accettazione:** con un account di prova, `login` ha successo, il token è nel keyring, `status` mostra l'utente.

### M2: Lettura da CLI

- Caricare mailbox e cartelle (`load_user_mailbox`, `load_folders_for_mailbox`, `FolderSystem`).
- Elencare le mail di una cartella con paginazione, caricare `MailDetails`, scaricare e decifrare allegati (portare `BlobFacade.downloadAndDecrypt`).
- Sintetizzare il MIME (sezione 6.4).
- **Accettazione:** `tuta-bridge dump --folder inbox --limit 10` scrive 10 `.eml` apribili da Thunderbird, con corpo e allegati corretti.

### M3: Store e sync iniziale

- Schema SQLite, mapping UID, sync iniziale (lazy per i corpi), `resync` completo.
- **Accettazione:** dopo la sync, lo store è coerente con la mailbox web; rilancio idempotente (nessun UID duplicato o cambiato).

### M4: Event bus

- Websocket con `groupsToLastEventBatchIds`, parsing di `entityUpdate`, applicazione degli aggiornamenti (nuova mail, mail modificata/spostata/cancellata, cambio stato letto), persistenza dei batch ID, gestione `OutOfSyncError` (resync completo), riconnessione con backoff.
- **Accettazione:** una mail inviata all'account compare nello store entro pochi secondi; riavviando il bridge dopo una pausa non si perdono eventi.

### M5: IMAP in sola lettura

- Server IMAP con TLS locale, `LOGIN`, `LIST`, `SELECT`, `FETCH` (tutti gli attributi sopra), `SEARCH` base, `STATUS`, `IDLE`, `NOOP`, `LOGOUT`.
- **Accettazione:** Thunderbird configurato su `127.0.0.1` mostra cartelle e messaggi (con allegati) e riceve le nuove mail via IDLE; inoltre `mbsync`/`isync` (o `offlineimap`) sincronizza l'intera mailbox in una Maildir senza errori e una seconda sincronizzazione **non riscarica nulla** (UID e dimensioni stabili); un client da terminale (neomutt o aerc) legge le stesse mail.

### M6: Scritture IMAP

- `STORE` flag (`\Seen`), `MOVE`/`COPY`, `EXPUNGE` → cestino/archivio, coerenza con gli eventi websocket (evitare "echi" doppi).
- **Accettazione:** segnare come letto/spostare in Thunderbird si riflette nella versione web di Tuta e viceversa; lo stesso vale usando un secondo client di tipo diverso.

### M7: SMTP

- Server di submission, parsing MIME in ingresso, creazione bozza + invio, destinatari interni ed esterni, allegati, Bcc.
- **Accettazione:** mail inviata da Thunderbird a un altro account Tuta e a un indirizzo esterno, ricevuta correttamente; compare in "Inviata". Ripetere con un secondo client (es. `msmtp` o neomutt).

### M8: Rifinitura

- Servizio `systemd --user`, log senza contenuti, gestione errori utente (sessione scaduta, 2FA, modello server cambiato), documentazione di setup per Thunderbird e per gli altri client testati (con matrice di compatibilità), test di regressione.
- **Facoltativo:** calendario/contatti (le facade esistono già nell'SDK), più account.

---

## 9. Registro delle verifiche (da compilare durante il lavoro)

Aggiornare questa tabella a mano mentre si procede.

| # | Domanda aperta | Dove guardare | Esito |
|---|---|---|---|
| 1 | Come l'SDK ottiene il modello dei tipi? Scaricabile dal server a runtime? | `type_model_provider.rs`, `ApplicationTypesService` | |
| 2 | Come si carica una lista di mail con paginazione? | `entity_client.rs`, `crypto_entity_client.rs` | |
| 3 | `uniffi` da Git funziona fuori dal workspace? | `Cargo.toml` del workspace e dell'SDK | |
| 4 | Come si calcola `authVerifier`? | `grep -rn createAuthVerifierAsBase64Url src/` | |
| 5 | Campi esatti di `SecondFactorAuthData` per TOTP | entità generate in `sys`, `LoginFacadeTest.ts` | |
| 6 | Valori di `Mail.state` e `Mail.replyType` | entità/costanti `tutanota_constants.rs` | |
| 7 | Cartelle vs etichette in `Mail.sets` e `MailSetKind` | `folder_system.rs`, `tutanota_constants.rs` | |
| 8 | Contenuto di `MailDetails.headers` e formato/compressione di `Body` | entità, mapper, `MailFacade.ts` | |
| 9 | Una mail spostata mantiene lo stesso ID? | `SimpleMoveMailService`, `MoveMailService` | |
| 10 | Gestione dei destinatari esterni in `sendDraft` | `MailFacade.ts` righe ~753-823 | |
| 11 | Ruolo del messaggio `leaderStatus` per un client singolo | `EventBusClient.ts` | |
| 12 | Cosa dicono i ToS di Tuta sui client non ufficiali | sito di Tuta | |

---

## 10. Strategia di test

- **Unit test** con `TestRestClient` e fixture JSON, sullo schema di `download_mail_test.rs` e dei test dell'SDK.
- **Test di protocollo IMAP/SMTP** in locale con un client scriptabile (es. `imaplib`/`smtplib` di Python) e poi con una **matrice di client reali** (vedi 6.7): Thunderbird, `mbsync`/`isync`, un client da terminale (neomutt o aerc), un client desktop (Evolution o KMail); Apple Mail e Outlook se disponibili.
- **Test d'integrazione contro il server reale**: solo con un **account di prova dedicato**, mai con l'account principale, e con rate basso. Non automatizzarli in CI.
- Test di robustezza: perdita di rete, token scaduto, websocket chiuso, fuori sincronia oltre i 45 giorni, messaggi con allegati grandi, caratteri non ASCII in oggetto e nomi.
- Non esiste un server Tuta locale utilizzabile in questo contesto: i test dell'SDK che richiedono `localhost:9000` non sono eseguibili salvo disporne uno.

---

## 11. Riferimenti

- Repository: `https://github.com/tutao/tutanota` (commit analizzato `5dba964`).
- SDK Rust: `tuta-sdk/rust/sdk/` (`src/lib.rs`, `src/login/`, `src/mail_facade.rs`, `src/folder_system.rs`, `src/blobs/`, `src/crypto/`, `src/entities/generated/tutanota.rs`, `src/services/generated/`, `tests/`).
- Client TypeScript: `src/platform-kit/base/facades/LoginFacade.ts`, `src/app-kit/local-store/event/EventBusClient.ts`, `src/applications/common/api/worker/facades/lazy/{MailFacade,BlobFacade}.ts`.
- Estensione ufficiale Thunderbird (basata su webview, open source), annunciata il 13 febbraio 2026: utile come riferimento per il lato Thunderbird, non per il protocollo.
- Esempio di bridge non ufficiale per un altro provider: Hydroxide (Proton), per la struttura IMAP/SMTP.

---

## 12. Regole operative per l'agente di sviluppo

1. **Nessun contatto con il server Tuta reale senza conferma esplicita** del proprietario; e solo con l'account di prova.
2. **Mai** scrivere password, token, chiavi o contenuti di mail nei log, nei test, nei commit o in fixture. Le fixture devono essere sintetiche.
3. Commit piccoli, con messaggi chiari; un test per ogni comportamento non banale.
4. Mantenere `NOTES.md` con le scoperte e aggiornare la tabella della sezione 9 appena un punto viene chiarito.
5. Se il codice di Tuta contraddice questo documento, **fermarsi, annotare la discrepanza e adattare il piano**.
6. Non reimplementare crittografia: usare sempre le primitive dell'SDK/`crypto-primitives`.
7. Rispettare il modello a milestone: non iniziare M5 senza aver chiuso M2-M4 con il criterio di accettazione soddisfatto.
8. Scegliere e dichiarare subito la licenza del progetto (compatibile con GPLv3).
9. Nessun comportamento specifico di un singolo client nel nucleo del server: eventuali workaround vanno isolati in `compat/` (vedi 6.7).
