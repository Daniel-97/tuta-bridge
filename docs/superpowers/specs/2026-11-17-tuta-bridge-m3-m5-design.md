# Tuta Bridge — design M3–M5: stato minimo, sync e IMAP in lettura

Data: 17 novembre 2026
Stato: proposta, in attesa di approvazione
Riferimenti: `tuta-bridge-spec.md`, `docs/superpowers/specs/2026-11-15-tuta-bridge-m0-m2-design.md`

## 1. Intento

Rendere Thunderbird (e altri client IMAP) utilizzabile contro Tuta senza
duplicare sul bridge la cache dei contenuti. Il bridge conserva solo ciò che
serve al protocollo IMAP: UID stabili, `UIDVALIDITY`, ultimo batch di eventi e
un indice leggero delle intestazioni. Corpi, allegati e cache offline restano
responsabilità di Thunderbird.

## 2. Ambito

- **M3:** SQLite minimale, mapping UID, sync iniziale e `resync`.
- **M4:** event bus websocket, aggiornamenti incrementali, persistenza dei batch.
- **M5:** server IMAP in sola lettura con TLS locale, IDLE e FETCH on demand.

Fuori ambito: scritture IMAP (M6), SMTP (M7), più account, calendario/contatti.

## 3. Decisione: niente cache dei contenuti

Il bridge **non** salva:

- corpi HTML o plain;
- allegati o immagini inline;
- `.eml` completi;
- una copia offline della mailbox.

Ogni `FETCH BODY[]`/`BODY.PEEK[]` sintetizza il messaggio al momento, leggendo
Tuta. Una piccola cache in memoria per sessione evita di rifetchare lo stesso
corpo durante la stessa connessione.

Thunderbird conserva la sua copia locale e gestisce l’offline. Se Thunderbird
chiede un corpo non ancora scaricato mentre è offline, il bridge non può
servirlo: è il compromesso accettato.

## 4. Cosa conserva SQLite

SQLite contiene **stato di protocollo e metadati**, mai contenuti completi:

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    mail_address TEXT NOT NULL UNIQUE
);

CREATE TABLE mailboxes (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    list_id TEXT NOT NULL,              -- lista degli entry della cartella
    name TEXT NOT NULL,
    kind TEXT NOT NULL,                 -- inbox/sent/drafts/trash/junk/archive/custom
    parent_list_id TEXT,
    uidvalidity INTEGER NOT NULL,
    next_uid INTEGER NOT NULL,
    UNIQUE (account_id, list_id)
);

CREATE TABLE messages (
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,
    tuta_list_id TEXT NOT NULL,
    tuta_element_id TEXT NOT NULL,
    received_at_ms INTEGER NOT NULL,
    sent_at_ms INTEGER NOT NULL DEFAULT 0,
    subject TEXT NOT NULL,
    from_name TEXT,
    from_address TEXT NOT NULL,
    recipients_json TEXT,               -- to/cc/bcc/reply_to; NULL finché non arricchito
    unread INTEGER NOT NULL,
    message_id TEXT,
    in_reply_to TEXT,
    references_json TEXT NOT NULL,
    rfc822_size INTEGER,                -- calcolato al primo rendering
    envelope_complete INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox_id, uid),
    UNIQUE (mailbox_id, tuta_list_id, tuta_element_id)
);

CREATE TABLE sync_state (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL,
    last_batch_id TEXT NOT NULL,
    initial_sync_done INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, group_id)
);

PRAGMA user_version = 1;
```

`messages` è un indice di intestazioni, non una cache di posta: nessun corpo,
nessun allegato, nessun blob. I campi che il modello `Mail` non espone (ad
esempio tutti i destinatari e `Message-ID`) restano `NULL` finché un client non
chiede `ENVELOPE`/`RFC822.SIZE`; in quel momento il bridge carica i dettagli,
aggiorna **solo i metadati** nel DB e scarta corpo e allegati.

### Perché l’indice delle intestazioni

Thunderbird e `mbsync` chiedono spesso `FETCH 1:* (ENVELOPE FLAGS INTERNALDATE
RFC822.SIZE)`. Senza indice ogni richiesta diventerebbe una chiamata Tuta per
messaggio. L’indice evita questo e rende `SEARCH` su intestazioni, flag, data e
dimensione una query SQL. È la parte che rende il bridge utilizzabile su
mailbox grandi.

## 5. UID e UIDVALIDITY

- `mailboxes.uidvalidity` viene inizializzata a un valore intero positivo
  (timestamp Unix) e non cambia mai, salvo `resync`.
- `next_uid` parte da 1; ogni nuova mail nella cartella riceve il valore
  corrente e poi `next_uid` viene incrementato nella stessa transazione.
- La sync iniziale assegna gli UID in ordine crescente di arrivo Tuta.
- `UIDNEXT` esposto da IMAP è `next_uid`.
- Spostamento: rimozione del mapping nella cartella di origine, nuovo UID nella
  destinazione.
- `resync`: cancellazione di `messages`, `uid_map` implicito in `messages` e
  `sync_state`; nuova `uidvalidity` per ogni cartella. Thunderbird vede il
  cambio e riscarica gli header.
- Una seconda sync senza novità non cambia UID né `UIDVALIDITY`.

Il mapping UID vive nella tabella `messages` (`mailbox_id`, `uid`,
`tuta_list_id`, `tuta_element_id`); non serve una tabella separata.

## 6. Sync iniziale (M3)

1. Login e caricamento mailbox/cartelle (`MailFacade`).
2. Upsert delle cartelle in `mailboxes`.
3. Per ogni cartella: pagine di `MailSetEntry` e `Mail` (solo intestazioni),
   inserimento in `messages` con UID assegnato.
4. Nessun caricamento di `MailDetails`, allegati o corpi.
5. Transazione per pagina: o UID e indice entrano insieme, o niente.
6. `resync` ripete il processo dopo aver invalidato le cartelle.

Il body index può essere aggiornato in background; l’accettazione M3 richiede
che la seconda esecuzione sia idempotente e non cambi UID.

## 7. Event bus (M4)

- Un solo websocket, con `groupsToLastEventBatchIds` letto da `sync_state`.
- Gli eventi `entityUpdate` aggiornano `messages` e notificano gli watcher IMAP.
- `last_batch_id` viene salvato nella stessa transazione dell’aggiornamento.
- Batch scaduti oltre 45 giorni o `OutOfSyncError`: `resync` completo.
- Riconnessione con backoff; un solo backend per tutte le connessioni IMAP.

## 8. IMAP in lettura (M5)

- `LIST`/`LSUB` leggono `mailboxes`; attributi SPECIAL-USE da `kind`.
- `SELECT`/`EXAMINE`: `UIDVALIDITY`, `UIDNEXT`, `EXISTS` da SQLite.
- `FETCH`/`UID FETCH`:
  - `FLAGS`, `UID`, `INTERNALDATE`, `ENVELOPE`, `RFC822.SIZE` da `messages`;
  - se `envelope_complete = 0` o `rfc822_size` è nullo, il bridge carica i
    dettagli, aggiorna i metadati e scarta il contenuto;
  - `BODYSTRUCTURE`/`BODY[]`/`BODY.PEEK[]` sintetizzano il MIME on demand;
  - `RFC822.SIZE` viene calcolato al primo rendering e salvato come numero.
- `SEARCH`: supporta header, flag, data e dimensione dall’indice. `BODY`/`TEXT`
  non sono supportati in v1 (richiederebbero una cache dei corpi) e vanno
  documentati come limite.
- `IDLE`: watcher in memoria per cartella; nessuna tabella aggiuntiva.
- Messaggi grandi: streaming dei literal, senza caricare tutto in memoria dove
  possibile.
- TLS locale, sole connessioni su loopback, password locale del bridge.

## 9. Sicurezza

- Database `state.sqlite3` in `$XDG_DATA_HOME/tuta-bridge`, directory `0700`,
  file `0600`; anche `-wal`/`-shm` devono restare `0600` (umask del processo).
- Nessun segreto nel database; le credenziali restano nel Secret Service.
- Il database contiene metadati (oggetto, indirizzi, date): va trattato come
  dati personali, non come cache innocua.
- Log senza soggetti, indirizzi o corpi.
- `resync` cancellabile dall’utente; perdere il DB non perde mail, solo gli UID.

## 10. Trade-off

| Scelta | Beneficio | Costo |
|---|---|---|
| Niente cache corpi/allegati | Meno dati decifrati su disco, molto meno codice | Prima lettura più lenta; offline dipende da Thunderbird |
| Indice intestazioni in SQLite | ENVELOPE/SEARCH veloci, startup ragionevole | Metadati su disco |
| UID persistenti | Thunderbird non riscarica tutto | Un piccolo DB obbligatorio |
| `SEARCH BODY` non supportato | Nessuna cache dei corpi | Ricerca sul corpo assente in v1 |

## 11. Criteri di accettazione

- **M3:** dopo la sync iniziale, `messages` contiene le stesse mail della
  cartella Tuta; una seconda sync non cambia UID/UIDVALIDITY; `resync` li cambia
  in modo coerente.
- **M4:** una mail nuova compare nell’indice entro pochi secondi; un riavvio
  dopo una pausa non perde eventi; un batch scaduto porta a `resync`.
- **M5:** Thunderbird vede cartelle, oggetti, mittenti, date e flag; apre un
  corpo con allegato; `IDLE` aggiorna la cartella; `mbsync` completa una seconda
  sincronizzazione senza riscaricare i corpi, e un client terminale legge gli
  stessi messaggi.

## 12. Decisioni lasciate al costruttore

- `rusqlite` (bundled) dietro `spawn_blocking`/connessione dedicata oppure
  `sqlx` SQLite: la scelta non cambia lo schema né le porte.
- Formato esatto di `recipients_json` e `references_json` (JSON compatto).
- Strategia di streaming dei literal IMAP.
- Se offrire un’opzione esplicita per la ricerca sul corpo con download on
  demand, fuori da M5.
