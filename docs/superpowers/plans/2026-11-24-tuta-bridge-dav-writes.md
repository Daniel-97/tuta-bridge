# Tuta Bridge DAV Writes Implementation Plan - CardDAV and CalDAV

**Goal:** Let a standard client create, edit and delete Tuta contacts and
calendar events through the bridge's CardDAV and CalDAV servers, with every
change reflected in Tuta and in the local caches without double-echo - the
DAV equivalent of what M6 did for IMAP.

**Architecture:** A new write port per feature (`ContactWriter`,
`CalendarWriter`) over the SDK's generic encrypted-entity write path:
`CryptoEntityClient::create_instance` / `update_instance` (the SDK derives
the session key and owner-encrypts it, the same way the web client writes
these entities - no hand-rolled cryptography, unlike the SMTP draft path)
and a raw authenticated DELETE on the entity REST endpoint for deletions (decision 8: the SDK's `erase_list_element` is a `todo!()` at the pinned rev). The DAV handlers gain
`PUT` and `DELETE` dispatch with RFC preconditions (`If-Match`,
`If-None-Match: *`); every other write method stays the existing fixed
`403`. After the remote write succeeds, the handler applies an optimistic
local update (upsert with the new ETag) so the client sees the new ETag in
the PUT response; the event echo is idempotent by construction - the
contact upsert already skips rows whose ETag is unchanged, and the calendar
row carries a content fingerprint.

**Tech Stack:** existing tokio/TLS/quick-xml stack; hand-written vCard 4.0
and iCalendar VEVENT parsers (same style as the existing generators: no new
dependencies); existing SQLite caches (no schema change: the contact and
calendar rows already carry everything the write path needs).

## Design decisions (controller - user review gates this plan)

1. **The parser accepts what the bridge serves, plus the common shapes.**
   The vCard importer maps the same fields the exporter emits (and the
   standard variations Thunderbird writes); the iCalendar importer accepts
   the RRULE forms the exporter generates (`FREQ`, `INTERVAL`, `UNTIL`,
   `COUNT`, weekly `BYDAY`, and the month-end `BYMONTHDAY/BYSETPOS=-1`
   pattern to Tuta's end-of-month flag). Anything else - per-property for
   vCard, per-event for iCal - is dropped or refused per decision 3.
2. **Contacts: full round-trip.** Unknown vCard properties are dropped
   silently, exactly like Tuta's own importer; the fields we do not
   support were never exported either (README documents the set). PUT on
   an existing href updates in place; DELETE tombstones the row (the
   sync-collection already speaks tombstones).
3. **Calendars: explicit refusal over silent loss.** An event is refused
   (403 with a fixed precondition body) when it carries: attendees other
   than the organizer (invitation mails are out of scope - accepting the
   event without inviting them would be silent breakage), a
   `RECURRENCE-ID` or `EXDATE` (occurrence-level editing is out of
   scope), or an RRULE shape the exporter never generates. VALARM is
   accepted and ignored - documented in the README, because refusing a
   whole event over a reminder would be hostile and reminders are not
   carried to Tuta either way.
4. **Which list an event goes to:** the current behavior (second review,
   2026-11-25) follows the web client's `isLongEvent`: **any** repeating
   event (bounded `UNTIL`/`COUNT` included) goes to the calendar's
   long-events list, as does a one-off longer than the 15-day event-id
   randomization range; only a short one-off goes to the short-events
   list. An in-place update may not move an event between the lists.
   (This supersedes the original split that filed bounded rules short.)
5. **Preconditions are honored:** `If-Match` on update, `If-None-Match: *`
   on create; a stale `If-Match` answers `412`. The privilege sets flip
   from read-only to writable on both collections so clients stop marking
   them read-only.
6. **No echo machinery of our own:** our write produces the same Tuta
   events the web client's edits do; the existing contact/calendar event
   handling refreshes the caches, and idempotence falls out of the
   unchanged-ETag/fingerprint upserts. A failed remote write leaves the
   cache and the ETag untouched (the client retries).
7. **Not in scope (documented):** invitations (attendee mail), shared
   calendars, alarms carried to Tuta, photo import, per-occurrence
   edits, address-book or calendar creation and deletion (`MKCOL` stays
   the fixed 403).

8. **Deletions go through the raw entity DELETE, mirroring the web
   client.** The pinned SDK's `EntityClient::erase_list_element` (and
   `erase_element`) is a `todo!()` - calling it would panic at runtime, and
   no facade or generated service deletes single instances. The web
   client's `entityClient.erase` is a plain authenticated
   `DELETE /rest/tutanota/{contact|calendarevent}/{listId}/{elementId}`
   with no cryptography involved, and the bridge already speaks that
   dialect (the `SecondFactorAuthService` cancellation in
   `pre_session.rs`). The writer issues the same DELETE through the
   session's `RestClient` with `cv`, `v` (type model version 118 for both
   types) and `accessToken`; a 404 maps to "already gone", auth failures
   to the session error, `400`/`403`/`473` to the fixed permanent
   refusal (`403`), and `5xx` or a transport failure to the retryable
   network error. (Second review, 2026-11-25: the earlier "everything
   else network" mapping was too coarse.) A conditional DELETE is not a
   raw delete: a contact re-checks the request ETag against the freshly
   loaded card, and an event series verifies **every** row (each row's
   cached fingerprint, or `*` for existence) before its first remote
   delete, so a mismatch answers `412` and removes nothing; a network
   failure part way through the deletes may still be partial.

9. **Creation is split by id type, and event creation is refused.**
   Verified against the pinned SDK and the web client: the web client
   pre-assigns element ids, registers a kdf nonce per new encrypted
   instance through `UpdateKdfNonceService`, and POSTs with the id in the
   body; the Rust SDK's generic create does none of this - it POSTs with
   `_id: null` (entity_client.rs nulls the id field on every POST) and
   never registers a nonce. For custom-id types (`CalendarEvent`) the
   create cannot work: the POST return carries no id for custom types,
   so a null-id event would be created unreachable. Event creation is
   therefore refused with a fixed 403 precondition (upstream-blocked, the
   same family as the SMTP E2E caveat: the SDK does not expose the web
   client's machinery); events support update and delete. For
   generated-id types (`Contact`) the SDK create is the only create API
   the SDK has - the same API the mobile clients use - so contact
   creation stays, but it is the first manual-acceptance checkpoint:
   if the live server rejects the null-id create, contact creation
   flips to the same 403 and the README notes it as upstream-blocked.

10. **The contact list id is resolved structurally, never learned
   from cards.** The write path needs the account's contacts list id,
   and learning it from the first rendered card leaves an empty
   address book unable to create its first contact. The SDK resolves
   it structurally: load the `RootInstance` at
   `(user group id, ContactList root id)` - the same chain
   `ContactFacade::fetch_contact_lists` walks - then the
   `ContactList` entity, whose `contacts` field is the list id,
   regardless of how many contacts exist. The book load/refresh (Task 6
   wiring) always records it in `contact_books.list_id`, so the 409 of
   decision "book not loaded" only ever fires before the first load.

## Global Constraints

- All code, identifiers, comments, and commit messages in English.
- Never write passwords, tokens, subjects, addresses, names, or event
  titles to logs or errors; the DAV logs carry methods, resource names,
  and counters only.
- The caches stay metadata-only: PUT bodies are parsed in memory, never
  written to disk.
- No automated test contacts the real Tuta server; loopback only.
- The Tuta SDK pin stays `rev = 5dba96493532804ebd5a541024aa217ca3b7874d`.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass
  before every commit.

## Review Focus

1. A PUT racing the event echo of its own write: the upsert with the new
   ETag and the echo must not double-count the revision (contact ctag,
   calendar ctag).
2. `If-Match` must be enforced against the *stored* ETag, not the
   rendered body, so an unchanged reload can never answer `412`.
3. The importer must never accept-and-then-mangle: an RRULE it cannot map
   refuses the PUT whole.
4. DELETE of a resource that vanished remotely answers `404`, not a
   tombstone for a row that never existed.
5. Contact groups (Thunderbird's mailing-list categories) must not be
   creatable: `MKCOL` stays the fixed 403.

## File Structure

Create:

- `src/ports/dav_writer.rs` - the two write ports.
- `src/adapters/carddav/import.rs` - vCard 4.0 parser to `ContactPatch`.
- `src/adapters/caldav/import.rs` - VEVENT parser to `EventPatch`.
- `src/adapters/tuta/dav_writer.rs` - the SDK implementation (contact +
  calendar create/update/delete).
- `tests/carddav_writes.rs`, `tests/caldav_writes.rs`.

Modify: `src/adapters/carddav/handler.rs`, `src/adapters/caldav/handler.rs`
(PUT/DELETE + preconditions + writable privilege sets), the `DavHandler`
trait, `src/adapters/sqlite_contacts.rs` / `sqlite_calendar.rs` (upsert
with caller-supplied ETag), session wiring, README + details doc + NOTES.

---

### Task 1: write ports and the SDK writer

**Files:** create `src/ports/dav_writer.rs`, `src/adapters/tuta/dav_writer.rs`;
wire into the module lists and the DAV session construction.

TDD first: a fake writer records calls; the handler must reach the port and
nothing else. Verify against the pinned SDK (and the web client's
`constructContact`) that `create_instance` fills `_ownerEncSessionKey` and
that `Contact._ownerGroup` comes from the contact list's owner group; the
same check for `CalendarEvent` against the calendar's owner group. Commit:
`feat: add the dav write ports`.

### Task 2: vCard 4.0 importer

**Files:** create `src/adapters/carddav/import.rs`.

Unfolding (LF or CRLF), unescaping, property/param parsing, the field
mapping of decision 1, silent drop of unknown properties. A round-trip
test pins the contract: `parse(render(contact))` reproduces the same
`ContactPatch` for every field the exporter emits. Commit:
`feat: import vcard 4.0 for carddav writes`.

### Task 3: CardDAV PUT and DELETE

**Files:** modify `src/adapters/carddav/handler.rs`, `sqlite_contacts.rs`,
tests.

PUT: parse, preconditions per decision 5, remote write, optimistic upsert
with the new ETag (render the updated contact to compute it), answer `201`
on create and `204` with the new `ETag` on update. DELETE: `If-Match`,
remote delete, tombstone. Echo idempotence test (review focus 1) and the
unchanged-ETag reload test (review focus 2). Commit:
`feat: accept carddav writes`.

### Task 4: iCalendar VEVENT importer

**Files:** create `src/adapters/caldav/import.rs`.

Unfolding, unescaping, `DTSTART`/`DTEND` with `TZID` or `VALUE=DATE`,
`SUMMARY`/`DESCRIPTION`/`LOCATION`, `ORGANIZER` (must be one of the
account's addresses, else refuse), the RRULE subset of decision 1 with the
refusals of decision 3, VALARM ignored. Commit:
`feat: import vevents for caldav writes`.

### Task 5: CalDAV PUT and DELETE

**Files:** modify `src/adapters/caldav/handler.rs`, `sqlite_calendar.rs`,
tests.

Same shape as Task 3, plus the list choice of decision 4 and the
whole-event refusal body of decision 3. Commit:
`feat: accept caldav writes`.

### Task 6: wiring and privilege flip

**Files:** the `DavHandler` trait, session wiring in `watch.rs`, the
privilege sets, `serve` startup lines, tests/serve.rs e2e.

Commit: `feat: wire dav writes into serve`.

### Task 7: documentation and manual acceptance

README features table flips CardDAV/CalDAV to read/write with the
documented limits; details doc gains the write sections; NOTES records the
SDK write path and the refusal contract. Manual acceptance: create/edit/
delete a contact and a single event and a weekly series in Thunderbird;
verify in the Tuta web client, then the reverse direction; check the
split-series edit case still behaves; second refresh transfers nothing.
Commit: `docs: document dav writes`.
