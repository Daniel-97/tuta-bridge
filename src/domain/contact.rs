//! A decrypted Tuta contact, reduced to what the CardDAV listener
//! renders as vCard.
//!
//! These types deliberately omit `Debug`: they carry names, addresses
//! and notes, which must never end up in logs or error texts.

/// The kind of an email address, phone number, postal address or
/// website, as Tuta labels it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ContactFieldKind {
    Home,
    Work,
    Mobile,
    Fax,
    Other,
    /// A user-defined label; the label text itself is not kept.
    Custom,
}

/// One typed value of a contact (an address, a number, a URL).
#[derive(Clone, PartialEq, Eq)]
pub struct ContactField {
    pub kind: ContactFieldKind,
    pub value: String,
}

/// How a related person relates to the contact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ContactRelationKind {
    Parent,
    Sibling,
    Child,
    Friend,
    Relative,
    Spouse,
    Partner,
    Assistant,
    Manager,
    Other,
}

/// A related person, by name (Tuta stores free text, not a reference).
#[derive(Clone, PartialEq, Eq)]
pub struct ContactRelation {
    pub kind: ContactRelationKind,
    pub person: String,
}

/// One contact of the user's address book.
///
/// Empty strings mean "not set". Dates keep Tuta's ISO form
/// (`YYYY-MM-DD`, or `--MM-DD` without a year).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ContactCard {
    /// The Tuta contact list the contact lives in.
    pub list_id: String,
    /// The contact's element id: its `UID` and its CardDAV href.
    pub element_id: String,
    /// Honorific prefix (`Dr.`).
    pub title: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub name_suffix: String,
    pub nickname: String,
    pub company: String,
    pub department: String,
    /// The job title.
    pub role: String,
    pub birthday: Option<String>,
    /// Anniversaries (Tuta's custom dates of the anniversary kind).
    pub anniversaries: Vec<String>,
    pub comment: String,
    pub emails: Vec<ContactField>,
    pub phones: Vec<ContactField>,
    pub addresses: Vec<ContactField>,
    pub websites: Vec<ContactField>,
    pub relations: Vec<ContactRelation>,
}
