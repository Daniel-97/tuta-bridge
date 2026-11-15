use tuta_bridge::adapters::tuta::mail_source::{
    folder_from_parts, folder_kind, resolve_folder, summary_from_parts,
};
use tuta_bridge::domain::{Error, FolderKind};

#[test]
fn maps_system_folder_types() {
    assert_eq!(folder_kind(1), Some(FolderKind::Inbox));
    assert_eq!(folder_kind(2), Some(FolderKind::Sent));
    assert_eq!(folder_kind(3), Some(FolderKind::Trash));
    assert_eq!(folder_kind(4), Some(FolderKind::Archive));
    assert_eq!(folder_kind(5), Some(FolderKind::Junk));
    assert_eq!(folder_kind(6), Some(FolderKind::Drafts));
    assert_eq!(folder_kind(0), Some(FolderKind::Custom));
    assert_eq!(folder_kind(7), None); // "All" is skipped
}

#[test]
fn resolves_folder_aliases_and_custom_names() {
    let folders = vec![
        folder_from_parts("i", "Inbox", 1).unwrap(),
        folder_from_parts("c", "Projects", 0).unwrap(),
    ];
    assert_eq!(resolve_folder(&folders, "INBOX").unwrap().list_id, "i");
    assert_eq!(resolve_folder(&folders, "projects").unwrap().list_id, "c");
    assert!(matches!(
        resolve_folder(&folders, "missing"),
        Err(Error::FolderNotFound(_))
    ));
}

#[test]
fn summary_keeps_ids_and_time() {
    let s = summary_from_parts("l", "e", 5, "subject", true);
    assert_eq!(s.list_id, "l");
    assert_eq!(s.element_id, "e");
    assert!(s.unread);
}
