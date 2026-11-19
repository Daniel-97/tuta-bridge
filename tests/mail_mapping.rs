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
fn system_folders_without_a_name_use_the_kind_default() {
    let inbox = folder_from_parts("l", "", 1).unwrap();
    assert_eq!(inbox.kind, FolderKind::Inbox);
    assert_eq!(inbox.name, "Inbox");

    let trash = folder_from_parts("l", "", 3).unwrap();
    assert_eq!(trash.kind, FolderKind::Trash);
    assert_eq!(trash.name, "Trash");
}

#[test]
fn custom_folders_keep_their_name_verbatim() {
    let custom = folder_from_parts("l", "Custom Name", 0).unwrap();
    assert_eq!(custom.kind, FolderKind::Custom);
    assert_eq!(custom.name, "Custom Name");
}

#[test]
fn custom_folders_with_an_empty_name_are_skipped() {
    assert!(folder_from_parts("l", "", 0).is_none());
}

#[test]
fn whitespace_only_names_count_as_empty_for_system_kinds() {
    // Tuta's MailSetKind: ARCHIVE = 4 (DRAFT = 6), so a type-4 set maps to Archive.
    let archive = folder_from_parts("l", "  ", 4).unwrap();
    assert_eq!(archive.kind, FolderKind::Archive);
    assert_eq!(archive.name, "Archive");
}

#[test]
fn summary_keeps_ids_and_time() {
    let s = summary_from_parts("l", "e", 5, "subject", true);
    assert_eq!(s.list_id, "l");
    assert_eq!(s.element_id, "e");
    assert!(s.unread);
}

/// A fake list of `total` descending ids served `count` at a time, recording
/// every `(start, count)` request.
async fn paged(total: u32, limit: usize, page_size: usize) -> (Vec<u32>, Vec<(String, usize)>) {
    use std::sync::Mutex;
    use tuta_bridge::adapters::tuta::mail_source::load_paged;

    let requests = Mutex::new(Vec::new());
    let items = load_paged(
        limit,
        page_size,
        "max".to_string(),
        |start: String, count: usize| {
            requests.lock().unwrap().push((start.clone(), count));
            let below = start.parse::<u32>().unwrap_or(total + 1);
            async move { Ok((1..below).rev().take(count).collect::<Vec<u32>>()) }
        },
        |id: &u32| Some(id.to_string()),
    )
    .await
    .unwrap();
    let requests = requests.into_inner().unwrap();
    (items, requests)
}

#[tokio::test]
async fn a_limit_above_the_page_size_is_loaded_in_pages() {
    let (items, requests) = paged(25, 23, 10).await;
    assert_eq!(items, (3..=25).rev().collect::<Vec<u32>>());
    assert_eq!(
        requests,
        vec![
            ("max".to_string(), 10),
            ("16".to_string(), 10),
            ("6".to_string(), 3),
        ]
    );
}

#[tokio::test]
async fn paging_stops_at_the_end_of_the_list() {
    let (items, requests) = paged(12, 1000, 10).await;
    assert_eq!(items.len(), 12);
    assert_eq!(requests.len(), 2, "a short page ends the listing");

    let (items, requests) = paged(0, 50, 10).await;
    assert!(items.is_empty());
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn a_small_limit_requests_only_that_many() {
    let (items, requests) = paged(500, 3, 1000).await;
    assert_eq!(items, vec![500, 499, 498]);
    assert_eq!(requests, vec![("max".to_string(), 3)]);
}

#[tokio::test]
async fn a_cursor_that_does_not_advance_ends_the_listing() {
    use tuta_bridge::adapters::tuta::mail_source::load_paged;

    let mut calls = 0;
    let items = load_paged(
        100,
        2,
        "max".to_string(),
        |_start: String, _count: usize| {
            calls += 1;
            async { Ok(vec![7_u32, 7]) }
        },
        |_id: &u32| Some("same".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(calls, 2);
}
