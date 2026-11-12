use super::*;

// Stateless one-way mirror reconciliation for `rbw mirror` into a
// destination collection.
//
// Servers assign fresh cipher ids on import, so a copy can't keep its
// source id. The pairing lives in one state item per destination
// collection instead: a secure note in the destination account's personal
// vault (outside the mirrored collection, so the collection stays an exact
// copy) with a JSON attachment mapping
//
//   destination cipher id -> v1:<source cipher id>:<content digest>
//
// Each run pairs copies with source entries by that map rather than by
// name/username: unchanged entries are skipped, changed ones updated,
// missing ones created, and copies whose source is gone are reported as
// stale (and moved to the trash with `prune`). Nothing is stored on the
// machine running the mirror, and the source account is only ever read.
//
// Losing the state is safe: unmapped copies are adopted by (name,
// username) and rewritten from their source, which re-establishes the map.
const MIRROR_MARKER_VERSION: &str = "v1";
const MIRROR_STATE_FILE_PREFIX: &str = "rbw-mirror-state-";

pub(super) struct MirrorSync {
    // Source cipher id -> full marker value for that entry.
    pub(super) markers: std::collections::HashMap<String, String>,
    // Source cipher id -> number of attachments it carries, when
    // attachments are mirrored. A copy whose attachment count differs (e.g.
    // an upload failed last run) is updated even when its marker matches.
    pub(super) attachment_counts: std::collections::HashMap<String, usize>,
    // Attachments are mirrored: updates replace the copy's attachments.
    pub(super) attachments: bool,
    // Move stale copies in the destination collection to the trash.
    pub(super) prune: bool,
}

impl MirrorSync {
    pub(super) fn from_vault(
        vault: &ExportedVault,
        attachments: bool,
        prune: bool,
    ) -> Self {
        let mut markers = std::collections::HashMap::new();
        let mut attachment_counts = std::collections::HashMap::new();
        for entry in &vault.entries {
            markers.insert(entry.id.clone(), mirror_marker_value(entry));
            if attachments {
                attachment_counts
                    .insert(entry.id.clone(), entry.attachments.len());
            }
        }
        Self {
            markers,
            attachment_counts,
            attachments,
            prune,
        }
    }
}

pub(super) fn mirror_marker_value(entry: &ExportedEntry) -> String {
    use sha2::Digest as _;
    // `ExportedEntry` serializes deterministically (struct field order,
    // `Vec`s in vault order) and includes attachment contents when they
    // were exported, so any source change -- including a replaced
    // attachment -- changes the digest.
    let bytes = serde_json::to_vec(entry).unwrap_or_default();
    let digest = sha2::Sha256::digest(&bytes);
    let hex = digest.iter().take(16).fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    format!("{MIRROR_MARKER_VERSION}:{}:{hex}", entry.id)
}

// The source cipher id a marker value names, if it is a marker at all.
pub(super) fn mirror_marker_source_id(value: &str) -> Option<&str> {
    let rest = value
        .strip_prefix(MIRROR_MARKER_VERSION)?
        .strip_prefix(':')?;
    let (id, digest) = rest.rsplit_once(':')?;
    (!id.is_empty() && !digest.is_empty()).then_some(id)
}

// One source entry, as the planner sees it.
pub(super) struct MirrorSource {
    pub(super) source_id: Option<String>,
    pub(super) key: (String, Option<String>),
    pub(super) marker: Option<String>,
    // `None` when attachments aren't mirrored (never compared).
    pub(super) attachments: Option<usize>,
}

// One entry currently in the destination collection.
pub(super) struct MirrorDest {
    pub(super) key: (String, Option<String>),
    pub(super) marker: Option<String>,
    pub(super) attachments: usize,
    // False when the copy's organization doesn't match the destination
    // collection's: the server rejects edits to it, so it is never reused.
    pub(super) org_ok: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MirrorAction {
    Unchanged(usize),
    Update(usize),
    Create,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct MirrorPlan {
    // One action per source entry, same order as the input; indices point
    // into the destination slice.
    pub(super) actions: Vec<MirrorAction>,
    // Destination copies that no source entry maps to.
    pub(super) stale: Vec<usize>,
}

pub(super) fn plan_mirror(
    sources: &[MirrorSource],
    dests: &[MirrorDest],
) -> MirrorPlan {
    let mut actions: Vec<Option<MirrorAction>> =
        sources.iter().map(|_| None).collect();
    let mut used = vec![false; dests.len()];

    // 1. Copies that carry a marker are matched by source id. The first
    //    copy wins; further copies of the same source are stale.
    let mut by_source: std::collections::HashMap<&str, Vec<usize>> =
        std::collections::HashMap::new();
    for (index, dest) in dests.iter().enumerate() {
        if !dest.org_ok {
            continue;
        }
        if let Some(id) =
            dest.marker.as_deref().and_then(mirror_marker_source_id)
        {
            by_source.entry(id).or_default().push(index);
        }
    }
    for (source_index, source) in sources.iter().enumerate() {
        let Some(id) = source.source_id.as_deref() else {
            continue;
        };
        let Some(&dest_index) =
            by_source.get(id).and_then(|candidates| candidates.first())
        else {
            continue;
        };
        used[dest_index] = true;
        let dest = &dests[dest_index];
        actions[source_index] = Some(
            if source.marker.is_some()
                && dest.marker == source.marker
                && source.attachments.is_none_or(|n| n == dest.attachments)
            {
                MirrorAction::Unchanged(dest_index)
            } else {
                MirrorAction::Update(dest_index)
            },
        );
    }

    // 2. Copies without a marker (made before markers existed) are adopted
    //    by (name, username). Same-key entries are interchangeable here:
    //    the update rewrites the whole copy from its source, so pairing
    //    them in order is exact.
    let mut unmarked: std::collections::HashMap<
        &(String, Option<String>),
        std::collections::VecDeque<usize>,
    > = std::collections::HashMap::new();
    for (index, dest) in dests.iter().enumerate() {
        let has_marker = dest
            .marker
            .as_deref()
            .and_then(mirror_marker_source_id)
            .is_some();
        if dest.org_ok && !has_marker {
            unmarked.entry(&dest.key).or_default().push_back(index);
        }
    }
    for (source_index, source) in sources.iter().enumerate() {
        if actions[source_index].is_some() {
            continue;
        }
        let adopted = unmarked
            .get_mut(&source.key)
            .and_then(std::collections::VecDeque::pop_front);
        actions[source_index] =
            Some(adopted.map_or(MirrorAction::Create, |dest_index| {
                used[dest_index] = true;
                MirrorAction::Update(dest_index)
            }));
    }

    MirrorPlan {
        actions: actions
            .into_iter()
            .map(|action| action.unwrap_or(MirrorAction::Create))
            .collect(),
        stale: (0..dests.len()).filter(|&index| !used[index]).collect(),
    }
}

pub(super) fn mirror_state_name(dest_collection_id: &str) -> String {
    format!("rbw mirror state {dest_collection_id}")
}

// Marker recorded for a copy whose update failed: keeps the pairing but
// never matches a real marker, so the next run updates it again.
pub(super) fn mirror_retry_marker(source_id: &str) -> String {
    format!("{MIRROR_MARKER_VERSION}:{source_id}:retry")
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(super) struct MirrorState {
    pub(super) version: u32,
    pub(super) dest_collection_id: String,
    // Destination cipher id -> marker.
    pub(super) copies: std::collections::BTreeMap<String, String>,
}

// The destination account's state item for `dest_collection_id`, if any.
pub(super) fn find_mirror_state_entry(
    db: &rbw::db::Db,
    dest_collection_id: &str,
) -> Option<rbw::db::Entry> {
    let wanted = mirror_state_name(dest_collection_id);
    db.entries
        .iter()
        .filter(|entry| {
            !entry.deleted
                && entry.org_id.is_none()
                && matches!(entry.data, rbw::db::EntryData::SecureNote)
        })
        .find(|entry| {
            crate::actions::decrypt(&entry.name, entry.key.as_deref(), None)
                .is_ok_and(|name| name == wanted)
        })
        .cloned()
}

// Reads the newest state file attached to the state item. A missing or
// unreadable state is an empty one: every copy is then adopted.
pub(super) fn load_mirror_state(
    db: &mut rbw::db::Db,
    dest_collection_id: &str,
) -> anyhow::Result<MirrorState> {
    let Some(entry) = find_mirror_state_entry(db, dest_collection_id) else {
        return Ok(MirrorState::default());
    };
    let decrypted = decrypt_cipher(&entry)?;
    let attachments = export_attachments(db, &entry, &decrypted.attachments)?;
    let newest = attachments
        .iter()
        .filter(|a| a.file_name.starts_with(MIRROR_STATE_FILE_PREFIX))
        .max_by(|a, b| a.file_name.cmp(&b.file_name));
    let Some(newest) = newest else {
        return Ok(MirrorState::default());
    };
    let bytes = rbw::base64::decode(&newest.data_base64)?;
    let state: MirrorState = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(e) => {
            eprintln!(
                "{} ignoring unreadable mirror state ({e}); copies will be \
                 matched by name/username this run",
                style::warning("Warning:", stdout_supports_color()),
            );
            return Ok(MirrorState::default());
        }
    };
    if state.version != 1 || state.dest_collection_id != dest_collection_id {
        return Ok(MirrorState::default());
    }
    Ok(state)
}

fn store_tokens(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    tokens: Option<rbw::actions::RefreshedTokens>,
) -> anyhow::Result<()> {
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(db)?;
    }
    Ok(())
}

// Writes `state` as a new attachment on the state item (creating the item
// on first use), then removes the older state files. The new file is
// uploaded before the old ones are deleted, so an interrupted save leaves
// at least one readable state behind.
pub(super) fn save_mirror_state(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    state: &MirrorState,
) -> anyhow::Result<()> {
    let entry = if let Some(entry) =
        find_mirror_state_entry(db, &state.dest_collection_id)
    {
        entry
    } else {
        let name = crate::actions::encrypt(
            &mirror_state_name(&state.dest_collection_id),
            None,
            None,
        )?;
        let notes = crate::actions::encrypt(
            "Maintained by `rbw mirror`: maps the copies in a mirrored \
             collection to their source entries. Deleting it is safe; the \
             next mirror run rebuilds it.",
            None,
            None,
        )?;
        let (tokens, _id) = rbw::actions::add(
            access_token,
            refresh_token,
            &name,
            &rbw::db::EntryData::SecureNote,
            &[],
            Some(&notes),
            None,
        )?;
        store_tokens(db, access_token, refresh_token, tokens)?;
        crate::actions::sync()?;
        *db = load_db()?;
        *access_token = db.access_token.clone().unwrap_or_default();
        *refresh_token = db.refresh_token.clone().unwrap_or_default();
        find_mirror_state_entry(db, &state.dest_collection_id)
            .context("the mirror state item was not created")?
    };

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let file = serde_json::json!({
        "file_name": format!("{MIRROR_STATE_FILE_PREFIX}{stamp:016}.json"),
        "data_base64": rbw::base64::encode(serde_json::to_vec(state)?),
    });
    let (restored, failed) = upload_imported_attachments(
        db,
        access_token,
        refresh_token,
        &entry,
        &[file],
        &std::collections::HashSet::new(),
    )?;
    anyhow::ensure!(
        restored == 1 && failed == 0,
        "failed to upload the mirror state"
    );
    for old in &entry.attachments {
        let (tokens, ()) = rbw::actions::delete_attachment(
            access_token,
            refresh_token,
            &entry.id,
            &old.id,
        )?;
        store_tokens(db, access_token, refresh_token, tokens)?;
    }
    Ok(())
}

// The (destination cipher id -> marker) map after a run: every copy that
// is now known to hold its source's current contents, plus the retry
// markers of copies whose update failed. Fresh copies are only mapped
// when their (name, username) key is unique among this run's creations
// and among the unmapped copies; any others are adopted (and rewritten)
// by the next run instead of being paired by guesswork.
pub(super) fn next_mirror_state(
    sources: &[MirrorSource],
    actions: &[MirrorAction],
    dest_ids: &[String],
    failed_updates: &std::collections::HashSet<String>,
    after: &[(String, (String, Option<String>))],
) -> std::collections::BTreeMap<String, String> {
    let mut copies = std::collections::BTreeMap::new();
    let mut created_keys: std::collections::HashMap<
        &(String, Option<String>),
        Vec<usize>,
    > = std::collections::HashMap::new();
    for (index, (source, action)) in sources.iter().zip(actions).enumerate() {
        let (Some(source_id), Some(marker)) =
            (source.source_id.as_deref(), source.marker.as_ref())
        else {
            continue;
        };
        match action {
            MirrorAction::Unchanged(dest) | MirrorAction::Update(dest) => {
                let id = &dest_ids[*dest];
                let value = if failed_updates.contains(id) {
                    mirror_retry_marker(source_id)
                } else {
                    marker.clone()
                };
                copies.insert(id.clone(), value);
            }
            MirrorAction::Create => {
                created_keys.entry(&source.key).or_default().push(index);
            }
        }
    }

    let known: std::collections::HashSet<&str> =
        dest_ids.iter().map(String::as_str).collect();
    let mut fresh: std::collections::HashMap<
        &(String, Option<String>),
        Vec<&str>,
    > = std::collections::HashMap::new();
    for (id, key) in after {
        if !known.contains(id.as_str()) && !copies.contains_key(id) {
            fresh.entry(key).or_default().push(id);
        }
    }
    for (key, indices) in created_keys {
        let (&[index], Some(&[id])) =
            (indices.as_slice(), fresh.get(key).map(Vec::as_slice))
        else {
            continue;
        };
        if let Some(marker) = sources[index].marker.clone() {
            copies.insert(id.to_string(), marker);
        }
    }
    copies
}

// Every live entry in the destination collection: its (name, username)
// key and its marker from `state`, if mapped.
pub(super) fn read_mirror_dests(
    db: &rbw::db::Db,
    dest_collection_id: &str,
    dest_org_id: &str,
    state: &MirrorState,
) -> anyhow::Result<Vec<(rbw::db::Entry, MirrorDest)>> {
    let members: Vec<&rbw::db::Entry> = db
        .entries
        .iter()
        // Trashed copies are already gone from the mirror's point of view:
        // they are neither reused nor pruned again.
        .filter(|entry| {
            !entry.deleted
                && entry
                    .collection_ids
                    .iter()
                    .any(|id| id == dest_collection_id)
        })
        .collect();

    let mut requests = BatchRequests::new();
    let plans: Vec<(usize, Option<usize>)> = members
        .iter()
        .map(|entry| {
            let key = entry.key.as_deref();
            let org = entry.org_id.as_deref();
            let name = requests.push(&entry.name, key, org);
            let user = match &entry.data {
                rbw::db::EntryData::Login {
                    username: Some(username),
                    ..
                } => Some(requests.push(username, key, org)),
                _ => None,
            };
            (name, user)
        })
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let plain = |index: usize| match &results[index] {
        rbw::protocol::DecryptResult::Success { plaintext } => {
            Some(plaintext.clone())
        }
        rbw::protocol::DecryptResult::Failure { .. } => None,
    };

    Ok(members
        .into_iter()
        .zip(plans)
        .map(|(entry, (name, user))| {
            // An entry whose name can't be decrypted can't be matched by
            // key; it is still listed so it can be reported as stale.
            let key = entry_match_key(
                plain(name).unwrap_or_default(),
                user.and_then(plain),
            );
            let dest = MirrorDest {
                key,
                marker: state.copies.get(&entry.id).cloned(),
                attachments: entry.attachments.len(),
                org_ok: entry_organization_matches_destination(
                    entry.org_id.as_deref(),
                    dest_org_id,
                ),
            };
            (entry.clone(), dest)
        })
        .collect())
}
