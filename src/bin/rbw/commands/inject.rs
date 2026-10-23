use super::*;

pub(super) struct InjectContext {
    pub(super) entries: Vec<rbw::db::Entry>,
}

impl InjectContext {
    pub(super) fn load() -> anyhow::Result<Self> {
        unlock(None, None)?;

        let db = load_db()?;
        Ok(Self {
            entries: db.entries,
        })
    }

    pub(super) fn render_input(
        &self,
        input: Option<&std::path::Path>,
    ) -> anyhow::Result<String> {
        let template = read_inject_template(input)?;
        InjectTemplate::new(&template)
            .render(|reference| self.resolve(reference))
    }

    pub(super) fn env_bindings_from_file(
        &self,
        env_file: &std::path::Path,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let template =
            std::fs::read_to_string(env_file).with_context(|| {
                format!("failed to read env file {}", env_file.display())
            })?;
        parse_run_env_file(&template, |reference| self.resolve(reference))
            .with_context(|| {
                format!("failed to parse env file {}", env_file.display())
            })
    }

    pub(super) fn resolve(
        &self,
        reference: &InjectReference,
    ) -> anyhow::Result<String> {
        let (entry, _) = self.find_entry_raw(&reference.target)?;
        let decrypted = decrypt_cipher(&entry).with_context(|| {
            format!("failed to decrypt entry '{}'", reference.id)
        })?;
        resolve_inject_value(&decrypted, reference.field.as_deref())
            .with_context(|| {
                format!(
                    "failed to resolve inject reference '{}'",
                    reference.id
                )
            })
    }

    pub(super) fn find_entry_raw(
        &self,
        target: &InjectReferenceTarget,
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                decrypt_search_cipher(entry)
                    .map(|decrypted| (entry.clone(), decrypted))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        target.find_entry(&entries)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum InjectReferenceTarget {
    Uuid(String),
    Name(String),
}

impl InjectReferenceTarget {
    pub(super) fn parse(raw_target: &str) -> anyhow::Result<Self> {
        if let Ok(uuid) = uuid::Uuid::parse_str(raw_target) {
            Ok(Self::Uuid(uuid.to_string()))
        } else if Self::is_valid_name(raw_target) {
            Ok(Self::Name(raw_target.to_string()))
        } else {
            anyhow::bail!(
                "invalid item uuid or supported name '{raw_target}'"
            );
        }
    }

    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Uuid(value) | Self::Name(value) => value,
        }
    }

    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Uuid(_) => "id",
            Self::Name(_) => "name",
        }
    }

    pub(super) fn matches_entry(
        &self,
        entry: &rbw::db::Entry,
        decrypted: &DecryptedSearchCipher,
    ) -> bool {
        match self {
            Self::Uuid(id) => entry.id.eq_ignore_ascii_case(id),
            Self::Name(name) => decrypted.name.eq_ignore_ascii_case(name),
        }
    }

    pub(super) fn find_entry(
        &self,
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
            .iter()
            .filter(|(entry, decrypted)| self.matches_entry(entry, decrypted))
            .cloned()
            .collect();

        if matches.is_empty() {
            anyhow::bail!(
                "no entry found for item {} '{}'",
                self.kind(),
                self.as_str()
            );
        } else if matches.len() == 1 {
            Ok(matches[0].clone())
        } else {
            let entries: Vec<String> = matches
                .iter()
                .map(|(_, decrypted)| decrypted.display_name())
                .collect();
            match self {
                Self::Name(name) => anyhow::bail!(
                    "multiple entries found for item name '{}': {}; use bw://<uuid> instead",
                    name,
                    entries.join(", ")
                ),
                Self::Uuid(id) => anyhow::bail!(
                    "multiple entries found for item id '{}': {}",
                    id,
                    entries.join(", ")
                ),
            }
        }
    }

    pub(super) fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
            })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct InjectReference {
    pub(super) id: String,
    pub(super) target: InjectReferenceTarget,
    pub(super) field: Option<String>,
}

impl InjectReference {
    pub(super) fn parse(reference: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(reference).with_context(|| {
            format!("invalid inject reference '{reference}'")
        })?;
        if parsed.scheme() != "bw" {
            anyhow::bail!(
                "invalid inject reference scheme '{}'",
                parsed.scheme()
            );
        }
        if parsed.fragment().is_some() {
            anyhow::bail!("inject references do not support fragments");
        }
        if !parsed.username().is_empty() {
            anyhow::bail!("inject references do not support usernames");
        }
        if parsed.password().is_some() {
            anyhow::bail!("inject references do not support passwords");
        }
        if parsed.port().is_some() {
            anyhow::bail!("inject references do not support ports");
        }
        if !parsed.path().is_empty() {
            anyhow::bail!("inject references do not support paths");
        }

        let raw_target = parsed
            .host_str()
            .context("inject reference is missing an item id or name")?;
        let target = InjectReferenceTarget::parse(raw_target)?;

        let mut field = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "field" => {
                    if field.replace(value.into_owned()).is_some() {
                        anyhow::bail!(
                            "inject reference has multiple field parameters"
                        );
                    }
                }
                _ => anyhow::bail!(
                    "unsupported inject query parameter '{key}'"
                ),
            }
        }

        let field = field
            .map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "inject field query parameter cannot be empty"
                    );
                }
                Ok(trimmed.to_string())
            })
            .transpose()?;

        Ok(Self {
            id: target.as_str().to_string(),
            target,
            field,
        })
    }

    pub(super) fn parse_braced(expr: &str) -> anyhow::Result<Option<Self>> {
        let expr = expr.trim();
        let expr = if expr.starts_with('"') {
            match serde_json::from_str::<String>(expr) {
                Ok(expr) => expr,
                Err(_) => return Ok(None),
            }
        } else {
            expr.to_string()
        };
        if !expr.starts_with("bw://") {
            return Ok(None);
        }
        Self::parse(&expr).map(Some)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum InjectMarker {
    Braced,
    Raw,
}

pub(super) struct InjectTemplate<'a> {
    pub(super) src: &'a str,
}

impl<'a> InjectTemplate<'a> {
    pub(super) fn new(src: &'a str) -> Self {
        Self { src }
    }

    pub(super) fn render<F>(&self, mut resolver: F) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        self.render_with_variable_resolver(
            lookup_inject_template_variable,
            |reference| resolver(reference),
        )
    }

    pub(super) fn render_with_variable_resolver<F, G>(
        &self,
        mut lookup_variable: G,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
        G: FnMut(&str) -> Option<String>,
    {
        let expanded =
            self.expand_variables_with_lookup(&mut lookup_variable)?;
        InjectTemplate::new(&expanded)
            .render_secret_references(|reference| resolver(reference))
    }

    pub(super) fn render_secret_references<F>(
        &self,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some((idx, marker)) = self.next_marker(start) {
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("marker range should be valid"),
            );
            start = match marker {
                InjectMarker::Braced => {
                    self.render_braced(idx, &mut rendered, &mut resolver)?
                }
                InjectMarker::Raw => {
                    self.render_raw(idx, &mut rendered, &mut resolver)?
                }
            };
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("template tail range should be valid"),
        );
        Ok(rendered)
    }

    pub(super) fn expand_variables_with_lookup<G>(
        &self,
        lookup_variable: &mut G,
    ) -> anyhow::Result<String>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some(offset) = self
            .src
            .get(start..)
            .expect("variable search start should be valid")
            .find('$')
        {
            let idx = start + offset;
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("variable prefix range should be valid"),
            );
            if let Some((value, next_start)) =
                self.resolve_variable_at(idx, lookup_variable)?
            {
                rendered.push_str(&value);
                start = next_start;
            } else {
                rendered.push('$');
                start = idx + '$'.len_utf8();
            }
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("variable tail range should be valid"),
        );
        Ok(rendered)
    }

    pub(super) fn take_braced_expression(
        &self,
        idx: usize,
    ) -> anyhow::Result<(&'a str, usize)> {
        let rest = self
            .src
            .get(idx..)
            .expect("braced expression start should be valid")
            .strip_prefix("{{")
            .expect("braced expression must start with '{{'");
        let Some((expr, tail)) = rest.split_once("}}") else {
            anyhow::bail!("unterminated inject template expression");
        };
        Ok((expr, self.src.len() - tail.len()))
    }

    pub(super) fn render_braced<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let (expr, next_start) = self.take_braced_expression(idx)?;
        if let Some(reference) = InjectReference::parse_braced(expr)? {
            out.push_str(&resolver(&reference)?);
        } else {
            out.push_str("{{");
            out.push_str(expr);
            out.push_str("}}");
        }
        Ok(next_start)
    }

    pub(super) fn render_raw<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let end = self.raw_reference_end(idx);
        let candidate = self
            .src
            .get(idx..end)
            .expect("raw reference range should be valid");
        let reference = InjectReference::parse(candidate)?;
        out.push_str(&resolver(&reference)?);
        Ok(end)
    }

    pub(super) fn resolve_variable_at<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let rest = self
            .src
            .get(idx + '$'.len_utf8()..)
            .expect("variable suffix range should be valid");
        match rest.chars().next() {
            Some('{') => self.resolve_braced_variable(idx, lookup_variable),
            Some(ch) if Self::is_valid_variable_start(ch) => {
                let name_len = rest
                    .char_indices()
                    .take_while(|(_, ch)| {
                        Self::is_valid_variable_continue(*ch)
                    })
                    .last()
                    .map_or(0, |(offset, ch)| offset + ch.len_utf8());
                let name = rest
                    .get(..name_len)
                    .expect("raw variable name range should be valid");
                if let Some(value) = lookup_variable(name) {
                    Ok(Some((value, idx + '$'.len_utf8() + name_len)))
                } else {
                    anyhow::bail!(
                        "inject template variable '{name}' is not set"
                    );
                }
            }
            _ => Ok(None),
        }
    }

    pub(super) fn resolve_braced_variable<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let expr_start = idx + "${".len();
        let rest = self
            .src
            .get(expr_start..)
            .expect("braced variable start should be valid");
        let mut depth = 1usize;
        let mut end = None;
        let mut offset = 0;
        while offset < rest.len() {
            let tail = rest
                .get(offset..)
                .expect("braced variable tail range should be valid");
            if tail.starts_with("\\}") {
                offset += "\\}".len();
                continue;
            }
            if tail.starts_with("${") {
                depth += 1;
                offset += "${".len();
                continue;
            }
            let ch = tail
                .chars()
                .next()
                .expect("braced variable tail should not be empty");
            if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(expr_start + offset);
                    break;
                }
            }
            offset += ch.len_utf8();
        }
        let end = end.context("unterminated inject template variable")?;
        let expr = self
            .src
            .get(expr_start..end)
            .expect("braced variable expression range should be valid");
        let (name, default) = match expr.split_once(":-") {
            Some((name, default)) => (name.trim(), Some(default)),
            None => (expr.trim(), None),
        };
        if !Self::is_valid_variable_name(name) {
            return Ok(None);
        }
        let value = if let Some(value) = lookup_variable(name) {
            value
        } else if let Some(default) = default {
            InjectTemplate::new(default)
                .expand_variables_with_lookup(lookup_variable)?
        } else {
            anyhow::bail!("inject template variable '{name}' is not set");
        };
        Ok(Some((value, end + '}'.len_utf8())))
    }

    pub(super) fn next_marker(
        &self,
        start: usize,
    ) -> Option<(usize, InjectMarker)> {
        let rest = self
            .src
            .get(start..)
            .expect("marker search start should be valid");
        let braced = rest
            .find("{{")
            .map(|offset| (start + offset, InjectMarker::Braced));
        let raw = rest
            .match_indices("bw://")
            .map(|(offset, _)| start + offset)
            .find(|&idx| Self::raw_reference_can_start(self.src, idx))
            .map(|idx| (idx, InjectMarker::Raw));

        match (braced, raw) {
            (Some(braced), Some(raw)) => {
                Some(if braced.0 <= raw.0 { braced } else { raw })
            }
            (Some(braced), None) => Some(braced),
            (None, Some(raw)) => Some(raw),
            (None, None) => None,
        }
    }

    pub(super) fn raw_reference_end(&self, start: usize) -> usize {
        let mut end = start + "bw://".len();
        let mut seen_query = false;
        let mut seen_query_equals = false;
        for (offset, ch) in self
            .src
            .get(end..)
            .expect("raw reference start should be valid")
            .char_indices()
        {
            let is_allowed = if ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_')
                || (seen_query_equals && matches!(ch, '.' | '%' | '+'))
            {
                true
            } else if ch == '?' && !seen_query {
                seen_query = true;
                true
            } else if ch == '=' && seen_query && !seen_query_equals {
                seen_query_equals = true;
                true
            } else {
                false
            };
            if !is_allowed {
                break;
            }
            end = start + "bw://".len() + offset + ch.len_utf8();
        }
        end
    }

    pub(super) fn raw_reference_can_start(
        template: &str,
        idx: usize,
    ) -> bool {
        template
            .get(..idx)
            .and_then(|prefix| prefix.chars().next_back())
            .is_none_or(|ch| {
                !ch.is_ascii_alphanumeric()
                    && !matches!(ch, '-' | '+' | '\\' | '.')
            })
    }

    pub(super) fn is_valid_variable_name(name: &str) -> bool {
        let mut chars = name.chars();
        matches!(chars.next(), Some(ch) if Self::is_valid_variable_start(ch))
            && chars.all(Self::is_valid_variable_continue)
    }

    pub(super) fn is_valid_variable_start(ch: char) -> bool {
        ch.is_ascii_alphabetic() || ch == '_'
    }

    pub(super) fn is_valid_variable_continue(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || ch == '_'
    }
}

pub(super) fn lookup_inject_template_variable(name: &str) -> Option<String> {
    std::env::vars().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

pub(super) fn read_inject_template(
    input: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    let mut template = String::new();
    match input {
        Some(path) => {
            std::fs::File::open(path)
                .with_context(|| {
                    format!("failed to open template {}", path.display())
                })?
                .read_to_string(&mut template)
                .with_context(|| {
                    format!("failed to read template {}", path.display())
                })?;
        }
        None => {
            std::io::stdin()
                .read_to_string(&mut template)
                .context("failed to read template from stdin")?;
        }
    }
    Ok(template)
}

pub(super) fn parse_run_env_file<F>(
    template: &str,
    mut resolver: F,
) -> anyhow::Result<Vec<(String, String)>>
where
    F: FnMut(&InjectReference) -> anyhow::Result<String>,
{
    dotenvy::from_read_iter(std::io::Cursor::new(template))
        .map(|item| {
            let (key, value) = item.map_err(anyhow::Error::from)?;
            InjectTemplate::new(&value)
                .render_secret_references(|reference| resolver(reference))
                .map(|rendered| (key, rendered))
        })
        .collect()
}

pub(super) fn build_inject_run_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::Command> {
    let Some(program) = command.first() else {
        anyhow::bail!("missing child command");
    };

    let mut child = std::process::Command::new(program);
    child.args(&command[1..]);
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());
    for (key, value) in env_bindings {
        child.env(key, value);
    }
    Ok(child)
}

pub(super) fn run_inject_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::ExitStatus> {
    let mut child = build_inject_run_command(command, env_bindings)?;
    child.status().with_context(|| {
        let program = command.first().map_or_else(
            || "<missing command>".to_string(),
            |program| program.to_string_lossy().into_owned(),
        );
        format!("failed to run child command '{program}'")
    })
}

pub(super) fn resolve_inject_value(
    cipher: &DecryptedCipher,
    field: Option<&str>,
) -> anyhow::Result<String> {
    let normalized = field
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_lowercase);
    match normalized.as_deref() {
        None | Some("password") => match &cipher.data {
            DecryptedData::Login {
                password: Some(password),
                ..
            } => Ok(password.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no password", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some("username" | "user") => match &cipher.data {
            DecryptedData::Login {
                username: Some(username),
                ..
            } => Ok(username.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no username", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some(field) => cipher
            .fields
            .iter()
            .find(|custom| {
                custom
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(field))
            })
            .and_then(|custom| custom.value.clone())
            .with_context(|| {
                format!(
                    "entry '{}' has no field named '{}'",
                    cipher.name, field
                )
            }),
    }
}

pub(super) fn write_rendered_template_file(
    path: &std::path::Path,
    rendered: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "rendered template target '{}' must not be a symlink",
                        path.display()
                    );
                }
                if !metadata.file_type().is_file() {
                    anyhow::bail!(
                        "rendered template target '{}' is not a regular file",
                        path.display()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect rendered template {}",
                        path.display()
                    )
                });
            }
        }

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => std::path::Path::new("."),
        };
        let mut file = tempfile::Builder::new()
            .prefix(".rbw-rendered-template.")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "failed to open temporary rendered template near {}",
                    path.display()
                )
            })?;
        file.as_file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set secure permissions on {}",
                    path.display()
                )
            })?;
        file.write_all(rendered.as_bytes()).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        file.as_file_mut().sync_all().with_context(|| {
            format!("failed to sync rendered template {}", path.display())
        })?;
        file.persist(path)
            .map_err(|err| err.error)
            .with_context(|| {
                format!(
                    "failed to persist rendered template {}",
                    path.display()
                )
            })?;
        std::fs::File::open(parent)
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, rendered).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        Ok(())
    }
}
