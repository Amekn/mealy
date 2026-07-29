//! Full-screen terminal workbench backed only by canonical daemon projections.

use super::{
    CliError, MAXIMUM_LOCAL_IMAGE_ATTACHMENT_TOTAL_BYTES, MAXIMUM_SESSION_TRANSCRIPT_EXPORT_BYTES,
    authorized, decode, generate_idempotency_key, load_connection, prepare_local_image_attachment,
    read_bounded_success_body, server_error, submit_image_input_with_retry,
    submit_input_with_retry, terminal_safe_single_line, terminal_safe_text,
    validate_session_transcript_json, write_private_new_file,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use crossterm::{
    event::{
        DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyCode, KeyEvent,
        KeyEventKind, KeyModifiers,
    },
    execute,
};
use futures_util::StreamExt as _;
use mealy_application::{
    ApprovalSubject, InputAdmissionLimits, MAXIMUM_PROVIDER_IMAGE_INPUTS, valid_session_metadata,
};
use mealy_domain::{ApprovalId, ArtifactId, EffectId, PrincipalId, SessionId, TaskId};
use mealy_protocol::{
    API_VERSION, AdminStatusResponse, ApprovalDecisionCommand, ApprovalResolutionReceipt,
    ApprovalResponse, ApprovalStatusResponse, CreateSessionCheckpointRequest, CreateSessionRequest,
    CreateSessionResponse, DeliveryMode, ForkSessionRequest, LocalConnectionInfo,
    PendingApprovalsResponse, ProviderCatalogResponse, ProviderCatalogRouteResponse,
    ProviderSelectionCommand, ResolveApprovalRequest, SessionCheckpointResponse,
    SessionForkResponse, SessionProviderSelectionResponse, SessionSearchResponse,
    SessionStatusResponse, SessionSummaryResponse, SessionTranscriptExport, SessionsResponse,
    SubmitImageInputRequest, SubmitInputRequest, SubmittedImageInput, TimelineEvent,
    TimelinePageResponse, UpdateSessionProviderSelectionRequest, UpdateSessionTitleRequest,
};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use reqwest::Client;
use std::{
    collections::BTreeSet,
    io::{IsTerminal as _, stdout},
    path::{Path, PathBuf},
    time::Duration,
};

const MAXIMUM_SESSIONS: usize = 100;
const MAXIMUM_SEARCH_RESULTS: usize = 100;
const MAXIMUM_APPROVALS: usize = 100;
const MAXIMUM_RECENT_EVENTS: usize = 500;
const TIMELINE_INITIAL_CURSOR_WINDOW: u64 = 10_000;
const MAXIMUM_RENDERED_EVENT_DETAIL_BYTES: usize = 8 * 1024;
const MAXIMUM_NOTICE_BYTES: usize = 512;
const MAXIMUM_IMAGE_PATH_BYTES: usize = 4_096;
const MAXIMUM_CONSECUTIVE_REFRESH_FAILURES: u8 = 5;
const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_IMAGE_PROMPT: &str = "Describe the attached image or images.";

/// Initial session choice for the workbench.
#[derive(Clone, Debug)]
pub(super) enum WorkbenchSelection {
    /// Resume the most recent exact-binding session, creating one only if none exists.
    Automatic,
    /// Create and select a fresh session.
    New,
    /// Select one exact existing session.
    Exact(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Focus {
    Sessions,
    Conversation,
    Composer,
    Activity,
}

impl Focus {
    const fn next(self) -> Self {
        match self {
            Self::Sessions => Self::Conversation,
            Self::Conversation => Self::Composer,
            Self::Composer => Self::Activity,
            Self::Activity => Self::Sessions,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Sessions => Self::Activity,
            Self::Conversation => Self::Sessions,
            Self::Composer => Self::Conversation,
            Self::Activity => Self::Composer,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputPurpose {
    Search,
    Rename,
    ImagePath,
}

#[derive(Clone, Debug)]
enum Overlay {
    Help,
    Input {
        purpose: InputPurpose,
        editor: Editor,
    },
    Approval {
        index: usize,
    },
    Provider {
        index: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportFormat {
    Json,
    Html,
}

impl ExportFormat {
    const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
        }
    }

    const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/vnd.mealy.session-transcript+json; charset=utf-8",
            Self::Html => "text/html; charset=utf-8",
        }
    }
}

#[derive(Debug)]
enum Action {
    None,
    Quit,
    Refresh,
    SelectSession,
    CreateSession,
    Send(String),
    AttachImage(String),
    Search(String),
    Rename(String),
    Checkpoint,
    Fork,
    Export(ExportFormat),
    SetSessionProvider(ProviderSelectionCommand),
    SetNextTurnProvider(ProviderSelectionCommand),
    ResolveApproval {
        index: usize,
        decision: ApprovalDecisionCommand,
    },
}

enum ActionCompletion {
    Finished(Result<(), CliError>),
    Exit,
}

#[derive(Clone, Debug, Default)]
struct Editor {
    content: String,
    cursor: usize,
}

impl Editor {
    fn with_content(content: String) -> Self {
        let cursor = content.len();
        Self { content, cursor }
    }

    fn insert_character(&mut self, character: char, maximum_bytes: usize) {
        if character == '\r'
            || (character.is_control() && !matches!(character, '\n' | '\t'))
            || self.content.len().saturating_add(character.len_utf8()) > maximum_bytes
        {
            return;
        }
        self.content.insert(self.cursor, character);
        self.cursor += character.len_utf8();
    }

    fn insert_text(&mut self, value: &str, maximum_bytes: usize) {
        for character in value.replace("\r\n", "\n").replace('\r', "\n").chars() {
            self.insert_character(character, maximum_bytes);
        }
    }

    fn backspace(&mut self) {
        if let Some(previous) = self.content[..self.cursor].char_indices().next_back() {
            self.content.drain(previous.0..self.cursor);
            self.cursor = previous.0;
        }
    }

    fn delete(&mut self) {
        if let Some(character) = self.content[self.cursor..].chars().next() {
            self.content
                .drain(self.cursor..self.cursor + character.len_utf8());
        }
    }

    fn move_left(&mut self) {
        if let Some(previous) = self.content[..self.cursor].char_indices().next_back() {
            self.cursor = previous.0;
        }
    }

    fn move_right(&mut self) {
        if let Some(character) = self.content[self.cursor..].chars().next() {
            self.cursor += character.len_utf8();
        }
    }

    fn clear(&mut self) {
        self.content.clear();
        self.cursor = 0;
    }

    fn rendered_with_cursor(&self) -> String {
        let before = terminal_safe_text(&self.content[..self.cursor]);
        let after = terminal_safe_text(&self.content[self.cursor..]);
        format!("{before}▏{after}")
    }
}

#[derive(Clone, Debug)]
struct SessionItem {
    session_id: String,
    title: String,
    status: String,
    revision: u64,
    pending_inputs: u64,
    active: bool,
    updated_at_ms: i64,
}

impl From<SessionSummaryResponse> for SessionItem {
    fn from(value: SessionSummaryResponse) -> Self {
        Self {
            session_id: value.session_id,
            title: value.title,
            status: value.status,
            revision: value.revision,
            pending_inputs: value.pending_inputs,
            active: value.active_turn_id.is_some(),
            updated_at_ms: value.updated_at_ms,
        }
    }
}

#[derive(Debug)]
struct Workbench {
    base_sessions: Vec<SessionItem>,
    sessions: Vec<SessionItem>,
    selected: usize,
    selected_session_id: Option<String>,
    selected_status: Option<SessionStatusResponse>,
    transcript: Option<SessionTranscriptExport>,
    timeline: Vec<TimelineEvent>,
    timeline_after: u64,
    admin: Option<AdminStatusResponse>,
    provider_catalog: Option<ProviderCatalogResponse>,
    session_provider_selection: Option<SessionProviderSelectionResponse>,
    next_turn_provider_selection: Option<ProviderSelectionCommand>,
    approvals: Vec<ApprovalResponse>,
    composer: Editor,
    pending_image_paths: Vec<PathBuf>,
    focus: Focus,
    overlay: Option<Overlay>,
    transcript_scroll: u16,
    activity_selected: usize,
    notice: String,
    notice_is_error: bool,
    busy: Option<String>,
    search_query: Option<String>,
    consecutive_refresh_failures: u8,
}

impl Workbench {
    fn new() -> Self {
        Self {
            base_sessions: Vec::new(),
            sessions: Vec::new(),
            selected: 0,
            selected_session_id: None,
            selected_status: None,
            transcript: None,
            timeline: Vec::new(),
            timeline_after: 0,
            admin: None,
            provider_catalog: None,
            session_provider_selection: None,
            next_turn_provider_selection: None,
            approvals: Vec::new(),
            composer: Editor::default(),
            pending_image_paths: Vec::new(),
            focus: Focus::Composer,
            overlay: None,
            transcript_scroll: u16::MAX,
            activity_selected: 0,
            notice: "Loading canonical daemon state…".to_owned(),
            notice_is_error: false,
            busy: None,
            search_query: None,
            consecutive_refresh_failures: 0,
        }
    }

    fn selected_session(&self) -> Option<&SessionItem> {
        self.sessions.get(self.selected)
    }

    fn selected_id(&self) -> Option<&str> {
        self.selected_session_id.as_deref()
    }

    fn set_notice(&mut self, notice: impl AsRef<str>, is_error: bool) {
        self.notice = bounded_single_line(notice.as_ref(), MAXIMUM_NOTICE_BYTES);
        self.notice_is_error = is_error;
    }

    fn select_index(&mut self, index: usize) -> bool {
        if self.sessions.is_empty() {
            let changed = self.selected_session_id.take().is_some();
            self.selected = 0;
            self.selected_status = None;
            self.transcript = None;
            self.timeline.clear();
            self.timeline_after = 0;
            self.transcript_scroll = u16::MAX;
            self.activity_selected = 0;
            return changed;
        }
        let index = index.min(self.sessions.len() - 1);
        self.selected = index;
        let id = self.sessions[index].session_id.clone();
        if self.selected_session_id.as_deref() == Some(&id) {
            return false;
        }
        self.selected_session_id = Some(id);
        self.selected_status = None;
        self.transcript = None;
        self.timeline.clear();
        self.timeline_after = 0;
        self.transcript_scroll = u16::MAX;
        self.activity_selected = 0;
        self.session_provider_selection = None;
        self.next_turn_provider_selection = None;
        true
    }

    fn preserve_or_select(&mut self, preferred: Option<&str>) -> bool {
        let target = preferred
            .or(self.selected_session_id.as_deref())
            .and_then(|id| {
                self.sessions
                    .iter()
                    .position(|session| session.session_id == id)
            })
            .unwrap_or(0);
        self.select_index(target)
    }

    fn sync_base_sessions(&mut self, sessions: Vec<SessionItem>) {
        let selected = self.selected_session_id.clone();
        self.base_sessions = sessions;
        if self.search_query.is_none() {
            self.sessions.clone_from(&self.base_sessions);
            self.preserve_or_select(selected.as_deref());
        } else {
            for visible in &mut self.sessions {
                if let Some(current) = self
                    .base_sessions
                    .iter()
                    .find(|item| item.session_id == visible.session_id)
                {
                    visible.status.clone_from(&current.status);
                    visible.revision = current.revision;
                    visible.pending_inputs = current.pending_inputs;
                    visible.active = current.active;
                    visible.updated_at_ms = current.updated_at_ms;
                }
            }
        }
    }

    fn clear_search(&mut self) -> bool {
        self.search_query = None;
        let selected = self.selected_session_id.clone();
        self.sessions.clone_from(&self.base_sessions);
        self.preserve_or_select(selected.as_deref())
    }

    fn apply_search(&mut self, response: SessionSearchResponse) -> bool {
        let selected = self.selected_session_id.clone();
        let mut observed = BTreeSet::new();
        self.sessions = response
            .hits
            .into_iter()
            .filter(|hit| observed.insert(hit.session_id.clone()))
            .map(|hit| {
                self.base_sessions
                    .iter()
                    .find(|item| item.session_id == hit.session_id)
                    .cloned()
                    .unwrap_or(SessionItem {
                        session_id: hit.session_id,
                        title: hit.session_title,
                        status: "historical".to_owned(),
                        revision: 0,
                        pending_inputs: 0,
                        active: false,
                        updated_at_ms: hit.created_at_ms,
                    })
            })
            .collect();
        self.search_query = Some(response.query);
        self.preserve_or_select(selected.as_deref())
    }

    fn next_session(&mut self, direction: i8) -> bool {
        if self.sessions.is_empty() {
            return false;
        }
        let next = if direction < 0 {
            self.selected.saturating_sub(1)
        } else {
            self.selected.saturating_add(1).min(self.sessions.len() - 1)
        };
        self.select_index(next)
    }

    fn next_activity(&mut self, direction: i8) {
        if self.timeline.is_empty() {
            self.activity_selected = 0;
            return;
        }
        self.activity_selected = if direction < 0 {
            self.activity_selected.saturating_sub(1)
        } else {
            self.activity_selected
                .saturating_add(1)
                .min(self.timeline.len() - 1)
        };
    }
}

struct TerminalGuard {
    terminal: Option<DefaultTerminal>,
}

impl TerminalGuard {
    fn enter() -> Result<Self, CliError> {
        let mut terminal = ratatui::try_init()?;
        execute!(terminal.backend_mut(), EnableBracketedPaste)?;
        terminal.clear()?;
        Ok(Self {
            terminal: Some(terminal),
        })
    }

    fn terminal_mut(&mut self) -> Result<&mut DefaultTerminal, CliError> {
        self.terminal
            .as_mut()
            .ok_or_else(|| CliError::Protocol("terminal workbench is already restored".to_owned()))
    }

    fn restore(&mut self) -> Result<(), CliError> {
        if self.terminal.take().is_some() {
            execute!(stdout(), DisableBracketedPaste)?;
            ratatui::try_restore()?;
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.terminal.take().is_some() {
            let _ = execute!(stdout(), DisableBracketedPaste);
            let _ = ratatui::try_restore();
        }
    }
}

/// Runs the terminal workbench until the owner exits or the daemon is persistently unavailable.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_workbench(
    client: &Client,
    home: &Path,
    initial_connection: &LocalConnectionInfo,
    selection: WorkbenchSelection,
) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        return Err(CliError::WorkbenchRequiresTerminal);
    }
    let mut terminal = TerminalGuard::enter()?;
    let mut state = Workbench::new();
    initialize_workbench(client, home, initial_connection, &mut state, selection).await?;
    let mut events = EventStream::new();
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;

    let outcome = loop {
        terminal
            .terminal_mut()?
            .draw(|frame| render(frame, &mut state))?;
        let action = tokio::select! {
            event = events.next() => {
                match event {
                    Some(Ok(event)) => handle_event(&mut state, event),
                    Some(Err(error)) => break Err(CliError::Io(error)),
                    None => break Err(CliError::Protocol(
                        "terminal event stream ended unexpectedly".to_owned(),
                    )),
                }
            }
            _ = refresh.tick() => Action::Refresh,
        };
        if matches!(action, Action::Quit) {
            break Ok(());
        }
        if matches!(action, Action::None) {
            continue;
        }
        state.busy = Some(action_label(&action).to_owned());
        terminal
            .terminal_mut()?
            .draw(|frame| render(frame, &mut state))?;
        let is_refresh = matches!(action, Action::Refresh);
        let completion = {
            let mut operation = Box::pin(perform_action(client, home, &mut state, action));
            loop {
                tokio::select! {
                    result = &mut operation => break ActionCompletion::Finished(result),
                    event = events.next() => {
                        match event {
                            Some(Ok(Event::Key(key)))
                                if key.kind == KeyEventKind::Press
                                    && key.modifiers.contains(KeyModifiers::CONTROL)
                                    && key.code == KeyCode::Char('c') =>
                            {
                                break ActionCompletion::Exit;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(error)) => {
                                break ActionCompletion::Finished(Err(CliError::Io(error)));
                            }
                            None => {
                                break ActionCompletion::Finished(Err(CliError::Protocol(
                                    "terminal event stream ended unexpectedly".to_owned(),
                                )));
                            }
                        }
                    }
                }
            }
        };
        state.busy = None;
        let ActionCompletion::Finished(result) = completion else {
            break Ok(());
        };
        match result {
            Ok(()) => {
                if is_refresh {
                    state.consecutive_refresh_failures = 0;
                }
            }
            Err(error) if is_refresh => {
                state.consecutive_refresh_failures =
                    state.consecutive_refresh_failures.saturating_add(1);
                state.set_notice(
                    format!(
                        "Daemon refresh failed ({}/{}): {}",
                        state.consecutive_refresh_failures,
                        MAXIMUM_CONSECUTIVE_REFRESH_FAILURES,
                        error
                    ),
                    true,
                );
                if state.consecutive_refresh_failures >= MAXIMUM_CONSECUTIVE_REFRESH_FAILURES {
                    break Err(CliError::Protocol(format!(
                        "terminal workbench lost the daemon after \
                         {MAXIMUM_CONSECUTIVE_REFRESH_FAILURES} consecutive refresh failures: \
                         {error}"
                    )));
                }
            }
            Err(error) => state.set_notice(error.to_string(), true),
        }
    };
    terminal.restore()?;
    outcome
}

async fn initialize_workbench(
    client: &Client,
    home: &Path,
    initial_connection: &LocalConnectionInfo,
    state: &mut Workbench,
    selection: WorkbenchSelection,
) -> Result<(), CliError> {
    let sessions = fetch_sessions(client, initial_connection).await?;
    state.sync_base_sessions(sessions);
    let preferred = match selection {
        WorkbenchSelection::Exact(session_id) => session_id
            .parse::<SessionId>()
            .map_err(|_| {
                CliError::Protocol(
                    "terminal workbench requires a valid exact session ID".to_owned(),
                )
            })?
            .to_string()
            .into(),
        WorkbenchSelection::New => Some(create_session(client, initial_connection).await?),
        WorkbenchSelection::Automatic if state.sessions.is_empty() => {
            Some(create_session(client, initial_connection).await?)
        }
        WorkbenchSelection::Automatic => None,
    };
    if preferred.is_some() {
        state.sync_base_sessions(fetch_sessions(client, initial_connection).await?);
    }
    if let Some(session_id) = preferred {
        let Some(index) = state
            .sessions
            .iter()
            .position(|item| item.session_id == session_id)
        else {
            return Err(CliError::Protocol(
                "selected session is not visible to this exact owner/channel binding".to_owned(),
            ));
        };
        state.select_index(index);
    } else {
        state.select_index(0);
    }
    refresh_all(client, home, state, true).await?;
    state.set_notice(
        "Ready. Enter sends · Tab changes pane · F1 shows every control.",
        false,
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn perform_action(
    client: &Client,
    home: &Path,
    state: &mut Workbench,
    action: Action,
) -> Result<(), CliError> {
    match action {
        Action::None | Action::Quit => Ok(()),
        Action::Refresh => refresh_all(client, home, state, false).await,
        Action::SelectSession => refresh_selected(client, home, state, true).await,
        Action::CreateSession => {
            let connection = current_connection(home)?;
            let session_id = create_session(client, &connection).await?;
            state.search_query = None;
            state.sync_base_sessions(fetch_sessions(client, &connection).await?);
            let index = state
                .sessions
                .iter()
                .position(|item| item.session_id == session_id)
                .ok_or_else(|| {
                    CliError::Protocol(
                        "fresh session was absent from canonical session discovery".to_owned(),
                    )
                })?;
            state.select_index(index);
            refresh_selected(client, home, state, true).await?;
            state.set_notice("Created a fresh durable session.", false);
            Ok(())
        }
        Action::Send(content) => {
            let session_id = selected_id_owned(state)?;
            let maximum = InputAdmissionLimits::default().maximum_content_bytes();
            if (content.is_empty() && state.pending_image_paths.is_empty())
                || content.len() > maximum
            {
                return Err(CliError::Protocol(format!(
                    "composer content must contain 1 through {maximum} UTF-8 bytes"
                )));
            }
            let connection = current_connection(home)?;
            let admission = if state.pending_image_paths.is_empty() {
                let request = SubmitInputRequest {
                    api_version: API_VERSION.to_owned(),
                    provider_selection: state.next_turn_provider_selection.clone(),
                    idempotency_key: generate_idempotency_key()?,
                    delivery_mode: DeliveryMode::Queue,
                    content,
                };
                submit_input_with_retry(client, home, &connection, &session_id, &request).await?
            } else {
                let selection = state
                    .next_turn_provider_selection
                    .as_ref()
                    .or_else(|| {
                        state
                            .session_provider_selection
                            .as_ref()
                            .map(|selection| &selection.provider_selection)
                    })
                    .cloned()
                    .ok_or_else(|| {
                        CliError::Protocol(
                            "image input requires a loaded exact provider/model route".to_owned(),
                        )
                    })?;
                submit_workbench_images(
                    client,
                    home,
                    &connection,
                    &session_id,
                    if content.is_empty() {
                        DEFAULT_IMAGE_PROMPT.to_owned()
                    } else {
                        content
                    },
                    selection,
                    &state.pending_image_paths,
                )
                .await?
            };
            state.composer.clear();
            state.pending_image_paths.clear();
            state.next_turn_provider_selection = None;
            state.set_notice(
                format!(
                    "Input {} is durably queued; the workbench will follow canonical progress.",
                    short_id(&admission.inbox_entry_id)
                ),
                false,
            );
            refresh_all(client, home, state, false).await
        }
        Action::AttachImage(path) => {
            if path.is_empty()
                || path.len() > MAXIMUM_IMAGE_PATH_BYTES
                || state.pending_image_paths.len() >= MAXIMUM_PROVIDER_IMAGE_INPUTS
            {
                return Err(CliError::Protocol(
                    "attach one image path at a time, up to four images".to_owned(),
                ));
            }
            let path = PathBuf::from(path);
            prepare_local_image_attachment(home, &path)?;
            if state.pending_image_paths.contains(&path) {
                return Err(CliError::Protocol(
                    "the selected image is already attached to this turn".to_owned(),
                ));
            }
            state.pending_image_paths.push(path);
            state.set_notice(
                format!(
                    "Attached {} image(s); F9 adds another and Esc clears the draft.",
                    state.pending_image_paths.len()
                ),
                false,
            );
            Ok(())
        }
        Action::Search(query) => {
            if query.is_empty() {
                let changed = state.clear_search();
                state.set_notice("Search cleared; showing recent sessions.", false);
                if changed {
                    refresh_selected(client, home, state, true).await?;
                }
                return Ok(());
            }
            if query.len() > 4_096 || query.trim() != query || query.chars().any(char::is_control) {
                return Err(CliError::Protocol(
                    "session search must be trimmed, nonempty, control-free, and at most 4096 bytes"
                        .to_owned(),
                ));
            }
            let connection = current_connection(home)?;
            let response = super::search_session_transcripts(
                client,
                &connection,
                &query,
                MAXIMUM_SEARCH_RESULTS,
            )
            .await?;
            validate_search_response(&response, &query)?;
            let changed = state.apply_search(response);
            state.set_notice(
                format!(
                    "Search matched {} conversation(s). Submit an empty search to clear.",
                    state.sessions.len()
                ),
                false,
            );
            if changed {
                refresh_selected(client, home, state, true).await?;
            }
            Ok(())
        }
        Action::Rename(title) => {
            if !valid_session_metadata(&title) {
                return Err(CliError::Protocol(
                    "session title is empty, unsafe, or exceeds its metadata bound".to_owned(),
                ));
            }
            let session_id = selected_id_owned(state)?;
            let connection = current_connection(home)?;
            let status = fetch_session_status(client, &connection, &session_id).await?;
            let response = authorized(
                client.patch(format!("{}/v1/sessions/{session_id}", connection.base_url)),
                &connection,
            )
            .json(&UpdateSessionTitleRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision: status.revision,
                title: title.clone(),
            })
            .send()
            .await?;
            let updated = decode::<mealy_protocol::SessionTitleResponse>(response).await?;
            if updated.session_id != session_id || updated.title != title {
                return Err(CliError::Protocol(
                    "session title response did not match the command".to_owned(),
                ));
            }
            state.sync_base_sessions(fetch_sessions(client, &connection).await?);
            state.set_notice("Conversation title updated canonically.", false);
            Ok(())
        }
        Action::Checkpoint => {
            let session_id = selected_id_owned(state)?;
            let connection = current_connection(home)?;
            let checkpoint = create_checkpoint(client, &connection, &session_id).await?;
            state.set_notice(
                format!(
                    "Checkpoint {} captured cursor {}.",
                    short_id(&checkpoint.checkpoint_id),
                    checkpoint.source_cursor.0
                ),
                false,
            );
            refresh_all(client, home, state, false).await
        }
        Action::Fork => {
            let session_id = selected_id_owned(state)?;
            let connection = current_connection(home)?;
            let checkpoint = create_checkpoint(client, &connection, &session_id).await?;
            let response = authorized(
                client.post(format!(
                    "{}/v1/sessions/{session_id}/forks",
                    connection.base_url
                )),
                &connection,
            )
            .json(&ForkSessionRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: generate_idempotency_key()?,
                checkpoint_id: checkpoint.checkpoint_id,
            })
            .send()
            .await?;
            let fork = decode::<SessionForkResponse>(response).await?;
            if fork.source_session_id != session_id
                || fork.fork_session_id.parse::<SessionId>().is_err()
            {
                return Err(CliError::Protocol(
                    "session fork response violated its lineage binding".to_owned(),
                ));
            }
            state.search_query = None;
            state.sync_base_sessions(fetch_sessions(client, &connection).await?);
            let index = state
                .sessions
                .iter()
                .position(|item| item.session_id == fork.fork_session_id)
                .ok_or_else(|| {
                    CliError::Protocol(
                        "forked session was absent from canonical discovery".to_owned(),
                    )
                })?;
            state.select_index(index);
            refresh_selected(client, home, state, true).await?;
            state.set_notice(
                format!(
                    "Forked {} immutable prior turn(s) into a fresh session.",
                    fork.referenced_turns
                ),
                false,
            );
            Ok(())
        }
        Action::Export(format) => {
            let session_id = selected_id_owned(state)?;
            let connection = current_connection(home)?;
            let (bytes, _) =
                fetch_transcript_bytes(client, &connection, &session_id, format).await?;
            let path = PathBuf::from(format!("mealy-session-{session_id}.{}", format.extension()));
            write_private_new_file(&path, &bytes)?;
            state.set_notice(
                format!(
                    "Verified {} transcript written privately to {}.",
                    format.extension().to_ascii_uppercase(),
                    path.display()
                ),
                false,
            );
            Ok(())
        }
        Action::SetSessionProvider(provider_selection) => {
            let session_id = selected_id_owned(state)?;
            let connection = current_connection(home)?;
            let current =
                fetch_session_provider_selection(client, &connection, &session_id).await?;
            let response = authorized(
                client.patch(format!(
                    "{}/v1/sessions/{session_id}/provider-selection",
                    connection.base_url
                )),
                &connection,
            )
            .json(&UpdateSessionProviderSelectionRequest {
                api_version: API_VERSION.to_owned(),
                expected_revision: current.revision,
                provider_selection: provider_selection.clone(),
            })
            .send()
            .await?;
            let updated = decode::<SessionProviderSelectionResponse>(response).await?;
            validate_session_provider_selection(&updated, &session_id)?;
            if updated.provider_selection != provider_selection {
                return Err(CliError::Protocol(
                    "provider-selection update did not match the chosen route".to_owned(),
                ));
            }
            state.session_provider_selection = Some(updated);
            state.set_notice(
                format!(
                    "{} is now the default for future turns in this conversation.",
                    provider_selection_label(&provider_selection)
                ),
                false,
            );
            refresh_all(client, home, state, false).await
        }
        Action::SetNextTurnProvider(provider_selection) => {
            state.next_turn_provider_selection = Some(provider_selection.clone());
            state.set_notice(
                format!(
                    "{} will be used only for the next submitted turn.",
                    provider_selection_label(&provider_selection)
                ),
                false,
            );
            Ok(())
        }
        Action::ResolveApproval { index, decision } => {
            let approval = state.approvals.get(index).cloned().ok_or_else(|| {
                CliError::Protocol("the selected approval is no longer pending".to_owned())
            })?;
            let connection = current_connection(home)?;
            let response = authorized(
                client.post(format!(
                    "{}/v1/approvals/{}/resolve",
                    connection.base_url, approval.approval_id
                )),
                &connection,
            )
            .json(&ResolveApprovalRequest {
                api_version: API_VERSION.to_owned(),
                idempotency_key: generate_idempotency_key()?,
                expected_subject_digest: approval.subject_digest.clone(),
                decision,
            })
            .send()
            .await?;
            let receipt = decode::<ApprovalResolutionReceipt>(response).await?;
            if receipt.approval_id != approval.approval_id {
                return Err(CliError::Protocol(
                    "approval resolution did not match the reviewed subject".to_owned(),
                ));
            }
            state.set_notice(
                format!(
                    "Approval {} is now {:?}.",
                    short_id(&receipt.approval_id),
                    receipt.status
                ),
                false,
            );
            refresh_all(client, home, state, false).await
        }
    }
}

async fn refresh_all(
    client: &Client,
    home: &Path,
    state: &mut Workbench,
    force_selected: bool,
) -> Result<(), CliError> {
    let connection = current_connection(home)?;
    let sessions = fetch_sessions(client, &connection).await?;
    state.sync_base_sessions(sessions);
    state.admin = Some(fetch_admin_status(client, &connection).await?);
    state.provider_catalog = Some(fetch_provider_catalog(client, &connection).await?);
    state.approvals = fetch_approvals(client, &connection).await?;
    refresh_selected(client, home, state, force_selected).await
}

async fn submit_workbench_images(
    client: &Client,
    home: &Path,
    connection: &LocalConnectionInfo,
    session_id: &str,
    content: String,
    provider_selection: ProviderSelectionCommand,
    paths: &[PathBuf],
) -> Result<mealy_protocol::InputAdmissionResponse, CliError> {
    if !matches!(provider_selection, ProviderSelectionCommand::Exact { .. })
        || paths.is_empty()
        || paths.len() > MAXIMUM_PROVIDER_IMAGE_INPUTS
    {
        return Err(CliError::Protocol(
            "image input requires one to four images and an exact provider/model route".to_owned(),
        ));
    }
    let mut total_source_bytes = 0_u64;
    let mut images = Vec::with_capacity(paths.len());
    for path in paths {
        let (media_type, bytes) = prepare_local_image_attachment(home, path)?;
        total_source_bytes = total_source_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or(CliError::InvalidLocalAttachment)?;
        if total_source_bytes > MAXIMUM_LOCAL_IMAGE_ATTACHMENT_TOTAL_BYTES {
            return Err(CliError::InvalidLocalAttachment);
        }
        images.push(SubmittedImageInput {
            artifact_id: ArtifactId::new().to_string(),
            media_type: media_type.to_owned(),
            data_base64: BASE64_STANDARD.encode(bytes),
        });
    }
    let request = SubmitImageInputRequest {
        api_version: API_VERSION.to_owned(),
        idempotency_key: generate_idempotency_key()?,
        delivery_mode: DeliveryMode::Queue,
        content,
        provider_selection,
        images,
    };
    submit_image_input_with_retry(client, home, connection, session_id, &request).await
}

async fn refresh_selected(
    client: &Client,
    home: &Path,
    state: &mut Workbench,
    force: bool,
) -> Result<(), CliError> {
    let Some(session_id) = state.selected_id().map(str::to_owned) else {
        state.selected_status = None;
        state.transcript = None;
        state.timeline.clear();
        state.timeline_after = 0;
        state.session_provider_selection = None;
        return Ok(());
    };
    let connection = current_connection(home)?;
    state.session_provider_selection =
        Some(fetch_session_provider_selection(client, &connection, &session_id).await?);
    let status = fetch_session_status(client, &connection, &session_id).await?;
    let changed = force
        || state
            .selected_status
            .as_ref()
            .is_none_or(|previous| previous.latest_cursor != status.latest_cursor);
    if changed {
        let transcript_changed =
            refresh_timeline(client, &connection, state, &status, force).await?;
        if force || state.transcript.is_none() || transcript_changed {
            let (bytes, _) =
                fetch_transcript_bytes(client, &connection, &session_id, ExportFormat::Json)
                    .await?;
            let transcript = serde_json::from_slice::<SessionTranscriptExport>(&bytes)?;
            state.transcript = Some(transcript);
            state.transcript_scroll = u16::MAX;
        }
    }
    state.selected_status = Some(status);
    Ok(())
}

async fn refresh_timeline(
    client: &Client,
    connection: &LocalConnectionInfo,
    state: &mut Workbench,
    status: &SessionStatusResponse,
    force: bool,
) -> Result<bool, CliError> {
    let session_id = status.session_id.as_str();
    let mut after = if force || state.timeline.is_empty() {
        state.timeline.clear();
        status
            .latest_cursor
            .0
            .saturating_sub(TIMELINE_INITIAL_CURSOR_WINDOW)
    } else {
        state.timeline_after
    };
    let mut transcript_changed = false;
    for page_number in 0..10 {
        let response = authorized(
            client
                .get(format!(
                    "{}/v1/sessions/{session_id}/timeline",
                    connection.base_url
                ))
                .query(&[("after", after), ("limit", 1000_u64)]),
            connection,
        )
        .send()
        .await?;
        let page = decode::<TimelinePageResponse>(response).await?;
        validate_timeline_page(&page, after)?;
        transcript_changed |= page.events.iter().any(|event| {
            matches!(
                event.event_type.as_str(),
                "message.assistant.final" | "task.succeeded"
            )
        });
        if force && page_number == 0 {
            state.timeline = page.events;
        } else {
            state.timeline.extend(page.events);
        }
        if state.timeline.len() > MAXIMUM_RECENT_EVENTS {
            state
                .timeline
                .drain(..state.timeline.len() - MAXIMUM_RECENT_EVENTS);
        }
        if let Some(last) = state.timeline.last() {
            after = last.cursor.0;
        } else {
            after = page.high_watermark.0.min(status.latest_cursor.0);
        }
        if !page.has_more {
            state.timeline_after = after;
            state.activity_selected = state.timeline.len().saturating_sub(1);
            return Ok(transcript_changed);
        }
    }
    Err(CliError::Protocol(
        "recent timeline exceeded its 10000-event catch-up bound".to_owned(),
    ))
}

async fn fetch_sessions(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<Vec<SessionItem>, CliError> {
    let response = authorized(
        client.get(format!(
            "{}/v1/sessions?limit={MAXIMUM_SESSIONS}",
            connection.base_url
        )),
        connection,
    )
    .send()
    .await?;
    let response = decode::<SessionsResponse>(response).await?;
    if response.sessions.len() > MAXIMUM_SESSIONS
        || response.sessions.iter().any(|item| {
            item.session_id.parse::<SessionId>().is_err()
                || !valid_session_metadata(&item.title)
                || !matches!(item.title_source.as_str(), "owner" | "derived")
                || !matches!(item.status.as_str(), "active" | "paused" | "closed")
                || item.created_at_ms < 0
                || item.updated_at_ms < item.created_at_ms
        })
        || response
            .sessions
            .windows(2)
            .any(|pair| pair[0].updated_at_ms < pair[1].updated_at_ms)
    {
        return Err(CliError::Protocol(
            "session workbench received invalid or unordered session summaries".to_owned(),
        ));
    }
    Ok(response
        .sessions
        .into_iter()
        .map(SessionItem::from)
        .collect())
}

async fn create_session(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<String, CliError> {
    let response = authorized(
        client.post(format!("{}/v1/sessions", connection.base_url)),
        connection,
    )
    .json(&CreateSessionRequest {
        api_version: API_VERSION.to_owned(),
        provider_selection: None,
    })
    .send()
    .await?;
    let created = decode::<CreateSessionResponse>(response).await?;
    created.session_id.parse::<SessionId>().map_err(|_| {
        CliError::Protocol("session creation returned an invalid session ID".to_owned())
    })?;
    Ok(created.session_id)
}

async fn fetch_session_status(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
) -> Result<SessionStatusResponse, CliError> {
    let response = authorized(
        client.get(format!(
            "{}/v1/sessions/{session_id}/status",
            connection.base_url
        )),
        connection,
    )
    .send()
    .await?;
    let status = decode::<SessionStatusResponse>(response).await?;
    if status.session_id != session_id {
        return Err(CliError::Protocol(
            "session status did not match the selected session".to_owned(),
        ));
    }
    Ok(status)
}

async fn fetch_admin_status(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<AdminStatusResponse, CliError> {
    let response = authorized(
        client.get(format!("{}/v1/admin/status", connection.base_url)),
        connection,
    )
    .send()
    .await?;
    decode(response).await
}

async fn fetch_provider_catalog(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<ProviderCatalogResponse, CliError> {
    let response = authorized(
        client.get(format!("{}/v1/providers/catalog", connection.base_url)),
        connection,
    )
    .send()
    .await?;
    let catalog = decode::<ProviderCatalogResponse>(response).await?;
    if catalog.api_version != API_VERSION
        || catalog.catalog_scope != "configured_route"
        || catalog.routes.is_empty()
        || catalog.routes.iter().enumerate().any(|(index, route)| {
            route.route_ordinal != u64::try_from(index).unwrap_or(u64::MAX)
                || !matches!(route.route_role.as_str(), "primary" | "fallback")
                || route.provider_id.is_empty()
                || route.model_id.is_empty()
        })
    {
        return Err(CliError::Protocol(
            "provider catalog violated its ordered configured-route contract".to_owned(),
        ));
    }
    Ok(catalog)
}

async fn fetch_session_provider_selection(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
) -> Result<SessionProviderSelectionResponse, CliError> {
    let response = authorized(
        client.get(format!(
            "{}/v1/sessions/{session_id}/provider-selection",
            connection.base_url
        )),
        connection,
    )
    .send()
    .await?;
    let selection = decode::<SessionProviderSelectionResponse>(response).await?;
    validate_session_provider_selection(&selection, session_id)?;
    Ok(selection)
}

fn validate_session_provider_selection(
    selection: &SessionProviderSelectionResponse,
    session_id: &str,
) -> Result<(), CliError> {
    if selection.api_version != API_VERSION
        || selection.session_id != session_id
        || selection.applies_to != "future_new_turns"
        || selection.updated_at_ms < 0
    {
        return Err(CliError::Protocol(
            "session provider-selection response violated its scope binding".to_owned(),
        ));
    }
    Ok(())
}

async fn fetch_approvals(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<Vec<ApprovalResponse>, CliError> {
    let response = authorized(
        client.get(format!("{}/v1/approvals", connection.base_url)),
        connection,
    )
    .send()
    .await?;
    let pending = decode::<PendingApprovalsResponse>(response).await?;
    if pending.approvals.len() > MAXIMUM_APPROVALS
        || pending
            .approvals
            .iter()
            .any(|approval| !valid_approval(approval))
    {
        return Err(CliError::Protocol(
            "pending approval response violated its exact-subject or workbench bound".to_owned(),
        ));
    }
    Ok(pending.approvals)
}

fn valid_approval(approval: &ApprovalResponse) -> bool {
    let Ok(approval_id) = approval.approval_id.parse::<ApprovalId>() else {
        return false;
    };
    let Ok(effect_id) = approval.subject.effect_id.parse::<EffectId>() else {
        return false;
    };
    let Ok(principal_id) = approval.subject.principal_id.parse::<PrincipalId>() else {
        return false;
    };
    let Ok(task_id) = approval.subject.task_id.parse::<TaskId>() else {
        return false;
    };
    let subject = ApprovalSubject {
        effect_id,
        principal_id,
        task_id,
        tool_id: approval.subject.tool_id.clone(),
        tool_version: approval.subject.tool_version.clone(),
        canonical_arguments_digest: approval.subject.canonical_arguments_digest.clone(),
        capability_scope: approval.subject.capability_scope.clone(),
        target_resources: approval.subject.target_resources.clone(),
        executable_identity_digest: approval.subject.executable_identity_digest.clone(),
        policy_version: approval.subject.policy_version.clone(),
        expires_at_ms: approval.subject.expires_at_ms,
    };
    approval.api_version == API_VERSION
        && approval_id.to_string() == approval.approval_id
        && approval.effect_id == approval.subject.effect_id
        && approval.effect_id.parse::<EffectId>().ok() == Some(effect_id)
        && approval.status == ApprovalStatusResponse::Pending
        && approval.decision.is_none()
        && approval.resolved_at_ms.is_none()
        && approval.requested_at_ms >= 0
        && subject
            .subject_digest()
            .is_ok_and(|digest| digest == approval.subject_digest)
}

async fn create_checkpoint(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
) -> Result<SessionCheckpointResponse, CliError> {
    let status = fetch_session_status(client, connection, session_id).await?;
    let response = authorized(
        client.post(format!(
            "{}/v1/sessions/{session_id}/checkpoints",
            connection.base_url
        )),
        connection,
    )
    .json(&CreateSessionCheckpointRequest {
        api_version: API_VERSION.to_owned(),
        expected_revision: status.revision,
        label: None,
    })
    .send()
    .await?;
    let checkpoint = decode::<SessionCheckpointResponse>(response).await?;
    if checkpoint.session_id != session_id
        || checkpoint.source_session_revision != status.revision
        || checkpoint.revision != status.revision.saturating_add(1)
    {
        return Err(CliError::Protocol(
            "checkpoint response did not match the selected session revision".to_owned(),
        ));
    }
    Ok(checkpoint)
}

async fn fetch_transcript_bytes(
    client: &Client,
    connection: &LocalConnectionInfo,
    session_id: &str,
    format: ExportFormat,
) -> Result<(Vec<u8>, String), CliError> {
    let response = authorized(
        client.get(format!(
            "{}/v1/sessions/{session_id}/exports/{}",
            connection.base_url,
            format.extension()
        )),
        connection,
    )
    .send()
    .await?;
    if !response.status().is_success() {
        return Err(server_error(response).await);
    }
    let digest = response
        .headers()
        .get("x-mealy-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::Protocol("session transcript omitted its canonical digest".to_owned())
        })?;
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(format.media_type())
    {
        return Err(CliError::Protocol(
            "session transcript returned an unexpected media type".to_owned(),
        ));
    }
    let expected_disposition = format!(
        "attachment; filename=\"mealy-session-{session_id}.{}\"",
        format.extension()
    );
    if response
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        != Some(expected_disposition.as_str())
    {
        return Err(CliError::Protocol(
            "session transcript returned unexpected attachment metadata".to_owned(),
        ));
    }
    let bytes =
        read_bounded_success_body(response, MAXIMUM_SESSION_TRANSCRIPT_EXPORT_BYTES).await?;
    if mealy_application::sha256_digest(&bytes) != digest {
        return Err(CliError::Protocol(
            "session transcript bytes did not match the canonical digest".to_owned(),
        ));
    }
    match format {
        ExportFormat::Json => validate_session_transcript_json(&bytes, session_id)?,
        ExportFormat::Html => super::validate_session_transcript_html(&bytes, session_id)?,
    }
    Ok((bytes, digest))
}

fn current_connection(home: &Path) -> Result<LocalConnectionInfo, CliError> {
    let connection = load_connection(home)?;
    if connection.api_version != API_VERSION {
        return Err(CliError::Protocol(
            "daemon connection descriptor uses an unsupported API version".to_owned(),
        ));
    }
    Ok(connection)
}

fn selected_id_owned(state: &Workbench) -> Result<String, CliError> {
    state
        .selected_id()
        .map(str::to_owned)
        .ok_or_else(|| CliError::Protocol("no conversation is selected".to_owned()))
}

fn validate_search_response(
    response: &SessionSearchResponse,
    expected_query: &str,
) -> Result<(), CliError> {
    if response.query != expected_query
        || response.hits.len() > MAXIMUM_SEARCH_RESULTS
        || response.hits.iter().any(|hit| {
            hit.session_id.parse::<SessionId>().is_err()
                || !valid_session_metadata(&hit.session_title)
                || !matches!(hit.session_title_source.as_str(), "owner" | "derived")
                || hit.created_at_ms < 0
        })
    {
        return Err(CliError::Protocol(
            "session search response violated its bounded canonical contract".to_owned(),
        ));
    }
    Ok(())
}

fn validate_timeline_page(page: &TimelinePageResponse, after: u64) -> Result<(), CliError> {
    if page.events.len() > 1000
        || (page.has_more && page.events.is_empty())
        || page
            .events
            .first()
            .is_some_and(|event| event.cursor.0 <= after)
        || page
            .events
            .windows(2)
            .any(|pair| pair[0].cursor.0 >= pair[1].cursor.0)
        || page
            .events
            .last()
            .is_some_and(|event| event.cursor > page.high_watermark)
    {
        return Err(CliError::Protocol(
            "timeline response violated its cursor or page bound".to_owned(),
        ));
    }
    Ok(())
}

fn handle_event(state: &mut Workbench, event: Event) -> Action {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(state, key),
        Event::Paste(value) => {
            if let Some(Overlay::Input { editor, .. }) = state.overlay.as_mut() {
                editor.insert_text(&value, 4_096);
            } else if state.overlay.is_none() && state.focus == Focus::Composer {
                editor_insert_composer(&mut state.composer, &value);
            }
            Action::None
        }
        _ => Action::None,
    }
}

fn handle_key(state: &mut Workbench, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }
    if let Some(overlay) = state.overlay.take() {
        return handle_overlay_key(state, overlay, key);
    }
    match key.code {
        KeyCode::F(1) => state.overlay = Some(Overlay::Help),
        KeyCode::F(2) => {
            if let Some(session) = state.selected_session() {
                state.overlay = Some(Overlay::Input {
                    purpose: InputPurpose::Rename,
                    editor: Editor::with_content(session.title.clone()),
                });
            }
        }
        KeyCode::F(3) => return Action::Checkpoint,
        KeyCode::F(4) => return Action::Fork,
        KeyCode::F(5) => return Action::Refresh,
        KeyCode::F(6) if key.modifiers.contains(KeyModifiers::SHIFT) => {
            return Action::Export(ExportFormat::Html);
        }
        KeyCode::F(6) => return Action::Export(ExportFormat::Json),
        KeyCode::F(7) if !state.approvals.is_empty() => {
            state.overlay = Some(Overlay::Approval { index: 0 });
        }
        KeyCode::F(8) if state.provider_catalog.is_some() && state.selected_id().is_some() => {
            state.overlay = Some(Overlay::Provider {
                index: current_provider_index(state),
            });
        }
        KeyCode::F(9)
            if state.selected_id().is_some()
                && state.pending_image_paths.len() < MAXIMUM_PROVIDER_IMAGE_INPUTS =>
        {
            state.overlay = Some(Overlay::Input {
                purpose: InputPurpose::ImagePath,
                editor: Editor::default(),
            });
        }
        KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
            state.focus = state.focus.previous();
        }
        KeyCode::BackTab => state.focus = state.focus.previous(),
        KeyCode::Tab => state.focus = state.focus.next(),
        KeyCode::Esc => {
            if state.focus == Focus::Composer
                && (!state.composer.content.is_empty() || !state.pending_image_paths.is_empty())
            {
                state.composer.clear();
                state.pending_image_paths.clear();
                state.set_notice("Composer cleared.", false);
            } else {
                state.focus = Focus::Sessions;
            }
        }
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Action::CreateSession;
        }
        KeyCode::Char('q') if state.focus != Focus::Composer => return Action::Quit,
        _ => return handle_focused_key(state, key),
    }
    Action::None
}

fn handle_overlay_key(state: &mut Workbench, mut overlay: Overlay, key: KeyEvent) -> Action {
    match &mut overlay {
        Overlay::Help => {
            if matches!(key.code, KeyCode::Esc | KeyCode::F(1) | KeyCode::Enter) {
                return Action::None;
            }
        }
        Overlay::Approval { index } => match key.code {
            KeyCode::Esc | KeyCode::F(7) => return Action::None,
            KeyCode::Char('a' | 'y') => {
                return Action::ResolveApproval {
                    index: *index,
                    decision: ApprovalDecisionCommand::Approve,
                };
            }
            KeyCode::Char('d' | 'n') => {
                return Action::ResolveApproval {
                    index: *index,
                    decision: ApprovalDecisionCommand::Deny,
                };
            }
            KeyCode::Up => *index = index.saturating_sub(1),
            KeyCode::Down => {
                *index = index
                    .saturating_add(1)
                    .min(state.approvals.len().saturating_sub(1));
            }
            _ => {}
        },
        Overlay::Provider { index } => {
            let maximum = state
                .provider_catalog
                .as_ref()
                .map_or(0, |catalog| catalog.routes.len());
            match key.code {
                KeyCode::Esc | KeyCode::F(8) => return Action::None,
                KeyCode::Up => *index = index.saturating_sub(1),
                KeyCode::Down => *index = index.saturating_add(1).min(maximum),
                KeyCode::Home => *index = 0,
                KeyCode::End => *index = maximum,
                KeyCode::Enter => {
                    return provider_selection_at(state, *index)
                        .map_or(Action::None, Action::SetSessionProvider);
                }
                KeyCode::Char('t') => {
                    return provider_selection_at(state, *index)
                        .map_or(Action::None, Action::SetNextTurnProvider);
                }
                _ => {}
            }
        }
        Overlay::Input { purpose, editor } => {
            let maximum = match purpose {
                InputPurpose::Search | InputPurpose::ImagePath => 4_096,
                InputPurpose::Rename => 160,
            };
            match key.code {
                KeyCode::Esc => return Action::None,
                KeyCode::Enter => {
                    let value = editor.content.trim().to_owned();
                    return match purpose {
                        InputPurpose::Search => Action::Search(value),
                        InputPurpose::Rename => Action::Rename(value),
                        InputPurpose::ImagePath => Action::AttachImage(value),
                    };
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    editor.insert_character(character, maximum);
                }
                KeyCode::Backspace => editor.backspace(),
                KeyCode::Delete => editor.delete(),
                KeyCode::Left => editor.move_left(),
                KeyCode::Right => editor.move_right(),
                KeyCode::Home => editor.cursor = 0,
                KeyCode::End => editor.cursor = editor.content.len(),
                _ => {}
            }
        }
    }
    state.overlay = Some(overlay);
    Action::None
}

#[allow(clippy::too_many_lines)]
fn handle_focused_key(state: &mut Workbench, key: KeyEvent) -> Action {
    match state.focus {
        Focus::Sessions => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                state.next_session(-1).then_some(Action::SelectSession)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                state.next_session(1).then_some(Action::SelectSession)
            }
            KeyCode::Home => state.select_index(0).then_some(Action::SelectSession),
            KeyCode::End if !state.sessions.is_empty() => state
                .select_index(state.sessions.len() - 1)
                .then_some(Action::SelectSession),
            KeyCode::Char('/') => {
                state.overlay = Some(Overlay::Input {
                    purpose: InputPurpose::Search,
                    editor: Editor::with_content(state.search_query.clone().unwrap_or_default()),
                });
                None
            }
            KeyCode::Enter => {
                state.focus = Focus::Composer;
                None
            }
            _ => None,
        },
        Focus::Conversation => {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    state.transcript_scroll = state.transcript_scroll.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    state.transcript_scroll = state.transcript_scroll.saturating_add(1);
                }
                KeyCode::PageUp => {
                    state.transcript_scroll = state.transcript_scroll.saturating_sub(10);
                }
                KeyCode::PageDown => {
                    state.transcript_scroll = state.transcript_scroll.saturating_add(10);
                }
                KeyCode::Home => state.transcript_scroll = 0,
                KeyCode::End => state.transcript_scroll = u16::MAX,
                KeyCode::Enter => state.focus = Focus::Composer,
                _ => {}
            }
            None
        }
        Focus::Composer => {
            let maximum = InputAdmissionLimits::default().maximum_content_bytes();
            match key.code {
                KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => {
                    state.composer.insert_character('\n', maximum);
                    None
                }
                KeyCode::Enter
                    if !state.composer.content.trim().is_empty()
                        || !state.pending_image_paths.is_empty() =>
                {
                    Some(Action::Send(state.composer.content.clone()))
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    state.composer.insert_character(character, maximum);
                    None
                }
                KeyCode::Backspace => {
                    state.composer.backspace();
                    None
                }
                KeyCode::Delete => {
                    state.composer.delete();
                    None
                }
                KeyCode::Left => {
                    state.composer.move_left();
                    None
                }
                KeyCode::Right => {
                    state.composer.move_right();
                    None
                }
                KeyCode::Home => {
                    state.composer.cursor = 0;
                    None
                }
                KeyCode::End => {
                    state.composer.cursor = state.composer.content.len();
                    None
                }
                _ => None,
            }
        }
        Focus::Activity => {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => state.next_activity(-1),
                KeyCode::Down | KeyCode::Char('j') => state.next_activity(1),
                KeyCode::Enter => state.focus = Focus::Composer,
                _ => {}
            }
            None
        }
    }
    .unwrap_or(Action::None)
}

fn editor_insert_composer(editor: &mut Editor, value: &str) {
    editor.insert_text(
        value,
        InputAdmissionLimits::default().maximum_content_bytes(),
    );
}

fn action_label(action: &Action) -> &'static str {
    match action {
        Action::None | Action::Quit => "",
        Action::Refresh => "Refreshing",
        Action::SelectSession => "Loading conversation",
        Action::CreateSession => "Creating conversation",
        Action::Send(_) => "Admitting input",
        Action::AttachImage(_) => "Attaching image",
        Action::Search(_) => "Searching transcripts",
        Action::Rename(_) => "Updating title",
        Action::Checkpoint => "Creating checkpoint",
        Action::Fork => "Checkpointing and forking",
        Action::Export(_) => "Verifying transcript export",
        Action::SetSessionProvider(_) => "Updating conversation model",
        Action::SetNextTurnProvider(_) => "Selecting next-turn model",
        Action::ResolveApproval { .. } => "Resolving exact approval",
    }
}

fn render(frame: &mut Frame<'_>, state: &mut Workbench) {
    let area = frame.area();
    if area.width < 60 || area.height < 18 {
        let warning = Paragraph::new(
            "Mealy workbench needs at least 60×18 cells.\nResize the terminal or press Ctrl-C.",
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .title(" Terminal too small ")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(warning, area.inner(Margin::new(2, 2)));
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(5),
        Constraint::Length(1),
    ])
    .split(area);
    render_header(frame, state, rows[0]);
    render_body(frame, state, rows[1]);
    render_composer(frame, state, rows[2]);
    render_footer(frame, state, rows[3]);
    if let Some(overlay) = &state.overlay {
        render_overlay(frame, state, overlay);
    }
}

fn render_header(frame: &mut Frame<'_>, state: &Workbench, area: Rect) {
    let selected = state
        .selected_session()
        .map_or("No conversation", |session| session.title.as_str());
    let status = state.admin.as_ref().map_or_else(
        || "provider unavailable".to_owned(),
        |admin| {
            format!(
                "{} · {} · {} context · {} µin/{} µout · {}",
                bounded_single_line(&admin.provider_id, 40),
                bounded_single_line(&admin.provider_model_id, 48),
                admin.provider_context_tokens,
                admin.provider_input_microunits_per_million_tokens,
                admin.provider_output_microunits_per_million_tokens,
                bounded_single_line(&admin.provider_health, 24)
            )
        },
    );
    let selection = state.session_provider_selection.as_ref().map_or_else(
        || "selection loading".to_owned(),
        |selection| provider_selection_label(&selection.provider_selection),
    );
    let line = Line::from(vec![
        Span::styled(
            " MEALY ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", bounded_single_line(selected, 80)),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{selection} · {status}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line)
            .block(Block::default().borders(Borders::BOTTOM))
            .alignment(Alignment::Left),
        area,
    );
}

fn render_body(frame: &mut Frame<'_>, state: &mut Workbench, area: Rect) {
    if area.width >= 110 {
        let columns = Layout::horizontal([
            Constraint::Percentage(24),
            Constraint::Percentage(48),
            Constraint::Percentage(28),
        ])
        .split(area);
        render_sessions(frame, state, columns[0]);
        render_conversation(frame, state, columns[1]);
        render_activity(frame, state, columns[2]);
    } else {
        let columns = Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
            .split(area);
        render_sessions(frame, state, columns[0]);
        render_conversation(frame, state, columns[1]);
    }
}

fn render_sessions(frame: &mut Frame<'_>, state: &Workbench, area: Rect) {
    let title = state.search_query.as_ref().map_or_else(
        || format!(" Conversations ({}) ", state.sessions.len()),
        |query| {
            format!(
                " Search: {} ({}) ",
                bounded_single_line(query, 24),
                state.sessions.len()
            )
        },
    );
    let items = state
        .sessions
        .iter()
        .enumerate()
        .map(|(index, session)| {
            let marker = if index == state.selected { "›" } else { " " };
            let activity = if session.active {
                "running"
            } else if session.pending_inputs > 0 {
                "queued"
            } else {
                session.status.as_str()
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{marker} "),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(bounded_single_line(&session.title, 64)),
                ]),
                Line::styled(
                    format!(
                        "  {} · {} · r{}",
                        short_id(&session.session_id),
                        bounded_single_line(activity, 20),
                        session.revision
                    ),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
            .style(if index == state.selected {
                Style::default().bg(Color::Rgb(28, 44, 52))
            } else {
                Style::default()
            })
        })
        .collect::<Vec<_>>();
    let border_style = focus_border(state.focus == Focus::Sessions);
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        ),
        area,
    );
}

fn render_conversation(frame: &mut Frame<'_>, state: &mut Workbench, area: Rect) {
    let title = state.selected_status.as_ref().map_or_else(
        || " Conversation ".to_owned(),
        |status| {
            format!(
                " Conversation · {} queued{} ",
                status.pending_inputs,
                status.active_turn_id.as_ref().map_or("", |_| " · running")
            )
        },
    );
    let lines = transcript_lines(state.transcript.as_ref());
    let content_width = usize::from(area.width.saturating_sub(2)).max(1);
    let total_rows = u16::try_from(
        lines
            .iter()
            .map(|line| line.width().max(1).div_ceil(content_width))
            .sum::<usize>(),
    )
    .unwrap_or(u16::MAX);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(focus_border(state.focus == Focus::Conversation));
    let inner = block.inner(area);
    let paragraph = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false });
    let maximum_scroll = total_rows.saturating_sub(inner.height);
    if state.transcript_scroll == u16::MAX || state.transcript_scroll > maximum_scroll {
        state.transcript_scroll = maximum_scroll;
    }
    frame.render_widget(paragraph.scroll((state.transcript_scroll, 0)), area);
}

fn transcript_lines(transcript: Option<&SessionTranscriptExport>) -> Vec<Line<'static>> {
    let Some(transcript) = transcript else {
        return vec![Line::styled(
            "Loading the verified canonical transcript…",
            Style::default().fg(Color::DarkGray),
        )];
    };
    if transcript.turns.is_empty() {
        return vec![
            Line::styled(
                "This conversation has no completed canonical turns yet.",
                Style::default().fg(Color::DarkGray),
            ),
            Line::raw(""),
            Line::raw("Compose below; durable admission is acknowledged before work begins."),
        ];
    }
    let mut lines = Vec::new();
    if transcript.bounds.omitted_turns > 0 {
        lines.push(Line::styled(
            format!(
                "{} older successful turn(s) are outside this bounded transcript window.",
                transcript.bounds.omitted_turns
            ),
            Style::default().fg(Color::Yellow),
        ));
        lines.push(Line::raw(""));
    }
    for turn in &transcript.turns {
        lines.push(Line::styled(
            format!("YOU  · turn {}", turn.sequence),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        extend_safe_text_lines(&mut lines, &turn.user.content, Style::default());
        for image in &turn.user.images {
            lines.push(Line::styled(
                format!(
                    "IMAGE · {} · {}×{} · {} bytes · sha256:{} · artifact {}",
                    bounded_single_line(&image.media_type, 32),
                    image.width,
                    image.height,
                    image.size_bytes,
                    bounded_single_line(&image.sha256_digest, 16),
                    bounded_single_line(&image.artifact_id, 36),
                ),
                Style::default().fg(Color::Magenta),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "MEALY  · {} / {}",
                bounded_single_line(&turn.provider_id, 48),
                bounded_single_line(&turn.model_id, 64)
            ),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
        extend_safe_text_lines(&mut lines, &turn.assistant.content, Style::default());
        if let Some(artifact_id) = &turn.assistant.artifact_id {
            lines.push(Line::styled(
                format!(
                    "ARTIFACT · {} · {} bytes · sha256:{} · {}",
                    bounded_single_line(&turn.assistant.media_type, 48),
                    turn.assistant.byte_length,
                    bounded_single_line(&turn.assistant.content_digest, 16),
                    bounded_single_line(artifact_id, 36),
                ),
                Style::default().fg(Color::Magenta),
            ));
        }
        lines.push(Line::raw(""));
    }
    lines
}

fn extend_safe_text_lines(lines: &mut Vec<Line<'static>>, value: &str, style: Style) {
    for line in terminal_safe_text(value).split('\n') {
        lines.push(Line::styled(line.to_owned(), style));
    }
}

fn render_activity(frame: &mut Frame<'_>, state: &Workbench, area: Rect) {
    let sections = Layout::vertical([
        Constraint::Percentage(48),
        Constraint::Percentage(32),
        Constraint::Percentage(20),
    ])
    .split(area);
    let start = state.timeline.len().saturating_sub(20);
    let items = state.timeline[start..]
        .iter()
        .enumerate()
        .map(|(offset, event)| {
            let index = start + offset;
            ListItem::new(Line::from(vec![
                Span::styled(
                    if index == state.activity_selected {
                        "› "
                    } else {
                        "  "
                    },
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw(bounded_single_line(&event.event_type, 64)),
                Span::styled(
                    format!(" #{}", event.cursor.0),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .style(if index == state.activity_selected {
                Style::default().bg(Color::Rgb(42, 32, 52))
            } else {
                Style::default()
            })
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title(" Durable activity ")
                .borders(Borders::ALL)
                .border_style(focus_border(state.focus == Focus::Activity)),
        ),
        sections[0],
    );

    let detail = state
        .timeline
        .get(state.activity_selected)
        .map_or_else(|| "No recent canonical event.".to_owned(), event_detail);
    frame.render_widget(
        Paragraph::new(detail)
            .block(
                Block::default()
                    .title(" Evidence preview ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        sections[1],
    );

    let approval_text = if let Some(approval) = state.approvals.first() {
        format!(
            "{} pending\n{} · {}\nF7 to review exact subject",
            state.approvals.len(),
            bounded_single_line(&approval.subject.capability_scope, 48),
            short_id(&approval.approval_id)
        )
    } else {
        "No pending approvals.\nEffects remain fail-closed.".to_owned()
    };
    frame.render_widget(
        Paragraph::new(approval_text)
            .block(Block::default().title(" Approvals ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        sections[2],
    );
}

fn event_detail(event: &TimelineEvent) -> String {
    let mut value = serde_json::to_string_pretty(&event.payload)
        .unwrap_or_else(|_| "{\"error\":\"payload could not be rendered\"}".to_owned());
    if value.len() > MAXIMUM_RENDERED_EVENT_DETAIL_BYTES {
        let mut boundary = MAXIMUM_RENDERED_EVENT_DETAIL_BYTES.saturating_sub('…'.len_utf8());
        while boundary > 0 && !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.truncate(boundary);
        value.push('…');
    }
    format!(
        "{}\n{} · {}\n{}",
        bounded_single_line(&event.event_type, 128),
        bounded_single_line(&event.aggregate_kind, 64),
        short_id(&event.aggregate_id),
        terminal_safe_text(&value)
    )
}

fn render_composer(frame: &mut Frame<'_>, state: &Workbench, area: Rect) {
    let route = state.next_turn_provider_selection.as_ref().map_or_else(
        || "inherits conversation model".to_owned(),
        |selection| format!("next turn: {}", provider_selection_label(selection)),
    );
    let title = if let Some(busy) = &state.busy {
        format!(" {busy}… ")
    } else {
        format!(
            " Composer · {} / {} bytes · {} image(s) · {} ",
            state.composer.content.len(),
            InputAdmissionLimits::default().maximum_content_bytes(),
            state.pending_image_paths.len(),
            route,
        )
    };
    let text = if state.composer.content.is_empty() {
        if state.pending_image_paths.is_empty() {
            Line::styled(
                "Type a request. Enter sends; Shift-Enter adds a line; F9 attaches an image.",
                Style::default().fg(Color::DarkGray),
            )
        } else {
            Line::styled(
                format!(
                    "{} image(s) attached. Enter sends with the default image prompt.",
                    state.pending_image_paths.len()
                ),
                Style::default().fg(Color::Magenta),
            )
        }
    } else {
        Line::raw(state.composer.rendered_with_cursor())
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(focus_border(state.focus == Focus::Composer)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, state: &Workbench, area: Rect) {
    let style = if state.notice_is_error {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " F1 help · F2 rename · F3 checkpoint · F4 fork · F6 export · F8 model · F9 image · ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(bounded_single_line(&state.notice, 180), style),
        ])),
        area,
    );
}

fn render_overlay(frame: &mut Frame<'_>, state: &Workbench, overlay: &Overlay) {
    let area = centered_rect(78, 72, frame.area());
    frame.render_widget(Clear, area);
    match overlay {
        Overlay::Help => {
            let help = [
                "Navigation",
                "  Tab / Shift-Tab     move between panes",
                "  ↑ ↓ or j k          select a conversation or activity event",
                "  PageUp/PageDown     scroll the conversation",
                "  /                   canonical transcript search (session pane)",
                "  Ctrl-N              new durable conversation",
                "",
                "Conversation",
                "  Enter               durably queue composer content",
                "  Shift-Enter         add a composer line",
                "  F2                  rename with revision fencing",
                "  F3                  create an immutable checkpoint",
                "  F4                  checkpoint then fork into fresh operational state",
                "  F6 / Shift-F6       verified private JSON / inert HTML export",
                "  F8                  choose default model; t applies only to next turn",
                "  F9                  attach one PNG/JPEG/WebP path (up to four)",
                "  Esc                 clear composer text and pending images",
                "",
                "Governance",
                "  F7                  review exact pending approval; a=approve, d=deny",
                "  Activity pane       inspect bounded structured event/tool evidence",
                "  F5                  refresh canonical daemon projections",
                "  Ctrl-C              restore terminal and exit",
                "",
                "The line-oriented `mealyctl chat` and scriptable commands remain available.",
            ]
            .join("\n");
            frame.render_widget(
                Paragraph::new(help)
                    .block(
                        Block::default()
                            .title(" Workbench controls · Esc/F1 closes ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan)),
                    )
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Overlay::Input { purpose, editor } => render_input_overlay(frame, area, *purpose, editor),
        Overlay::Approval { index } => {
            let text = state.approvals.get(*index).map_or_else(
                || "This approval is no longer pending.".to_owned(),
                |approval| approval_detail(approval, *index, state.approvals.len()),
            );
            frame.render_widget(
                Paragraph::new(text)
                    .block(
                        Block::default()
                            .title(" Exact approval · a approve · d deny · Esc cancel ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Yellow)),
                    )
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Overlay::Provider { index } => {
            render_provider_overlay(frame, state, area, *index);
        }
    }
}

fn render_input_overlay(frame: &mut Frame<'_>, area: Rect, purpose: InputPurpose, editor: &Editor) {
    let (title, hint) = match purpose {
        InputPurpose::Search => (
            " Search canonical transcripts ",
            "Enter searches user/final-assistant text; empty Enter clears; Esc cancels.",
        ),
        InputPurpose::Rename => (
            " Rename conversation ",
            "Enter commits with revision fencing; Esc cancels.",
        ),
        InputPurpose::ImagePath => (
            " Attach local image ",
            "Enter validates one no-follow PNG/JPEG/WebP path; F9 repeats up to four.",
        ),
    };
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(area);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(editor.rendered_with_cursor())
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(hint)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        rows[2],
    );
}

fn render_provider_overlay(frame: &mut Frame<'_>, state: &Workbench, area: Rect, index: usize) {
    let Some(catalog) = state.provider_catalog.as_ref() else {
        frame.render_widget(
            Paragraph::new("The configured provider catalog is unavailable.").block(
                Block::default()
                    .title(" Model selection ")
                    .borders(Borders::ALL),
            ),
            area,
        );
        return;
    };
    let mut items = Vec::with_capacity(catalog.routes.len().saturating_add(1));
    items.push(provider_list_item(
        index == 0,
        "Automatic",
        if catalog.automatic_fallback_enabled {
            "compatible primary with configured fallback"
        } else {
            "configured primary; no fallback"
        },
        "daemon chooses at admission",
    ));
    for (offset, route) in catalog.routes.iter().enumerate() {
        items.push(provider_route_list_item(index == offset + 1, route));
    }
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title(" Model · ↑/↓ choose · Enter conversation default · t next turn · Esc ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn provider_route_list_item(
    selected: bool,
    route: &ProviderCatalogRouteResponse,
) -> ListItem<'static> {
    let pressure = format!(
        "{}/{} active · {}/{} this minute",
        route.in_flight_requests,
        route.maximum_concurrent_requests,
        route.requests_in_current_minute,
        route.requests_per_minute
    );
    let detail = format!(
        "{} · {} · {} · {} context · {}",
        route.route_role, route.protocol, route.health, route.context_tokens, pressure
    );
    provider_list_item(
        selected,
        &format!("{}/{}", route.provider_id, route.model_id),
        &detail,
        if route.selectable {
            "selectable"
        } else {
            "not selectable"
        },
    )
}

fn provider_list_item(selected: bool, name: &str, detail: &str, status: &str) -> ListItem<'static> {
    ListItem::new(vec![
        Line::from(vec![
            Span::styled(
                if selected { "› " } else { "  " },
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                bounded_single_line(name, 100),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::styled(
            format!(
                "  {} · {}",
                bounded_single_line(detail, 160),
                bounded_single_line(status, 32)
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ])
    .style(if selected {
        Style::default().bg(Color::Rgb(28, 44, 52))
    } else {
        Style::default()
    })
}

fn current_provider_index(state: &Workbench) -> usize {
    let Some(ProviderSelectionCommand::Exact {
        provider_id,
        model_id,
    }) = state
        .session_provider_selection
        .as_ref()
        .map(|selection| &selection.provider_selection)
    else {
        return 0;
    };
    state
        .provider_catalog
        .as_ref()
        .and_then(|catalog| {
            catalog
                .routes
                .iter()
                .position(|route| route.provider_id == *provider_id && route.model_id == *model_id)
        })
        .map_or(0, |index| index + 1)
}

fn provider_selection_at(state: &Workbench, index: usize) -> Option<ProviderSelectionCommand> {
    if index == 0 {
        return Some(ProviderSelectionCommand::Automatic);
    }
    state
        .provider_catalog
        .as_ref()?
        .routes
        .get(index - 1)
        .filter(|route| route.selectable)
        .map(|route| ProviderSelectionCommand::Exact {
            provider_id: route.provider_id.clone(),
            model_id: route.model_id.clone(),
        })
}

fn provider_selection_label(selection: &ProviderSelectionCommand) -> String {
    match selection {
        ProviderSelectionCommand::Automatic => "Automatic routing".to_owned(),
        ProviderSelectionCommand::Exact {
            provider_id,
            model_id,
        } => format!(
            "{}/{}",
            bounded_single_line(provider_id, 64),
            bounded_single_line(model_id, 96)
        ),
    }
}

fn approval_detail(approval: &ApprovalResponse, index: usize, total: usize) -> String {
    let resources = approval
        .subject
        .target_resources
        .iter()
        .take(32)
        .map(|resource| format!("  - {}", bounded_single_line(resource, 256)))
        .collect::<Vec<_>>()
        .join("\n");
    let omitted_resources = approval.subject.target_resources.len().saturating_sub(32);
    format!(
        "Pending subject {} of {}\n\nApproval: {}\nEffect: {}\nCapability: {}\nPolicy: {}\nExpires: {} ms UTC\nSubject digest:\n{}\n\nTargets:\n{}\n\nOnly a/d resolves this exact rendered digest. ↑/↓ reviews another subject.",
        index + 1,
        total,
        bounded_single_line(&approval.approval_id, 128),
        bounded_single_line(&approval.effect_id, 128),
        bounded_single_line(&approval.subject.capability_scope, 256),
        bounded_single_line(&approval.subject.policy_version, 128),
        approval.subject.expires_at_ms,
        bounded_single_line(&approval.subject_digest, 128),
        if resources.is_empty() {
            "  (none)".to_owned()
        } else if omitted_resources > 0 {
            format!("{resources}\n  … {omitted_resources} additional target(s) omitted from view")
        } else {
            resources
        }
    )
}

fn focus_border(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn short_id(value: &str) -> String {
    bounded_single_line(value, 12)
}

fn bounded_single_line(value: &str, maximum_bytes: usize) -> String {
    let safe = terminal_safe_single_line(value);
    if safe.len() <= maximum_bytes {
        return safe;
    }
    let suffix = '…';
    let mut boundary = maximum_bytes.saturating_sub(suffix.len_utf8());
    while boundary > 0 && !safe.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut bounded = safe[..boundary].to_owned();
    bounded.push(suffix);
    bounded
}

#[cfg(test)]
mod tests {
    use super::{Editor, Workbench, bounded_single_line};

    #[test]
    fn editor_keeps_utf8_cursor_on_boundaries_and_enforces_bytes() {
        let mut editor = Editor::default();
        editor.insert_text("aλb", 4);
        assert_eq!(editor.content, "aλb");
        editor.move_left();
        editor.backspace();
        assert_eq!(editor.content, "ab");
        assert_eq!(editor.cursor, 1);
        editor.delete();
        assert_eq!(editor.content, "a");
        editor.insert_text("\u{001b}[31m", 8);
        assert_eq!(editor.content, "a[31m");
    }

    #[test]
    fn rendered_remote_labels_are_single_line_and_utf8_bounded() {
        assert_eq!(bounded_single_line("safe\nunsafe", 32), "safe�unsafe");
        assert_eq!(bounded_single_line("λλλλ", 7), "λλ…");
    }

    #[test]
    fn empty_workbench_navigation_is_total() {
        let mut state = Workbench::new();
        assert!(!state.next_session(1));
        assert!(!state.select_index(100));
        state.next_activity(1);
        assert_eq!(state.activity_selected, 0);
    }
}
