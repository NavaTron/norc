//! NavaTron NORC TUI Components
//!
//! Provides a composable terminal user interface for the NavaTron client
//! (and optionally server dashboard) using `ratatui` + `crossterm`.
//!
//! Layout (initial scaffold):
//! ┌───────────────────────────────────────────────┬──────────────────────┐
//! │ Messages                                     │ Rooms                │
//! │ (scrollback, highlights)                     │ (list, unread count) │
//! ├───────────────────────────────────────────────┴──────────────────────┤
//! │ Input (command / message / status)                                 │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │ Status Bar: time | net:connected | latency: -- | user: alice        │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//! This module provides a minimal non-blocking event loop harness which can be
//! embedded into the client binary. At this stage networking integration is
//! not wired—state mutations occur via public methods to be called by higher
//! level client tasks.
//!
//! Future improvements:
//! - Async mpsc channel bridging network events to UI thread
//! - Improved diff-based rendering & virtualization for large scrollback
//! - Theming & color fallback (feature gate `tui-color` vs monochrome)
//! - Keybinding configuration & command palette
//! - Search mode & scrollback persistence

#![deny(unsafe_code, missing_docs)]

use std::time::{Duration, Instant};
use std::io;
use crossterm::terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::event::{self, Event, KeyEvent, KeyCode};
use crossterm::execute;
use ratatui::{Terminal, backend::CrosstermBackend, Frame, layout::{Layout, Constraint, Direction, Rect}, widgets::{Block, Borders, Paragraph, List, ListItem, Wrap, Tabs}, text::{Span, Spans}};
use tracing::{debug, error};

/// Application mode (input / command / navigating)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
	/// Normal navigation mode
	Normal,
	/// Typing a chat message
	Insert,
	/// Command palette (slash-commands)
	Command,
}

/// Room metadata
#[derive(Debug, Clone)]
pub struct RoomItem {
	/// Room name
	pub name: String,
	/// Unread message count
	pub unread: u32,
	/// Whether user is currently joined
	pub joined: bool,
}

/// A single chat message in scrollback
#[derive(Debug, Clone)]
pub struct ChatMessage {
	/// Timestamp iso8601 (pre-formatted for simplicity here)
	pub ts: String,
	/// User id / system tag
	pub author: String,
	/// Message body
	pub body: String,
}

/// UI State container
#[derive(Debug)]
pub struct AppState {
	/// Current input buffer
	pub input: String,
	/// Collected messages in active room
	pub messages: Vec<ChatMessage>,
	/// Available rooms
	pub rooms: Vec<RoomItem>,
	/// Selected room index
	pub room_index: usize,
	/// Input mode
	pub mode: InputMode,
	/// Start time for uptime display
	pub start: Instant,
	/// Connection status
	pub connected: bool,
}

impl Default for AppState {
	fn default() -> Self {
		Self {
			input: String::new(),
			messages: Vec::new(),
			rooms: vec![RoomItem { name: "general".into(), unread: 0, joined: true }],
			room_index: 0,
			mode: InputMode::Normal,
			start: Instant::now(),
			connected: false,
		}
	}
}

impl AppState {
	/// Push a received message into scrollback
	pub fn push_message(&mut self, msg: ChatMessage) { self.messages.push(msg); }
	/// Set connection status
	pub fn set_connected(&mut self, v: bool) { self.connected = v; }
	/// Switch mode
	pub fn set_mode(&mut self, m: InputMode) { self.mode = m; }
	/// Cycle room selection
	pub fn next_room(&mut self) { if !self.rooms.is_empty() { self.room_index = (self.room_index + 1) % self.rooms.len(); }}
	/// Previous room
	pub fn prev_room(&mut self) { if !self.rooms.is_empty() { self.room_index = (self.room_index + self.rooms.len() - 1) % self.rooms.len(); }}
}

/// Run the TUI event/render loop until exit key is pressed (Esc or Ctrl+C)
pub fn run(mut state: AppState) -> io::Result<()> {
	enable_raw_mode()?;
	let mut stdout = io::stdout();
	execute!(stdout, EnterAlternateScreen)?;
	let backend = CrosstermBackend::new(stdout);
	let mut terminal = Terminal::new(backend)?;

	let tick_rate = Duration::from_millis(250);
	let mut last_tick = Instant::now();

	loop {
		terminal.draw(|f| draw_ui(f, &state))?;
		let timeout = tick_rate.saturating_sub(last_tick.elapsed());
		let should_tick = if event::poll(timeout)? { handle_event(&mut state)? } else { false };
		if should_tick || last_tick.elapsed() >= tick_rate { last_tick = Instant::now(); }
		if matches!(state.mode, InputMode::Command) && state.input == ":quit" { break; }
	}

	// Restore
	disable_raw_mode()?;
	let mut stdout = io::stdout();
	execute!(stdout, LeaveAlternateScreen)?;
	Ok(())
}

fn handle_event(state: &mut AppState) -> io::Result<bool> {
	if let Event::Key(key) = event::read()? {
		match state.mode {
			InputMode::Normal => match key.code {
				KeyCode::Char('q') | KeyCode::Esc => { state.input.clear(); state.set_mode(InputMode::Command); state.input.push_str(":quit"); },
				KeyCode::Char('i') => state.set_mode(InputMode::Insert),
				KeyCode::Char(':') => { state.set_mode(InputMode::Command); state.input.clear(); },
				KeyCode::Tab => state.next_room(),
				KeyCode::BackTab => state.prev_room(),
				_ => {}
			},
			InputMode::Insert => match key.code {
				KeyCode::Esc => state.set_mode(InputMode::Normal),
				KeyCode::Enter => { // submit message
					if !state.input.is_empty() {
						let body = std::mem::take(&mut state.input);
						state.push_message(ChatMessage { ts: timestamp(), author: "you".into(), body });
					}
				},
				KeyCode::Char(c) => state.input.push(c),
				KeyCode::Backspace => { state.input.pop(); },
				_ => {}
			},
			InputMode::Command => match key.code {
				KeyCode::Esc => { state.set_mode(InputMode::Normal); state.input.clear(); },
				KeyCode::Enter => { if state.input.trim() == ":quit" { /* loop sees and exits */ } else { state.input.clear(); state.set_mode(InputMode::Normal); } },
				KeyCode::Char(c) => state.input.push(c),
				KeyCode::Backspace => { state.input.pop(); },
				_ => {}
			}
		}
	}
	Ok(true)
}

fn draw_ui(f: &mut Frame<'_>, state: &AppState) {
	let chunks = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Min(5), // main
			Constraint::Length(3), // input
			Constraint::Length(1), // status
		]).split(f.size());

	let top_chunks = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage(70),
			Constraint::Percentage(30),
		])
		.split(chunks[0]);

	draw_messages(f, top_chunks[0], state);
	draw_rooms(f, top_chunks[1], state);
	draw_input(f, chunks[1], state);
	draw_status(f, chunks[2], state);
}

fn draw_messages(f: &mut Frame<'_>, area: Rect, state: &AppState) {
	let items: Vec<ListItem> = state.messages.iter().rev().take(200).map(|m| {
		ListItem::new(Spans::from(vec![
			Span::styled(format!("{} ", m.ts), ratatui::style::Style::default()),
			Span::styled(format!("<{}> ", m.author), ratatui::style::Style::default()),
			Span::raw(&m.body),
		]))
	}).collect();
	let list = List::new(items)
		.block(Block::default().title("Messages").borders(Borders::ALL));
	f.render_widget(list, area);
}

fn draw_rooms(f: &mut Frame<'_>, area: Rect, state: &AppState) {
	let items: Vec<ListItem> = state.rooms.iter().enumerate().map(|(i,r)| {
		let marker = if i == state.room_index { '>' } else { ' ' };
		let joined = if r.joined { '' } else { '*' };
		ListItem::new(format!("{}{} {} ({})", marker, joined, r.name, r.unread))
	}).collect();
	let list = List::new(items).block(Block::default().title("Rooms").borders(Borders::ALL));
	f.render_widget(list, area);
}

fn draw_input(f: &mut Frame<'_>, area: Rect, state: &AppState) {
	let title = match state.mode { InputMode::Insert => "Message", InputMode::Command => "Command", InputMode::Normal => "Input" };
	let paragraph = Paragraph::new(state.input.as_ref())
		.wrap(Wrap { trim: true })
		.block(Block::default().title(title).borders(Borders::ALL));
	f.render_widget(paragraph, area);
}

fn draw_status(f: &mut Frame<'_>, area: Rect, state: &AppState) {
	let uptime = state.start.elapsed().as_secs();
	let status_line = Spans::from(vec![
		Span::raw(format!("uptime:{}s", uptime)), Span::raw(" | "),
		Span::raw(format!("net:{}", if state.connected { "on" } else { "off" })), Span::raw(" | "),
		Span::raw(format!("room:{}", state.rooms.get(state.room_index).map(|r| &r.name).unwrap_or(&"?".into()))), Span::raw(" | "),
		Span::raw(format!("mode:{:?}", state.mode)),
	]);
	let block = Block::default().borders(Borders::ALL).title("Status");
	let paragraph = Paragraph::new(status_line).block(block);
	f.render_widget(paragraph, area);
}

fn timestamp() -> String { chrono::Utc::now().format("%H:%M:%S").to_string() }

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_state_room_cycle() {
		let mut s = AppState::default();
		s.rooms.push(RoomItem { name: "dev".into(), unread: 0, joined: true });
		let first = s.room_index;
		s.next_room();
		assert_ne!(first, s.room_index);
		s.prev_room();
		assert_eq!(first, s.room_index);
	}
}