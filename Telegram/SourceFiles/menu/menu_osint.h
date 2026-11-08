/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "menu/menu_osint_core.h"

class HistoryItem;
class History;

namespace Ui {
class PopupMenu;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace Osint {

// Adds "OSINT" items to a message context menu.
void AddMessageActions(
	not_null<Ui::PopupMenu*> menu,
	not_null<HistoryItem*> item,
	not_null<Window::SessionController*> controller);

void ShowMessageReport(
	not_null<HistoryItem*> item,
	not_null<Window::SessionController*> controller);

void ShowChatAnalysis(
	not_null<History*> history,
	not_null<Window::SessionController*> controller);

void ShowNotes(
	not_null<History*> history,
	not_null<Window::SessionController*> controller);

// Settings of OsintGram, stored in tdata/osintgram.json.
[[nodiscard]] const Settings &CurrentSettings();
void UpdateSettings(Fn<void(Settings&)> change);

// Downloads/OsintGram, where everything is saved.
[[nodiscard]] QString FolderPath();

// Whether the interface language is Russian.
[[nodiscard]] bool Russian();
[[nodiscard]] inline QString L(const QString &ru, const QString &en) {
	return Tr(Russian(), ru, en);
}

// Ghost mode, checked right before the corresponding API requests.
[[nodiscard]] bool GhostNoRead();
[[nodiscard]] bool GhostOffline();
[[nodiscard]] bool GhostNoStories();
[[nodiscard]] bool GhostNoTyping();

// Messages deleted on the server. Returns true when they must be kept.
[[nodiscard]] bool OnMessagesDeleted(
	const std::vector<not_null<HistoryItem*>> &items);

// Called before a message edit is applied.
void OnMessageEdited(
	not_null<HistoryItem*> item,
	const QString &newText,
	TimeId editDate);

// Label shown next to the time of a kept deleted message.
[[nodiscard]] QString BottomMark(not_null<const HistoryItem*> item);

// Removes tracking parameters from an external link, if enabled.
[[nodiscard]] QString CleanLink(const QString &url);

void ShowJournal(
	not_null<History*> history,
	not_null<Window::SessionController*> controller);

// Keyword monitoring of new messages, started once per session window.
void StartMonitor(not_null<Window::SessionController*> controller);
void ShowMonitorSettings(not_null<Window::SessionController*> controller);

} // namespace Osint
