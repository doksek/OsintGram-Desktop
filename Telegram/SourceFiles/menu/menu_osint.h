/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

class HistoryItem;
class History;

namespace Ui {
class PopupMenu;
} // namespace Ui

namespace Window {
class SessionController;
} // namespace Window

namespace Osint {

struct Indicator {
	QString type;
	QString value;
};

// Links, mentions, e-mails and crypto wallets found in a text.
[[nodiscard]] std::vector<Indicator> ExtractIndicators(const QString &text);

[[nodiscard]] QString Sha256(const QByteArray &data);
[[nodiscard]] QString Utc(TimeId date);

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

// Keyword monitoring of new messages, started once per session window.
void StartMonitor(not_null<Window::SessionController*> controller);
void ShowMonitorSettings(not_null<Window::SessionController*> controller);

// Perceptual (difference) hash of an image, 64 bits.
[[nodiscard]] uint64 ImageHash(const QImage &image);
[[nodiscard]] int HashDistance(uint64 a, uint64 b);

} // namespace Osint
