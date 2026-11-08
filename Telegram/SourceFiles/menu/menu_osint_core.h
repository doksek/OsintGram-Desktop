/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

// Pure logic of OsintGram: no session, no widgets, only QtCore / QtGui.
// Everything here is covered by tests/test_osint_core.cpp.

#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtGui/QImage>

#include <vector>

namespace Osint {

struct Indicator {
	QString type;
	QString value;
};

// Links, mentions, e-mails and crypto wallets found in a text.
[[nodiscard]] std::vector<Indicator> ExtractIndicators(const QString &text);

[[nodiscard]] QString Sha256(const QByteArray &data);
[[nodiscard]] QString Utc(qint64 unixtime);

// Perceptual (difference) hash of an image, 64 bits.
[[nodiscard]] quint64 ImageHash(const QImage &image);
[[nodiscard]] int HashDistance(quint64 a, quint64 b);

// Removes tracking parameters (utm_*, fbclid, gclid, ...) from a link.
[[nodiscard]] QString StripTracking(const QString &url);

// Picks the Russian or English text.
[[nodiscard]] inline QString Tr(bool russian, const QString &ru, const QString &en) {
	return russian ? ru : en;
}

struct Settings {
	// Ghost mode.
	bool ghostNoRead = false;
	bool ghostOffline = false;
	bool ghostNoStories = false;
	bool ghostNoTyping = false;

	// What other people delete or edit.
	bool keepDeleted = true;
	bool keepEdits = true;
	bool markDeleted = true;

	// Anonymity.
	bool stripTracking = true;

	// OSINT tools.
	bool showMenu = true;
	bool localTime = false;
	bool monitorEnabled = true;
	bool monitorToasts = true;

	[[nodiscard]] bool ghostAll() const {
		return ghostNoRead && ghostOffline && ghostNoStories && ghostNoTyping;
	}
	void setGhostAll(bool enabled) {
		ghostNoRead = ghostOffline = ghostNoStories = ghostNoTyping = enabled;
	}

	[[nodiscard]] QByteArray serialize() const;
	// Unknown or missing keys keep their default values.
	[[nodiscard]] static Settings Deserialize(const QByteArray &data);

	friend inline bool operator==(const Settings &, const Settings &) = default;
};

// One line of the local journal of deleted and edited messages.
struct JournalRecord {
	enum class Kind {
		Deleted,
		Edited,
	};
	Kind kind = Kind::Deleted;
	qint64 chatId = 0;
	qint64 messageId = 0;
	qint64 date = 0; // When the message was sent.
	qint64 at = 0; // When it was deleted or edited.
	QString chat;
	QString sender;
	QString text; // Last known text (for edits - the text before the edit).
	QString newText; // For edits only.

	[[nodiscard]] QByteArray toLine() const;
	[[nodiscard]] static std::vector<JournalRecord> ParseLines(
		const QByteArray &data);

	friend inline bool operator==(
		const JournalRecord &,
		const JournalRecord &) = default;
};

} // namespace Osint
