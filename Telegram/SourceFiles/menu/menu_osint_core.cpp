/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "menu/menu_osint_core.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>

#include <utility>

namespace Osint {
namespace {

[[nodiscard]] bool IsTrackingKey(const QString &key) {
	static const auto exact = QStringList{
		QStringLiteral("fbclid"),
		QStringLiteral("gclid"),
		QStringLiteral("dclid"),
		QStringLiteral("gbraid"),
		QStringLiteral("wbraid"),
		QStringLiteral("yclid"),
		QStringLiteral("ysclid"),
		QStringLiteral("msclkid"),
		QStringLiteral("igshid"),
		QStringLiteral("igsh"),
		QStringLiteral("mc_cid"),
		QStringLiteral("mc_eid"),
		QStringLiteral("_ga"),
		QStringLiteral("_gl"),
		QStringLiteral("_hsenc"),
		QStringLiteral("_hsmi"),
		QStringLiteral("mkt_tok"),
		QStringLiteral("oly_anon_id"),
		QStringLiteral("oly_enc_id"),
		QStringLiteral("vero_id"),
		QStringLiteral("spm"),
		QStringLiteral("scm"),
		QStringLiteral("twclid"),
		QStringLiteral("ttclid"),
		QStringLiteral("si"),
		QStringLiteral("feature"),
	};
	const auto lower = key.toLower();
	return lower.startsWith(QStringLiteral("utm_"))
		|| exact.contains(lower);
}

} // namespace

std::vector<Indicator> ExtractIndicators(const QString &text) {
	auto result = std::vector<Indicator>();
	if (text.isEmpty()) {
		return result;
	}
	static const auto patterns
		= std::vector<std::pair<QString, QRegularExpression>>{
		{ QStringLiteral("url"), QRegularExpression(QStringLiteral(
			"(?i)\\b(?:https?://|www\\.|t\\.me/|telegram\\.me/)"
			"[^\\s<>\"'()\\[\\]{}]+")) },
		{ QStringLiteral("mention"), QRegularExpression(QStringLiteral(
			"(?<![\\w@/])@[A-Za-z][A-Za-z0-9_]{3,31}\\b")) },
		{ QStringLiteral("email"), QRegularExpression(QStringLiteral(
			"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b")) },
		{ QStringLiteral("wallet_btc"), QRegularExpression(QStringLiteral(
			"\\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b")) },
		{ QStringLiteral("wallet_evm"), QRegularExpression(QStringLiteral(
			"\\b0x[a-fA-F0-9]{40}\\b")) },
		{ QStringLiteral("wallet_tron"), QRegularExpression(QStringLiteral(
			"\\bT[1-9A-HJ-NP-Za-km-z]{33}\\b")) },
		{ QStringLiteral("wallet_ton"), QRegularExpression(QStringLiteral(
			"(?<![A-Za-z0-9_-])(?:EQ|UQ)[A-Za-z0-9_-]{46}"
			"(?![A-Za-z0-9_-])")) },
	};
	static const auto trailing = QString::fromUtf8(".,;:!?\xC2\xBB");
	for (const auto &[type, regex] : patterns) {
		auto it = regex.globalMatch(text);
		while (it.hasNext()) {
			auto value = it.next().captured(0);
			if (type == QStringLiteral("url")) {
				while (!value.isEmpty() && trailing.contains(value.back())) {
					value.chop(1);
				}
			}
			if (!value.isEmpty()) {
				result.push_back({ type, value });
			}
		}
	}
	return result;
}

QString Sha256(const QByteArray &data) {
	return QString::fromLatin1(
		QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

QString Utc(qint64 unixtime) {
	if (unixtime <= 0) {
		return QStringLiteral("-");
	}
	return QDateTime::fromSecsSinceEpoch(unixtime).toUTC().toString(
		QStringLiteral("yyyy-MM-dd HH:mm:ss")) + QStringLiteral(" UTC");
}

quint64 ImageHash(const QImage &image) {
	if (image.isNull()) {
		return 0;
	}
	// Difference hash: 9x8 grayscale, compare horizontal neighbours.
	const auto small = image.convertToFormat(
		QImage::Format_Grayscale8
	).scaled(9, 8, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
	auto result = quint64(0);
	auto bit = 0;
	for (auto y = 0; y != 8; ++y) {
		const auto line = small.constScanLine(y);
		for (auto x = 0; x != 8; ++x) {
			if (line[x] > line[x + 1]) {
				result |= (quint64(1) << bit);
			}
			++bit;
		}
	}
	return result;
}

int HashDistance(quint64 a, quint64 b) {
	auto value = a ^ b;
	auto result = 0;
	while (value) {
		value &= (value - 1);
		++result;
	}
	return result;
}

QString StripTracking(const QString &url) {
	auto parsed = QUrl(url);
	if (!parsed.isValid()
		|| !parsed.hasQuery()
		|| (parsed.scheme() != QStringLiteral("http")
			&& parsed.scheme() != QStringLiteral("https"))) {
		return url;
	}
	auto query = QUrlQuery(parsed);
	auto kept = QList<QPair<QString, QString>>();
	auto removed = false;
	for (const auto &item : query.queryItems(QUrl::FullyEncoded)) {
		if (IsTrackingKey(item.first)) {
			removed = true;
		} else {
			kept.push_back(item);
		}
	}
	if (!removed) {
		return url;
	}
	auto cleaned = QUrlQuery();
	cleaned.setQueryItems(kept);
	parsed.setQuery(kept.isEmpty() ? QString() : cleaned.query(QUrl::FullyEncoded), QUrl::StrictMode);
	return parsed.toString(QUrl::FullyEncoded);
}

QByteArray Settings::serialize() const {
	auto o = QJsonObject();
	o.insert(QStringLiteral("ghostNoRead"), ghostNoRead);
	o.insert(QStringLiteral("ghostOffline"), ghostOffline);
	o.insert(QStringLiteral("ghostNoStories"), ghostNoStories);
	o.insert(QStringLiteral("ghostNoTyping"), ghostNoTyping);
	o.insert(QStringLiteral("keepDeleted"), keepDeleted);
	o.insert(QStringLiteral("keepEdits"), keepEdits);
	o.insert(QStringLiteral("markDeleted"), markDeleted);
	o.insert(QStringLiteral("stripTracking"), stripTracking);
	o.insert(QStringLiteral("showMenu"), showMenu);
	o.insert(QStringLiteral("localTime"), localTime);
	o.insert(QStringLiteral("monitorEnabled"), monitorEnabled);
	o.insert(QStringLiteral("monitorToasts"), monitorToasts);
	return QJsonDocument(o).toJson(QJsonDocument::Indented);
}

Settings Settings::Deserialize(const QByteArray &data) {
	auto result = Settings();
	const auto document = QJsonDocument::fromJson(data);
	if (!document.isObject()) {
		return result;
	}
	const auto o = document.object();
	const auto read = [&](const char *key, bool &field) {
		const auto value = o.value(QLatin1String(key));
		if (value.isBool()) {
			field = value.toBool();
		}
	};
	read("ghostNoRead", result.ghostNoRead);
	read("ghostOffline", result.ghostOffline);
	read("ghostNoStories", result.ghostNoStories);
	read("ghostNoTyping", result.ghostNoTyping);
	read("keepDeleted", result.keepDeleted);
	read("keepEdits", result.keepEdits);
	read("markDeleted", result.markDeleted);
	read("stripTracking", result.stripTracking);
	read("showMenu", result.showMenu);
	read("localTime", result.localTime);
	read("monitorEnabled", result.monitorEnabled);
	read("monitorToasts", result.monitorToasts);
	return result;
}

QByteArray JournalRecord::toLine() const {
	auto o = QJsonObject();
	o.insert(
		QStringLiteral("kind"),
		(kind == Kind::Deleted)
			? QStringLiteral("deleted")
			: QStringLiteral("edited"));
	o.insert(QStringLiteral("chat_id"), QString::number(chatId));
	o.insert(QStringLiteral("message_id"), QString::number(messageId));
	o.insert(QStringLiteral("date"), QString::number(date));
	o.insert(QStringLiteral("at"), QString::number(at));
	o.insert(QStringLiteral("chat"), chat);
	o.insert(QStringLiteral("sender"), sender);
	o.insert(QStringLiteral("text"), text);
	if (kind == Kind::Edited) {
		o.insert(QStringLiteral("new_text"), newText);
	}
	return QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n';
}

std::vector<JournalRecord> JournalRecord::ParseLines(const QByteArray &data) {
	auto result = std::vector<JournalRecord>();
	for (const auto &line : data.split('\n')) {
		if (line.trimmed().isEmpty()) {
			continue;
		}
		const auto document = QJsonDocument::fromJson(line);
		if (!document.isObject()) {
			continue;
		}
		const auto o = document.object();
		const auto kind = o.value(QStringLiteral("kind")).toString();
		if (kind != QStringLiteral("deleted")
			&& kind != QStringLiteral("edited")) {
			continue;
		}
		auto record = JournalRecord();
		record.kind = (kind == QStringLiteral("deleted"))
			? Kind::Deleted
			: Kind::Edited;
		const auto number = [&](const char *key) {
			return o.value(QLatin1String(key)).toString().toLongLong();
		};
		record.chatId = number("chat_id");
		record.messageId = number("message_id");
		record.date = number("date");
		record.at = number("at");
		record.chat = o.value(QStringLiteral("chat")).toString();
		record.sender = o.value(QStringLiteral("sender")).toString();
		record.text = o.value(QStringLiteral("text")).toString();
		record.newText = o.value(QStringLiteral("new_text")).toString();
		result.push_back(std::move(record));
	}
	return result;
}

} // namespace Osint
