/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "menu/menu_osint.h"

#include "base/flat_set.h"
#include "core/file_utilities.h"
#include "data/data_channel.h"
#include "data/data_document.h"
#include "data/data_media_types.h"
#include "data/data_peer.h"
#include "data/data_photo.h"
#include "data/data_photo_media.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "dialogs/dialogs_key.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/history_item_components.h"
#include "history/view/history_view_element.h"
#include "main/main_session.h"
#include "ui/image/image.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/popup_menu.h"
#include "window/window_session_controller.h"
#include "styles/style_info.h"
#include "styles/style_layers.h"
#include "styles/style_menu_icons.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QRegularExpression>
#include <QtCore/QStandardPaths>
#include <QtCore/QUrl>
#include <QtGui/QClipboard>
#include <QtGui/QDesktopServices>
#include <QtGui/QGuiApplication>

namespace Osint {
namespace {

// Everything OsintGram saves goes to Downloads/OsintGram.
[[nodiscard]] QString OutputFolder(const QString &sub = QString()) {
	auto base = QStandardPaths::writableLocation(
		QStandardPaths::DownloadLocation);
	if (base.isEmpty()) {
		base = QDir::homePath();
	}
	auto path = base + u"/OsintGram"_q;
	if (!sub.isEmpty()) {
		path += '/' + sub;
	}
	QDir().mkpath(path);
	return path;
}

[[nodiscard]] QString FileStamp() {
	return QDateTime::currentDateTimeUtc().toString(u"yyyyMMdd_HHmmss"_q);
}

[[nodiscard]] bool WriteFile(const QString &path, const QByteArray &data) {
	auto f = QFile(path);
	if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return false;
	}
	return (f.write(data) == data.size());
}

[[nodiscard]] int64 BareId(not_null<PeerData*> peer) {
	return int64(peer->id.value & PeerId::kChatTypeMask);
}

[[nodiscard]] QString PeerLine(PeerData *peer) {
	if (!peer) {
		return u"-"_q;
	}
	const auto username = peer->username();
	return peer->name()
		+ (username.isEmpty() ? QString() : (u" (@"_q + username + ')'))
		+ u" [id "_q + QString::number(BareId(peer)) + ']';
}

[[nodiscard]] QString MessageLink(not_null<PeerData*> peer, MsgId id) {
	const auto channel = peer->asChannel();
	if (!channel || id.bare <= 0) {
		return QString();
	}
	const auto username = peer->username();
	return username.isEmpty()
		? (u"https://t.me/c/"_q
			+ QString::number(BareId(peer))
			+ '/'
			+ QString::number(id.bare))
		: (u"https://t.me/"_q
			+ username
			+ '/'
			+ QString::number(id.bare));
}

void AppendPassport(QString &out, PeerData *peer) {
	if (!peer) {
		out += u"(unknown)\n"_q;
		return;
	}
	out += u"ID: "_q + QString::number(BareId(peer)) + '\n';
	out += u"Name: "_q + peer->name() + '\n';
	const auto username = peer->username();
	out += u"Username: "_q
		+ (username.isEmpty() ? u"-"_q : ('@' + username))
		+ '\n';
	auto all = QStringList();
	if (const auto user = peer->asUser()) {
		for (const auto &name : user->usernames()) {
			all.push_back('@' + name);
		}
	} else if (const auto channel = peer->asChannel()) {
		for (const auto &name : channel->usernames()) {
			all.push_back('@' + name);
		}
	}
	if (all.size() > 1) {
		out += u"All usernames: "_q + all.join(u", "_q) + '\n';
	}
	auto type = QString();
	if (const auto user = peer->asUser()) {
		type = user->isBot() ? u"bot"_q : u"user"_q;
	} else if (peer->isBroadcast()) {
		type = u"channel"_q;
	} else if (peer->isMegagroup()) {
		type = u"supergroup"_q;
	} else {
		type = u"group"_q;
	}
	out += u"Type: "_q + type + '\n';
	if (const auto channel = peer->asChannel()) {
		if (channel->membersCount() > 0) {
			out += u"Members: "_q
				+ QString::number(channel->membersCount())
				+ '\n';
		}
		if (channel->date > 0) {
			out += u"Date (creation or your join): "_q
				+ Utc(channel->date)
				+ '\n';
		}
	}
	auto flags = QStringList();
	if (peer->isVerified()) flags.push_back(u"verified"_q);
	if (peer->isPremium()) flags.push_back(u"premium"_q);
	if (peer->isScam()) flags.push_back(u"SCAM"_q);
	if (peer->isFake()) flags.push_back(u"FAKE"_q);
	out += u"Flags: "_q
		+ (flags.isEmpty() ? u"-"_q : flags.join(' '))
		+ '\n';
}

[[nodiscard]] std::vector<Indicator> ItemIndicators(
		not_null<HistoryItem*> item) {
	const auto &text = item->originalText();
	auto result = ExtractIndicators(text.text);
	for (const auto &entity : text.entities) {
		if (entity.type() == EntityType::CustomUrl
			&& !entity.data().isEmpty()) {
			result.push_back({ u"url_hidden"_q, entity.data() });
		}
	}
	return result;
}

[[nodiscard]] QString BuildReport(not_null<HistoryItem*> item) {
	const auto history = item->history();
	const auto peer = history->peer;
	auto out = QString();

	out += u"== MESSAGE ==\n"_q;
	out += u"Message ID: "_q + QString::number(item->id.bare) + '\n';
	out += u"Chat: "_q + PeerLine(peer) + '\n';
	const auto link = MessageLink(peer, item->id);
	if (!link.isEmpty()) {
		out += u"Link: "_q + link + '\n';
	}
	out += u"Date: "_q + Utc(item->date()) + '\n';
	if (const auto edited = item->Get<HistoryMessageEdited>()) {
		if (edited->date > 0) {
			out += u"Edited: "_q + Utc(edited->date) + '\n';
		}
	}
	if (item->viewsCount() > 0) {
		out += u"Views: "_q + QString::number(item->viewsCount()) + '\n';
	}
	const auto signature = item->originalPostAuthor();
	if (!signature.isEmpty()) {
		out += u"Author signature: "_q + signature + '\n';
	}

	out += u"\n== SENDER ==\n"_q;
	AppendPassport(out, item->from().get());

	if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
		out += u"\n== FORWARDED FROM ==\n"_q;
		if (forwarded->originalSender) {
			AppendPassport(out, forwarded->originalSender);
			if (forwarded->originalId.bare > 0) {
				out += u"Original message ID: "_q
					+ QString::number(forwarded->originalId.bare)
					+ '\n';
				const auto original = MessageLink(
					forwarded->originalSender,
					forwarded->originalId);
				if (!original.isEmpty()) {
					out += u"Original link: "_q + original + '\n';
				}
			}
		} else if (forwarded->originalHiddenSenderInfo) {
			out += u"Hidden account name: "_q
				+ forwarded->originalHiddenSenderInfo->name
				+ '\n';
		}
		if (!forwarded->originalPostAuthor.isEmpty()) {
			out += u"Original author signature: "_q
				+ forwarded->originalPostAuthor
				+ '\n';
		}
		out += u"Original date: "_q + Utc(forwarded->originalDate) + '\n';
		if (forwarded->savedFromPeer) {
			out += u"Saved from: "_q
				+ PeerLine(forwarded->savedFromPeer)
				+ '\n';
		}
	}

	if (const auto media = item->media()) {
		if (const auto document = media->document()) {
			out += u"\n== MEDIA ==\n"_q;
			out += u"Type: document\n"_q;
			if (!document->filename().isEmpty()) {
				out += u"File name: "_q + document->filename() + '\n';
			}
			out += u"MIME: "_q + document->mimeString() + '\n';
			out += u"Size: "_q + QString::number(document->size)
				+ u" bytes\n"_q;
			out += u"File ID: "_q + QString::number(document->id) + '\n';
		} else if (const auto photo = media->photo()) {
			out += u"\n== MEDIA ==\n"_q;
			out += u"Type: photo\n"_q;
			out += u"Photo ID: "_q + QString::number(photo->id) + '\n';
		}
	}

	const auto indicators = ItemIndicators(item);
	if (!indicators.empty()) {
		out += u"\n== INDICATORS ==\n"_q;
		for (const auto &indicator : indicators) {
			out += indicator.type + u": "_q + indicator.value + '\n';
		}
	}

	out += u"\n== INTEGRITY ==\n"_q;
	out += u"Text SHA-256: "_q
		+ Sha256(item->originalText().text.toUtf8())
		+ '\n';
	out += u"Report generated: "_q
		+ Utc(TimeId(QDateTime::currentSecsSinceEpoch()))
		+ u" by OsintGram\n"_q;
	return out;
}

[[nodiscard]] QJsonObject ItemJson(not_null<HistoryItem*> item) {
	const auto peer = item->history()->peer;
	auto o = QJsonObject();
	o.insert(u"message_id"_q, double(item->id.bare));
	o.insert(u"date_utc"_q, Utc(item->date()));
	o.insert(u"date_unix"_q, double(item->date()));
	const auto link = MessageLink(peer, item->id);
	if (!link.isEmpty()) {
		o.insert(u"link"_q, link);
	}
	o.insert(u"sender_id"_q, double(BareId(item->from())));
	o.insert(u"sender"_q, PeerLine(item->from().get()));
	o.insert(u"text"_q, item->originalText().text);
	o.insert(
		u"text_sha256"_q,
		Sha256(item->originalText().text.toUtf8()));
	if (item->viewsCount() > 0) {
		o.insert(u"views"_q, item->viewsCount());
	}
	if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
		auto f = QJsonObject();
		if (forwarded->originalSender) {
			f.insert(
				u"from_id"_q,
				double(BareId(forwarded->originalSender)));
			f.insert(u"from"_q, PeerLine(forwarded->originalSender));
			if (forwarded->originalId.bare > 0) {
				f.insert(
					u"original_id"_q,
					double(forwarded->originalId.bare));
			}
		} else if (forwarded->originalHiddenSenderInfo) {
			f.insert(
				u"from_name"_q,
				forwarded->originalHiddenSenderInfo->name);
		}
		f.insert(u"date_utc"_q, Utc(forwarded->originalDate));
		o.insert(u"forwarded_from"_q, f);
	}
	auto indicators = QJsonArray();
	for (const auto &indicator : ItemIndicators(item)) {
		auto x = QJsonObject();
		x.insert(u"type"_q, indicator.type);
		x.insert(u"value"_q, indicator.value);
		indicators.append(x);
	}
	o.insert(u"indicators"_q, indicators);
	return o;
}

[[nodiscard]] std::vector<not_null<HistoryItem*>> LoadedItems(
		not_null<History*> history) {
	auto result = std::vector<not_null<HistoryItem*>>();
	for (const auto &block : history->blocks) {
		for (const auto &view : block->messages) {
			const auto item = view->data();
			if (item->id.bare > 0 && !item->isService()) {
				result.push_back(item);
			}
		}
	}
	return result;
}

[[nodiscard]] QString CsvField(QString value) {
	if (value.contains(',')
		|| value.contains('"')
		|| value.contains('\n')) {
		value.replace(u"\""_q, u"\"\""_q);
		return '"' + value + '"';
	}
	return value;
}

[[nodiscard]] QString HtmlEscape(const QString &value) {
	return value.toHtmlEscaped().replace('\n', u"<br>"_q);
}

void ShowTextBox(
		not_null<Window::SessionController*> controller,
		const QString &title,
		const QString &text,
		std::vector<std::pair<QString, Fn<void()>>> buttons) {
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(title));
		box->setWidth(st::boxWideWidth * 3 / 2);
		const auto label = box->addRow(
			object_ptr<Ui::FlatLabel>(box, text, st::boxLabel));
		label->setSelectable(true);
		for (const auto &[name, callback] : buttons) {
			box->addButton(rpl::single(name), callback);
		}
		box->addButton(rpl::single(u"Закрыть"_q), [=] {
			box->closeBox();
		});
	}));
}

void SaveEvidence(
		not_null<HistoryItem*> item,
		not_null<Window::SessionController*> controller,
		const QString &report) {
	auto json = ItemJson(item);
	json.insert(u"tool"_q, u"OsintGram Desktop"_q);
	json.insert(
		u"captured_at_utc"_q,
		Utc(TimeId(QDateTime::currentSecsSinceEpoch())));
	json.insert(u"chat"_q, PeerLine(item->history()->peer));
	json.insert(u"report"_q, report);
	const auto body = QJsonDocument(json).toJson(QJsonDocument::Indented);
	const auto base = u"evidence_"_q
		+ QString::number(BareId(item->history()->peer))
		+ '_'
		+ QString::number(item->id.bare)
		+ '_'
		+ FileStamp();
	const auto folder = OutputFolder(u"evidence"_q);
	const auto jsonPath = folder + '/' + base + u".json"_q;
	const auto txt = report
		+ u"\nEvidence file: "_q + base + u".json\n"_q
		+ u"Evidence file SHA-256: "_q + Sha256(body) + '\n';
	const auto txtPath = folder + '/' + base + u".txt"_q;
	if (WriteFile(jsonPath, body) && WriteFile(txtPath, txt.toUtf8())) {
		controller->showToast(u"Сохранено: "_q + txtPath);
		File::ShowInFolder(txtPath);
	} else {
		controller->showToast(u"Не удалось сохранить в "_q + folder);
	}
}

struct ChatStats {
	int messages = 0;
	TimeId first = 0;
	TimeId last = 0;
	std::array<int, 24> hours = {};
	std::array<int, 7> weekdays = {};
	int64 viewsSum = 0;
	int withViews = 0;
	int maxViews = 0;
	int forwarded = 0;
	std::map<QString, int> sources;
	std::map<std::pair<QString, QString>, int> indicators;
};

[[nodiscard]] ChatStats CollectStats(
		const std::vector<not_null<HistoryItem*>> &items) {
	auto stats = ChatStats();
	for (const auto &item : items) {
		++stats.messages;
		const auto date = item->date();
		if (!stats.first || date < stats.first) {
			stats.first = date;
		}
		stats.last = std::max(stats.last, date);
		const auto utc = QDateTime::fromSecsSinceEpoch(date).toUTC();
		++stats.hours[utc.time().hour()];
		++stats.weekdays[utc.date().dayOfWeek() - 1];
		if (item->viewsCount() > 0) {
			stats.viewsSum += item->viewsCount();
			++stats.withViews;
			stats.maxViews = std::max(stats.maxViews, item->viewsCount());
		}
		if (const auto forwarded = item->Get<HistoryMessageForwarded>()) {
			++stats.forwarded;
			const auto source = forwarded->originalSender
				? PeerLine(forwarded->originalSender)
				: forwarded->originalHiddenSenderInfo
				? (forwarded->originalHiddenSenderInfo->name
					+ u" (hidden account)"_q)
				: u"(unknown)"_q;
			++stats.sources[source];
		}
		for (const auto &indicator : ItemIndicators(item)) {
			++stats.indicators[{ indicator.type, indicator.value }];
		}
	}
	return stats;
}

[[nodiscard]] QString Bar(int value, int max) {
	const auto width = (max > 0) ? (value * 20 + max - 1) / max : 0;
	return QString(width, QChar(0x2588));
}

[[nodiscard]] QString StatsText(
		not_null<History*> history,
		const ChatStats &stats) {
	auto out = QString();
	out += u"Чат: "_q + PeerLine(history->peer) + '\n';
	out += u"Загружено сообщений: "_q
		+ QString::number(stats.messages)
		+ '\n';
	if (stats.messages) {
		out += u"Период: "_q + Utc(stats.first) + u" — "_q
			+ Utc(stats.last) + '\n';
	}
	out += u"(Прокрутите чат вверх, чтобы подгрузить больше истории.)\n"_q;

	out += u"\n== Активность по часам (UTC) ==\n"_q;
	const auto maxHour = *std::max_element(
		stats.hours.begin(),
		stats.hours.end());
	for (auto h = 0; h != 24; ++h) {
		out += QString(u"%1:00 %2 %3\n"_q)
			.arg(h, 2, 10, QChar('0'))
			.arg(Bar(stats.hours[h], maxHour))
			.arg(stats.hours[h]);
	}
	out += u"\n== По дням недели (UTC) ==\n"_q;
	const auto names = std::array<QString, 7>{
		u"Пн"_q, u"Вт"_q, u"Ср"_q, u"Чт"_q, u"Пт"_q, u"Сб"_q, u"Вс"_q,
	};
	const auto maxDay = *std::max_element(
		stats.weekdays.begin(),
		stats.weekdays.end());
	for (auto d = 0; d != 7; ++d) {
		out += names[d] + ' ' + Bar(stats.weekdays[d], maxDay) + ' '
			+ QString::number(stats.weekdays[d]) + '\n';
	}

	if (stats.withViews > 0) {
		out += u"\n== Просмотры ==\n"_q;
		const auto average = stats.viewsSum / stats.withViews;
		out += u"Средние: "_q + QString::number(average) + '\n';
		out += u"Максимум: "_q + QString::number(stats.maxViews) + '\n';
		if (const auto channel = history->peer->asChannel()) {
			const auto members = channel->membersCount();
			if (members > 0) {
				const auto percent = average * 100 / members;
				out += u"Средние просмотры / подписчики: "_q
					+ QString::number(percent) + u"%"_q;
				if (percent < 5) {
					out += u" — очень низко, возможна накрутка подписчиков"_q;
				}
				out += '\n';
			}
		}
	}

	out += u"\n== Источники пересылок ==\n"_q;
	out += u"Пересланных сообщений: "_q
		+ QString::number(stats.forwarded)
		+ '\n';
	auto sources = std::vector<std::pair<int, QString>>();
	for (const auto &[name, count] : stats.sources) {
		sources.emplace_back(count, name);
	}
	ranges::sort(sources, std::greater<>());
	auto shown = 0;
	for (const auto &[count, name] : sources) {
		if (++shown > 20) {
			break;
		}
		out += QString::number(count) + u" × "_q + name + '\n';
	}

	out += u"\n== Индикаторы ==\n"_q;
	out += u"Уникальных: "_q
		+ QString::number(int(stats.indicators.size()))
		+ u" (ссылки, @упоминания, e-mail, кошельки)\n"_q;
	return out;
}

void ExportIndicators(
		not_null<History*> history,
		not_null<Window::SessionController*> controller) {
	const auto items = LoadedItems(history);
	auto counts = std::map<std::pair<QString, QString>, int>();
	auto first = std::map<std::pair<QString, QString>, HistoryItem*>();
	for (const auto &item : items) {
		for (const auto &indicator : ItemIndicators(item)) {
			const auto key = std::make_pair(indicator.type, indicator.value);
			++counts[key];
			auto &was = first[key];
			if (!was || item->date() < was->date()) {
				was = item.get();
			}
		}
	}
	if (counts.empty()) {
		controller->showToast(
			u"В загруженных сообщениях индикаторы не найдены"_q);
		return;
	}
	auto csv = QString(
		u"type,value,count,first_message_id,first_date_utc,first_link\n"_q);
	for (const auto &[key, count] : counts) {
		const auto item = first[key];
		const auto link = item
			? MessageLink(history->peer, item->id)
			: QString();
		csv += CsvField(key.first) + ','
			+ CsvField(key.second) + ','
			+ QString::number(count) + ','
			+ (item ? QString::number(item->id.bare) : QString()) + ','
			+ (item ? CsvField(Utc(item->date())) : QString()) + ','
			+ CsvField(link) + '\n';
	}
	const auto path = OutputFolder()
		+ u"/indicators_"_q
		+ QString::number(BareId(history->peer))
		+ '_'
		+ FileStamp()
		+ u".csv"_q;
	// UTF-8 BOM so that Excel shows Cyrillic correctly.
	if (WriteFile(path, QByteArray("\xEF\xBB\xBF") + csv.toUtf8())) {
		controller->showToast(u"Сохранено: "_q + path);
		File::ShowInFolder(path);
	} else {
		controller->showToast(u"Не удалось сохранить файл"_q);
	}
}

void ExportArchive(
		not_null<History*> history,
		not_null<Window::SessionController*> controller) {
	const auto items = LoadedItems(history);
	if (items.empty()) {
		controller->showToast(u"Нет загруженных сообщений"_q);
		return;
	}
	auto messages = QJsonArray();
	auto html = QString();
	html += u"<!DOCTYPE html><html><head><meta charset=\"utf-8\">"_q
		u"<title>OsintGram archive</title><style>"_q
		u"body{font-family:sans-serif;max-width:900px;margin:24px auto;}"_q
		u".m{border-bottom:1px solid #ddd;padding:8px 0;}"_q
		u".h{color:#666;font-size:12px;}</style></head><body>"_q;
	html += u"<h2>"_q + HtmlEscape(PeerLine(history->peer)) + u"</h2>"_q;
	for (const auto &item : items) {
		auto o = ItemJson(item);
		messages.append(o);
		html += u"<div class=\"m\"><div class=\"h\">#"_q
			+ QString::number(item->id.bare) + u" · "_q
			+ HtmlEscape(Utc(item->date())) + u" · "_q
			+ HtmlEscape(PeerLine(item->from().get()));
		if (const auto f = item->Get<HistoryMessageForwarded>()) {
			html += u" · переслано из "_q + HtmlEscape(f->originalSender
				? PeerLine(f->originalSender)
				: f->originalHiddenSenderInfo
				? f->originalHiddenSenderInfo->name
				: QString());
		}
		html += u" · sha256 "_q
			+ o.value(u"text_sha256"_q).toString().left(16)
			+ u"…</div>"_q
			+ HtmlEscape(item->originalText().text)
			+ u"</div>"_q;
	}
	auto root = QJsonObject();
	root.insert(u"tool"_q, u"OsintGram Desktop"_q);
	root.insert(
		u"captured_at_utc"_q,
		Utc(TimeId(QDateTime::currentSecsSinceEpoch())));
	root.insert(u"chat"_q, PeerLine(history->peer));
	root.insert(u"messages_count"_q, int(items.size()));
	root.insert(u"messages"_q, messages);
	const auto body = QJsonDocument(root).toJson(QJsonDocument::Indented);
	const auto hash = Sha256(body);
	html += u"<p class=\"h\">Создано OsintGram: "_q
		+ HtmlEscape(Utc(TimeId(QDateTime::currentSecsSinceEpoch())))
		+ u". SHA-256 файла JSON: "_q + hash + u"</p></body></html>"_q;

	const auto base = u"archive_"_q
		+ QString::number(BareId(history->peer))
		+ '_'
		+ FileStamp();
	const auto folder = OutputFolder(u"archives"_q);
	const auto jsonPath = folder + '/' + base + u".json"_q;
	const auto htmlPath = folder + '/' + base + u".html"_q;
	const auto hashPath = folder + '/' + base + u".sha256.txt"_q;
	const auto hashes = hash + u"  "_q + base + u".json\n"_q
		+ Sha256(html.toUtf8()) + u"  "_q + base + u".html\n"_q;
	if (WriteFile(jsonPath, body)
		&& WriteFile(htmlPath, html.toUtf8())
		&& WriteFile(hashPath, hashes.toUtf8())) {
		controller->showToast(u"Архив сохранён: "_q + htmlPath);
		File::ShowInFolder(htmlPath);
	} else {
		controller->showToast(u"Не удалось сохранить архив"_q);
	}
}

[[nodiscard]] QString NotesPath(not_null<History*> history) {
	return OutputFolder(u"notes"_q)
		+ u"/notes_"_q
		+ QString::number(BareId(history->peer))
		+ u".md"_q;
}


// ---------------------------------------------------------------------
// Photos: reverse search and the local index of perceptual hashes.

[[nodiscard]] PhotoData *ItemPhoto(not_null<HistoryItem*> item) {
	const auto media = item->media();
	return media ? media->photo() : nullptr;
}

[[nodiscard]] QImage LoadedPhotoImage(not_null<HistoryItem*> item) {
	const auto photo = ItemPhoto(item);
	if (!photo) {
		return QImage();
	}
	const auto view = photo->activeMediaView();
	if (!view) {
		return QImage();
	}
	for (const auto size : {
		Data::PhotoSize::Large,
		Data::PhotoSize::Thumbnail,
		Data::PhotoSize::Small,
	}) {
		if (const auto image = view->image(size)) {
			return image->original();
		}
	}
	return QImage();
}

struct IndexEntry {
	uint64 hash = 0;
	QString key;
	QString chat;
	QString date;
	QString link;
};

[[nodiscard]] QString IndexPath() {
	return OutputFolder(u"images"_q) + u"/index.tsv"_q;
}

[[nodiscard]] QString ItemKey(not_null<HistoryItem*> item) {
	return QString::number(BareId(item->history()->peer))
		+ ':'
		+ QString::number(item->id.bare);
}

[[nodiscard]] std::vector<IndexEntry> ReadIndex() {
	auto result = std::vector<IndexEntry>();
	auto f = QFile(IndexPath());
	if (!f.open(QIODevice::ReadOnly)) {
		return result;
	}
	const auto lines = QString::fromUtf8(f.readAll()).split('\n');
	for (const auto &line : lines) {
		const auto parts = line.split('\t');
		if (parts.size() < 5) {
			continue;
		}
		auto ok = false;
		const auto hash = parts[0].toULongLong(&ok, 16);
		if (!ok) {
			continue;
		}
		result.push_back({
			.hash = hash,
			.key = parts[1],
			.chat = parts[2],
			.date = parts[3],
			.link = parts[4],
		});
	}
	return result;
}

[[nodiscard]] QString Clean(QString value) {
	return value.replace('\t', ' ').replace('\n', ' ');
}

// Returns how many new photos were added to the index.
int AddToIndex(
		const std::vector<not_null<HistoryItem*>> &items,
		int *notLoaded = nullptr) {
	auto known = base::flat_set<QString>();
	for (const auto &entry : ReadIndex()) {
		known.emplace(entry.key);
	}
	auto added = QString();
	auto count = 0;
	for (const auto &item : items) {
		if (!ItemPhoto(item)) {
			continue;
		}
		const auto key = ItemKey(item);
		if (known.contains(key)) {
			continue;
		}
		const auto image = LoadedPhotoImage(item);
		if (image.isNull()) {
			if (notLoaded) {
				++*notLoaded;
			}
			continue;
		}
		known.emplace(key);
		added += QString::number(ImageHash(image), 16)
			+ '\t' + key
			+ '\t' + Clean(PeerLine(item->history()->peer))
			+ '\t' + Utc(item->date())
			+ '\t' + MessageLink(item->history()->peer, item->id)
			+ '\n';
		++count;
	}
	if (count > 0) {
		auto f = QFile(IndexPath());
		if (f.open(QIODevice::WriteOnly | QIODevice::Append)) {
			f.write(added.toUtf8());
		}
	}
	return count;
}

void ReverseSearch(
		not_null<HistoryItem*> item,
		not_null<Window::SessionController*> controller,
		const QString &url) {
	const auto image = LoadedPhotoImage(item);
	if (image.isNull()) {
		controller->showToast(
			u"Сначала откройте фото, чтобы оно загрузилось"_q);
		return;
	}
	const auto path = OutputFolder(u"images"_q)
		+ u"/photo_"_q
		+ ItemKey(item).replace(':', '_')
		+ u".jpg"_q;
	image.save(path, "JPG", 95);
	QGuiApplication::clipboard()->setImage(image);
	QDesktopServices::openUrl(QUrl(url));
	controller->showToast(
		u"Фото скопировано: на открывшейся странице нажмите Ctrl+V. "_q
		u"Файл также сохранён в Загрузки/OsintGram/images"_q);
}

void ShowSimilarPhotos(
		not_null<HistoryItem*> item,
		not_null<Window::SessionController*> controller) {
	const auto image = LoadedPhotoImage(item);
	if (image.isNull()) {
		controller->showToast(
			u"Сначала откройте фото, чтобы оно загрузилось"_q);
		return;
	}
	AddToIndex({ item });
	const auto hash = ImageHash(image);
	const auto key = ItemKey(item);
	auto matches = std::vector<std::pair<int, IndexEntry>>();
	const auto index = ReadIndex();
	for (const auto &entry : index) {
		if (entry.key == key) {
			continue;
		}
		const auto distance = HashDistance(hash, entry.hash);
		if (distance <= 8) {
			matches.emplace_back(distance, entry);
		}
	}
	ranges::sort(matches, ranges::less(), [](const auto &pair) {
		return pair.first;
	});
	auto text = QString();
	text += u"Фото в индексе: "_q
		+ QString::number(int(index.size()))
		+ u"\nПохожих найдено: "_q
		+ QString::number(int(matches.size()))
		+ u"\n\n"_q;
	for (const auto &[distance, entry] : matches) {
		text += (distance == 0 ? u"[точное совпадение] "_q : (u"[отличие "_q
				+ QString::number(distance)
				+ u"/64] "_q))
			+ entry.chat + '\n'
			+ entry.date
			+ (entry.link.isEmpty() ? QString() : (u"  "_q + entry.link))
			+ u"\n\n"_q;
	}
	text += u"Индекс пополняется кнопкой «Индексировать фото» в анализе "_q
		u"чата. Чем больше чатов проиндексировано, тем полнее поиск."_q;
	ShowTextBox(controller, u"OSINT: где ещё это фото"_q, text, {
		{ u"Копировать"_q, [=] {
			QGuiApplication::clipboard()->setText(text);
		} },
	});
}

void IndexChatPhotos(
		not_null<History*> history,
		not_null<Window::SessionController*> controller) {
	auto notLoaded = 0;
	const auto added = AddToIndex(LoadedItems(history), &notLoaded);
	auto text = u"Добавлено фото в индекс: "_q + QString::number(added);
	if (notLoaded > 0) {
		text += u". Не загружено (пропущено): "_q
			+ QString::number(notLoaded);
	}
	controller->showToast(text);
}

// ---------------------------------------------------------------------
// Keyword monitoring.

struct MonitorState {
	QStringList keywords;
};

[[nodiscard]] MonitorState &Monitor() {
	static auto state = MonitorState();
	return state;
}

[[nodiscard]] QString KeywordsPath() {
	return OutputFolder(u"monitor"_q) + u"/keywords.txt"_q;
}

[[nodiscard]] QString HitsPath() {
	return OutputFolder(u"monitor"_q) + u"/hits.csv"_q;
}

[[nodiscard]] QString ReadKeywordsText() {
	auto f = QFile(KeywordsPath());
	return f.open(QIODevice::ReadOnly)
		? QString::fromUtf8(f.readAll())
		: QString();
}

void ReloadKeywords() {
	auto &list = Monitor().keywords;
	list.clear();
	for (auto line : ReadKeywordsText().split('\n')) {
		line = line.trimmed();
		if (!line.isEmpty() && !line.startsWith('#')) {
			list.push_back(line.toLower());
		}
	}
}

void LogHit(not_null<HistoryItem*> item, const QString &keyword) {
	const auto path = HitsPath();
	const auto exists = QFile::exists(path);
	auto f = QFile(path);
	if (!f.open(QIODevice::WriteOnly | QIODevice::Append)) {
		return;
	}
	auto line = QString();
	if (!exists) {
		f.write("\xEF\xBB\xBF");
		line += u"found_at_utc,keyword,chat,message_id,date_utc,link,text\n"_q;
	}
	line += CsvField(Utc(TimeId(QDateTime::currentSecsSinceEpoch()))) + ','
		+ CsvField(keyword) + ','
		+ CsvField(PeerLine(item->history()->peer)) + ','
		+ QString::number(item->id.bare) + ','
		+ CsvField(Utc(item->date())) + ','
		+ CsvField(MessageLink(item->history()->peer, item->id)) + ','
		+ CsvField(item->originalText().text.left(500)) + '\n';
	f.write(line.toUtf8());
}

} // namespace

std::vector<Indicator> ExtractIndicators(const QString &text) {
	auto result = std::vector<Indicator>();
	if (text.isEmpty()) {
		return result;
	}
	static const auto patterns = std::vector<std::pair<QString, QRegularExpression>>{
		{ u"url"_q, QRegularExpression(
			u"(?i)\\b(?:https?://|www\\.|t\\.me/|telegram\\.me/)[^\\s<>\"'()\\[\\]{}]+"_q) },
		{ u"mention"_q, QRegularExpression(
			u"(?<![\\w@/])@[A-Za-z][A-Za-z0-9_]{3,31}\\b"_q) },
		{ u"email"_q, QRegularExpression(
			u"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"_q) },
		{ u"wallet_btc"_q, QRegularExpression(
			u"\\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b"_q) },
		{ u"wallet_evm"_q, QRegularExpression(
			u"\\b0x[a-fA-F0-9]{40}\\b"_q) },
		{ u"wallet_tron"_q, QRegularExpression(
			u"\\bT[1-9A-HJ-NP-Za-km-z]{33}\\b"_q) },
		{ u"wallet_ton"_q, QRegularExpression(
			u"(?<![A-Za-z0-9_-])(?:EQ|UQ)[A-Za-z0-9_-]{46}(?![A-Za-z0-9_-])"_q) },
	};
	for (const auto &[type, regex] : patterns) {
		auto it = regex.globalMatch(text);
		while (it.hasNext()) {
			auto value = it.next().captured(0);
			if (type == u"url"_q) {
				while (!value.isEmpty()
					&& u".,;:!?»"_q.contains(value.back())) {
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

QString Utc(TimeId date) {
	if (date <= 0) {
		return u"-"_q;
	}
	return QDateTime::fromSecsSinceEpoch(date).toUTC().toString(
		u"yyyy-MM-dd HH:mm:ss"_q) + u" UTC"_q;
}

void AddMessageActions(
		not_null<Ui::PopupMenu*> menu,
		not_null<HistoryItem*> item,
		not_null<Window::SessionController*> controller) {
	if (item->id.bare <= 0 || item->isService()) {
		return;
	}
	const auto weak = base::make_weak(controller);
	const auto itemId = item->fullId();
	const auto history = item->history();
	menu->addSeparator();
	menu->addAction(u"OSINT: отчёт по сообщению"_q, [=] {
		if (const auto strong = weak.get()) {
			if (const auto found = strong->session().data().message(itemId)) {
				ShowMessageReport(found, strong);
			}
		}
	}, &st::menuIconInfo);
	menu->addAction(u"OSINT: анализ чата"_q, [=] {
		if (const auto strong = weak.get()) {
			ShowChatAnalysis(history, strong);
		}
	}, &st::menuIconStats);
	menu->addAction(u"OSINT: заметки к чату"_q, [=] {
		if (const auto strong = weak.get()) {
			ShowNotes(history, strong);
		}
	}, &st::menuIconEdit);

	auto indicators = ItemIndicators(item);
	if (!indicators.empty()) {
		auto search = std::make_unique<Ui::PopupMenu>(menu, menu->st());
		auto seen = base::flat_set<QString>();
		for (const auto &indicator : indicators) {
			if (seen.size() >= 10 || !seen.emplace(indicator.value).second) {
				continue;
			}
			const auto value = indicator.value;
			search->addAction(value, [=] {
				if (const auto strong = weak.get()) {
					strong->searchMessages(value, Dialogs::Key());
				}
			});
		}
		menu->addAction(
			u"OSINT: искать во всех чатах"_q,
			std::move(search),
			&st::menuIconSearch);
	}

	if (ItemPhoto(item)) {
		auto photo = std::make_unique<Ui::PopupMenu>(menu, menu->st());
		const auto engines = std::vector<std::pair<QString, QString>>{
			{ u"Яндекс Картинки"_q, u"https://yandex.ru/images/"_q },
			{ u"Google Картинки"_q, u"https://images.google.com/"_q },
			{ u"Bing"_q, u"https://www.bing.com/visualsearch"_q },
			{ u"TinEye"_q, u"https://tineye.com/"_q },
		};
		for (const auto &[name, url] : engines) {
			const auto link = url;
			photo->addAction(name, [=] {
				if (const auto strong = weak.get()) {
					if (const auto found = strong->session().data().message(
							itemId)) {
						ReverseSearch(found, strong, link);
					}
				}
			});
		}
		photo->addAction(u"Где ещё было это фото"_q, [=] {
			if (const auto strong = weak.get()) {
				if (const auto found = strong->session().data().message(
						itemId)) {
					ShowSimilarPhotos(found, strong);
				}
			}
		});
		menu->addAction(
			u"OSINT: поиск по фото"_q,
			std::move(photo),
			&st::menuIconPhoto);
	}

	menu->addAction(u"OSINT: мониторинг слов"_q, [=] {
		if (const auto strong = weak.get()) {
			ShowMonitorSettings(strong);
		}
	}, &st::menuIconNotifications);
}

void ShowMessageReport(
		not_null<HistoryItem*> item,
		not_null<Window::SessionController*> controller) {
	const auto report = BuildReport(item);
	const auto weak = base::make_weak(controller);
	const auto itemId = item->fullId();
	ShowTextBox(controller, u"OSINT-отчёт"_q, report, {
		{ u"Копировать"_q, [=] {
			QGuiApplication::clipboard()->setText(report);
			if (const auto strong = weak.get()) {
				strong->showToast(u"Отчёт скопирован"_q);
			}
		} },
		{ u"Сохранить доказательство"_q, [=] {
			if (const auto strong = weak.get()) {
				if (const auto found = strong->session().data().message(
						itemId)) {
					SaveEvidence(found, strong, report);
				}
			}
		} },
	});
}

void ShowChatAnalysis(
		not_null<History*> history,
		not_null<Window::SessionController*> controller) {
	const auto text = StatsText(
		history,
		CollectStats(LoadedItems(history)));
	const auto weak = base::make_weak(controller);
	ShowTextBox(controller, u"OSINT: анализ чата"_q, text, {
		{ u"Индикаторы в CSV"_q, [=] {
			if (const auto strong = weak.get()) {
				ExportIndicators(history, strong);
			}
		} },
		{ u"Архив с хешами"_q, [=] {
			if (const auto strong = weak.get()) {
				ExportArchive(history, strong);
			}
		} },
		{ u"Индексировать фото"_q, [=] {
			if (const auto strong = weak.get()) {
				IndexChatPhotos(history, strong);
			}
		} },
		{ u"Копировать"_q, [=] {
			QGuiApplication::clipboard()->setText(text);
		} },
	});
}

void ShowNotes(
		not_null<History*> history,
		not_null<Window::SessionController*> controller) {
	const auto path = NotesPath(history);
	auto current = QString();
	{
		auto f = QFile(path);
		if (f.open(QIODevice::ReadOnly)) {
			current = QString::fromUtf8(f.readAll());
		}
	}
	const auto weak = base::make_weak(controller);
	const auto title = PeerLine(history->peer);
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"Заметки: "_q + history->peer->name()));
		box->setWidth(st::boxWideWidth * 3 / 2);
		const auto field = box->addRow(object_ptr<Ui::InputField>(
			box,
			st::editPeerDescription,
			Ui::InputField::Mode::MultiLine,
			rpl::single(u"Пишите сюда всё, что нашли по этому чату"_q),
			current));
		field->setMinHeight(st::boxWideWidth);
		const auto save = [=](bool close) {
			auto text = field->getLastText();
			if (!text.startsWith(u"# "_q)) {
				text = u"# "_q + title + u"\n\n"_q + text;
			}
			if (WriteFile(path, text.toUtf8())) {
				if (const auto strong = weak.get()) {
					strong->showToast(u"Заметки сохранены"_q);
				}
			}
			if (close) {
				box->closeBox();
			}
		};
		box->setFocusCallback([=] { field->setFocusFast(); });
		box->addButton(rpl::single(u"Сохранить"_q), [=] { save(true); });
		box->addButton(rpl::single(u"Открыть папку"_q), [=] {
			save(false);
			File::ShowInFolder(path);
		});
		box->addButton(rpl::single(u"Закрыть"_q), [=] {
			box->closeBox();
		});
	}));
}

uint64 ImageHash(const QImage &image) {
	// Difference hash: 9x8 grayscale, compare horizontal neighbours.
	const auto small = image.convertToFormat(QImage::Format_Grayscale8).scaled(
		9,
		8,
		Qt::IgnoreAspectRatio,
		Qt::SmoothTransformation);
	auto result = uint64(0);
	auto bit = 0;
	for (auto y = 0; y != 8; ++y) {
		const auto line = small.constScanLine(y);
		for (auto x = 0; x != 8; ++x) {
			if (line[x] > line[x + 1]) {
				result |= (uint64(1) << bit);
			}
			++bit;
		}
	}
	return result;
}

int HashDistance(uint64 a, uint64 b) {
	auto value = a ^ b;
	auto result = 0;
	while (value) {
		value &= (value - 1);
		++result;
	}
	return result;
}

void StartMonitor(not_null<Window::SessionController*> controller) {
	ReloadKeywords();
	const auto weak = base::make_weak(controller);
	controller->session().data().newItemAdded(
	) | rpl::on_next([=](not_null<HistoryItem*> item) {
		const auto &keywords = Monitor().keywords;
		if (keywords.isEmpty() || item->out() || item->isService()) {
			return;
		}
		const auto text = item->originalText().text.toLower();
		if (text.isEmpty()) {
			return;
		}
		for (const auto &keyword : keywords) {
			if (text.contains(keyword)) {
				LogHit(item, keyword);
				if (const auto strong = weak.get()) {
					strong->showToast(u"OSINT-мониторинг: «"_q
						+ keyword
						+ u"» в "_q
						+ item->history()->peer->name());
				}
				break;
			}
		}
	}, controller->lifetime());
}

void ShowMonitorSettings(not_null<Window::SessionController*> controller) {
	const auto current = ReadKeywordsText();
	const auto weak = base::make_weak(controller);
	controller->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"OSINT: мониторинг слов"_q));
		box->setWidth(st::boxWideWidth * 3 / 2);
		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			u"По одному слову, фразе, кошельку или ссылке на строку. "_q
			u"Когда новое сообщение в любом вашем чате или канале "_q
			u"содержит одно из них, появится уведомление, а находка "_q
			u"запишется в Загрузки/OsintGram/monitor/hits.csv. "_q
			u"Строки, начинающиеся с #, пропускаются."_q,
			st::boxLabel));
		const auto field = box->addRow(object_ptr<Ui::InputField>(
			box,
			st::editPeerDescription,
			Ui::InputField::Mode::MultiLine,
			rpl::single(u"например: airdrop\nTLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"_q),
			current));
		field->setMinHeight(st::boxWideWidth / 2);
		box->setFocusCallback([=] { field->setFocusFast(); });
		box->addButton(rpl::single(u"Сохранить"_q), [=] {
			if (!WriteFile(KeywordsPath(), field->getLastText().toUtf8())) {
				if (const auto strong = weak.get()) {
					strong->showToast(u"Не удалось сохранить список"_q);
				}
			}
			ReloadKeywords();
			box->closeBox();
		});
		box->addButton(rpl::single(u"Журнал находок"_q), [=] {
			if (!QFile::exists(HitsPath())) {
				(void)WriteFile(
					HitsPath(),
					QByteArray("\xEF\xBB\xBF")
						+ "found_at_utc,keyword,chat,message_id,"
						"date_utc,link,text\n");
			}
			File::ShowInFolder(HitsPath());
		});
		box->addButton(rpl::single(u"Закрыть"_q), [=] {
			box->closeBox();
		});
	}));
}

} // namespace Osint
