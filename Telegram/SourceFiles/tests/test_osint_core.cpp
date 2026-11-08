/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "menu/menu_osint_core.h"

#include <QtCore/QBuffer>

namespace {

using namespace Osint;

int Failed = 0;
int Passed = 0;

void Check(bool condition, const char *name) {
	if (condition) {
		++Passed;
	} else {
		++Failed;
		std::printf("FAIL: %s\n", name);
	}
}

[[nodiscard]] QStringList Values(
		const std::vector<Indicator> &list,
		const QString &type) {
	auto result = QStringList();
	for (const auto &indicator : list) {
		if (indicator.type == type) {
			result.push_back(indicator.value);
		}
	}
	return result;
}

void TestIndicators() {
	const auto text = QString::fromUtf8(
		"Пиши @scam_admin или на mail@test.ru, сайт "
		"https://evil.example.com/path?x=1. Также www.site.org! "
		"Канал t.me/somechan, мало букв @ab. "
		"BTC bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh "
		"ETH 0x52908400098527886E0F7030069857D2E4169EE7 "
		"TRON TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7 "
		"TON EQD4FPq-PRDieyQKkizFTRtSDyucUIqrj0v_zXJmqaDp6_0t");
	const auto list = ExtractIndicators(text);
	const auto urls = Values(list, QStringLiteral("url"));
	Check(urls.contains(QStringLiteral("https://evil.example.com/path?x=1")),
		"url without trailing dot");
	Check(urls.contains(QStringLiteral("www.site.org")),
		"www url without trailing !");
	Check(urls.contains(QStringLiteral("t.me/somechan")),
		"t.me link without scheme");
	const auto mentions = Values(list, QStringLiteral("mention"));
	Check(mentions == QStringList{ QStringLiteral("@scam_admin") },
		"only real mention, not e-mail, not too short");
	Check(Values(list, QStringLiteral("email"))
			== QStringList{ QStringLiteral("mail@test.ru") },
		"e-mail");
	Check(Values(list, QStringLiteral("wallet_btc")).size() == 1, "btc");
	Check(Values(list, QStringLiteral("wallet_evm")).size() == 1, "evm");
	Check(Values(list, QStringLiteral("wallet_tron")).size() == 1, "tron");
	Check(Values(list, QStringLiteral("wallet_ton")).size() == 1, "ton");
	Check(ExtractIndicators(QString()).empty(), "empty text");
	Check(ExtractIndicators(QStringLiteral("просто текст")).empty(),
		"plain text has no indicators");
}

void TestHashes() {
	Check(Sha256("abc") == QStringLiteral(
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
		"sha256 of abc");
	Check(Utc(0) == QStringLiteral("-"), "utc of zero");
	Check(Utc(86400) == QStringLiteral("1970-01-02 00:00:00 UTC"),
		"utc of one day");
	Check(HashDistance(0, 0) == 0, "distance zero");
	Check(HashDistance(0, ~quint64(0)) == 64, "distance all bits");
	Check(HashDistance(0b1011, 0b0001) == 2, "distance two bits");
}

[[nodiscard]] QImage Picture(int size, bool inverted) {
	auto image = QImage(size, size, QImage::Format_ARGB32);
	image.fill(inverted ? Qt::black : Qt::white);
	auto p = QPainter(&image);
	p.setPen(Qt::NoPen);
	p.setBrush(inverted ? Qt::white : Qt::black);
	p.drawEllipse(QRectF(size * 0.1, size * 0.2, size * 0.5, size * 0.5));
	p.setBrush(QColor(inverted ? 60 : 200, 120, 30));
	p.drawRect(QRectF(size * 0.55, size * 0.05, size * 0.4, size * 0.9));
	p.end();
	return image;
}

void TestImageHash() {
	const auto original = Picture(400, false);
	const auto hash = ImageHash(original);
	Check(hash != 0, "image hash is not empty");
	Check(ImageHash(original) == hash, "image hash is stable");
	const auto smaller = original.scaled(
		123,
		123,
		Qt::IgnoreAspectRatio,
		Qt::SmoothTransformation);
	Check(HashDistance(hash, ImageHash(smaller)) <= 6,
		"resized copy is similar");
	auto reencoded = QImage();
	{
		auto bytes = QByteArray();
		auto buffer = QBuffer(&bytes);
		buffer.open(QIODevice::WriteOnly);
		original.save(&buffer, "PNG");
		reencoded.loadFromData(bytes);
	}
	Check(HashDistance(hash, ImageHash(reencoded)) <= 6, "re-encoded copy");
	Check(HashDistance(hash, ImageHash(Picture(400, true))) > 8,
		"inverted picture is not a match");
	Check(ImageHash(QImage()) == 0, "null image");
}

void TestStripTracking() {
	Check(StripTracking(QStringLiteral(
			"https://site.com/a?utm_source=tg&id=5&fbclid=abc"))
		== QStringLiteral("https://site.com/a?id=5"),
		"utm and fbclid removed, id kept");
	Check(StripTracking(QStringLiteral("https://site.com/a?utm_medium=x"))
		== QStringLiteral("https://site.com/a"),
		"query removed completely");
	Check(StripTracking(QStringLiteral("https://site.com/a?id=5&q=b"))
		== QStringLiteral("https://site.com/a?id=5&q=b"),
		"clean link untouched");
	Check(StripTracking(QStringLiteral("tg://resolve?domain=x&utm_source=y"))
		== QStringLiteral("tg://resolve?domain=x&utm_source=y"),
		"non-web link untouched");
	Check(StripTracking(QStringLiteral(
			"https://youtu.be/abc?si=TRACK&t=42"))
		== QStringLiteral("https://youtu.be/abc?t=42"),
		"youtube si removed, time kept");
	Check(StripTracking(QStringLiteral("https://site.com/#utm_source=x"))
		== QStringLiteral("https://site.com/#utm_source=x"),
		"fragment untouched");
}

void TestSettings() {
	const auto defaults = Settings();
	Check(!defaults.ghostAll(), "ghost mode is off by default");
	Check(defaults.keepDeleted && defaults.stripTracking,
		"keeping and link cleaning are on by default");

	auto changed = Settings();
	changed.setGhostAll(true);
	changed.keepEdits = false;
	changed.localTime = true;
	Check(changed.ghostAll(), "ghost all switch");
	const auto restored = Settings::Deserialize(changed.serialize());
	Check(restored == changed, "settings round trip");

	const auto partial = Settings::Deserialize(
		QByteArray("{\"ghostOffline\": true, \"unknown\": 5}"));
	Check(partial.ghostOffline && !partial.ghostNoRead && partial.keepDeleted,
		"partial settings keep defaults");
	Check(Settings::Deserialize(QByteArray("garbage")) == Settings(),
		"broken file gives defaults");
	Check(Settings::Deserialize(QByteArray()) == Settings(),
		"empty file gives defaults");
	Check(Settings::Deserialize(QByteArray("{\"keepDeleted\": 1}"))
		.keepDeleted,
		"wrong type ignored");
}

void TestJournal() {
	auto deleted = JournalRecord();
	deleted.kind = JournalRecord::Kind::Deleted;
	deleted.chatId = 1987654321012;
	deleted.messageId = 4812;
	deleted.date = 1793000000;
	deleted.at = 1793000500;
	deleted.chat = QString::fromUtf8("Канал «Тест» [id 1987654321012]");
	deleted.sender = QStringLiteral("Admin (@admin) [id 5550123987]");
	deleted.text = QString::fromUtf8("строка 1\nстрока 2 \"кавычки\"");

	auto edited = deleted;
	edited.kind = JournalRecord::Kind::Edited;
	edited.text = QStringLiteral("before");
	edited.newText = QStringLiteral("after");

	const auto data = deleted.toLine()
		+ QByteArray("not json\n\n{\"kind\":\"other\"}\n")
		+ edited.toLine();
	Check(deleted.toLine().count('\n') == 1, "one record is one line");
	const auto parsed = JournalRecord::ParseLines(data);
	Check(parsed.size() == 2, "broken lines skipped");
	Check(parsed.size() == 2 && parsed[0] == deleted, "deleted round trip");
	Check(parsed.size() == 2 && parsed[1] == edited, "edited round trip");
	Check(JournalRecord::ParseLines(QByteArray()).empty(), "empty journal");
}

} // namespace

int main() {
	// Only QImage and raster QPainter are used, no application object needed.
	TestIndicators();
	TestHashes();
	TestImageHash();
	TestStripTracking();
	TestSettings();
	TestJournal();

	std::printf("OsintGram core tests: %d passed, %d failed\n", Passed, Failed);
	return Failed ? 1 : 0;
}
