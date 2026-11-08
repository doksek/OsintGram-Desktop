/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "settings/sections/settings_osint.h"

#include "core/file_utilities.h"
#include "menu/menu_osint.h"
#include "settings/settings_builder.h"
#include "ui/widgets/buttons.h"
#include "window/window_session_controller.h"
#include "styles/style_settings.h"

namespace Settings {
namespace {

using Osint::L;
using Field = bool Osint::Settings::*;

} // namespace

void BuildOsintSettings(Builder::SectionBuilder &builder) {
	const auto controller = builder.controller();

	// Lets the "everything" switch move the four ghost switches.
	const auto ghostChanged = std::make_shared<rpl::event_stream<>>();

	const auto add = [&](
			const QString &id,
			const QString &title,
			Field field,
			QStringList keywords,
			bool followsGhostAll) {
		const auto get = [=] { return Osint::CurrentSettings().*field; };
		const auto button = builder.addButton({
			.id = id,
			.title = rpl::single(title),
			.st = &st::settingsButtonNoIcon,
			.toggled = (rpl::single(rpl::empty_value())
				| rpl::then(ghostChanged->events())
				| rpl::map([=](rpl::empty_value) { return get(); })),
			.keywords = std::move(keywords),
		});
		if (!button) {
			return;
		}
		button->toggledValue(
		) | rpl::filter([=](bool checked) {
			return (checked != get());
		}) | rpl::on_next([=](bool checked) {
			Osint::UpdateSettings([&](Osint::Settings &settings) {
				settings.*field = checked;
			});
			if (followsGhostAll) {
				ghostChanged->fire({});
			}
		}, button->lifetime());
	};

	// Ghost mode.
	builder.addSubsectionTitle(
		rpl::single(L(u"Режим призрака"_q, u"Ghost mode"_q)));
	{
		const auto get = [] { return Osint::CurrentSettings().ghostAll(); };
		const auto all = builder.addButton({
			.id = u"osint/ghost_all"_q,
			.title = rpl::single(L(
				u"Включить режим призрака полностью"_q,
				u"Enable full ghost mode"_q)),
			.st = &st::settingsButtonNoIcon,
			.toggled = (rpl::single(rpl::empty_value())
				| rpl::then(ghostChanged->events())
				| rpl::map([=](rpl::empty_value) { return get(); })),
			.keywords = { u"ghost"_q, u"призрак"_q, u"анонимность"_q },
		});
		if (all) {
			all->toggledValue(
			) | rpl::filter([=](bool checked) {
				return (checked != get());
			}) | rpl::on_next([=](bool checked) {
				Osint::UpdateSettings([&](Osint::Settings &settings) {
					settings.setGhostAll(checked);
				});
				ghostChanged->fire({});
			}, all->lifetime());
		}
	}
	add(
		u"osint/ghost_read"_q,
		L(u"Не отправлять отметку «прочитано»"_q,
			u"Don't send read receipts"_q),
		&Osint::Settings::ghostNoRead,
		{ u"read"_q, u"прочитано"_q, u"галочки"_q },
		true);
	add(
		u"osint/ghost_offline"_q,
		L(u"Не показывать «в сети»"_q, u"Don't show «online»"_q),
		&Osint::Settings::ghostOffline,
		{ u"online"_q, u"в сети"_q },
		true);
	add(
		u"osint/ghost_stories"_q,
		L(u"Смотреть истории незаметно"_q,
			u"View stories without being seen"_q),
		&Osint::Settings::ghostNoStories,
		{ u"stories"_q, u"истории"_q },
		true);
	add(
		u"osint/ghost_typing"_q,
		L(u"Не показывать «печатает…»"_q, u"Don't show «typing…»"_q),
		&Osint::Settings::ghostNoTyping,
		{ u"typing"_q, u"печатает"_q },
		true);
	builder.addDividerText(rpl::single(L(
		u"Собеседник не увидит, что вы прочитали сообщение, прослушали "
		u"голосовое, посмотрели историю или печатаете. Статус «в сети» "
		u"не отправляется, но отправка сообщения может ненадолго "
		u"показать вас в сети — так работает сервер Telegram."_q,
		u"Others won't see that you read a message, listened to a voice "
		u"message, viewed a story or are typing. Your online status is not "
		u"sent, but sending a message may briefly show you online — this "
		u"is how Telegram servers work."_q)));

	// Deleted and edited messages.
	builder.addSkip();
	builder.addSubsectionTitle(rpl::single(L(
		u"Удалённые и изменённые сообщения"_q,
		u"Deleted and edited messages"_q)));
	add(
		u"osint/keep_deleted"_q,
		L(u"Сохранять удалённые сообщения"_q, u"Keep deleted messages"_q),
		&Osint::Settings::keepDeleted,
		{ u"deleted"_q, u"удалённые"_q },
		false);
	add(
		u"osint/mark_deleted"_q,
		L(u"Помечать удалённые словом «удалено»"_q,
			u"Mark them with «deleted»"_q),
		&Osint::Settings::markDeleted,
		{ u"deleted"_q, u"удалено"_q },
		false);
	add(
		u"osint/keep_edits"_q,
		L(u"Сохранять историю изменений"_q, u"Keep edit history"_q),
		&Osint::Settings::keepEdits,
		{ u"edited"_q, u"изменённые"_q },
		false);
	builder.addDividerText(rpl::single(L(
		u"Если собеседник удалит сообщение, оно останется у вас в чате. "
		u"Старые версии изменённых сообщений видны в «OSINT: отчёт» и "
		u"«OSINT: удалённые и изменённые». Журнал хранится на этом "
		u"компьютере в Загрузки/OsintGram/ghost и после перезапуска."_q,
		u"If someone deletes a message, it stays in your chat. Old versions "
		u"of edited messages are shown in «OSINT: report» and «OSINT: "
		u"deleted and edited». The journal is kept on this computer in "
		u"Downloads/OsintGram/ghost and survives restarts."_q)));

	// Anonymity.
	builder.addSkip();
	builder.addSubsectionTitle(
		rpl::single(L(u"Анонимность"_q, u"Anonymity"_q)));
	add(
		u"osint/strip_tracking"_q,
		L(u"Убирать слежку из ссылок (utm, fbclid…)"_q,
			u"Strip tracking from links (utm, fbclid…)"_q),
		&Osint::Settings::stripTracking,
		{ u"utm"_q, u"tracking"_q, u"слежка"_q, u"ссылки"_q },
		false);
	builder.addDividerText(rpl::single(L(
		u"При открытии ссылки из неё удаляются метки, по которым сайты "
		u"узнают, откуда вы пришли. Для полной анонимности используйте "
		u"прокси: Настройки → Продвинутые → Тип соединения."_q,
		u"When you open a link, the parameters sites use to know where "
		u"you came from are removed. For full anonymity use a proxy: "
		u"Settings → Advanced → Connection type."_q)));

	// OSINT tools.
	builder.addSkip();
	builder.addSubsectionTitle(
		rpl::single(L(u"OSINT-инструменты"_q, u"OSINT tools"_q)));
	add(
		u"osint/show_menu"_q,
		L(u"Пункты OSINT в меню сообщений"_q,
			u"OSINT items in message menu"_q),
		&Osint::Settings::showMenu,
		{ u"osint"_q, u"menu"_q, u"меню"_q },
		false);
	add(
		u"osint/local_time"_q,
		L(u"Анализ чата в местном времени (вместо UTC)"_q,
			u"Chat analysis in local time (instead of UTC)"_q),
		&Osint::Settings::localTime,
		{ u"utc"_q, u"time"_q, u"время"_q },
		false);
	add(
		u"osint/monitor"_q,
		L(u"Мониторинг слов"_q, u"Keyword monitoring"_q),
		&Osint::Settings::monitorEnabled,
		{ u"monitor"_q, u"мониторинг"_q },
		false);
	add(
		u"osint/monitor_toasts"_q,
		L(u"Всплывающие уведомления мониторинга"_q,
			u"Monitoring pop-up notifications"_q),
		&Osint::Settings::monitorToasts,
		{ u"monitor"_q, u"уведомления"_q },
		false);
	builder.addButton({
		.id = u"osint/monitor_words"_q,
		.title = rpl::single(L(
			u"Список слов для мониторинга…"_q,
			u"Monitoring keywords…"_q)),
		.st = &st::settingsButtonNoIcon,
		.onClick = [=] {
			if (controller) {
				Osint::ShowMonitorSettings(controller);
			}
		},
		.keywords = { u"monitor"_q, u"keywords"_q, u"слова"_q },
	});
	builder.addButton({
		.id = u"osint/open_folder"_q,
		.title = rpl::single(L(
			u"Открыть папку OsintGram"_q,
			u"Open OsintGram folder"_q)),
		.st = &st::settingsButtonNoIcon,
		.onClick = [] {
			File::ShowInFolder(Osint::FolderPath());
		},
		.keywords = { u"folder"_q, u"папка"_q, u"files"_q },
	});

	builder.addSkip();
	builder.addDivider();
	builder.addSkip();
}

} // namespace Settings
