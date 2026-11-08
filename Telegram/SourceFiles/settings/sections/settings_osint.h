/*
This file is part of OsintGram Desktop,
based on Forkgram and Telegram Desktop.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace Settings::Builder {
class SectionBuilder;
} // namespace Settings::Builder

namespace Settings {

// Ghost mode, anonymity and OSINT options, shown at the top of the
// OsintGram settings page.
void BuildOsintSettings(Builder::SectionBuilder &builder);

} // namespace Settings
