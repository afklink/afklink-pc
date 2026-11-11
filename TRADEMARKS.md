# Trademarks

The code in this repository is licensed under AGPL-3.0-only. The license covers the code; it
does not give permission to use the AFKLink name, logo or icons to identify other software.
The banner images `docs/banner.jpg` and `docs/banner.ru.jpg` are AFKLink brand artwork and are
not licensed under AGPL-3.0-only.

## What you may do

- Build and run this code, unchanged or modified, for yourself.
- Say that your project is based on AFKLink, or compatible with it, in plain words.
- Contribute changes back here.

## If you distribute a fork

A modified version you give to others must not look like AFKLink:

- Use a different name for the app and the project.
- Replace the icons in `app/src-tauri/icons/` and any other AFKLink logo.
- Change the application identifier `com.afklink.agent` in `app/src-tauri/tauri.conf.json`,
  so Windows does not treat your app as AFKLink.
- Sign your updates with your own key (replace `app/src-tauri/updater.pub`) and serve them
  from your own server. Official AFKLink builds accept only updates signed with the AFKLink key.

Do not present a fork as an official AFKLink release or suggest that the AFKLink project
endorses it.

Questions: dev@afklink.app.
