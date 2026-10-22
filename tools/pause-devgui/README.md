# Pause-menu DevGUI entry

The retail pause menu (`ui/emily_pause_menu.iggy`, `ui/corvo_pause_menu.iggy`)
still builds a "Dev GUI" button (`PauseMenuData._devGUI`, label
`ui_pause_devGUI`, English text "Dev GUI") but never lists it, maps no click
handler, and has no handler that sends the `DEV_GUI` ("DevGUI") notification.
The exe still handles that notification (0x78F140: closes the pause menu and
runs `devgui 1`).

`patch_pause_devgui.py` rewrites the menu's AS3 bytecode at the same total ABC
length: `_initMenuEntries` and `_initCallbackMenu` keep the entry list and the
callback dictionary in locals, and the bytes saved pay for a new
`PauseMenuScreen.devGUI()` method (a copy of `_onResumeClicked` that sends
`DEV_GUI`), its trait, and the list/dictionary entries for the button.

`repack_pause_devgui.py` extracts the two files from `game1_patch`, patches
them, and (with `--apply`, game closed) appends them uncompressed to
`game1_patch.resources` and repoints their index entries, after backing up the
index to `game1_patch.index.bak-devgui`. `--restore` puts that index back.
Run without arguments for a read-only dry run. The `.iggy` files are game data
and are not committed.

`idx.py` parses `*.index` files; `abcparse.py` parses and disassembles AS3 ABC
blocks (`python abcparse.py file.iggy <method name>...`).
