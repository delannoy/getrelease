# getrelease

Package manager for pre-compiled/pre-built github or gitlab releases.
Heavily inspired by [install-release](https://github.com/Rishang/install-release) and [eget](https://github.com/zyedidia/eget).

```bash
./getrelease.py -h
```
```

 Usage: getrelease.py [OPTIONS] COMMAND [ARGS]...

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                                                                                                │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ config           Write config options to file.                                                                                                               │
│ info             Query repository info.                                                                                                                      │
│ install          Identify, download, extract asset corresponding to system/OS and symlink executable file(s).                                                │
│ list             Print info for all installed utilities.                                                                                                     │
│ ls               Print info for all installed utilities.                                                                                                     │
│ remove           Uninstall utility.                                                                                                                          │
│ rm               Uninstall utility.                                                                                                                          │
│ uninstall        Uninstall utility.                                                                                                                          │
│ update           Upgrade utility to `latest` release.                                                                                                        │
│ update-all       Upgrade all installed utilities (except ones installed from url or from a release tag other than `latest`)                                  │
│ upgrade          Upgrade utility to `latest` release.                                                                                                        │
│ upgrade-all      Upgrade all installed utilities (except ones installed from url or from a release tag other than `latest`)                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

```bash
./getrelease.py info https://github.com/junegunn/fzf
```
```
                                         junegunn/fzf
┌─────────────┬──────────────────────────────────────────────────────────────────────────────┐
│ name        │ junegunn/fzf                                                                 │
│ description │ 🌸 A command-line fuzzy finder                                               │
│ topics      │ ['bash', 'cli', 'fish', 'fzf', 'go', 'neovim', 'tmux', 'unix', 'vim', 'zsh'] │
│ language    │ Go                                                                           │
│ stars       │ 52628                                                                        │
│ forks       │ 2194                                                                         │
│ url         │ https://github.com/junegunn/fzf                                              │
│ updated     │ 2023-06-09T12:43:19Z                                                         │
│ created     │ 2013-10-23T16:04:23Z                                                         │
│ issues      │ 321                                                                          │
│ downloads   │ True                                                                         │
│ visibility  │ public                                                                       │
│ archived    │ False                                                                        │
└─────────────┴──────────────────────────────────────────────────────────────────────────────┘
```

```bash
./getrelease.py install --help
```
```

 Usage: getrelease.py install [OPTIONS] REPO_ID

 Identify, download, extract asset corresponding to system/OS and symlink executable file(s).

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    repo_id      TEXT  url or owner/repo separated by a slash, e.g. "https://github.com/junegunn/fzf" or "junegunn/fzf" [default: None] [required]          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --tag            -t      TEXT  release tag [default: latest]                                                                                                 │
│ --url            -u      TEXT  install directly from url [default: None]                                                                                     │
│ --confirm        -y            proceed without prompting for confirmation                                                                                    │
│ --download-only  -d            download asset only and do not install it. Note that asset will be re-downloaded even if it already exists.                   │
│ --quiet          -q            set logging level to error                                                                                                    │
│ --verbose        -v            set logging level to debug                                                                                                    │
│ --asset-pattern          TEXT  regular expression to uniquely identify correct asset [default: .*]                                                           │
│ --bin-pattern            TEXT  regular expression to identify binary file(s) [default: .*]                                                                   │
│ --symlink-alias          TEXT  alias name for symlink (as opposed to the filename of the extracted binary file) [default: None]                              │
│ --help           -h            Show this message and exit.                                                                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

```bash
./getrelease.py install sharkdp/bat
```
```
                                                    sharkdp/bat
┌─────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ name        │ sharkdp/bat                                                                                        │
│ description │ A cat(1) clone with wings.                                                                         │
│ topics      │ ['cli', 'command-line', 'git', 'hacktoberfest', 'rust', 'syntax-highlighting', 'terminal', 'tool'] │
│ language    │ Rust                                                                                               │
│ stars       │ 41593                                                                                              │
│ forks       │ 1091                                                                                               │
│ url         │ https://github.com/sharkdp/bat                                                                     │
│ updated     │ 2023-06-09T14:21:10Z                                                                               │
│ created     │ 2018-04-21T10:52:23Z                                                                               │
│ issues      │ 212                                                                                                │
│ downloads   │ True                                                                                               │
│ visibility  │ public                                                                                             │
│ archived    │ False                                                                                              │
└─────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────┘
[2023-06-09 16:30:00] ERROR    a unique asset URL matching "linux" and "amd64|x64|x86[-_]?64|i686[-_]?64|ia[-_]?64" could not be identified:   getrelease.py:295
                               ['https://github.com/sharkdp/bat/releases/download/v0.23.0/bat-v0.23.0-x86_64-unknown-linux-gnu.tar.gz',
                               'https://github.com/sharkdp/bat/releases/download/v0.23.0/bat-v0.23.0-x86_64-unknown-linux-musl.tar.gz']
                               try specifying a (regex) `asset_pattern` (regex) asset_pattern: gnu
[2023-06-09 16:30:14] INFO     ['https://github.com/sharkdp/bat/releases/download/v0.23.0/bat-v0.23.0-x86_64-unknown-linux-gnu.tar.gz']        getrelease.py:292
Proceed with installation? y
/home/delannoy/.cache/bat-v0.23.0-x86_64-unknown-linux-gnu.tar.gz ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% 2.8/2.8 MB 1.7 MB/s 0:00:00
[2023-06-09 16:30:19] INFO     Downloaded /home/delannoy/.cache/bat-v0.23.0-x86_64-unknown-linux-gnu.tar.gz                                    getrelease.py:318
                      INFO     extracting /home/delannoy/.cache/bat-v0.23.0-x86_64-unknown-linux-gnu.tar.gz...                                 getrelease.py:334
                      INFO     symlinks = [PosixPath('/home/delannoy/.local/bin/bat')]                                                         getrelease.py:427
```
