#!/usr/bin/env python3

import dataclasses
import fileinput
import hashlib
import json
import logging
import os
import pathlib
import platform
import re
import stat
import tarfile
import typing
import urllib.error
import urllib.parse
import urllib.request

import packaging.version
import pandas
import rich.color
import rich.console
import rich.logging
import rich.progress
import rich.table
import typer
import typing_extensions

'''
Package manager for pre-compiled/pre-built github or gitlab releases.
Heavily inspired by [install-release](https://github.com/Rishang/install-release) and [eget](https://github.com/zyedidia/eget).
'''

# [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html#variables)
# [XDG Base Directory](https://wiki.archlinux.org/index.php/XDG_Base_Directory)
XDG_CACHE_HOME = pathlib.Path(f"{os.getenv('XDG_CACHE_HOME', pathlib.Path.home()/'.cache')}")
XDG_CONFIG_HOME = pathlib.Path(f"{os.getenv('XDG_CONFIG_HOME', pathlib.Path.home()/'.config')}")
XDG_DATA_HOME = pathlib.Path(f"{os.getenv('XDG_DATA_HOME', pathlib.Path.home()/'.local/share/')}")


@dataclasses.dataclass
class Config:
    '''Configuration options.'''

    log_level: int = logging.INFO
    github_token: str = os.getenv('GITHUB_TOKEN', '')
    gitlab_token: str = os.getenv('GITLAB_TOKEN', '')
    bin_dir: pathlib.Path = XDG_DATA_HOME.parent/'bin' # symlink destination directory
    cache_dir: pathlib.Path = XDG_CACHE_HOME # download directory
    data_dir: pathlib.Path = XDG_DATA_HOME # extracted data directory
    metadata_dir: pathlib.Path = XDG_CONFIG_HOME/f'{pathlib.Path(__file__).stem}' # installed releases metadata directory

    def __post_init__(self):
        self.file: pathlib.Path = self.metadata_dir/'config'
        self.read() if self.file.exists() else self.write()

    def read(self, **kwargs):
        '''Read configuration options from config file and overwrite them with any options provided when instantiating the class.'''
        with self.file.open(mode='r') as config_file:
            config = json.load(fp=config_file)
        config.update(dataclasses.asdict(self)) # update attributes from file with instantiated attributes
        _ = {setattr(self, k, v) for k, v in config.items()} # [Creating class instance properties from a dictionary?](https://stackoverflow.com/a/1639197)

    def write(self):
        '''Write configuration options to config file.'''
        self.metadata_dir.mkdir(exist_ok=True)
        attrs = dataclasses.asdict(self) # note that attributes defined in `__post_init__` (i.e. `self.file`) are not included in `attrs`
        attrs.update({k: str(v) for k, v in attrs.items() if isinstance(v, pathlib.Path)}) # convert `pathlib.Path` objects to `str` in order to json serialize `attrs`
        with self.file.open(mode='w') as config_file:
            json.dump(obj=attrs, fp=config_file)


cfg = Config()

rich_handler = rich.logging.RichHandler(rich_tracebacks=True, log_time_format="[%Y-%m-%d %H:%M:%S]")
logging.basicConfig(level=cfg.log_level, format='%(message)s', handlers=[rich_handler]) # [Logging Handler](https://rich.readthedocs.io/en/stable/logging.html)
log = logging.getLogger()


@dataclasses.dataclass
class SYS:
    '''Identify system info and define corresponding regex patterns.'''

    os: str = platform.system().lower() # [When to use os.name, sys.platform, or platform.system?](https://stackoverflow.com/a/11674977/13019084)

    platform: str = platform.processor().lower() if platform.processor() else platform.machine().lower() if platform.machine() else ''

    def __post_init__(self):
        self.arch_pattern_dict = {
            # https://github.com/workhorsy/py-cpuinfo/blob/f3f0fec58335b9699b9b294267c15f516045b1fe/cpuinfo/cpuinfo.py#L782
            # https://github.com/zyedidia/eget/blob/master/DOCS.md#detect
            'x86': 'x86$|x86_32|[i]?[3-6]86$|i86pc|ia[-_]?32|bepc',
            'x86_64': 'amd64|x64|x86[-_]?64|i686[-_]?64|ia[-_]?64',
            'arm8_32': 'armv8[-_]?[b-z]?',
            'arm8_64': 'aarch64|arm64|armv8[-_]?a', # https://en.wikipedia.org/wiki/arm_architecture_family#64.2f32-bit_architecture
            'arm7': 'arm$|armv[6-7]',
            'ppc_32': 'ppc$|ppc32|prep|pmac|powermac',
            'ppc_64': 'powerpc|ppc64',
            'sparc_32': 'sparc$|sparc32',
            'sparc_64': 'sparc64|sun4[u-v]',
            's390x': 's390[x]?',
            'mips_32': 'mips$',
            'mips_64': 'mips64',
            'riscv_32': 'riscv$|riscv32',
            'riscv_64': 'riscv64',
            'loong_32': 'loongarch32',
            'loong_64': 'loongarch64'}
        self.os_pattern_dict = {
            # https://github.com/zyedidia/eget/blob/master/DOCS.md#detect
            'android': 'android',
            'darwin': 'darwin|mac[.]?os|osx',
            'freebsd': 'freebsd',
            'illumos': 'illumos',
            'linux': 'linux',
            'netbsd': 'netbsd',
            'openbsd': 'openbsd',
            'plan9': 'plan9',
            'solaris': 'solaris',
            'windows': 'win|windows',
            'win32': 'win|windows'}
        if (platform.processor() and platform.machine()) and (platform.processor().lower() != platform.machine().lower()):
            log.warning(f'{platform.processor()=} != {platform.machine()=}')
        self.os_pattern = self.os_pattern_dict[self.os]
        arch = [arch for arch, pattern in self.arch_pattern_dict.items() if re.match(pattern=pattern, string=self.platform)]
        if len(arch) != 1:
            raise ValueError(f'Processor architecture could not be recognized correctly: {arch}')
        self.arch_pattern = self.arch_pattern_dict[arch.pop()]

    def testARCH(self) -> typing.Dict[str, typing.List[str]]:
        '''Check if entries in the `uname` wikipedia table match `self.arch_pattern`'''
        # https://en.wikipedia.org/wiki/Uname
        uname = pandas.read_html('https://en.wikipedia.org/wiki/Uname', match='Machine')[0]['Machine (-m) POSIX'].str.lower().drop_duplicates()
        return {a: [arch for arch, pattern in self.arch_pattern_dict.items() if re.match(pattern, a)] for a in uname}


@dataclasses.dataclass
class Github:
    '''Minimal wrapper for the [GitHub REST API](https://docs.github.com/en/rest).'''

    repo_id: str
    token: str = cfg.github_token

    def __post_init__(self):
        if not self.token:
            log.warning('`GITHUB_TOKEN` environment variable is not set. Setting it will increase the rate limit of GitHub API calls from 60/hr to 5000/hr:\nhttps://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting')

    def query(self, url: str, per_page: int = 100, **kwargs) -> typing.Dict[str, typing.Any]:
        '''Query GitHub/GitLab API.'''
        headers = {'Authorization': f'Bearer {self.token}'} # https://docs.github.com/en/rest/guides/getting-started-with-the-rest-api?tool=curl#using-headers # https://docs.gitlab.com/ee/api/rest/#personalprojectgroup-access-tokens
        params = urllib.parse.urlencode({'per_page': per_page, **kwargs})
        request = urllib.request.Request(url=f'{url}?{params}', headers=headers) if self.token else urllib.request.Request(url=f'{url}?{params}')
        log.debug(request.full_url)
        with urllib.request.urlopen(request) as response:
            response = json.load(response)
        return response

    def info(self) -> pandas.Series:
        '''Query repo info for `self.repo_id`.'''
        repo = self.query(url=f'https://api.github.com/repos/{self.repo_id}', per_page=1)
        if repo:
            return pandas.Series(repo)

    def releaseTag(self, tag: str = 'latest') -> pandas.Series:
        '''Query release tag info for `self.repo_id`.'''
        if tag in ('pre', 'pre-release', 'prerelease'):
            return self.preReleaseTag()
        tag = f'tags/{tag}' if tag != 'latest' else tag # [Get a release by tag name](https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name)
        response = self.query(url=f'https://api.github.com/repos/{self.repo_id}/releases/{tag}', per_page=1)
        return pandas.Series(response)

    def preReleaseTag(self) -> pandas.Series:
        '''Query release tag info for `self.repo_id`.'''
        response = self.query(url=f'https://api.github.com/repos/{self.repo_id}/releases', per_page=100)
        releases = pandas.DataFrame(response)
        return releases[releases.prerelease == True].head(1).squeeze()


@dataclasses.dataclass
class Gitlab(Github):
    '''Minimal wrapper for the [GitLab REST API](https://docs.gitlab.com/ee/api/rest/).'''

    repo_id: str
    token: str = cfg.gitlab_token

    def __post_init__(self):
        self.repo_id = self.repo_id.replace('/', '%2F') # [Get the `id` of gitlab project via gitlab api or gitlab-cli](https://stackoverflow.com/a/54824458)
        if not self.token:
            log.warning('`GITLAB_TOKEN` environment variable not set. Some API responses will return only limited fields. Setting it will increase the rate limit of GitLab API calls.\nhttps://docs.gitlab.com/ee/api/projects.html#list-all-projects\nhttps://docs.gitlab.com/ee/user/gitlab_com/index.html#gitlabcom-specific-rate-limits')

    def info(self) -> pandas.Series:
        '''Query repo info for `self.repo_id`.''' # [Get single project](https://docs.gitlab.com/ee/api/projects.html#get-single-project)
        repo = self.query(url=f'https://gitlab.com/api/v4/projects/{self.repo_id}', license=True, per_page=1)
        if repo:
            repo = pandas.Series(repo)
            repo['language'] = self.query(url=f'https://gitlab.com/api/v4/projects/{self.repo_id}/languages', per_page=1) # [Get repository languages with the GitLab API](https://stackoverflow.com/a/50573582)
            return repo

    def releaseTag(self, tag: str = 'latest') -> pandas.Series:
        '''Return release tag info for `self.repo_id`.'''
        tag = f'permalink/{tag}' if tag == 'latest' else tag
        response = self.query(url=f'https://gitlab.com/api/v4/projects/{self.repo_id}/releases/{tag}', per_page=1)
        return pandas.Series(response)


@dataclasses.dataclass
class Repo:
    '''Query GitHub/Gitlab repo info and release tag info.'''

    id: str
    github: bool = False
    gitlab: bool = False

    def __post_init__(self):
        self.github = True if 'github.com' in self.id else False
        self.gitlab = True if 'gitlab.com' in self.id else False
        self.id = self.parseID()

    def parseID(self) -> str:
        '''Parse owner/org and repo from `repo_id`'''
        if '/' not in self.id:
            raise ValueError("please provide url or owner/repo separated by a slash, e.g. 'https://github.com/junegunn/fzf' or 'junegunn/fzf'")
        if '.com' not in self.id:
            return self.id.strip('/')
        else:
            url = urllib.parse.urlparse(urllib.parse.urljoin('https:', self.id).replace('///', '//')) # [How to open "partial" links using Python?](https://stackoverflow.com/a/57510472)
            return str.join('/', url.path.strip('/').split('/')[:2])

    def info(self) -> pandas.Series:
        '''Return repo info for github or gitlab repo.'''
        func = Github(repo_id=self.id).info if self.github else Gitlab(repo_id=self.id).info if self.gitlab else None
        if func:
            return func()
        try:
            return Github(repo_id=self.id).info()
        except urllib.error.HTTPError:
            return Gitlab(repo_id=self.id).info()

    def releaseTag(self, tag: str = 'latest') -> pandas.Series:
        '''Return release tag info for github or gitlab repo.'''
        func = Github(repo_id=self.id).releaseTag if self.github else Gitlab(repo_id=self.id).releaseTag if self.gitlab else None
        if func:
            return func(tag=tag)
        try:
            return Github(repo_id=self.id).releaseTag(tag=tag)
        except urllib.error.HTTPError:
            return Gitlab(repo_id=self.id).releaseTag(tag=tag)


@dataclasses.dataclass
class Asset:
    '''Identify, download, extract asset.'''

    file_path: pathlib.Path
    extract_destination: pathlib.Path = cfg.data_dir
    col_url: rich.progress.TextColumn = rich.progress.TextColumn(text_format='[green]{task.fields[url]}')
    col_filename: rich.progress.TextColumn = rich.progress.TextColumn(text_format='[bold magenta]{task.fields[filename]}')
    col_bar: rich.progress.BarColumn = rich.progress.BarColumn(bar_width=60)
    col_progress: rich.progress.TaskProgressColumn = rich.progress.TaskProgressColumn(text_format='[progress.percentage]{task.percentage:>3.1f}%')
    col_download: rich.progress.DownloadColumn = rich.progress.DownloadColumn()
    col_transfer_speed: rich.progress.TransferSpeedColumn = rich.progress.TransferSpeedColumn()
    col_time_remaining: rich.progress.TimeRemainingColumn = rich.progress.TimeRemainingColumn()

    @classmethod
    def identify(cls, asset_urls: pandas.Series, asset_pattern: re.Pattern = '.*') -> str:
        '''Return download url for assets corresponding to `OS_PATTERN` and `ARCH_PATTERN`. Note that `asset_pattern` has twice the weight as the other criteria.'''
        os = asset_urls.str.contains(OS_PATTERN, regex=True, case=False).astype(int)
        arch = asset_urls.str.contains(ARCH_PATTERN, regex=True, case=False).astype(int)
        filetype_veto = asset_urls.str.endswith(('.deb', '.rpm', '.sha1', '.sha256', '.sha256sum', '.sum')).astype(int)
        asset_pattern = asset_urls.str.contains(asset_pattern, regex=True, case=False).astype(int)
        match = os + arch - filetype_veto + 2*asset_pattern
        asset = asset_urls[match == match.max()].to_list()
        log.debug(f'{asset = }')
        if len(asset) == 1:
            log.info(asset)
            return asset[0]
        else:
            log.warning(f'a unique asset URL matching "{OS_PATTERN}" and "{ARCH_PATTERN}" could not be identified:\n{asset}\ntry specifying a (regex) `asset_pattern`')
            asset_pattern = input('(regex) asset_pattern: ')
            return cls.identify(asset_urls=asset_urls, asset_pattern=asset_pattern)

    def download(self, url: str, force: bool = False):
        '''Download `url` to `self.file_path` with a `rich` progress bar.'''
        # https://github.com/Textualize/rich/blob/master/examples/downloader.py
        progress_columns = [v for k,v in dataclasses.asdict(self).items() if k.startswith('col_')] # [rich.progress.Progress](https://rich.readthedocs.io/en/stable/reference/progress.html#rich.progress.Progress)
        progress = rich.progress.Progress(*progress_columns)
        task_id = progress.add_task(description="download", start=False, url=url, filename=self.file_path)
        log.debug(f'requesting {url}')
        response = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': os.environ['USERAGENT']}))
        if self.file_path.exists():
            local_file_size, remote_file_size = self.file_path.stat().st_size, int(response.length)
            log.debug(f'{self.file_path} size = {local_file_size}\n{url} size = {remote_file_size}')
            log.info(f'local file size == remote file size: {local_file_size == remote_file_size}')
        if self.file_path.exists() and (local_file_size == remote_file_size) and (not force):
            return log.info(f'{self.file_path} already exists')
        progress.update(task_id=task_id, total=float(response.length))
        with progress:
            with self.file_path.open(mode='wb') as out_file:
                progress.start_task(task_id=task_id)
                for chunk in iter(lambda: response.read(2**10), b''):
                    out_file.write(chunk)
                    progress.update(task_id=task_id, advance=len(chunk))
        log.info(f'downloaded {self.file_path}')

    @staticmethod
    def chmodExecutable(file_path: pathlib.Path):
        '''Modify file permission to make file executable.'''
        file_path.chmod(mode=file_path.stat().st_mode | stat.S_IEXEC)
        log.debug(f'{stat.filemode(file_path.stat().st_mode)} {file_path}')

    def extract(self, destination: pathlib.Path = cfg.data_dir) -> pathlib.Path:
        '''Extract `self.file_path` to `destination`.'''
        if not tarfile.is_tarfile(self.file_path):
            log.info(f'{self.file_path} is not a tar archive')
            self.chmodExecutable(file_path=self.file_path)
            return self.file_path.rename(destination/self.file_path.stem)
        with tarfile.open(name=self.file_path, mode='r:*') as tar:
            base_dir = os.path.commonpath(tar.getnames()) # [With Python's 'tarfile', how can I get the top-most directory in a tar archive?](https://stackoverflow.com/a/11269228)
            log.info(f'extracting {self.file_path}...')
            tar.extractall(path=destination if base_dir else destination/self.file_path.stem.rstrip('.tar'))
        extracted_dir = destination/base_dir if base_dir else destination/self.file_path.stem.rstrip('.tar')
        log.debug(f'extracted {self.file_path} to {extracted_dir}')
        return extracted_dir


@dataclasses.dataclass
class Checksum:
    '''Identify and verify checksum for asset.'''

    asset_urls: pandas.Series
    asset_filename: str

    def fromFile(self) -> str:
        '''Parse file containing checksums and return checksum corresponding to `asset_url`.''' # 'cli/cli'
        checksums_file = self.asset_urls[self.asset_urls.str.contains('checksums.txt$|sha256.txt$|sha256sum.txt$', regex=True, flags=re.IGNORECASE)]
        if checksums_file.empty:
            return
        checksums_file = checksums_file.item()
        checksums = pandas.read_csv(checksums_file, sep='\s+', names=['checksum', 'filename'])
        return checksums[checksums.filename.str.endswith(self.asset_filename)]['checksum'].item()

    def fromFiles(self) -> str:
        '''Identify checksum file corresponding to `asset_url` and return its checksum.''' # 'neovim/neovim'
        checksum_files = self.asset_urls[self.asset_urls.str.contains('sha256$|sha256sum$|sum$', regex=True, flags=re.IGNORECASE)]
        if checksum_files.empty:
            return
        checksum_file_url = checksum_files[checksum_files.str.contains(self.asset_filename)].item()
        return pandas.read_csv(checksum_file_url, sep='\s+', names=['checksum', 'filename'])['checksum'].item()

    def verify(self, file_path: pathlib.Path) -> bool:
        '''Calculate asset checksum and verify against checksum file(s), if available.'''
        if self.asset_urls.empty:
            return
        checksum_from_file = self.fromFile()
        checksum_from_files = self.fromFiles()
        reference_checksum = checksum_from_file if checksum_from_file else checksum_from_files if checksum_from_files else None
        if reference_checksum:
            with file_path.open(mode='rb') as target_file:
                download_checksum = hashlib.sha256(target_file.read()).hexdigest()
            log.debug(f'{reference_checksum = }\n{download_checksum  = }')
            log.info(f'reference_checksum == download_checksum: {reference_checksum == download_checksum}')
            if reference_checksum != download_checksum:
                raise ValueError("checksums don't match!")


@dataclasses.dataclass
class Executables:
    '''Identify and symlink executable(s) from extracted asset.'''

    extracted_bin: typing.List[pathlib.Path]
    repo_id: str

    @staticmethod
    def isExecutableFile(file_path: pathlib.Path) -> bool:
        '''Check if `file_path` is a file and has executable permissions.'''
        return file_path.is_file() and os.access(file_path, mode=os.X_OK)

    @classmethod
    def identify(cls, extracted_path: pathlib.Path, bin_pattern: re.Pattern = '.*') -> typing.List[pathlib.Path]:
        '''Identify executable or binary files in `extracted_path`.'''
        if cls.isExecutableFile(extracted_path):
            log.debug(f'{extracted_path = }')
            return [extracted_path]
        executables = [f for f in extracted_path.rglob('*') if cls.isExecutableFile(f) and re.search(pattern=bin_pattern, string=str(f))]
        if len(executables) == 1:
            log.debug(f'{executables = }')
            return executables
        bin_dir_executables = [f for f in executables if f.parent.stem == 'bin'] # look inside `bin` directory
        base_dir_executables = [f for f in executables if f.parent == extracted_path] # look inside root directory
        executables = bin_dir_executables if bin_dir_executables else base_dir_executables if base_dir_executables else []
        if not executables:
            log.warning(f'no binaries found in {extracted_path}')
        log.debug(f'{executables = }')
        return executables

    @staticmethod
    def link(target: pathlib.Path, symlink: pathlib.Path):
        '''Create (and overwrite) a symbolic link at `symlink` that points to `target` if `target` is a file.'''
        if target.is_file():
            symlink.unlink(missing_ok=True)
            log.debug(f'{symlink} -> {target}')
            symlink.symlink_to(target=target)

    def symlink(self, symlink_alias: str = None, bin_dir: pathlib.Path = cfg.bin_dir) -> typing.List[pathlib.Path]:
        '''Create symlink for executable files, renaming accordingly in case of a single executable file.'''
        if len(self.extracted_bin) == 1:
            extracted_bin = self.extracted_bin[0]
            contains_system_info = re.findall(pattern=f'{OS_PATTERN}|{ARCH_PATTERN}', string=extracted_bin.name.lower())
            bin_name = symlink_alias if symlink_alias else self.repo_id.split('/')[-1] if contains_system_info else extracted_bin.name
            self.link(target=extracted_bin, symlink=bin_dir/bin_name)
            symlinks = [bin_dir/bin_name]
        else:
            _ = [self.link(target=binary, symlink=bin_dir/binary.name) for binary in self.extracted_bin]
            symlinks = [bin_dir/binary.name for binary in self.extracted_bin]
        log.info(f'{symlinks = }')
        return symlinks


@dataclasses.dataclass
class Meta:
    '''Write and read metadata for installed utilities.'''

    metadata_dir: pathlib.Path = cfg.metadata_dir

    def __post_init__(self):
        self.repo = dict(full_name='name', path_with_namespace='name', description='description', topics='topics', language='language', stargazers_count='stars', star_count='stars', html_url='url', web_url='url', updated_at='updated')
        self.tag = dict(tag_name='tag', published_at='published', released_at='published')
        self.meta = dict(installed='installed', symlinks='symlinks')

    def write(self, metadata: typing.Dict[str, typing.Any]):
        '''Write (and overwrite) release metadata.'''
        self.metadata_dir.mkdir(exist_ok=True)
        file_path = self.metadata_dir/f"{metadata['meta']['repo_id'].replace('/', '_')}.json"
        file_path.unlink(missing_ok=True)
        with file_path.open(mode='w') as out_file:
            json.dump(obj=metadata, fp=out_file)
        log.debug(f'release metadata written to {file_path}')

    def read(self, repo_id: str) -> typing.Dict[str, typing.Any]:
        '''Read release metadata.'''
        file_path = self.metadata_dir/f"{repo_id.replace('/', '_')}.json"
        if not file_path.is_file():
            return {}
        with file_path.open(mode='r') as in_file:
            return json.load(fp=in_file)

    def readKeys(self, file_path: pathlib.Path) -> pandas.Series:
        '''Read metadata `keys` from `file_path` as `pandas.Series`.'''
        keys = {'repo': self.repo, 'tag': self.tag, 'meta': self.meta}
        with file_path.open(mode='r') as f:
            metadata = json.load(f)
        return pandas.concat([pandas.Series({label: metadata[categ][key] for key, label in map.items() if metadata[categ].get(key)}) for categ, map in keys.items()], axis=0)


# [Python: How to remove default options on Typer CLI?](https://stackoverflow.com/a/63316503)
# [How do I get typer to accept the short `-h` as well as the long `--help` to output help text?](https://stackoverflow.com/a/74404356)
app = typer.Typer(add_completion=False, context_settings={"help_option_names": ["-h", "--help"]})


class Help:
    '''Help text for CLI arguments and options.'''

    log_level = f"log level {[l.lower() for l in logging._nameToLevel if l != 'NOTSET']}"
    github_token = 'token to increase the rate limit of GitHub API calls (can also be set as an environment variable: `GITHUB_TOKEN`)'
    gitlab_token = 'token to increase the rate limit of GitLab API calls (can also be set as an environment variable: `GITLAB_TOKEN`)'
    bin_dir = 'symlink destination directory'
    cache_dir = 'download directory'
    data_dir = 'extracted data directory'
    metadata_dir = 'metadata directory'
    repo_id = "url or owner/repo separated by a slash, e.g. 'https://github.com/junegunn/fzf' or 'junegunn/fzf'"
    url = 'install directly from url'
    tag = 'release tag'
    confirm = 'proceed without prompting for confirmation'
    force_download = 'download asset even if it already exists.'
    download_only = 'download asset only and do not install it; note that asset will be downloaded, even if it already exists.'
    quiet = 'set logging level to error'
    verbose = 'set logging level to debug'
    asset_pattern = 'regular expression to uniquely identify correct asset'
    bin_pattern = 'regular expression to identify binary file(s)'
    symlink_alias = 'alias name for symlink (as opposed to the filename of the extracted binary file)'


class Typer:
    '''Type hints for `typer`'''
    # https://typer.tiangolo.com/tutorial/arguments/help/
    # https://typer.tiangolo.com/tutorial/options/help/

    log_level = typing_extensions.Annotated[str, typer.Option(help=Help.log_level)]
    github_token = typing_extensions.Annotated[str, typer.Option(help=Help.github_token)]
    gitlab_token = typing_extensions.Annotated[str, typer.Option(help=Help.gitlab_token)]
    bin_dir = typing_extensions.Annotated[str, typer.Option(help=Help.bin_dir)]
    cache_dir = typing_extensions.Annotated[str, typer.Option(help=Help.cache_dir)]
    data_dir = typing_extensions.Annotated[str, typer.Option(help=Help.data_dir)]
    metadata_dir = typing_extensions.Annotated[str, typer.Option(help=Help.metadata_dir)]

    repo_id = typing_extensions.Annotated[str, typer.Argument(help=Help.repo_id)] # = typer.Argument(help=Help.repo_id)
    tag = typing_extensions.Annotated[str, typer.Option('--tag', '-t', help=Help.tag)]
    url = typing_extensions.Annotated[str, typer.Option('--url', '-u', help=Help.url)]
    asset_pattern = typing_extensions.Annotated[str, typer.Option(help=Help.asset_pattern)]
    bin_pattern = typing_extensions.Annotated[str, typer.Option(help=Help.bin_pattern)]
    symlink_alias = typing_extensions.Annotated[str, typer.Option(help=Help.symlink_alias)]

    confirm: bool = typing_extensions.Annotated[bool, typer.Option('--confirm', '-y', help=Help.confirm)]

    force_download: bool = typing_extensions.Annotated[bool, typer.Option('--force-download', '-f', help=Help.force_download)]
    download_only: bool = typing_extensions.Annotated[bool, typer.Option('--download-only', '-d', help=Help.download_only)]

    quiet: bool = typing_extensions.Annotated[bool, typer.Option('--quiet', '-q', help=Help.quiet)]
    verbose: bool = typing_extensions.Annotated[bool, typer.Option('--verbose', '-v', help=Help.verbose)]


@app.command()
def config(log_level: Typer.log_level = logging.getLevelName(Config.log_level).lower(),
           github_token: Typer.github_token = Config.github_token,
           gitlab_token: Typer.gitlab_token = Config.gitlab_token,
           bin_dir: Typer.bin_dir = Config.bin_dir,
           cache_dir: Typer.cache_dir = Config.cache_dir,
           data_dir: Typer.data_dir = Config.data_dir,
           metadata_dir: Typer.metadata_dir = Config.metadata_dir):
    '''Write config options to file.'''
    kwargs = locals()
    kwargs['log_level'] = logging.getLevelName(log_level.upper()) # logging._nameToLevel.get(log_level.upper())
    kwargs.update({k: pathlib.Path(v) for k, v in kwargs.items() if isinstance(v, str) or k.endswith('_token')}) # convert paths to `pathlib.Path` objects
    Config(**kwargs).write()


@app.command()
def info(repo_id: Typer.repo_id) -> pandas.Series:
    '''Query repository info.'''
    keys =  {**Meta().repo, **dict(created_at='created', open_issues_count='issues', has_downloads='downloads', visibility='visibility', archived='archived')}
    try:
        repo_info = Repo(id=repo_id).info()
    except urllib.error.HTTPError as e:
        log.error(f'{e.code} {e.reason} {e.url}')
        return pandas.Series()
    title = repo_info.get('full_name', repo_info.get('path_with_namespace'))
    table = rich.table.Table(title=title, border_style='blue', show_header=False)
    [table.add_row(key, str(val)) for key, val in repo_info[repo_info.index.intersection(keys)].rename(keys).items()]
    if log.level <= logging.INFO:
        rich.console.Console().print(table)
    return repo_info


@app.command('list')
@app.command('ls')
def ls():
    '''Print info for all installed utilities.'''
    repo = [Meta().readKeys(file_path=file_path) for file_path in cfg.metadata_dir.glob('*json')]
    if not repo:
        return
    repo = pandas.concat(repo, axis=1).T
    repo['url'] = repo.url.str.split('/').str[2]
    repo['tag'] = repo.tag.apply(parseVersion)
    repo['language'] = repo.language.apply(lambda row: pandas.Series(row).idxmax() if isinstance(row, dict) else row)
    repo['symlinks'] = repo.symlinks.apply(lambda row: [pathlib.Path(f).stem for f in row])
    repo['topics'] = repo.topics.str[0:3]
    repo[['updated', 'published', 'installed']] = repo[['updated', 'published', 'installed']].apply(pandas.to_datetime, format='ISO8601').apply(lambda row: row.dt.strftime('%Y-%m-%d'))
    repo = repo.sort_values(by='name', key=lambda x: x.str.split('/', expand=True)[1]).reset_index(drop=True)
    rich.console.Console().print(table(data=repo))


@app.command()
def install(repo_id: Typer.repo_id,
            tag: Typer.tag = 'latest',
            url: Typer.url = None,
            asset_pattern: Typer.asset_pattern = '.*',
            bin_pattern: Typer.bin_pattern = '.*',
            symlink_alias: Typer.symlink_alias = None,
            confirm: Typer.confirm = False,
            force_download: Typer.force_download = False,
            download_only: Typer.download_only = False,
            quiet: Typer.quiet = False,
            verbose:Typer.verbose = False):
    '''Identify, download, extract asset corresponding to system/OS and symlink executable file(s).'''
    kwargs = {k: v for k, v in locals().items() if k not in ('confirm', 'force_download', 'download_only', 'quiet', 'verbose')}
    log.setLevel(logging.ERROR if quiet else logging.DEBUG if verbose else cfg.log_level)
    repo, repo_info = repoInfo(repo_id=repo_id)
    tag = tag if not url else parseVersion(url)
    tag_info = tagInfo(repo=repo, tag=tag)
    asset_urls = assetURL(tag_info=tag_info, tag=tag)
    if not url:
        if tag_info.empty:
            return log.error(f'`{tag}` tag not found')
        if asset_urls.empty:
            return log.error(f'no assets corresponding to `{tag}` tag found')
        url = Asset.identify(asset_urls=asset_urls, asset_pattern=asset_pattern)
    if not url:
        return log.error('no release assets found or provided! :(')
    tag_date = pandas.Timestamp(tag_info.get('published_at', tag_info.get('released_at')))
    if (not confirm) and (input(f'proceed with installation of `{tag}` tag ({tag_date})? ').lower() not in ('y', 'yes', 'yep')):
        return
    asset_url, asset_filename = url, url.split('/')[-1]
    file_path = cfg.cache_dir/asset_filename
    Asset(file_path=file_path).download(url=asset_url, force=force_download or download_only)
    Checksum(asset_urls=asset_urls, asset_filename=asset_filename).verify(file_path=file_path)
    if download_only:
        return
    download_meta = dict(repo_id=repo.id, tag=str(tag), asset_pattern=asset_pattern, asset_url=asset_url, asset=str(file_path))
    install_meta = extractAndSymlink(repo=repo, file_path=file_path, bin_pattern=bin_pattern, symlink_alias=symlink_alias)
    metadata = dict(repo=repo_info.to_dict(), tag=tag_info.to_dict() if not tag_info.empty else {'tag_name': url}, meta={**kwargs, **download_meta, **install_meta})
    Meta().write(metadata=metadata)


@app.command('update')
@app.command('upgrade')
def upgrade(repo_id: Typer.repo_id, confirm: Typer.confirm = False, quiet: Typer.quiet = False, verbose: Typer.verbose = False):
    '''Upgrade utility to `latest` release.'''
    log.setLevel(logging.ERROR if quiet else logging.DEBUG if verbose else cfg.log_level)
    repo = Repo(id=repo_id)
    metadata = Meta().read(repo_id=repo.id)
    tag_info = metadata.get('tag', {})
    installed_tag = tag_info.get('tag_name')
    installed_tag_date = pandas.Timestamp(tag_info.get('published_at', tag_info.get('released_at', '1970-01-01T00:00:00Z')))
    latest_tag = tagInfo(repo=repo, tag='latest')
    if latest_tag.empty:
        return
    latest_tag_date = pandas.Timestamp(latest_tag.get('published_at', latest_tag.get('released_at')))
    if installed_tag_date >= latest_tag_date:
        log.info(f'{repo.id} installed tag `{installed_tag}` ({installed_tag_date}) is up to date')
        return
    kwarg_tag = metadata.get('meta', {}).get('tag')
    log.info(f"updating {repo.id} from `{installed_tag}` ({installed_tag_date}) to `{latest_tag.get('tag_name')}` ({latest_tag_date})")
    if (kwarg_tag != 'latest') and (input(f'upgrade from `{kwarg_tag}` tag to `latest` tag? ').lower() not in ('y', 'yes', 'yep')):
        return
    uninstall(repo_id=repo.id, confirm=confirm)
    metadata = metadata if metadata else {'meta': {'repo_id': repo.id}}
    # kwargs = {k: v for k, v in metadata.get('meta').items() if (k in install.__annotations__.keys()) and (k not in ('tag', 'confirm', 'download_only', 'quiet', 'verbose'))}
    kwargs = {k: v for k, v in metadata.get('meta').items() if (k in install.__annotations__.keys()) and (k != 'tag')}
    install(**kwargs, tag='latest', confirm=confirm, quiet=quiet, verbose=verbose)


@app.command('update-all')
@app.command('upgrade-all')
def upgradeAll(confirm: Typer.confirm = False, quiet: Typer.quiet = False, verbose: Typer.verbose = False):
    '''Upgrade all installed utilities (except ones installed from url or from a release tag other than `latest`)'''
    log.setLevel(logging.ERROR if quiet else logging.DEBUG if verbose else cfg.log_level)
    with fileinput.input(files=cfg.metadata_dir.glob('*json'), mode='r') as meta_files:
        metadata = [json.loads(f).get('meta') for f in meta_files]
    # _ = [upgrade(repo_id=repo.get('repo_id'), confirm=confirm) for repo in metadata if (repo.get('tag') == 'latest') and (not repo.get('url'))]
    _ = [upgrade(repo_id=repo.get('repo_id'), confirm=confirm) for repo in metadata if not repo.get('url')]


@app.command('uninstall')
@app.command('remove')
@app.command('rm')
def uninstall(repo_id: Typer.repo_id, confirm: Typer.confirm = False, quiet: Typer.quiet = False, verbose: Typer.verbose = False):
    '''Uninstall utility.'''
    log.setLevel(logging.ERROR if quiet else logging.DEBUG if verbose else cfg.log_level)
    repo = Repo(id=repo_id)
    metadata = Meta().read(repo_id=repo.id).get('meta')
    meta_filepath = cfg.metadata_dir/f"{repo.id.replace('/', '_')}.json"
    if not metadata:
        return log.warning(f'`{repo.id}` does not seem to be installed. Please check if metadata file exists in `{meta_filepath}`')
    log.info(f"the following symlinks/files/directories will be deleted:\n{str.join(', ', metadata.get('symlinks'))}\n{metadata.get('asset')}\n{metadata.get('extracted_path')}\n{meta_filepath}")
    if (not confirm) and (input('proceed with uninstallation? ').lower() not in ('y', 'yes', 'yep')):
        return
    _ = [rmRecursive(path=pathlib.Path(path)) for path in metadata.get('symlinks')]
    rmRecursive(path=pathlib.Path(metadata.get('asset')))
    rmRecursive(path=pathlib.Path(metadata.get('extracted_path')))
    meta_filepath.unlink(missing_ok=True)


def parseVersion(version: str) -> packaging.version.Version:
    '''Parse version based on `packaging.version.VERSION_PATTERN`.'''
    pattern = re.compile(pattern=packaging.version.VERSION_PATTERN, flags=(re.VERBOSE|re.IGNORECASE)) # https://packaging.pypa.io/en/stable/version.html#packaging.version.VERSION_PATTERN
    parsed_version = re.search(pattern=pattern, string=version)
    return packaging.version.parse(parsed_version.group(0)) if parsed_version else version

def table(data: pandas.DataFrame, title: str = 'Installed Releases') -> rich.table.Table:
    '''Print `data`: pandas.DataFrame as a `rich.table`.''' # [Convert a pandas.DataFrame object into a rich.Table object for stylized printing in Python.](https://gist.github.com/avi-perl/83e77d069d97edbdde188a4f41a015c4)
    ansi_color_names = pandas.Series(rich.color.ANSI_COLOR_NAMES).drop_duplicates().sort_values()
    row_styles = ansi_color_names[ansi_color_names>=160].index.to_list()
    table = rich.table.Table(title=title, border_style='blue', header_style='orange1', show_edge=False, row_styles=row_styles)
    [table.add_column(str(col), max_width=60, no_wrap=True) for col in data.columns]
    [table.add_row(*[str(x) for x in val]) for val in data.values]
    return table

def repoInfo(repo_id: str) -> typing.Tuple[Repo, pandas.Series]:
    repo_info = info(repo_id=repo_id)
    if repo_info.empty:
        return Repo('/'), pandas.Series()
    repo_url = repo_info.get('html_url', repo_info.get('web_url'))
    return Repo(id=repo_url), repo_info

def tagInfo(repo: Repo, tag: str) -> pandas.Series:
    try:
        return repo.releaseTag(tag=tag)
    except urllib.error.HTTPError as e:
        log.warning(f'{e.code} {e.reason} {e.url}')
        return pandas.Series()

def assetURL(tag_info: pandas.Series, tag: str) -> pandas.Series:
    if tag_info.empty or not tag_info.assets:
        return pandas.Series()
    assets = pandas.DataFrame(tag_info.assets.get('links') if 'links' in tag_info.assets else tag_info.assets)
    urls = assets.get('browser_download_url', assets.get('direct_asset_url', pandas.Series()))
    if urls.empty:
        return pandas.Series()
    return urls

def extractAndSymlink(repo: Repo, file_path: pathlib.Path, bin_pattern: str, symlink_alias: str) -> typing.Dict[str, typing.Union[str, typing.List[str]]]:
    extracted_path = Asset(file_path=file_path).extract(destination=cfg.data_dir)
    extracted_bin = Executables.identify(extracted_path=extracted_path, bin_pattern=bin_pattern)
    symlinks = Executables(extracted_bin=extracted_bin, repo_id=repo.id).symlink(symlink_alias=symlink_alias)
    now = pandas.Timestamp.now('UTC').strftime('%Y-%m-%dT%H:%M:%SZ')
    return dict(extracted_path=str(extracted_path), extracted_bin=[str(bin) for bin in extracted_bin], symlinks=[str(link) for link in symlinks], installed=now)

def rmRecursive(path: pathlib.Path):
    '''Remove `path` recursively.''' # [PathLib recursively remove directory?](https://stackoverflow.com/a/66552066)
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    if path.is_dir():
        _ = [rmRecursive(child) for child in path.iterdir()]
        path.rmdir()
    log.debug(f'removed {path}')

def test():
    import time
    go = {'wagoodman/dive': {},
          'wader/fq': {},
          'antonmedv/fx': {},
          'junegunn/fzf': {},
          'dundee/gdu': dict(asset_pattern='linux_amd64.tgz'),
          'tomnomnom/gron': {},
          'charmbracelet/gum': dict(asset_pattern='tar.gz$'),
          'jesseduffield/lazygit': {},
          'gokcehan/lf': {},
          'zyedidia/micro': dict(asset_pattern='linux64.tar.gz'),
          'solarkennedy/uq': {},
          'mikefarah/yq': dict(asset_pattern='amd64$')}
    rust = {'sharkdp/bat': dict(asset_pattern='linux-gnu.tar.gz'),
            'ClementTsang/bottom': dict(tag='prerelease', asset_pattern='linux-gnu.tar.gz'),
            'bootandy/dust': dict(asset_pattern='linux-gnu.tar.gz'),
            'eza-community/eza': dict(asset_pattern='linux-gnu.tar.gz'),
            'sharkdp/fd': dict(asset_pattern='linux-gnu.tar.gz'),
            'sharkdp/hyperfine': dict(asset_pattern='linux-gnu.tar.gz'),
            'stewart/rff': dict(asset_pattern='linux-gnu.tar.gz'),
            'BurntSushi/ripgrep': {},
            'starship/starship': dict(asset_pattern='linux-gnu.tar.gz'),
            'categulario/tiempo-rs': {},
            'typst/typst': {},
            'atanunq/viu': {},
            'BurntSushi/xsv': {},
            'ajeetdsouza/zoxide': {}}
    other = {'aristocratos/btop': {},
             'cli/cli': {},
             'moparisthebest/static-curl': dict(symlink_alias='curl'),
             'helix-editor/helix': {},
             'ImageMagick/ImageMagick': dict(asset_pattern='gcc'),
             'jqlang/jq': dict(asset_pattern='linux64'),
             'johnkerl/miller': {},
             'neovim/neovim': dict(tag='prerelease'),
             'jarun/nnn': dict(asset_pattern='nnn-static', symlink_alias='nnn'),
             'jgm/pandoc': dict(bin_pattern='pandoc$'),
             'quarto-dev/quarto-cli': dict(asset_pattern='linux-amd64', tag='prerelease'),
             'koalaman/shellcheck': {},
             'vscodium/vscodium': dict(asset_pattern='VSCodium-linux-x64', bin_pattern='codium'),
             'natecraddock/zf': {}}
    from_url = {'exiftool/exiftool': dict(url='https://exiftool.org/Image-ExifTool-12.77.tar.gz'),
                'golang/go': dict(url='https://go.dev/dl/go1.22.0.linux-amd64.tar.gz'),
                'rofl0r/ncdu': dict(url='https://dev.yorhel.nl/download/ncdu-2.3-linux-x86_64.tar.gz')}
    for repo_id, kwargs in {**go, **rust, **other, **from_url}.items():
        _ = kwargs.pop('tag', None)
        install(repo_id, **kwargs, tag='prerelease')
        # uninstall(repo_id)

ARCH_PATTERN = SYS().arch_pattern
OS_PATTERN = SYS().os_pattern

if __name__ == '__main__':
    app()
