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
import types
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

'''
to do:
* implement "pre-release" tag?
* use `repo_info` to specify github/gitlab in `Repo().releaseTag()` call
* replace `getKeys` function?
* https://gitlab.com/graphviz/graphviz/-/releases
'''

rich_handler = rich.logging.RichHandler(rich_tracebacks=True, log_time_format="[%Y-%m-%d %H:%M:%S]")
logging.basicConfig(level=cfg.log_level, format='%(message)s', handlers=[rich_handler]) # [Logging Handler](https://rich.readthedocs.io/en/stable/logging.html)
log = logging.getLogger()

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
    metadata_dir: pathlib.Path = XDG_CONFIG_HOME/f"{pathlib.Path(__file__).stem}" # installed releases metadata directory

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


@dataclasses.dataclass
class SYS:
    '''Identify system info and define corresponding regex patterns.'''

    OS: str = platform.system().lower()

    PLATFORM: str = platform.processor().lower() if platform.processor() else platform.machine().lower() if platform.machine() else ''

    ARCH_PATTERN: types.MappingProxyType = types.MappingProxyType({ # https://adamj.eu/tech/2022/01/05/how-to-make-immutable-dict-in-python/
            # https://github.com/workhorsy/py-cpuinfo/blob/f3f0fec58335b9699b9b294267c15f516045b1fe/cpuinfo/cpuinfo.py#L782
            # https://github.com/zyedidia/eget/blob/master/DOCS.md#detect
            # https://en.wikipedia.org/wiki/Uname
            'X86': 'x86$|x86_32|[i]?[3-6]86|i86pc|ia[-_]?32|bepc',
            'X86_64': 'amd64|x64|x86[-_]?64|i686[-_]?64|ia[-_]?64',
            'ARM8_32': 'armv8[-_]?[b-z]?',
            'ARM8_64': 'aarch64|arm64|armv8[-_]?a', # https://en.wikipedia.org/wiki/ARM_architecture_family#64.2F32-bit_architecture
            'ARM7': 'arm$|armv[6-7]',
            'PPC_32': 'ppc$|ppc32|prep|pmac|powermac',
            'PPC_64': 'powerpc|ppc64',
            'SPARC_32': 'sparc$|sparc32',
            'SPARC_64': 'sparc64|sun4[u-v]',
            'S390X': 's390[x]?',
            'MIPS_32': 'mips$',
            'MIPS_64': 'mips64',
            'RISCV_32': 'riscv$|riscv32',
            'RISCV_64': 'riscv64',
            'LOONG_32': 'loongarch32',
            'LOONG_64': 'loongarch64'})

    OS_PATTERN: types.MappingProxyType = types.MappingProxyType({
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
            'win32': 'win|windows'})

    def __post_init__(self):
        if platform.processor() and platform.machine() and (platform.processor().lower() != platform.machine().lower()):
            log.warning(f'{platform.processor()=} != {platform.machine()=}')
        self.os_pattern = self.OS_PATTERN.get(self.OS)
        arch = [arch for arch, pattern in self.ARCH_PATTERN.items() if re.match(f'{pattern}', self.PLATFORM)]
        assert len(arch) == 1, f'Processor architecture could not be recognized correctly: {arch}'
        self.arch_pattern = self.ARCH_PATTERN.get(arch[0])

    def uname_wiki(self):
        '''Check if entries in the `uname` wikipedia table match `self.ARCH_PATTERN`'''
        uname = pandas.read_html('https://en.wikipedia.org/wiki/Uname', match='Machine')[0]['Machine (-m) POSIX']
        return [(a, [arch for arch, pattern in self.ARCH_PATTERN.items() if re.match(f'{pattern}', a.lower())]) for a in uname]


ARCH_PATTERN = SYS().arch_pattern
OS_PATTERN = SYS().os_pattern


@dataclasses.dataclass
class Github:
    '''Minimal wrapper for querying the [GitHub REST API](https://docs.github.com/en/rest)'''

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
            if response.status != 200:
                return log.error(f'response status: {response.status}')
            response = json.load(response)
        return response

    def info(self) -> pandas.Series:
        '''Query repo info for `self.repo_id`.'''
        repo = self.query(url=f'https://api.github.com/repos/{self.repo_id}', per_page=1)
        if repo:
            return pandas.Series(repo)

    def releaseTag(self, tag: str = 'latest', **kwargs) -> pandas.Series:
        '''Query release tag info for `self.repo_id`.'''
        if tag in ['pre', 'pre-release', 'prerelease']:
            return self.preReleaseTag(**kwargs)
        tag = f'tags/{tag}' if tag != 'latest' else tag # [Get a release by tag name](https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name)
        response = self.query(url=f'https://api.github.com/repos/{self.repo_id}/releases/{tag}', **kwargs)
        return pandas.Series(response)

    def preReleaseTag(self, **kwargs) -> pandas.Series:
        '''Query release tag info for `self.repo_id`.'''
        response = self.query(url=f'https://api.github.com/repos/{self.repo_id}/releases', **kwargs)
        releases = pandas.DataFrame(response)
        return releases[releases.prerelease == True].squeeze().rename()


@dataclasses.dataclass
class Gitlab(Github):
    '''Minimal wrapper for querying the [GitLab REST API](https://docs.gitlab.com/ee/api/rest/)'''

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
            repo['language'] = self.query(url=f"https://gitlab.com/api/v4/projects/{self.repo_id}/languages", per_page=1) # [Get repository languages with the GitLab API](https://stackoverflow.com/a/50573582)
            return repo

    def releaseTag(self, tag: str = 'latest', **kwargs) -> pandas.Series:
        '''Return release tag info for `self.repo_id`.'''
        tag = f'permalink/{tag}' if tag == 'latest' else tag # [Get a release by tag name](https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name)
        response = self.query(url=f"https://gitlab.com/api/v4/projects/{self.repo_id}/releases/{tag}", **kwargs)
        return pandas.Series(response)


@dataclasses.dataclass
class Repo:
    '''Query GitHub/Gitlab repo info and release tag info.'''

    id: str
    tag: str = 'latest'
    github: bool = False
    gitlab: bool = False
    NAME_KEYS: types.MappingProxyType = types.MappingProxyType({'full_name':'name', 'path_with_namespace':'name'})
    STAR_KEYS: types.MappingProxyType = types.MappingProxyType({'stargazers_count':'stars', 'star_count':'stars'})
    URL_KEYS: types.MappingProxyType = types.MappingProxyType({'html_url':'url', 'web_url':'url'})

    def __post_init__(self):
        self.github = True if 'github.com' in self.id else False
        self.gitlab = True if 'gitlab.com' in self.id else False
        self.id = self.parseID(self.id)

    @staticmethod
    def parseID(repo_id: str) -> str:
        '''Parse owner/org and repo from `repo_id`'''
        assert '/' in repo_id, 'please provide url or owner/repo separated by a slash, e.g. "https://github.com/junegunn/fzf" or "junegunn/fzf"'
        if '.com' in repo_id:
            url = urllib.parse.urlparse(urllib.parse.urljoin('https:', repo_id).replace('///', '//')) # [How to open "partial" links using Python?](https://stackoverflow.com/a/57510472)
            return str.join('/', url.path.strip('/').split('/')[:2])
        else:
            return repo_id.strip('/')

    def info(self) -> pandas.Series:
        '''Return release tag info for github or gitlab repo.'''
        func = Github(repo_id=self.id).info if self.github else Gitlab(repo_id=self.id).info if self.gitlab else None
        if func:
            return func()
        try:
            return Github(repo_id=self.id).info()
        except urllib.error.HTTPError:
            return Gitlab(repo_id=self.id).info()

    def releaseTag(self) -> pandas.Series:
        '''Return release tag info for github or gitlab repo.'''
        func = Github(repo_id=self.id).releaseTag if self.github else Gitlab(repo_id=self.id).releaseTag if self.gitlab else None
        if func:
            return func(tag=self.tag, per_page=1)
        try:
            return Github(repo_id=self.id).releaseTag(tag=self.tag, per_page=1)
        except urllib.error.HTTPError:
            return Gitlab(repo_id=self.id).releaseTag(tag=self.tag, per_page=1)


@dataclasses.dataclass
class Asset:
    '''Identify, download, extract asset.'''

    filepath: pathlib.Path
    extract_destination: pathlib.Path = cfg.data_dir
    col_text: rich.progress.TextColumn = rich.progress.TextColumn(text_format='[bold blue]{task.fields[filename]}')
    col_bar: rich.progress.BarColumn = rich.progress.BarColumn(bar_width=60)
    col_progress: rich.progress.TaskProgressColumn = rich.progress.TaskProgressColumn(text_format='[progress.percentage]{task.percentage:>3.1f}%')
    col_download: rich.progress.DownloadColumn = rich.progress.DownloadColumn()
    col_transfer_speed: rich.progress.TransferSpeedColumn = rich.progress.TransferSpeedColumn()
    col_time_remaining: rich.progress.TimeRemainingColumn = rich.progress.TimeRemainingColumn()

    def __post_init__(self):
        # [rich.progress.Progress](https://rich.readthedocs.io/en/stable/reference/progress.html#rich.progress.Progress)
        self.progress_columns = [v for k,v in dataclasses.asdict(self).items() if k.startswith('col_')]

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
            log.error(f'a unique asset URL matching "{OS_PATTERN}" and "{ARCH_PATTERN}" could not be identified:\n{asset}\ntry specifying a (regex) `asset_pattern`')
            asset_pattern = input('(regex) asset_pattern: ')
            return cls.identify(asset_urls=asset_urls, asset_pattern=asset_pattern)

    def download(self, url: str, force: bool = False):
        '''Download `url` to `self.filepath` with a `rich` progress bar.'''
        # https://github.com/Textualize/rich/blob/master/examples/downloader.py
        progress = rich.progress.Progress(*self.progress_columns)
        task_id = progress.add_task(description="download", start=False, filename=self.filepath)
        log.debug(f"Requesting {url}")
        response = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': os.environ['USERAGENT']}))
        if self.filepath.exists():
            log.debug(f'{self.filepath} size = {self.filepath.stat().st_size}\n{url} size = {int(response.length)}')
            log.info(f'local file size == remote file size: {self.filepath.stat().st_size == int(response.length)}')
        if self.filepath.exists() and (self.filepath.stat().st_size == int(response.length)) and (not force):
            return logging.info(f'{self.filepath} already exists')
        progress.update(task_id=task_id, total=float(response.length))
        with progress:
            with self.filepath.open(mode='wb') as out_file:
                progress.start_task(task_id=task_id)
                for chunk in iter(lambda: response.read(2**10), b''):
                    out_file.write(chunk)
                    progress.update(task_id=task_id, advance=len(chunk))
        log.info(f'Downloaded {self.filepath}')

    @staticmethod
    def chmod(file_path: pathlib.Path):
        '''Modify file permission to make file executable.'''
        file_path.chmod(mode=file_path.stat().st_mode | stat.S_IEXEC)
        log.debug(f'{stat.filemode(file_path.stat().st_mode)} {file_path}')

    def extract(self, destination: pathlib.Path = cfg.data_dir) -> pathlib.Path:
        '''Extract `self.filepath` to `destination`.'''
        if not tarfile.is_tarfile(self.filepath):
            log.warning(f'{self.filepath} is not a tar archive')
            self.chmod(file_path=self.filepath)
            return self.filepath.rename(destination/self.filepath.stem)
        with tarfile.open(name=self.filepath, mode='r:*') as tar:
            base_dir = os.path.commonpath(tar.getnames()) # [With Python's 'tarfile', how can I get the top-most directory in a tar archive?](https://stackoverflow.com/a/11269228)
            log.info(f'extracting {self.filepath}...')
            tar.extractall(path=destination if base_dir else destination/self.filepath.stem.rstrip('.tar'))
        extracted_dir = destination/base_dir if base_dir else destination/self.filepath.stem.rstrip('.tar')
        log.debug(f'extracted {self.filepath} to {extracted_dir}')
        return extracted_dir


@dataclasses.dataclass
class Checksum:
    '''Identify and verify checksum for asset.'''

    assets: pandas.DataFrame
    asset_url: str
    url_keys: typing.Tuple[str, str] = ('browser_download_url', 'direct_asset_url')

    def fromFile(self) -> pathlib.Path:
        '''Parse file containing checksums and return checksum corresponding to `asset_url`.'''
        checksums_file = self.assets[self.assets._get(self.url_keys).str.contains('checksums.txt$|sha256.txt$|sha256sum.txt$', regex=True, flags=re.IGNORECASE)].squeeze()
        if not checksums_file.empty and isinstance(checksums_file, pandas.Series):
            checksums = pandas.read_csv(checksums_file._get(self.url_keys), sep='\s+', names=['checksum', 'filename'])
            return checksums[checksums.filename.str.endswith(self.asset_url.split('/')[-1])].squeeze().get('checksum')

    def fromFiles(self) -> pathlib.Path:
        '''Identify checksum file corresponding to `asset_url` and return its checksum.'''
        checksum_files = self.assets[self.assets._get(self.url_keys).str.contains('sha256$|sha256sum$|sum$', regex=True, flags=re.IGNORECASE)].squeeze()
        if not checksum_files.empty and isinstance(checksum_files, pandas.DataFrame):
            checksum_file_url = checksum_files[checksum_files._get(self.url_keys).str.contains(self.asset_url.split('/')[-1])].squeeze()._get(self.url_keys)
            return pandas.read_csv(checksum_file_url, sep='\s+', names=['checksum', 'filename']).squeeze().get('checksum')

    def verify(self, filepath: pathlib.Path) -> bool:
        '''Calculate asset checksum and verify against checksum file(s), if available.'''
        if self.assets.empty:
            return None
        checksum_from_file = self.fromFile()
        checksum_from_files = self.fromFiles()
        reference_checksum = checksum_from_file if checksum_from_file else checksum_from_files if checksum_from_files else None
        if reference_checksum:
            with filepath.open(mode='rb') as target_file:
                download_checksum = hashlib.sha256(target_file.read()).hexdigest()
            log.debug(f'{reference_checksum = }\n{download_checksum  = }')
            log.info(f'reference_checksum == download_checksum: {reference_checksum == download_checksum}')
            assert reference_checksum == download_checksum, "checksums don't match!"


@dataclasses.dataclass
class Executables:
    '''Identify and symlink executable(s) from extracted asset.'''

    extracted_bin: typing.List[pathlib.Path]
    repo_id: str

    @staticmethod
    def isExecutableFile(filepath: pathlib.Path) -> bool:
        '''Check if `filepath` is a file and has executable permissions.'''
        return filepath.is_file() and os.access(filepath, mode=os.X_OK)

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
    def link(symlink: pathlib.Path, target: pathlib.Path):
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
            self.link(symlink=bin_dir/bin_name, target=extracted_bin)
            symlinks = [bin_dir/bin_name]
        else:
            _ = [self.link(symlink=bin_dir/binary.name, target=binary) for binary in self.extracted_bin]
            symlinks = [bin_dir/binary.name for binary in self.extracted_bin]
        log.info(f'{symlinks = }')
        return symlinks


@dataclasses.dataclass
class Meta:
    '''Write and read metadata for installed utilities.'''

    metadata_dir: pathlib.Path = cfg.metadata_dir

    def __post_init__(self):
        self.repo = {**Repo.NAME_KEYS, **{'description':'description', 'topics':'topics', 'language':'language'}, **Repo.STAR_KEYS, **{'forks_count':'forks'}, **Repo.URL_KEYS, **{'updated_at':'updated'}}
        self.tag = {'tag_name': 'tag', 'published_at': 'published', 'released_at': 'published'}
        self.meta ={'symlinks': 'symlinks', 'installed': 'installed'}

    def write(self, metadata: typing.Dict[str, typing.Any]):
        '''Write (and overwrite) release metadata.'''
        self.metadata_dir.mkdir(exist_ok=True)
        filepath = self.metadata_dir/f"{metadata.get('meta').get('repo_id').replace('/', '_')}.json"
        filepath.unlink(missing_ok=True)
        with filepath.open(mode='w') as out_file:
            json.dump(obj=metadata, fp=out_file)
        log.debug(f'release metadata written to {filepath}')

    def read(self, repo_id: str) -> typing.Dict[str, typing.Any]:
        '''Read release metadata.'''
        filepath = self.metadata_dir/f"{repo_id.replace('/', '_')}.json"
        if not filepath.is_file():
            return {}
        with filepath.open(mode='r') as in_file:
            return json.load(fp=in_file)

    def readKeys(self, filepath: pathlib.Path) -> pandas.Series:
        '''Read metadata `keys` from `filepath` as `pandas.Series`.'''
        keys = {'repo': self.repo, 'tag': self.tag, 'meta': self.meta}
        with filepath.open(mode='r') as f:
            metadata = json.load(f)
        return pandas.concat([pandas.Series(metadata.get(k))._get(keys.get(k)).rename(keys.get(k)) for k in metadata.keys()], axis=0)


# [Python: How to remove default options on Typer CLI?](https://stackoverflow.com/a/63316503)
# [How do I get typer to accept the short `-h` as well as the long `--help` to output help text?](https://stackoverflow.com/a/74404356)
app = typer.Typer(add_completion=False, context_settings={"help_option_names": ["-h", "--help"]})


@dataclasses.dataclass
class Help:
    '''Help text for CLI arguments and options.'''

    log_level: str = f"log level {[l.lower() for l in logging._nameToLevel if l != 'NOTSET']}"
    github_token: str = 'token to increase the rate limit of GitHub API calls (can also be set as an environment variable: `GITHUB_TOKEN`)'
    gitlab_token: str = 'token to increase the rate limit of GitLab API calls (can also be set as an environment variable: `GITLAB_TOKEN`)'
    bin_dir: str = 'symlink destination directory'
    cache_dir: str = 'download directory'
    data_dir: str = 'extracted data directory'
    metadata_dir:str = 'metadata directory'
    repo_id: str = 'url or owner/repo separated by a slash, e.g. "https://github.com/junegunn/fzf" or "junegunn/fzf"'
    url: str = 'install directly from url'
    tag: str = 'release tag'
    confirm: str = 'proceed without prompting for confirmation'
    download_only: str = 'download asset only and do not install it. Note that asset will be re-downloaded even if it already exists.'
    quiet: str = 'set logging level to error'
    verbose: str = 'set logging level to debug'
    asset_pattern: str = 'regular expression to uniquely identify correct asset'
    bin_pattern: str = 'regular expression to identify binary file(s)'
    symlink_alias: str = 'alias name for symlink (as opposed to the filename of the extracted binary file)'


@app.command()
def config(log_level: typing_extensions.Annotated[str, typer.Option(help=Help.log_level)] = logging.getLevelName(Config.log_level).lower(),
           github_token: typing_extensions.Annotated[str, typer.Option(help=Help.github_token)] = Config.github_token,
           gitlab_token: typing_extensions.Annotated[str, typer.Option(help=Help.gitlab_token)] = Config.gitlab_token,
           bin_dir: typing_extensions.Annotated[str, typer.Option(help=Help.bin_dir)] = Config.bin_dir,
           cache_dir: typing_extensions.Annotated[str, typer.Option(help=Help.cache_dir)] = Config.cache_dir,
           data_dir: typing_extensions.Annotated[str, typer.Option(help=Help.data_dir)] = Config.data_dir,
           metadata_dir: typing_extensions.Annotated[str, typer.Option(help=Help.metadata_dir)] = Config.metadata_dir):
    '''Write config options to file.'''
    kwargs = locals()
    kwargs['log_level'] = logging.getLevelName(log_level.upper()) # logging._nameToLevel.get(log_level.upper())
    kwargs.update({k: pathlib.Path(v) for k, v in kwargs.items() if isinstance(v, str) or k.endswith('_token')}) # convert paths to `pathlib.Path` objects
    Config(**kwargs).write()

@app.command()
def info(repo_id: typing_extensions.Annotated[str, typer.Argument(help=Help.repo_id)]) -> pandas.Series:
    '''Query repository info.'''
    keys =  {**Meta().repo, **{'created_at': 'created', 'open_issues_count': 'issues', 'has_downloads': 'downloads', 'visibility': 'visibility', 'archived': 'archived'}}
    repo_info = Repo(id=repo_id).info()
    table = rich.table.Table(title=repo_info._get(['full_name', 'path_with_namespace']), border_style='blue', show_header=False)
    [table.add_row(key, str(val)) for key, val in repo_info._get(keys).rename(keys).items()]
    if log.level <= logging.INFO:
        rich.console.Console().print(table)
    return repo_info

@app.command('list')
@app.command('ls')
def ls():
    '''Print info for all installed utilities.'''
    repo = pandas.concat([Meta().readKeys(filepath=filepath) for filepath in cfg.metadata_dir.glob('*json')], axis=1).T
    repo['url'] = repo.url.str.split('/').str[2]
    repo['tag'] = repo.tag.apply(parseVersion)
    repo['language'] = repo.language.apply(lambda row: pandas.Series(row).idxmax() if isinstance(row, dict) else row)
    repo['symlinks'] = repo.symlinks.apply(lambda row: [pathlib.Path(f).stem for f in row])
    repo['topics'] = repo.topics.str[0:4]
    repo[['updated', 'published', 'installed']] = repo[['updated', 'published', 'installed']].apply(pandas.to_datetime, format='ISO8601').apply(lambda row: row.dt.strftime('%Y-%m-%d'))
    repo = repo.sort_values(by='name', key=lambda x: x.str.split('/', expand=True)[1]).reset_index(drop=True)
    rich.console.Console().print(table(data=repo))

@app.command()
def install(repo_id: typing_extensions.Annotated[str, typer.Argument(help=Help.repo_id)],
            tag: typing_extensions.Annotated[str, typer.Option('--tag', '-t', help=Help.tag)] = 'latest',
            url: typing_extensions.Annotated[str, typer.Option('--url', '-u', help=Help.url)] = None,
            confirm: typing_extensions.Annotated[bool, typer.Option('--confirm', '-y', help=Help.confirm)] = False,
            download_only: typing_extensions.Annotated[bool, typer.Option('--download-only', '-d', help=Help.download_only)] = False,
            quiet: typing_extensions.Annotated[bool, typer.Option('--quiet', '-q', help=Help.quiet)] = False,
            verbose: typing_extensions.Annotated[bool, typer.Option('--verbose', '-v', help=Help.verbose)] = False,
            asset_pattern: typing_extensions.Annotated[str, typer.Option(help=Help.asset_pattern)] = '.*',
            bin_pattern: typing_extensions.Annotated[str, typer.Option(help=Help.bin_pattern)] = '.*',
            symlink_alias: typing_extensions.Annotated[str, typer.Option(help=Help.symlink_alias)] = None):
    '''Identify, download, extract asset corresponding to system/OS and symlink executable file(s).'''
    kwargs = locals()
    log.setLevel(logging.ERROR if quiet else logging.DEBUG if verbose else cfg.log_level)
    tag_info = pandas.Series({'tag_name': url, 'published_at': None})
    assets = pandas.DataFrame()
    repo_info = info(repo_id=repo_id)
    repo_id = repo_info._get(Repo.URL_KEYS)
    if not url:
        tag_info = Repo(id=repo_id, tag=tag).releaseTag()
        assets = pandas.DataFrame(tag_info.assets.get('links') if 'links' in tag_info.assets else tag_info.assets)
        if not assets.empty:
            url = Asset.identify(asset_urls=assets._get(['browser_download_url', 'direct_asset_url']), asset_pattern=asset_pattern)
    if (not url):
        log.error('no release assets found! :(')
        return
    if (not confirm and input('Proceed with installation? ').lower() not in ('y', 'yes', 'yep')):
        return
    asset_url = url
    filepath = cfg.cache_dir/asset_url.split('/')[-1]
    Asset(filepath=filepath).download(url=asset_url, force=download_only)
    Checksum(assets=assets, asset_url=asset_url).verify(filepath=filepath)
    if download_only:
        return
    extracted_path = Asset(filepath=filepath).extract(destination=cfg.data_dir)
    extracted_bin = Executables.identify(extracted_path=extracted_path, bin_pattern=bin_pattern)
    repo_id = Repo.parseID(repo_id=repo_id)
    symlinks = Executables(extracted_bin=extracted_bin, repo_id=repo_id).symlink(symlink_alias=symlink_alias)
    meta = {**kwargs, 'repo_id': repo_id, 'asset_url': asset_url, 'asset': str(filepath), 'extracted_path': str(extracted_path), 'extracted_bin': [str(bin) for bin in extracted_bin], 'symlinks': [str(link) for link in symlinks], 'installed': pandas.Timestamp.now('UTC').strftime('%Y-%m-%dT%H:%M:%SZ')}
    Meta().write(metadata={'repo': dict(repo_info), 'tag': dict(tag_info), 'meta': meta})

@app.command('update')
@app.command('upgrade')
def upgrade(repo_id: typing_extensions.Annotated[str, typer.Argument(help=Help.repo_id)],
            confirm: typing_extensions.Annotated[bool, typer.Option('--confirm', '-y', help=Help.confirm)] = False,
            quiet: typing_extensions.Annotated[bool, typer.Option('--quiet', '-q', help=Help.quiet)] = False,
            verbose: typing_extensions.Annotated[bool, typer.Option('--verbose', '-v', help=Help.verbose)] = False):
    '''Upgrade utility to `latest` release.'''
    log.level = logging.ERROR if quiet else cfg.log_level
    log.level = logging.DEBUG if verbose else cfg.log_level
    repo_id = Repo.parseID(repo_id=repo_id)
    beggining_of_time = {'published_at': '1970-01-01T00:00:00Z'}
    metadata = Meta().read(repo_id=repo_id)
    installed_tag = metadata.get('tag', {}).get('tag_name')
    installed_tag_date = pandas.Timestamp(pandas.Series(metadata.get('tag', beggining_of_time))._get(['published_at', 'released_at']))
    latest_tag = Repo(id=repo_id, tag='latest').releaseTag()
    latest_tag_date = pandas.Timestamp(latest_tag._get(['published_at', 'released_at']))
    if installed_tag_date >= latest_tag_date:
        log.info(f"{repo_id} installed tag `{installed_tag}` ({installed_tag_date}) is up to date")
    else:
        log.info(f"updating {repo_id} from `{installed_tag}` ({installed_tag_date}) to `{latest_tag.get('tag_name')}` ({latest_tag_date})")
        uninstall(repo_id=repo_id, confirm=confirm)
        metadata = metadata if metadata else {'meta': {'repo_id': repo_id}}
        kwargs = {k: v for k, v in metadata.get('meta').items() if (k in install.__annotations__.keys()) and (k not in ('confirm', 'download_only', 'quiet', 'verbose'))}
        install(**kwargs, confirm=confirm)

@app.command('update-all')
@app.command('upgrade-all')
def upgrade_all(confirm: typing_extensions.Annotated[bool, typer.Option('--confirm', '-y', help=Help.confirm)] = False,
                quiet: typing_extensions.Annotated[bool, typer.Option('--quiet', '-q', help=Help.quiet)] = False,
                verbose: typing_extensions.Annotated[bool, typer.Option('--verbose', '-v', help=Help.verbose)] = False):
    '''Upgrade all installed utilities (except ones installed from url or from a release tag other than `latest`)'''
    log.level = logging.ERROR if quiet else cfg.log_level
    log.level = logging.DEBUG if verbose else cfg.log_level
    with fileinput.input(files=cfg.metadata_dir.glob('*json'), mode='r') as meta_files:
        metadata = [json.loads(f).get('meta') for f in meta_files]
    _ = [upgrade(repo_id=repo.get('repo_id'), confirm=confirm) for repo in metadata if (repo.get('tag') == 'latest') and (not repo.get('url'))]

@app.command('uninstall')
@app.command('remove')
@app.command('rm')
def uninstall(repo_id: typing_extensions.Annotated[str, typer.Argument(help=Help.repo_id)],
              confirm: typing_extensions.Annotated[bool, typer.Option('--confirm', '-y', help=Help.confirm)] = False,
              quiet: typing_extensions.Annotated[bool, typer.Option('--quiet', '-q', help=Help.quiet)] = False,
              verbose: typing_extensions.Annotated[bool, typer.Option('--verbose', '-v', help=Help.verbose)] = False):
    '''Uninstall utility.'''
    log.level = logging.ERROR if quiet else cfg.log_level
    log.level = logging.DEBUG if verbose else cfg.log_level
    repo_id = Repo.parseID(repo_id=repo_id)
    metadata = Meta().read(repo_id=repo_id).get('meta')
    meta_filepath = cfg.metadata_dir/f"{repo_id.replace('/', '_')}.json"
    if not metadata:
        return log.warning(f'Utility `{repo_id}` does not seem to be installed. Please check if metadata file exists in `{meta_filepath}`')
    logging.info(f"The following symlinks/files/directories will be deleted:\n{str.join(', ', metadata.get('symlinks'))}\n{metadata.get('asset')}\n{metadata.get('extracted_path')}\n{meta_filepath}")
    if confirm or input('Proceed with uninstallation? ').lower() in ('y', 'yes', 'yep'):
        _ = [rm_recursive(path=pathlib.Path(path)) for path in metadata.get('symlinks')]
        rm_recursive(path=pathlib.Path(metadata.get('asset')))
        rm_recursive(path=pathlib.Path(metadata.get('extracted_path')))
        meta_filepath.unlink(missing_ok=True)


def getKeys(obj: pandas.Series, keys: typing.Union[str, typing.List[str]], default_value: typing.Any = None) -> typing.Union[pandas.Series, typing.Any]:
    '''Get existing keys from `pandas.Series` or `pandas.DataFrame`.'''
    # [Pandas .loc without KeyError](https://stackoverflow.com/a/46307319)
    keys = [keys] if isinstance(keys, str) else keys
    idx = [k for k in keys if k in obj.index] if isinstance(obj, pandas.Series) else [k for k in keys if k in obj.columns] if isinstance(obj, pandas.DataFrame) else []
    return obj[idx].squeeze() if idx else default_value

pandas.Series._get = getKeys
pandas.DataFrame._get = getKeys

def parseVersion(version: str) -> packaging.version.Version:
    '''Parse version based on `packaging.version.VERSION_PATTERN`.'''
    pattern = re.compile(pattern=packaging.version.VERSION_PATTERN, flags=(re.VERBOSE|re.IGNORECASE)) # https://packaging.pypa.io/en/stable/version.html#packaging.version.VERSION_PATTERN
    parsed_version = re.search(pattern=pattern, string=version)
    return packaging.version.parse(parsed_version.group(0)) if parsed_version else version

def rm_recursive(path: pathlib.Path):
    '''Remove `path` recursively.''' # [PathLib recursively remove directory?](https://stackoverflow.com/a/66552066)
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    if path.is_dir():
        _ = [rm_recursive(child) for child in path.iterdir()]
        path.rmdir()
    log.debug(f'removed {path}')

def table(data: pandas.DataFrame, title: str = 'Installed Releases') -> rich.table.Table:
    '''Print `data`: pandas.DataFrame as a `rich.table`.''' # [Convert a pandas.DataFrame object into a rich.Table object for stylized printing in Python.](https://gist.github.com/avi-perl/83e77d069d97edbdde188a4f41a015c4)
    table = rich.table.Table(title=title, border_style='blue', header_style='orange1', show_edge=False, row_styles=list(rich.color.ANSI_COLOR_NAMES)[157:])
    [table.add_column(str(col), max_width=60, no_wrap=True) for col in data.columns]
    [table.add_row(*[str(x) for x in val]) for val in data.values]
    return table

def test():
    import time
    for repo_id in ('aristocratos/btop', 'cli/cli', 'wagoodman/dive', 'helix-editor/helix', 'stedolan/jq', 'johnkerl/miller', 'neovim/neovim', 'koalaman/shellcheck', 'categulario/tiempo-rs', 'natecraddock/zf'):
        install(repo_id, confirm=True)
        time.sleep(2)
        # uninstall(repo_id, confirm=True)
    install('moparisthebest/static-curl', symlink_alias='curl', confirm=True)
    install('exiftool/exiftool', url='https://exiftool.org/Image-ExifTool-12.71.tar.gz', confirm=True)
    install('golang/go', url='https://go.dev/dl/go1.20.4.linux-amd64.tar.gz', confirm=True)
    install('charmbracelet/gum', asset_pattern='tar.gz$', confirm=True)
    # install('ImageMagick/ImageMagick', asset_pattern='gcc', confirm=True)
    install('https://github.com/jarun/nnn/releases', asset_pattern='nnn-static', symlink_alias='nnn', confirm=True)
    install('jgm/pandoc', bin_pattern='pandoc$', confirm=True)
    install('stewart/rff', asset_pattern='gnu', confirm=True)
    install('vscodium/vscodium', asset_pattern='VSCodium-linux-x64', bin_pattern='codium', confirm=True)

if __name__ == '__main__':
    app()
