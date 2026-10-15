"""Resolve the latest official stable template release once per CI run."""
import json
import os
import re
import urllib.request


def github(path):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'network-mapping-scanner-build'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    request = urllib.request.Request('https://api.github.com/repos/projectdiscovery/nuclei-templates/' + path,
                                     headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def resolve():
    release = github('releases/latest')
    version = release['tag_name']
    assert not release['draft'] and not release['prerelease'], 'Expected a stable template release'
    assert re.fullmatch(r'v\d+\.\d+\.\d+', version), 'Invalid template release tag'
    reference = github('git/ref/tags/' + version)['object']
    if reference['type'] == 'tag':
        reference = github('git/tags/' + reference['sha'])['object']
    assert reference['type'] == 'commit', 'Template release must resolve to a commit'
    revision = reference['sha']
    assert re.fullmatch(r'[a-f0-9]{40}', revision), 'Invalid template revision'
    return {'templates_version': version, 'templates_revision': revision}


if __name__ == '__main__':
    result = resolve()
    output = ''.join(f'{key}={value}\n' for key, value in result.items())
    print(output, end='')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(output)
