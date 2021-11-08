#!/bin/sh

set -euo pipefail

[ -d build ] && rm -r build
[ -d dist ] && rm -r dist
[ -d improvado_async_hvac.egg-info ] && rm -r improvado_async_hvac.egg-info

python ./setup.py sdist bdist_wheel

twine upload -r improvado dist/* --verbose
