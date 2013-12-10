# Copyright © 2013 by its contributors. See AUTHORS for details.
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

ROOT=$(shell pwd)
CACHE=${ROOT}/.cache
PYENV=${ROOT}/.pyenv
CONF=${ROOT}/conf
APP_NAME=coinjoin
PACKAGE=coinjoin

-include Makefile.local

.PHONY: all
all: python-env

.PHONY: check
check: all
	mkdir -p build/report/xunit
	@echo  >.pytest.py "import unittest2"
	@echo >>.pytest.py "import xmlrunner"
	@echo >>.pytest.py "unittest2.main("
	@echo >>.pytest.py "    testRunner=xmlrunner.XMLTestRunner("
	@echo >>.pytest.py "        output='build/report/xunit'),"
	@echo >>.pytest.py "    argv=['unit2', 'discover',"
	@echo >>.pytest.py "        '-s','xunit',"
	@echo >>.pytest.py "        '-p','*.py',"
	@echo >>.pytest.py "        '-t','.',"
	@echo >>.pytest.py "    ]"
	@echo >>.pytest.py ")"
	chmod +x .pytest.py
	"${PYENV}"/bin/coverage run .pytest.py || { rm -f .pytest.py; exit 1; }
	"${PYENV}"/bin/coverage xml --omit=".pytest.py" -o build/report/coverage.xml
	-rm -f .pytest.py

.PHONY: debugcheck
debugcheck: all
	mkdir -p build/report/xunit
	@echo  >.pytest.py "import unittest2"
	@echo >>.pytest.py "import xmlrunner"
	@echo >>.pytest.py "import exceptions, ipdb, sys"
	@echo >>.pytest.py "class PDBAssertionError(exceptions.AssertionError):"
	@echo >>.pytest.py "    def __init__(self, *args):"
	@echo >>.pytest.py "        exceptions.AssertionError.__init__(self, *args)"
	@echo >>.pytest.py "        print 'Assertion failed, entering PDB...'"
	@echo >>.pytest.py "        if hasattr(sys, '_getframe'):"
	@echo >>.pytest.py "            ipdb.set_trace(sys._getframe().f_back.f_back.f_back)"
	@echo >>.pytest.py "        else:"
	@echo >>.pytest.py "            ipdb.set_trace()"
	@echo >>.pytest.py "unittest2.TestCase.failureException = PDBAssertionError"
	@echo >>.pytest.py "unittest2.main("
	@echo >>.pytest.py "    testRunner=xmlrunner.XMLTestRunner("
	@echo >>.pytest.py "        output='build/report/xunit'),"
	@echo >>.pytest.py "    argv=['unit2', 'discover',"
	@echo >>.pytest.py "        '-s','xunit',"
	@echo >>.pytest.py "        '-p','*.py',"
	@echo >>.pytest.py "        '-t','.',"
	@echo >>.pytest.py "    ]"
	@echo >>.pytest.py ")"
	@chmod +x .pytest.py
	"${PYENV}"/bin/coverage run .pytest.py || { rm -f .pytest.py; exit 1; }
	"${PYENV}"/bin/coverage xml --omit=".pytest.py" -o build/report/coverage.xml
	rm -f .pytest.py

.PHONY: shell
shell: all
	"${PYENV}"/bin/ipython

.PHONY: mostlyclean
mostlyclean:
	-rm -rf dist
	-rm -rf build
	-rm -rf .coverage

.PHONY: clean
clean: mostlyclean
	-rm -rf "${PYENV}"

.PHONY: distclean
distclean: clean
	-rm -rf "${CACHE}"
	-rm -rf Makefile.local

.PHONY: maintainer-clean
maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'

# ===--------------------------------------------------------------------===

.PHONY: dist
dist:
	"${PYENV}"/bin/python setup.py sdist

# ===--------------------------------------------------------------------===

${CACHE}/virtualenv/virtualenv-1.10.tar.gz:
	mkdir -p "${CACHE}"/virtualenv
	curl -L 'https://pypi.python.org/packages/source/v/virtualenv/virtualenv-1.10.tar.gz' >'$@' || { rm -f '$@'; exit 1; }

${CACHE}/pyenv-1.10-base.tar.gz: ${CACHE}/virtualenv/virtualenv-1.10.tar.gz
	-rm -rf "${PYENV}"
	mkdir -p "${PYENV}"
	
	# virtualenv is used to create a separate Python installation
	# for this project in ${PYENV}.
	tar \
	    -C "${CACHE}"/virtualenv --gzip \
	    -xf "${CACHE}"/virtualenv/virtualenv-1.10.tar.gz
	python "${CACHE}"/virtualenv/virtualenv-1.10/virtualenv.py \
	    --clear \
	    --distribute \
	    --never-download \
	    --prompt="(${APP_NAME}) " \
	    "${PYENV}"
	-rm -rf "${CACHE}"/virtualenv/virtualenv-1.10
	
	# Snapshot the Python environment
	tar -C "${PYENV}" --gzip -cf "$@" .
	rm -rf "${PYENV}"

${CACHE}/pyenv-1.10-extras.tar.gz: ${CACHE}/pyenv-1.10-base.tar.gz ${ROOT}/requirements.txt ${CONF}/requirements*.txt
	-rm -rf "${PYENV}"
	mkdir -p "${PYENV}"
	mkdir -p "${CACHE}"/pypi
	
	# Uncompress saved Python environment
	tar -C "${PYENV}" --gzip -xf "${CACHE}"/pyenv-1.10-base.tar.gz
	find "${PYENV}" -not -type d -print0 >"${ROOT}"/.pkglist
	
	# readline is installed here to get around a bug on Mac OS X
	# which is causing readline to not build properly if installed
	# from pip, and the fact that a different package must be used
	# to support it on Windows/Cygwin.
	if [ "x`uname -o`" == "xCygwin" ]; then \
	    "${PYENV}"/bin/pip install pyreadline; \
	else \
	    "${PYENV}"/bin/easy_install readline; \
	fi
	
	# pip is used to install Python dependencies for this project.
	for reqfile in "${ROOT}"/requirements.txt \
	               "${CONF}"/requirements*.txt; do \
	    CFLAGS=-I/opt/local/include LDFLAGS=-L/opt/local/lib \
	    "${PYENV}"/bin/python "${PYENV}"/bin/pip install \
	        --download-cache="${CACHE}"/pypi \
	        -r "$$reqfile" || exit 1; \
	done
	
	# Snapshot the Python environment
	cat "${ROOT}"/.pkglist | xargs -0 rm -rf
	tar -C "${PYENV}" --gzip -cf "$@" .
	rm -rf "${PYENV}" "${ROOT}"/.pkglist

.PHONY:
python-env: ${PYENV}/.stamp-h

${PYENV}/.stamp-h: ${CACHE}/pyenv-1.10-base.tar.gz ${CACHE}/pyenv-1.10-extras.tar.gz
	-rm -rf "${PYENV}"
	mkdir -p "${PYENV}"
	
	# Uncompress saved Python environment
	tar -C "${PYENV}" --gzip -xf "${CACHE}"/pyenv-1.10-base.tar.gz
	tar -C "${PYENV}" --gzip -xf "${CACHE}"/pyenv-1.10-extras.tar.gz
	
	# All done!
	touch "$@"
