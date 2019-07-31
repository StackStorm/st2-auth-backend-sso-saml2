set -e

install_package() {
  PIP=/opt/stackstorm/st2/bin/pip
  WHEELSDIR=/opt/stackstorm/share/wheels
  ${PIP} install --find-links ${WHEELSDIR} --no-index --quiet --upgrade st2-enterprise-sso-backend
}

install_package
