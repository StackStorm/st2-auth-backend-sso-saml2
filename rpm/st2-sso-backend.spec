%define pkg_version %(python setup.py --version 2>/dev/null)
%define version %(echo "${PKG_VERSION:-%{pkg_version}}")
#define epoch %(_epoch=`echo %{version} | grep -q dev || echo 1`; echo "${_epoch:-0}")
%define release %(echo "${PKG_RELEASE:-1}")
%define st2dir /opt/stackstorm
%define st2wheels %{st2dir}/share/wheels
%define pip %{st2dir}/st2/bin/pip

Name:           st2-sso-backend
Version:        %{version}
%if 0%{?epoch}
Epoch: %{epoch}
%endif
Release:        %{release}
License:        Extreme Workflow Composer EULA
Summary:        SSO Backend for EWC
URL:            https://www.extremenetworks.com/product/workflow-composer/
Source0:        st2-enterprise-sso-backend

Requires: st2

%define _builddir %(pwd)
%define _rpmdir %(pwd)/build

%description
  SSO Backend for Extreme Workflow Composer

%prep
  rm -rf %{buildroot}
  mkdir -p %{buildroot}

%build
  make

%install
  %make_install

%clean
  rm -rf %{buildroot}

%post
  %{pip} install --find-links %{st2wheels} --no-index --quiet --upgrade st2-enterprise-sso-backend

%postun
  if [ $1 -eq 0 ]; then
    %{pip} uninstall -y --quiet st2-enterprise-sso-backend 1>/dev/null || :
  fi

%files
  %doc rpm/LICENSE
  %{st2wheels}/*
