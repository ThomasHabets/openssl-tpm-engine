
%define name            openssl-tpm-engine
%define version         0.4.2
%define release         1

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        OpenSSL engine and tools to interface with the TSS API

Group:          Applications/System
License:        OpenSSL
URL:            http://sourceforge.net/projects/trousers/files/OpenSSL%20TPM%20Engine/
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  autoconf automake libtool openssl-devel

%description
This package contains 2 sets of code, a command-line utility used to
generate a TSS key blob and write it to disk and an OpenSSL engine which
interfaces with the TSS API.

%prep
%setup -q


%build
sh bootstrap.sh
sh configure --with-openssl=/usr --prefix=/usr
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
if [ "$RPM_BUILD_ROOT/usr/lib" != "$RPM_BUILD_ROOT/%{_libdir}" ]; then
	mkdir -p $RPM_BUILD_ROOT/%{_libdir}
	cp -R $RPM_BUILD_ROOT/usr/lib/* $RPM_BUILD_ROOT/%{_libdir}/
	rm -fr $RPM_BUILD_ROOT/usr/lib
fi


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc LICENSE README
%{_libdir}/openssl/engines/libtpm.so.0.0.0
%{_libdir}/openssl/engines/libtpm.so
%{_libdir}/openssl/engines/libtpm.so.0
%{_libdir}/openssl/engines/libtpm.la
%{_bindir}/create_tpm_key

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Thu Feb 27 2014 Jan Schaumann <jschauma@netmeister.org> - 0.4.2-1
- initial rpm spec file, pulling sources of 0.4.2 from
