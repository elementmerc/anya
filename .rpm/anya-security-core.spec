%define __spec_install_post %{nil}
%define debug_package %{nil}

Name: anya
Summary: Fast static malware analysis tool
Version: @@VERSION@@
Release: 1%{?dist}
License: AGPL-3.0-or-later
Group: Development/Tools
URL: https://github.com/elementmerc/anya

%description
Anya performs static analysis on binary files (PE, ELF) to identify
suspicious characteristics without executing them. Analysis covers
cryptographic hashes, Shannon entropy, string extraction, PE and ELF
structure parsing, import table analysis, MITRE ATT&CK technique
mapping, and more.

%install
mkdir -p %{buildroot}/usr/bin
install -m 755 %{_topdir}/../target/release/anya %{buildroot}/usr/bin/anya

%files
/usr/bin/anya
