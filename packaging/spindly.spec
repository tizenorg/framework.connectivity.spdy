Name:       spindly
Summary:    SPDY Protocol Library
Version:    0.0.10
Release:    1
Group:      TO_BE/FILLED_IN
License:    BSD-2.0
Source0:    spindly-%{version}.tar.gz

BuildRequires:  pkgconfig(zlib)
BuildRequires:  pkgconfig(check)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(libssl)
#BuildRequires:  pkgconfig(libtool)
BuildRequires:  libtool
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
SPDY Protocol libraryXB-Public-Package: no


%package devel
Summary:    Development files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
%description devel
Development files for %{name}


%prep
%setup -q


%build
./buildconf
./configure --prefix=/usr
make %{?jobs:-j%jobs}
#cp spindly.pc /usr/lib/pkgconfig -rf
#cp include/*.h /usr/include -rf

%install
rm -rf %{buildroot}
%make_install
rm -rf %{buildroot}/usr/lib/spindly
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig




%files
%defattr(-,root,root,-)
/usr/lib/*.so.*
/usr/share/license/%{name}
%manifest spindly.manifest

%files devel
%defattr(-,root,root,-)
/usr/lib/*.so
%{_libdir}/pkgconfig/spindly.pc
#%{_includedir}/*.h
/usr/include/spindly/spindly.h
