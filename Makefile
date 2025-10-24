build:
	go vet
	go build
install: build
	go install
package:
	go build
	mv checkwebcertificate build/checkwebcertificate/usr/bin/
	cd build ; dpkg-deb --root-owner-group --build checkwebcertificate