all: dep clean conf build

dep:
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

conf:
	git clone https://github.com/coreruleset/coreruleset
	wget https://raw.githubusercontent.com/corazawaf/coraza/v2/master/coraza.conf-recommended

build:
	xcaddy build --with packetframe_httpgate=./httpgate

clean:
	rm -rf coraza* coreruleset*

release:
	nfpm package --packager deb --config nfpm.yml -t pfcaddy.deb

run:
	./caddy run --config Caddyfile
