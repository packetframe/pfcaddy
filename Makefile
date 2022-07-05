all: dep coraza build coraza-conf

dep:
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

coraza:
	rm -rf coraza
	git clone https://github.com/corazawaf/coraza-caddy coraza

	# Enable PCRE for CRS support
	sed -i '/.*coraza-pcre/s/\/\/ //g' coraza/caddy/main.go

coraza-conf:
	curl -sL https://raw.githubusercontent.com/corazawaf/coraza/v2/master/coraza.conf-recommended -O
	curl -sL https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.2.tar.gz -O
	tar -xvzf v3.3.2.tar.gz
	rm v3.3.2.tar.gz
	mv coreruleset-3.3.2 coreruleset

build:
	bash build.sh

clean:
	rm -rf coraza* coreruleset*

release:
	nfpm package --packager deb --config nfpm.yml -t pfcaddy.deb
