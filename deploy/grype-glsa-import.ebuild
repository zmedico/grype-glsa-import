# Copyright 2022 Sony Interactive Entertainment Inc.

EAPI=8
GK_PROJ=gitlab.gaikai.org:cgei/releng/grype-glsa-import
inherit gk-dist go-module

DESCRIPTION="Import Gentoo glsa data into a grype database"

SLOT="0"
KEYWORDS=""
BDEPEND=">=dev-lang/go-1.18"

src_unpack() {
	gk-dist_src_unpack
}

src_compile() {
	ego build -o bin/grype-glsa-import
}

src_install() {
	dobin bin/grype-glsa-import
}
