package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"os"
	"github.com/anchore/grype/grype/db/v3"
	"github.com/anchore/grype/grype/db/v3/store"
)

var (
	// Exclude this one because it's prone to false-positives.
	excludeList = []string{}
)

type Vulnerable struct {
	Range string `xml:"range,attr"`
	Version string `xml:",chardata"`
}

type Package struct {
	Vulnerable []Vulnerable `xml:"vulnerable"`
	Name string `xml:"name,attr"`
}

type Affected struct {
	Packages []Package `xml:"package"`
}

type Impact struct {
	Type string `xml:"type,attr"`
}

type Uri struct {
	Link string `xml:"link,attr"`
	Description string `xml:",chardata"`
}

type References struct {
	Uris []Uri `xml:"uri"`
}

type Glsa struct {
	Id       string `xml:"id,attr"`
	Title    string `xml:"title"`
	Synopsis string `xml:"synopsis"`
	Affected Affected `xml:"affected"`
	Impact Impact `xml:"impact"`
	References References `xml:"references"`
}

func errPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: glsa-import <glsa_dir> <db_path>")
	}
	dbPath := os.Args[2]
	st, err := store.New(dbPath, false)
	errPanic(err)

	glsaDir := os.Args[1]
	files, err := os.ReadDir(glsaDir)
	errPanic(err)

	// Match CVE references. Also match CAN references from 2005 and earlier,
	// and translate them to CVE references.
	cveRegex := regexp.MustCompile(`C(AN|VE)-(\d{4}-\d+)`)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".xml") {
			continue
		}
		xmlFile, err := os.Open(fmt.Sprintf("%s/%s", glsaDir, file.Name()))
		errPanic(err)
		byteValue, err := io.ReadAll(xmlFile)
		errPanic(err)
		xmlFile.Close()

		var glsa Glsa
		xml.Unmarshal(byteValue, &glsa)

		glsaId := "GLSA-" + glsa.Id

		exclude := false
		for _, excludeId := range excludeList {
			if excludeId == glsaId {
				exclude = true
				break
			}
		}
		if exclude {
			continue
		}

		severity := ""
		switch impact := glsa.Impact.Type; impact {
		case "minimal":
			severity = "Negligible"
		case "low":
			severity = "Low"
		case  "normal":
			severity = "Medium"
		case  "medium":
			severity = "Medium"
		case "high":
			severity = "High"
		default:
			severity = ""
		}
		if severity == "" {
			log.Panicf("unrecognized impact type: %s", glsa.Impact.Type)
		}

		var relatedVulns []v3.VulnerabilityReference
		for _, uri := range glsa.References.Uris {
			cveMatch := cveRegex.FindStringSubmatch(uri.Description)
			if cveMatch != nil {
				cveId := fmt.Sprintf("CVE-%s", cveMatch[2])
				vulnRef := v3.VulnerabilityReference{ID: cveId, Namespace: "nvd"}
				vulnMetadata, err := st.GetVulnerabilityMetadata(vulnRef.ID, vulnRef.Namespace)
				errPanic(err)
				if vulnMetadata != nil {
					relatedVulns = append(relatedVulns, vulnRef)
				}
			}
		}

		for _, p := range glsa.Affected.Packages {
			if len(p.Vulnerable) != 1 {
				continue
			}

			operator := ""
			switch op := p.Vulnerable[0].Range; op {
			case "lt":
				operator = "<"
			case  "le":
				operator = "<="
			case "eq":
				operator = "="
			// case "rle":
			// 	operator = "<=~"
			//} case "rlt":
			//	operator = "<~"
			}
			if operator == "" {
				continue
			}

			vuln := v3.Vulnerability{
				ID: glsaId,
				PackageName: p.Name,
				Namespace: "gentoo:",
				VersionConstraint: operator + " " + p.Vulnerable[0].Version,
				VersionFormat: "portage",
				CPEs: nil,
				RelatedVulnerabilities: relatedVulns,
				Fix: v3.Fix{
					Versions: []string{},
					State: v3.FixedState,
				},
				Advisories: []v3.Advisory{},
			}
			err = st.AddVulnerability(vuln)
			errPanic(err)
		}

		vulnMetadata := v3.VulnerabilityMetadata{
			ID: glsaId,
			Namespace: "gentoo:",
			DataSource: fmt.Sprintf("https://security.gentoo.org/glsa/%s", glsa.Id),
			RecordSource: "",
			Severity: severity,
			URLs: []string{fmt.Sprintf("https://security.gentoo.org/glsa/%s", glsa.Id)},
			Description: glsa.Synopsis,
			Cvss: []v3.Cvss{},
		}
		err = st.AddVulnerabilityMetadata(vulnMetadata)
		errPanic(err)
	}
}
