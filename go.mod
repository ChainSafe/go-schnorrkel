module github.com/ChainSafe/go-schnorrkel

go 1.19

require (
	github.com/cosmos/go-bip39 v0.0.0-20180819234021-555e2067c45d
	github.com/gtank/merlin v0.1.1-0.20191105220539-8318aed1a79f
	github.com/gtank/ristretto255 v0.1.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20191206172530-e9b2fee46413
)

require (
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20181016162300-f8f6d4d2b643 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect
	gopkg.in/yaml.v2 v2.2.2 // indirect
)

replace gopkg.in/yaml.v2 => github.com/go-yaml/yaml/v2 v2.2.2
